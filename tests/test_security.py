"""Tests for the security fixes: no plaintext SSH password persistence,
config file permission hardening, no default SSH user, SSH host-key policy,
and the CLI scan-authorization gate.
"""

import os
import stat
import sys
from unittest.mock import patch, MagicMock

import pytest

import pynetworkintel.config as config_module
from pynetworkintel.config import ConfigManager, SSHConfig, AppConfig
from pynetworkintel.discovery.ssh_config import SSHConfigGrabber
from pynetworkintel.models import Device


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Point ConfigManager at a throwaway directory instead of ~/.pynetworkintel."""
    config_dir = tmp_path / ".pynetworkintel"
    config_file = config_dir / "config.yaml"
    monkeypatch.setattr(config_module, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)
    return config_dir, config_file


class TestSSHConfigDefaults:
    def test_no_default_username(self):
        ssh = SSHConfig()
        assert ssh.username is None

    def test_to_dict_excludes_password(self):
        ssh = SSHConfig(username="admin", password="super-secret")
        data = ssh.to_dict()
        assert "password" not in data
        assert data["username"] == "admin"


class TestConfigPersistence:
    def test_save_config_does_not_write_password_to_disk(self, isolated_config):
        config_dir, config_file = isolated_config
        manager = ConfigManager()

        app_config = AppConfig()
        app_config.ssh = SSHConfig(username="admin", password="hunter2")
        manager.save_config(app_config)

        contents = config_file.read_text()
        assert "hunter2" not in contents
        assert "password" not in contents

    def test_save_config_sets_restrictive_permissions(self, isolated_config):
        config_dir, config_file = isolated_config
        manager = ConfigManager()
        manager.save_config(AppConfig())

        mode = stat.S_IMODE(os.stat(config_file).st_mode)
        assert mode == 0o600

    def test_loading_config_never_populates_password_from_disk(self, isolated_config, tmp_path):
        config_dir, config_file = isolated_config
        config_dir.mkdir(parents=True, exist_ok=True)
        # Simulate an old/hand-edited config file that still has a password in it
        config_file.write_text("ssh:\n  username: admin\n  password: leaked-secret\n")

        manager = ConfigManager()
        assert manager.config.ssh.password is None
        assert manager.config.ssh.username == "admin"

    def test_update_from_env_reads_password_from_env_var_only(self, isolated_config, monkeypatch):
        monkeypatch.setenv("PYNETWORKINTEL_SSH_PASSWORD", "env-secret")
        manager = ConfigManager()
        manager.update_from_env()
        assert manager.config.ssh.password == "env-secret"


class TestSSHHostKeyPolicy:
    def test_connect_uses_warning_policy_not_auto_add(self):
        grabber = SSHConfigGrabber(username="admin", password="x")

        with patch("paramiko.SSHClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            grabber._connect("10.0.0.1", timeout=5)

            mock_client.set_missing_host_key_policy.assert_called_once()
            policy_arg = mock_client.set_missing_host_key_policy.call_args[0][0]
            import paramiko

            assert isinstance(policy_arg, paramiko.WarningPolicy)
            assert not isinstance(policy_arg, paramiko.AutoAddPolicy)


class TestSSHGrabberRequiresUsername:
    def test_grab_configs_skips_when_no_username_configured(self):
        grabber = SSHConfigGrabber(username=None, password="irrelevant")
        device = Device(ip="10.0.0.5")

        with patch("paramiko.SSHClient") as mock_client_cls:
            result = grabber.grab_configs(device)

        assert result is False
        mock_client_cls.assert_not_called()

    def test_grab_configs_proceeds_when_username_configured(self):
        grabber = SSHConfigGrabber(username="admin", password="x")
        device = Device(ip="10.0.0.5")

        with patch.object(grabber, "_connect") as mock_connect, \
             patch.object(grabber, "_grab_linux_configs"):
            mock_connect.return_value = MagicMock()
            result = grabber.grab_configs(device)

        assert result is True
        mock_connect.assert_called_once()


class TestCLIAuthorizationGate:
    def _make_args(self, i_am_authorized=False):
        ns = MagicMock()
        ns.i_am_authorized = i_am_authorized
        return ns

    def test_flag_bypasses_prompt(self):
        from pynetworkintel.cli import confirm_authorization

        args = self._make_args(i_am_authorized=True)
        with patch("builtins.input") as mock_input:
            assert confirm_authorization("192.168.1.0/24", args) is True
        mock_input.assert_not_called()

    def test_env_var_bypasses_prompt(self, monkeypatch):
        from pynetworkintel.cli import confirm_authorization, AUTH_ENV_VAR

        monkeypatch.setenv(AUTH_ENV_VAR, "1")
        args = self._make_args(i_am_authorized=False)
        with patch("builtins.input") as mock_input:
            assert confirm_authorization("192.168.1.0/24", args) is True
        mock_input.assert_not_called()

    def test_non_tty_without_flag_refuses(self, monkeypatch):
        from pynetworkintel.cli import confirm_authorization

        monkeypatch.delenv("PYNETWORKINTEL_I_AM_AUTHORIZED", raising=False)
        args = self._make_args(i_am_authorized=False)
        with patch("sys.stdin.isatty", return_value=False):
            assert confirm_authorization("192.168.1.0/24", args) is False

    def test_interactive_yes_confirms(self, monkeypatch):
        from pynetworkintel.cli import confirm_authorization

        monkeypatch.delenv("PYNETWORKINTEL_I_AM_AUTHORIZED", raising=False)
        args = self._make_args(i_am_authorized=False)
        with patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            assert confirm_authorization("192.168.1.0/24", args) is True

    def test_interactive_no_refuses(self, monkeypatch):
        from pynetworkintel.cli import confirm_authorization

        monkeypatch.delenv("PYNETWORKINTEL_I_AM_AUTHORIZED", raising=False)
        args = self._make_args(i_am_authorized=False)
        with patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            assert confirm_authorization("192.168.1.0/24", args) is False

    def test_interactive_empty_response_refuses(self, monkeypatch):
        from pynetworkintel.cli import confirm_authorization

        monkeypatch.delenv("PYNETWORKINTEL_I_AM_AUTHORIZED", raising=False)
        args = self._make_args(i_am_authorized=False)
        with patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", side_effect=EOFError):
            assert confirm_authorization("192.168.1.0/24", args) is False


class TestCLINoSSHPasswordFlag:
    def test_ssh_password_flag_not_registered(self):
        """--ssh-password must not exist as a CLI flag (would leak into shell
        history / process listings). --ssh-key and the env var are the only
        supported ways to authenticate with a password/key."""
        import pynetworkintel.cli as cli

        parser = cli.argparse.ArgumentParser()
        # Re-parse a scan command line and ensure --ssh-password is unrecognized
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["pynetworkintel", "scan", "10.0.0.1", "--ssh-password", "x"]):
                cli.main()

    def test_ssh_user_has_no_default(self):
        """`pynetworkintel scan <target>` without --ssh-user must resolve to
        ssh_user=None (previously defaulted to "root")."""
        import pynetworkintel.cli as cli

        argv_backup = sys.argv
        try:
            sys.argv = ["pynetworkintel", "scan", "10.0.0.1", "--i-am-authorized"]
            with patch("pynetworkintel.cli.handle_scan") as mock_handle:
                mock_handle.return_value = 0
                cli.main()
                called_args = mock_handle.call_args[0][0]
                assert called_args.ssh_user is None
        finally:
            sys.argv = argv_backup

"""SSH-based configuration retrieval from devices."""

import logging
from typing import Optional, List, Dict, Any
import paramiko
from paramiko.ssh_exception import SSHException, AuthenticationException

from pynetworkintel.models import Device

logger = logging.getLogger(__name__)


class SSHConfigGrabber:
    """Grab configuration files from remote devices via SSH."""

    def __init__(self, username: str, key_path: Optional[str] = None, password: Optional[str] = None):
        self.username = username
        self.key_path = key_path
        self.password = password

    def grab_configs(self, device: Device, timeout: int = 10) -> bool:
        """
        Connect to device and grab configuration files.

        Args:
            device: Device to grab configs from
            timeout: SSH connection timeout in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            client = self._connect(device.ip, timeout)
            self._grab_linux_configs(client, device)
            client.close()
            return True

        except (SSHException, AuthenticationException, Exception) as e:
            logger.warning(f"Failed to grab configs from {device.ip}: {e}")
            return False

    def _connect(self, ip: str, timeout: int) -> paramiko.SSHClient:
        """Establish SSH connection to device."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.key_path:
            client.connect(
                ip,
                username=self.username,
                key_filename=self.key_path,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        elif self.password:
            client.connect(
                ip,
                username=self.username,
                password=self.password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        else:
            raise ValueError("Either key_path or password must be provided")

        return client

    def _grab_linux_configs(self, client: paramiko.SSHClient, device: Device):
        """Grab configuration files from Linux/Unix device."""
        configs_to_grab = [
            "/etc/ssh/sshd_config",
            "/etc/sysctl.conf",
            "/etc/hostname",
            "/etc/os-release",
        ]

        for config_path in configs_to_grab:
            content = self._read_file(client, config_path)
            if content:
                device.add_config(config_path, content, "linux")

        # Try to grab firewall rules (iptables)
        iptables = self._run_command(client, "sudo iptables -L -v -n 2>/dev/null || iptables -L -v -n 2>/dev/null")
        if iptables:
            device.add_config("/etc/iptables/rules", iptables, "linux")

        # Try to grab firewall rules (firewalld)
        firewalld = self._run_command(client, "sudo firewall-cmd --list-all 2>/dev/null || firewall-cmd --list-all 2>/dev/null")
        if firewalld:
            device.add_config("/etc/firewalld/config", firewalld, "linux")

    def _read_file(self, client: paramiko.SSHClient, path: str) -> Optional[str]:
        """Read file from remote device."""
        try:
            sftp = client.open_sftp()
            with sftp.file(path, "r") as f:
                content = f.read().decode("utf-8", errors="replace")
            sftp.close()
            return content
        except Exception as e:
            logger.debug(f"Could not read {path}: {e}")
            return None

    def _run_command(self, client: paramiko.SSHClient, cmd: str) -> Optional[str]:
        """Run command on remote device and return output."""
        try:
            _, stdout, stderr = client.exec_command(cmd, timeout=10)
            output = stdout.read().decode("utf-8", errors="replace")
            return output if output.strip() else None
        except Exception as e:
            logger.debug(f"Could not run command '{cmd}': {e}")
            return None

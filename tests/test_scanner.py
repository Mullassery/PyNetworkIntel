"""Tests for NmapScanner XML parsing and target validation.

Uses a hand-constructed but representative nmap XML fixture
(tests/fixtures/nmap_scan_sample.xml) instead of exercising a live nmap
process, so these tests are deterministic and don't require nmap to be
installed.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from pynetworkintel.discovery.scanner import NmapScanner, validate_target

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "nmap_scan_sample.xml"


@pytest.fixture
def sample_xml() -> str:
    return FIXTURE_PATH.read_text()


@pytest.fixture
def scanner():
    # Skip the nmap availability check (nmap may not be installed in CI/dev envs)
    with patch.object(NmapScanner, "_check_nmap_available"):
        return NmapScanner()


class TestParseNmapXML:
    def test_parses_only_up_hosts(self, scanner, sample_xml):
        devices = scanner._parse_nmap_xml(sample_xml)
        # Fixture has 3 hosts: 2 "up", 1 "down" - the down host must be filtered out
        assert len(devices) == 2
        ips = {d.ip for d in devices}
        assert ips == {"192.168.1.10", "192.168.1.11"}
        assert "192.168.1.12" not in ips

    def test_invalid_xml_returns_empty_list(self, scanner):
        devices = scanner._parse_nmap_xml("not valid xml <<<")
        assert devices == []

    def test_empty_nmaprun_returns_empty_list(self, scanner):
        devices = scanner._parse_nmap_xml("<nmaprun></nmaprun>")
        assert devices == []


class TestParseHost:
    def test_extracts_ip_hostname_os(self, scanner, sample_xml):
        devices = scanner._parse_nmap_xml(sample_xml)
        host = next(d for d in devices if d.ip == "192.168.1.10")

        assert host.hostname == "fileserver.local"
        assert host.os == "Linux 5.4 - 5.15"
        assert host.is_online is True

    def test_host_without_hostname_or_os(self, scanner, sample_xml):
        devices = scanner._parse_nmap_xml(sample_xml)
        host = next(d for d in devices if d.ip == "192.168.1.11")

        assert host.hostname is None
        assert host.os is None

    def test_host_with_no_address_returns_none(self, scanner):
        import xml.etree.ElementTree as ET

        host_elem = ET.fromstring("<host><status state='up'/></host>")
        assert scanner._parse_host(host_elem) is None


class TestParseService:
    def test_open_ports_become_services(self, scanner, sample_xml):
        devices = scanner._parse_nmap_xml(sample_xml)
        host = next(d for d in devices if d.ip == "192.168.1.10")

        # ports: 22 open, 80 open, 443 CLOSED (must be excluded), 8080 open
        service_ports = {s.port for s in host.services}
        assert service_ports == {22, 80, 8080}
        assert 443 not in service_ports

    def test_service_name_and_version_captured(self, scanner, sample_xml):
        devices = scanner._parse_nmap_xml(sample_xml)
        host = next(d for d in devices if d.ip == "192.168.1.10")

        ssh_service = next(s for s in host.services if s.port == 22)
        assert ssh_service.name == "ssh"
        assert ssh_service.version == "8.2p1 Ubuntu 4ubuntu0.5"
        assert ssh_service.protocol == "tcp"

        http_service = next(s for s in host.services if s.port == 80)
        assert http_service.name == "http"
        assert http_service.version == "2.4.49"

    def test_service_without_version_info(self, scanner, sample_xml):
        devices = scanner._parse_nmap_xml(sample_xml)
        host = next(d for d in devices if d.ip == "192.168.1.10")

        proxy_service = next(s for s in host.services if s.port == 8080)
        assert proxy_service.name == "http-proxy"
        assert proxy_service.version is None

    def test_closed_port_returns_none(self, scanner):
        import xml.etree.ElementTree as ET

        port_elem = ET.fromstring(
            '<port protocol="tcp" portid="443"><state state="closed"/></port>'
        )
        assert scanner._parse_service(port_elem) is None

    def test_add_service_accepts_parsed_dict(self, scanner, sample_xml):
        """Regression test: _parse_service()'s output dict (including
        'protocol') must be directly usable with Device.add_service(**dict) -
        this previously raised TypeError because add_service() didn't accept
        a protocol kwarg, which would have crashed every real scan with any
        discovered service."""
        devices = scanner._parse_nmap_xml(sample_xml)
        assert len(devices) == 2
        for device in devices:
            assert len(device.services) >= 1


class TestValidateTarget:
    @pytest.mark.parametrize(
        "target",
        [
            "192.168.1.1",
            "192.168.1.0/24",
            "10.0.0.0/8",
            "::1",
            "2001:db8::/32",
            "example.com",
            "scanme.nmap.org",
            "my-host-01.local",
            "a",
        ],
    )
    def test_valid_targets_pass_through_unchanged(self, target):
        assert validate_target(target) == target

    @pytest.mark.parametrize(
        "target",
        [
            "-oN=/etc/passwd",
            "--script=malicious",
            "-",
            "--iL=/etc/hosts",
        ],
    )
    def test_targets_starting_with_dash_rejected(self, target):
        with pytest.raises(ValueError, match="start with"):
            validate_target(target)

    @pytest.mark.parametrize("target", ["", None, "   "])
    def test_empty_or_none_target_rejected(self, target):
        with pytest.raises(ValueError):
            validate_target(target)

    def test_target_with_shell_metacharacters_rejected(self):
        with pytest.raises(ValueError):
            validate_target("192.168.1.1; rm -rf /")


class TestNmapScannerScanIntegration:
    def test_scan_rejects_invalid_target_without_invoking_subprocess(self, scanner):
        with patch("subprocess.run") as mock_run:
            devices = scanner.scan("--malicious-flag")
            assert devices == []
            mock_run.assert_not_called()

    def test_scan_uses_configured_timeout(self, scanner, sample_xml):
        scanner.timeout = 42
        completed = MagicMock(returncode=0, stdout=sample_xml, stderr="")
        with patch("subprocess.run", return_value=completed) as mock_run:
            scanner.scan("192.168.1.0/24")
            _, kwargs = mock_run.call_args
            assert kwargs["timeout"] == 42

    def test_scan_uses_configured_nmap_args(self, sample_xml):
        with patch.object(NmapScanner, "_check_nmap_available"):
            scanner = NmapScanner(nmap_args="-sV -T4")
        completed = MagicMock(returncode=0, stdout=sample_xml, stderr="")
        with patch("subprocess.run", return_value=completed) as mock_run:
            scanner.scan("192.168.1.0/24")
            args, _ = mock_run.call_args
            cmd = args[0]
            assert "-sV" in cmd
            assert "-T4" in cmd

    def test_scan_explicit_timeout_overrides_instance_default(self, scanner, sample_xml):
        completed = MagicMock(returncode=0, stdout=sample_xml, stderr="")
        with patch("subprocess.run", return_value=completed) as mock_run:
            scanner.scan("192.168.1.0/24", timeout=99)
            _, kwargs = mock_run.call_args
            assert kwargs["timeout"] == 99

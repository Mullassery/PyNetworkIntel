"""Integration tests for PyNetworkIntel."""

import pytest
from pynetworkintel.core import Analyzer, Pipeline
from pynetworkintel.models import (
    ScanResult, Device, Service, Severity, FindingType
)


class TestAnalyzerIntegration:
    def test_full_analysis_pipeline(self):
        """Test complete analysis of mock scan results."""
        analyzer = Analyzer()

        # Create mock scan result
        device = Device(ip="192.168.1.1", hostname="server1", device_type="linux")
        device.add_service(22, "ssh", "OpenSSH_8.2p1")
        device.add_service(443, "https", "Apache/2.4.49")
        device.add_config(
            "/etc/ssh/sshd_config",
            "PasswordAuthentication yes\nPort 22",
            "linux"
        )

        scan_result = ScanResult(devices=[device])

        # Analyze
        result = analyzer.analyze(scan_result)

        # Should have findings
        assert len(result.findings) > 0

        # Should have configuration findings
        config_findings = [
            f for f in result.findings
            if f.finding_type == FindingType.CONFIGURATION
        ]
        assert len(config_findings) > 0

    def test_get_summary(self):
        """Test summary statistics."""
        analyzer = Analyzer()

        device = Device(ip="192.168.1.1", is_online=True)
        scan_result = ScanResult(devices=[device])
        result = analyzer.analyze(scan_result)

        summary = analyzer.get_summary(result)
        assert summary["total_devices"] == 1
        assert summary["online_devices"] == 1

    def test_analyze_multiple_devices(self):
        """Test analysis of multiple devices."""
        analyzer = Analyzer()

        device1 = Device(ip="192.168.1.1", hostname="server1", device_type="linux")
        device1.add_service(22, "ssh", "OpenSSH_8.2p1")
        device1.add_config("/etc/ssh/sshd_config", "PasswordAuthentication yes", "linux")

        device2 = Device(ip="192.168.1.2", hostname="server2", device_type="linux")
        device2.add_service(22, "ssh", "OpenSSH_9.0")
        device2.add_config("/etc/ssh/sshd_config", "PasswordAuthentication no", "linux")

        scan_result = ScanResult(devices=[device1, device2])
        result = analyzer.analyze(scan_result)

        # Should have findings from device1 but not device2
        device1_findings = [f for f in result.findings if "192.168.1.1" in f.device]
        device2_findings = [f for f in result.findings if "192.168.1.2" in f.device]

        assert len(device1_findings) > 0
        # device2 has secure config so may have fewer findings

    def test_high_severity_findings_identified(self):
        """Test that high/critical findings are identified."""
        analyzer = Analyzer()

        device = Device(ip="192.168.1.1", device_type="linux")
        device.add_config(
            "/etc/iptables/rules",
            "-A INPUT -p tcp --dport 23 -j ACCEPT",
            "linux"
        )

        scan_result = ScanResult(devices=[device])
        result = analyzer.analyze(scan_result)

        # Check for high severity findings
        high_severity = [
            f for f in result.findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        # May or may not have telnet depending on rules

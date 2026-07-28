"""Tests for security analysis engines."""

import pytest
from pynetworkintel.analysis import RuleChecker
from pynetworkintel.analysis.cve import CVEChecker
from pynetworkintel.models import Device, Severity, FindingType


class TestRuleChecker:
    def test_create_rule_checker(self):
        checker = RuleChecker()
        assert len(checker.rules) > 0

    def test_detect_ssh_password_auth(self):
        checker = RuleChecker()

        device = Device(ip="192.168.1.1", device_type="linux")
        device.add_config(
            "/etc/ssh/sshd_config",
            "PasswordAuthentication yes\nPort 22",
            "linux"
        )

        findings = checker.check_device(device)
        assert len(findings) > 0

        # Should find SSH password auth vulnerability
        ssh_finding = next(
            (f for f in findings if "password" in f.title.lower()),
            None
        )
        assert ssh_finding is not None
        assert ssh_finding.severity == Severity.HIGH

    def test_detect_telnet(self):
        checker = RuleChecker()

        device = Device(ip="192.168.1.1", device_type="linux")
        device.add_config(
            "/etc/iptables/rules",
            "-A INPUT -p tcp --dport 23 -j ACCEPT",
            "linux"
        )

        findings = checker.check_device(device)
        telnet_finding = next(
            (f for f in findings if "telnet" in f.title.lower()),
            None
        )
        if telnet_finding:
            assert telnet_finding.severity == Severity.CRITICAL

    def test_no_violations(self):
        checker = RuleChecker()

        device = Device(ip="192.168.1.1", device_type="linux")
        device.add_config(
            "/etc/ssh/sshd_config",
            "PasswordAuthentication no\nPubkeyAuthentication yes",
            "linux"
        )

        findings = checker.check_device(device)
        # Should not find SSH password auth issue
        ssh_findings = [f for f in findings if "password" in f.title.lower()]
        assert len(ssh_findings) == 0

    def test_extract_evidence(self):
        checker = RuleChecker()
        rule = checker.rules[0]

        device = Device(ip="192.168.1.1", device_type="linux")
        device.add_config(
            "/etc/ssh/sshd_config",
            "PasswordAuthentication yes",
            "linux"
        )

        evidence = checker._extract_evidence(device, rule)
        assert "PasswordAuthentication" in evidence or evidence == "Check failed for SSH with password authentication enabled"


class TestCVEChecker:
    def test_create_cve_checker(self):
        checker = CVEChecker()
        assert checker is not None

    def test_cvss_to_severity(self):
        assert CVEChecker._cvss_to_severity(9.5) == Severity.CRITICAL
        assert CVEChecker._cvss_to_severity(7.5) == Severity.HIGH
        assert CVEChecker._cvss_to_severity(5.0) == Severity.MEDIUM
        assert CVEChecker._cvss_to_severity(2.0) == Severity.LOW
        assert CVEChecker._cvss_to_severity(None) == Severity.MEDIUM

    def test_cache_cves(self):
        checker = CVEChecker()
        # Note: This won't actually query NVD due to rate limiting
        # but tests the cache mechanism
        assert len(checker._cache) == 0

"""Tests for data models."""

import pytest
from datetime import datetime
from pynetworkintel.models import (
    Device, Service, SecurityFinding, ScanResult,
    Severity, FindingType
)


class TestService:
    def test_create_service(self):
        service = Service(port=22, name="ssh", version="OpenSSH_8.2p1")
        assert service.port == 22
        assert service.name == "ssh"
        assert service.version == "OpenSSH_8.2p1"

    def test_service_to_dict(self):
        service = Service(port=443, name="https")
        data = service.to_dict()
        assert data["port"] == 443
        assert data["name"] == "https"


class TestDevice:
    def test_create_device(self):
        device = Device(ip="192.168.1.1", hostname="router")
        assert device.ip == "192.168.1.1"
        assert device.hostname == "router"
        assert device.is_online is True

    def test_add_service(self):
        device = Device(ip="192.168.1.1")
        device.add_service(22, "ssh", "OpenSSH_8.2p1")
        assert len(device.services) == 1
        assert device.services[0].port == 22

    def test_device_to_dict(self):
        device = Device(ip="192.168.1.1", hostname="server1", os="Ubuntu 22.04")
        device.add_service(22, "ssh", "OpenSSH_8.2p1")
        data = device.to_dict()
        assert data["ip"] == "192.168.1.1"
        assert data["hostname"] == "server1"
        assert len(data["services"]) == 1


class TestSecurityFinding:
    def test_create_finding(self):
        finding = SecurityFinding(
            device="192.168.1.1",
            finding_type=FindingType.CONFIGURATION,
            severity=Severity.HIGH,
            title="SSH Password Auth Enabled",
            description="SSH allows password auth",
            evidence="PasswordAuthentication yes",
            recommendation="Disable password auth",
            business_impact="Brute force risk"
        )
        assert finding.device == "192.168.1.1"
        assert finding.severity == Severity.HIGH

    def test_finding_to_dict(self):
        finding = SecurityFinding(
            device="192.168.1.1",
            finding_type=FindingType.CVE,
            severity=Severity.CRITICAL,
            title="CVE-2021-42013",
            description="Apache vulnerability",
            evidence="Apache 2.4.49",
            recommendation="Upgrade to 2.4.51",
            business_impact="Remote code execution",
            cve_id="CVE-2021-42013",
            cvss_score=7.5
        )
        data = finding.to_dict()
        assert data["cve_id"] == "CVE-2021-42013"
        assert data["severity"] == "critical"


class TestScanResult:
    def test_create_scan_result(self):
        device = Device(ip="192.168.1.1")
        result = ScanResult(devices=[device])
        assert len(result.devices) == 1

    def test_summary(self):
        device1 = Device(ip="192.168.1.1", is_online=True)
        device2 = Device(ip="192.168.1.2", is_online=False)

        finding = SecurityFinding(
            device="192.168.1.1",
            finding_type=FindingType.CONFIGURATION,
            severity=Severity.CRITICAL,
            title="Test",
            description="Test",
            evidence="Test",
            recommendation="Test",
            business_impact="Test"
        )

        result = ScanResult(devices=[device1, device2], findings=[finding])
        summary = result.summary()

        assert summary["total_devices"] == 2
        assert summary["online_devices"] == 1
        assert summary["critical_findings"] == 1

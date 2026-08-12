"""Basic coverage for the iot/ module (protocol/vulnerability analysis).

Real socket-based device probing (discovery.py) is not exercised here since
it requires actual network access; these tests cover the pure-logic
protocol/vulnerability analysis pieces instead.
"""

import pytest

from pynetworkintel.iot.protocols import ProtocolAnalyzer
from pynetworkintel.iot.vulnerabilities import IoTVulnerabilityAnalyzer


class TestProtocolAnalyzer:
    def test_known_protocols_present(self):
        analyzer = ProtocolAnalyzer()
        for proto in ("MQTT", "CoAP", "Modbus TCP", "S7comm"):
            assert proto in analyzer.protocol_info

    def test_mqtt_default_port(self):
        analyzer = ProtocolAnalyzer()
        assert analyzer.protocol_info["MQTT"]["default_port"] == 1883

    def test_modbus_has_no_encryption(self):
        analyzer = ProtocolAnalyzer()
        assert analyzer.protocol_info["Modbus TCP"]["encryption"] == "None"


class TestIoTVulnerabilityAnalyzer:
    def test_outdated_firmware_flagged(self):
        analyzer = IoTVulnerabilityAnalyzer()
        vulns = analyzer.check_firmware_vulnerabilities("Generic Camera", "1.2.0")
        assert any(v["type"] == "outdated_firmware" for v in vulns)

    def test_recent_firmware_not_flagged_as_outdated(self):
        analyzer = IoTVulnerabilityAnalyzer()
        vulns = analyzer.check_firmware_vulnerabilities("Generic Camera", "3.5.0")
        assert not any(v["type"] == "outdated_firmware" for v in vulns)

    def test_unparseable_firmware_version_returns_empty(self):
        analyzer = IoTVulnerabilityAnalyzer()
        vulns = analyzer.check_firmware_vulnerabilities("Generic Camera", "not-a-version")
        assert vulns == []

    def test_protocol_vulnerabilities_for_unencrypted_device(self):
        analyzer = IoTVulnerabilityAnalyzer()
        device = {"protocols": ["Modbus TCP"], "services": []}
        vulns = analyzer.check_protocol_vulnerabilities(device)
        assert isinstance(vulns, list)

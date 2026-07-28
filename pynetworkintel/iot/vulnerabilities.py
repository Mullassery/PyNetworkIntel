"""IoT device vulnerability analysis."""
from typing import Dict, List, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)


class IoTVulnerabilityAnalyzer:
    """Analyze IoT devices for known vulnerabilities."""

    def __init__(self):
        """Initialize IoT vulnerability analyzer."""
        self.known_vuln_patterns = {
            "firmware_outdated": {
                "pattern": r"v?(\d+)\.(\d+)\.(\d+)",
                "threshold_years": 2,
            },
            "default_credentials": {
                "patterns": ["admin:admin", "root:root", "guest:guest"],
            },
            "hardcoded_secrets": {
                "patterns": [r"api[_-]?key", r"secret[_-]?key", r"password"],
            },
        }

    def check_firmware_vulnerabilities(self, device_model: str, firmware_version: str) -> List[Dict[str, Any]]:
        """Check for known firmware vulnerabilities."""
        vulnerabilities = []

        # Parse firmware version
        version_match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", firmware_version)
        if not version_match:
            return vulnerabilities

        major, minor, patch = map(int, version_match.groups())

        # Check for known vulnerability patterns
        if major < 2 or (major == 2 and minor < 5):
            vulnerabilities.append({
                "type": "outdated_firmware",
                "severity": "high",
                "description": f"Firmware {firmware_version} may contain known vulnerabilities",
                "recommendation": "Update to latest firmware version",
                "cve_score": 7.5,
            })

        # Model-specific vulnerabilities
        model_vulns = self._get_model_vulnerabilities(device_model)
        vulnerabilities.extend(model_vulns)

        return vulnerabilities

    def check_protocol_vulnerabilities(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for protocol-based vulnerabilities."""
        vulnerabilities = []

        protocols = device.get("protocols", [])
        services = device.get("services", [])

        # MQTT vulnerabilities
        if "MQTT" in protocols:
            vulns = self._check_mqtt_vulnerabilities(device)
            vulnerabilities.extend(vulns)

        # HTTP vulnerabilities
        if "HTTP" in services:
            vulns = self._check_http_vulnerabilities(device)
            vulnerabilities.extend(vulns)

        # Modbus vulnerabilities
        if "Modbus TCP" in protocols:
            vulnerabilities.append({
                "type": "no_authentication",
                "severity": "critical",
                "description": "Modbus TCP has no authentication mechanism",
                "recommendation": "Restrict network access via firewall",
                "cve_score": 9.8,
            })

        return vulnerabilities

    def scan_device_security(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive security scan on device."""
        firmware_vulns = self.check_firmware_vulnerabilities(
            device.get("model", "Unknown"),
            device.get("firmware_version", "Unknown")
        )
        protocol_vulns = self.check_protocol_vulnerabilities(device)

        all_vulns = firmware_vulns + protocol_vulns

        # Calculate risk score
        risk_score = self._calculate_device_risk(all_vulns)

        return {
            "device_id": device.get("device_id"),
            "device_type": device.get("device_type"),
            "vulnerabilities_found": len(all_vulns),
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "vulnerabilities": all_vulns,
            "recommendations": self._get_recommendations(all_vulns),
        }

    def detect_default_credentials(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for default credentials in device configuration."""
        issues = []

        # Check based on device type and manufacturer
        manufacturer = device.get("manufacturer", "").lower()
        device_type = device.get("device_type", "").lower()

        default_creds = self._get_default_creds_for_device(manufacturer, device_type)

        for cred_set in default_creds:
            issues.append({
                "type": "default_credentials",
                "severity": "critical",
                "username": cred_set.get("username"),
                "password": cred_set.get("password"),
                "description": "Device likely has default credentials",
                "recommendation": "Change default credentials immediately",
                "cve_score": 9.1,
            })

        return issues

    def analyze_device_fleet(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security across IoT device fleet."""
        all_vulns = []
        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for device in devices:
            scan_result = self.scan_device_security(device)
            all_vulns.extend(scan_result["vulnerabilities"])

            risk_level = scan_result.get("risk_level", "low")
            risk_distribution[risk_level] += 1

        # Identify common vulnerability patterns
        vuln_types = {}
        for vuln in all_vulns:
            vuln_type = vuln.get("type", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        return {
            "total_devices": len(devices),
            "total_vulnerabilities": len(all_vulns),
            "risk_distribution": risk_distribution,
            "most_common_issues": sorted(
                vuln_types.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            "remediation_priority": self._get_remediation_priority(all_vulns),
        }

    @staticmethod
    def _get_model_vulnerabilities(model: str) -> List[Dict[str, Any]]:
        """Get known vulnerabilities for device model."""
        model_lower = model.lower()

        # Example known vulnerabilities
        known_vulns = {
            "esp8266": [
                {
                    "type": "weak_ssl",
                    "severity": "high",
                    "description": "ESP8266 has limited SSL/TLS support",
                    "recommendation": "Implement application-level encryption",
                    "cve_score": 7.5,
                }
            ],
            "raspberry pi": [
                {
                    "type": "default_ssh",
                    "severity": "high",
                    "description": "Default SSH credentials may be present",
                    "recommendation": "Change default pi/raspberry credentials",
                    "cve_score": 7.9,
                }
            ],
        }

        for key, vulns in known_vulns.items():
            if key in model_lower:
                return vulns

        return []

    @staticmethod
    def _check_mqtt_vulnerabilities(device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check MQTT-specific vulnerabilities."""
        vulns = []

        if device.get("port") == 1883:  # Unencrypted MQTT
            vulns.append({
                "type": "mqtt_unencrypted",
                "severity": "high",
                "description": "MQTT running on port 1883 without TLS",
                "recommendation": "Use port 8883 with TLS encryption",
                "cve_score": 7.2,
            })

        return vulns

    @staticmethod
    def _check_http_vulnerabilities(device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check HTTP-specific vulnerabilities."""
        vulns = []

        if device.get("port") == 80:  # Unencrypted HTTP
            vulns.append({
                "type": "http_unencrypted",
                "severity": "high",
                "description": "HTTP running on port 80 without HTTPS",
                "recommendation": "Use port 443 with HTTPS",
                "cve_score": 7.1,
            })

        return vulns

    @staticmethod
    def _calculate_device_risk(vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate overall device risk score (0-100)."""
        if not vulnerabilities:
            return 0.0

        cve_scores = [v.get("cve_score", 5.0) for v in vulnerabilities]
        severity_multipliers = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.7,
        }

        total_score = 0.0
        for vuln in vulnerabilities:
            base_score = vuln.get("cve_score", 5.0)
            severity = vuln.get("severity", "medium")
            multiplier = severity_multipliers.get(severity, 1.0)
            total_score += base_score * multiplier

        avg_score = total_score / len(vulnerabilities)
        return min(avg_score, 100.0)

    @staticmethod
    def _get_risk_level(risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 70:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 30:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _get_recommendations(vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get recommendations from vulnerabilities."""
        recommendations = []

        for vuln in vulnerabilities:
            if vuln.get("recommendation") and vuln["recommendation"] not in recommendations:
                recommendations.append(vuln["recommendation"])

        return recommendations[:5]  # Return top 5 recommendations

    @staticmethod
    def _get_remediation_priority(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get prioritized list of remediations."""
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]

        priority = []

        if critical_vulns:
            priority.append({
                "priority": 1,
                "count": len(critical_vulns),
                "action": "Address critical vulnerabilities immediately",
            })

        if high_vulns:
            priority.append({
                "priority": 2,
                "count": len(high_vulns),
                "action": "Address high-severity vulnerabilities",
            })

        return priority

    @staticmethod
    def _get_default_creds_for_device(manufacturer: str, device_type: str) -> List[Dict[str, str]]:
        """Get default credentials for device type."""
        defaults = {
            "ubiquiti": [
                {"username": "ubnt", "password": "ubnt"},
                {"username": "admin", "password": "admin"},
            ],
            "tp-link": [
                {"username": "admin", "password": "admin"},
            ],
            "dlink": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": ""},
            ],
            "netgear": [
                {"username": "admin", "password": "password"},
            ],
        }

        for key, creds in defaults.items():
            if key in manufacturer.lower():
                return creds

        return []

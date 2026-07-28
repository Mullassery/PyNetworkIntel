"""IoT protocol analysis and detection."""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ProtocolAnalyzer:
    """Analyze IoT protocols for security issues."""

    def __init__(self):
        """Initialize protocol analyzer."""
        self.protocol_info = {
            "MQTT": {
                "default_port": 1883,
                "secure_port": 8883,
                "encryption": "Optional (TLS on 8883)",
                "auth": "Optional username/password",
                "vulnerabilities": [
                    "Lack of encryption by default",
                    "Weak authentication mechanisms",
                    "No message signing",
                    "Susceptible to DDoS",
                ],
            },
            "CoAP": {
                "default_port": 5683,
                "secure_port": 5684,
                "encryption": "Optional (DTLS)",
                "auth": "Optional",
                "vulnerabilities": [
                    "UDP-based, susceptible to amplification attacks",
                    "Weak security by default",
                    "Replay attack potential",
                ],
            },
            "Modbus TCP": {
                "default_port": 502,
                "secure_port": None,
                "encryption": "None",
                "auth": "None",
                "vulnerabilities": [
                    "No built-in security",
                    "No encryption",
                    "No authentication",
                    "Legacy protocol",
                ],
            },
            "S7comm": {
                "default_port": 102,
                "secure_port": None,
                "encryption": "None",
                "auth": "Basic",
                "vulnerabilities": [
                    "Industrial control protocol without modern security",
                    "Sensitive to packet manipulation",
                    "No encryption by default",
                ],
            },
            "HTTP": {
                "default_port": 80,
                "secure_port": 443,
                "encryption": "Optional (HTTPS)",
                "auth": "Multiple options",
                "vulnerabilities": [
                    "Clear-text communication",
                    "Man-in-the-middle attacks",
                    "Credential sniffing",
                ],
            },
        }

    def analyze_protocol_security(self, protocol: str) -> Dict[str, Any]:
        """Analyze security of a specific protocol."""
        if protocol not in self.protocol_info:
            return {"error": f"Unknown protocol: {protocol}"}

        info = self.protocol_info[protocol]

        return {
            "protocol": protocol,
            "default_port": info.get("default_port"),
            "secure_port": info.get("secure_port"),
            "encryption": info.get("encryption"),
            "authentication": info.get("auth"),
            "known_vulnerabilities": info.get("vulnerabilities", []),
            "security_score": self._calculate_protocol_security(protocol),
            "recommendations": self._get_protocol_recommendations(protocol),
        }

    def detect_unencrypted_protocols(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect devices using unencrypted protocols."""
        unencrypted = []

        unencrypted_protocols = ["HTTP", "Modbus TCP", "S7comm"]

        for device in devices:
            for protocol in device.get("protocols", []):
                if protocol in unencrypted_protocols:
                    unencrypted.append({
                        "device_id": device.get("device_id"),
                        "ip": device.get("ip_address"),
                        "protocol": protocol,
                        "risk": "high",
                        "recommendation": f"Use encrypted variant: {self._get_encrypted_variant(protocol)}",
                    })

        return unencrypted

    def detect_weak_authentication(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect devices with weak or no authentication."""
        weak_auth = []

        no_auth_protocols = ["Modbus TCP", "CoAP", "S7comm"]

        for device in devices:
            for protocol in device.get("protocols", []):
                if protocol in no_auth_protocols:
                    weak_auth.append({
                        "device_id": device.get("device_id"),
                        "ip": device.get("ip_address"),
                        "protocol": protocol,
                        "issue": "No authentication mechanism",
                        "risk": "critical",
                        "recommendation": "Implement network-level access controls",
                    })

        return weak_auth

    def analyze_protocol_usage(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze protocol usage across devices."""
        protocol_stats = {}
        security_issues = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for device in devices:
            for protocol in device.get("protocols", []):
                if protocol not in protocol_stats:
                    protocol_stats[protocol] = 0
                protocol_stats[protocol] += 1

                # Calculate risk
                analysis = self.analyze_protocol_security(protocol)
                score = analysis.get("security_score", 0)

                if score < 30:
                    security_issues["critical"] += 1
                elif score < 50:
                    security_issues["high"] += 1
                elif score < 70:
                    security_issues["medium"] += 1
                else:
                    security_issues["low"] += 1

        return {
            "protocol_usage": protocol_stats,
            "total_devices": len(devices),
            "security_summary": security_issues,
            "recommendation": "Prioritize securing critical and high-risk protocols",
        }

    def get_default_credentials(self, protocol: str) -> List[Dict[str, str]]:
        """Get list of known default credentials for protocol."""
        defaults = {
            "MQTT": [
                {"username": "admin", "password": "admin"},
                {"username": "guest", "password": "guest"},
            ],
            "HTTP": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "root", "password": "root"},
            ],
            "S7comm": [
                {"username": "", "password": ""},  # Often no auth
            ],
        }

        return defaults.get(protocol, [])

    @staticmethod
    def _calculate_protocol_security(protocol: str) -> int:
        """Calculate security score (0-100)."""
        scores = {
            "MQTT": 60,
            "CoAP": 50,
            "Modbus TCP": 20,
            "S7comm": 30,
            "HTTP": 40,
        }

        return scores.get(protocol, 50)

    @staticmethod
    def _get_protocol_recommendations(protocol: str) -> List[str]:
        """Get security recommendations for protocol."""
        recommendations = {
            "MQTT": [
                "Use TLS encryption (port 8883)",
                "Implement strong username/password authentication",
                "Deploy on isolated network segment",
                "Monitor for unauthorized access attempts",
            ],
            "CoAP": [
                "Use DTLS for encryption",
                "Implement authentication tokens",
                "Rate limit CoAP requests",
                "Monitor UDP traffic for amplification attacks",
            ],
            "Modbus TCP": [
                "Never expose to internet",
                "Implement firewall rules to restrict access",
                "Use industrial firewalls",
                "Monitor for unauthorized commands",
            ],
            "S7comm": [
                "Network isolation is critical",
                "Implement VPN for remote access",
                "Monitor for reconnaissance traffic",
                "Keep firmware updated",
            ],
            "HTTP": [
                "Always use HTTPS (port 443)",
                "Implement strong authentication",
                "Use certificates",
                "Enable HSTS",
            ],
        }

        return recommendations.get(protocol, [])

    @staticmethod
    def _get_encrypted_variant(protocol: str) -> str:
        """Get encrypted variant of protocol."""
        variants = {
            "MQTT": "MQTT over TLS (port 8883)",
            "CoAP": "CoAP over DTLS (port 5684)",
            "HTTP": "HTTPS (port 443)",
        }

        return variants.get(protocol, "N/A")

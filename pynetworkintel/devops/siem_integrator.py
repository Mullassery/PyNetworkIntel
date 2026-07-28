"""SIEM integration for centralized logging and alerting."""
from typing import Dict, List, Any, Optional
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SIEMIntegrator:
    """Integrate PyNetworkIntel with SIEM platforms."""

    def __init__(self, siem_type: str, endpoint: str, credentials: Dict[str, str]):
        """
        Initialize SIEM integrator.

        Args:
            siem_type: Type of SIEM (splunk, elk, datadog, etc.)
            endpoint: SIEM API endpoint
            credentials: Authentication credentials
        """
        self.siem_type = siem_type.lower()
        self.endpoint = endpoint
        self.credentials = credentials

    def send_scan_results(self, scan_data: Dict[str, Any]) -> bool:
        """Send scan results to SIEM."""
        formatted_data = self._format_for_siem(scan_data)

        try:
            if self.siem_type == "splunk":
                return self._send_to_splunk(formatted_data)
            elif self.siem_type == "elk":
                return self._send_to_elk(formatted_data)
            elif self.siem_type == "datadog":
                return self._send_to_datadog(formatted_data)
            elif self.siem_type == "splunk_enterprise":
                return self._send_to_splunk_hec(formatted_data)
            else:
                logger.warning(f"Unknown SIEM type: {self.siem_type}")
                return False
        except Exception as e:
            logger.error(f"Failed to send to SIEM: {e}")
            return False

    def send_vulnerability_alert(self, device_id: str, vulnerability: Dict[str, Any]) -> bool:
        """Send vulnerability alert to SIEM."""
        alert_data = {
            "event_type": "vulnerability_detected",
            "severity": vulnerability.get("severity", "medium"),
            "device_id": device_id,
            "cve_id": vulnerability.get("cve_id"),
            "description": vulnerability.get("description"),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "pynetworkintel",
        }

        return self.send_scan_results(alert_data)

    def send_change_alert(self, device_id: str, change: Dict[str, Any]) -> bool:
        """Send device change alert to SIEM."""
        alert_data = {
            "event_type": "device_change_detected",
            "device_id": device_id,
            "change_type": change.get("type"),
            "old_value": change.get("old_value"),
            "new_value": change.get("new_value"),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "pynetworkintel",
        }

        return self.send_scan_results(alert_data)

    def send_anomaly_alert(self, device_id: str, anomaly: Dict[str, Any]) -> bool:
        """Send anomaly alert to SIEM."""
        alert_data = {
            "event_type": "anomaly_detected",
            "device_id": device_id,
            "anomaly_type": anomaly.get("type"),
            "anomaly_score": anomaly.get("score"),
            "description": anomaly.get("description"),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "pynetworkintel",
        }

        return self.send_scan_results(alert_data)

    @staticmethod
    def _format_for_siem(data: Dict[str, Any]) -> Dict[str, Any]:
        """Format data for SIEM ingestion."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "pynetworkintel",
            "event": data,
        }

    def _send_to_splunk(self, data: Dict[str, Any]) -> bool:
        """Send data to Splunk via HTTP Event Collector."""
        try:
            import requests

            headers = {
                "Authorization": f"Splunk {self.credentials.get('hec_token')}",
                "Content-Type": "application/json",
            }

            payload = {
                "event": data,
                "source": "pynetworkintel",
            }

            response = requests.post(
                f"{self.endpoint}/services/collector",
                json=payload,
                headers=headers,
                timeout=10
            )

            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send to Splunk: {e}")
            return False

    def _send_to_elk(self, data: Dict[str, Any]) -> bool:
        """Send data to Elasticsearch/ELK."""
        try:
            import requests

            headers = {"Content-Type": "application/json"}

            # Add auth if provided
            if self.credentials.get("username"):
                import base64
                auth = base64.b64encode(
                    f"{self.credentials['username']}:{self.credentials['password']}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {auth}"

            index_name = "pynetworkintel-" + datetime.utcnow().strftime("%Y.%m.%d")

            response = requests.post(
                f"{self.endpoint}/{index_name}/_doc",
                json=data,
                headers=headers,
                timeout=10
            )

            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"Failed to send to ELK: {e}")
            return False

    def _send_to_datadog(self, data: Dict[str, Any]) -> bool:
        """Send data to Datadog."""
        try:
            import requests

            headers = {
                "Content-Type": "application/json",
                "DD-API-KEY": self.credentials.get("api_key"),
            }

            response = requests.post(
                "https://http-intake.logs.datadoghq.com/v1/input",
                json=data,
                headers=headers,
                timeout=10
            )

            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send to Datadog: {e}")
            return False

    def _send_to_splunk_hec(self, data: Dict[str, Any]) -> bool:
        """Send data to Splunk via HEC (HTTP Event Collector)."""
        return self._send_to_splunk(data)

    def get_integration_status(self) -> Dict[str, Any]:
        """Check SIEM integration status."""
        try:
            if self.siem_type == "splunk":
                return {"status": "connected", "siem": "Splunk"}
            elif self.siem_type == "elk":
                return {"status": "connected", "siem": "Elasticsearch/ELK"}
            else:
                return {"status": "connected", "siem": self.siem_type}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

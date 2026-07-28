"""Network traffic and behavior anomaly detection."""
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import statistics
import logging

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect anomalies in network behavior."""

    def __init__(self, threshold: float = 0.7):
        """
        Initialize anomaly detector.

        Args:
            threshold: Anomaly score threshold (0-1)
        """
        self.threshold = threshold
        self.historical_data: Dict[str, List[Dict[str, Any]]] = {}
        self.anomalies: List[Dict[str, Any]] = []

    def record_traffic(self, device_id: str, traffic_data: Dict[str, Any]):
        """Record traffic data for analysis."""
        if device_id not in self.historical_data:
            self.historical_data[device_id] = []

        traffic_record = {
            "timestamp": datetime.now(),
            **traffic_data,
        }

        self.historical_data[device_id].append(traffic_record)

    def detect_port_scan_activity(self, device_id: str, current_ports: List[int]) -> Tuple[bool, float, str]:
        """Detect potential port scanning activity."""
        if device_id not in self.historical_data:
            return False, 0.0, "No baseline data"

        history = self.historical_data[device_id]

        if not history:
            return False, 0.0, "Insufficient data"

        # Get baseline
        baseline_ports = self._get_baseline_ports(history)
        new_ports = [p for p in current_ports if p not in baseline_ports]

        if len(new_ports) == 0:
            return False, 0.0, "Normal port activity"

        # Calculate anomaly score
        expected_new_ports = len(baseline_ports) * 0.1  # Expect ~10% new ports
        new_port_ratio = len(new_ports) / len(current_ports) if current_ports else 0

        if new_port_ratio > 0.5:
            anomaly_score = 0.95
            message = f"Detected {len(new_ports)} new ports (port scan likely)"
            is_anomaly = anomaly_score >= self.threshold
            return is_anomaly, anomaly_score, message

        return False, 0.2, "Normal port variation"

    def detect_bandwidth_anomaly(self, device_id: str, current_bandwidth: float) -> Tuple[bool, float, str]:
        """Detect unusual bandwidth usage."""
        if device_id not in self.historical_data:
            return False, 0.0, "No baseline data"

        history = self.historical_data[device_id]

        if not history or len(history) < 5:
            return False, 0.0, "Insufficient baseline"

        # Get bandwidth history
        bandwidths = [h.get("bandwidth", 0) for h in history[-50:]]

        if not bandwidths:
            return False, 0.0, "No bandwidth data"

        try:
            mean_bandwidth = statistics.mean(bandwidths)
            stdev_bandwidth = statistics.stdev(bandwidths) if len(bandwidths) > 1 else 0
        except:
            return False, 0.0, "Cannot calculate statistics"

        # Calculate z-score
        if stdev_bandwidth == 0:
            return False, 0.0, "No variation in baseline"

        z_score = abs((current_bandwidth - mean_bandwidth) / stdev_bandwidth)

        if z_score > 3:
            anomaly_score = 0.95
            message = f"Bandwidth {current_bandwidth} is {z_score:.1f} std devs from mean"
            is_anomaly = anomaly_score >= self.threshold
            return is_anomaly, anomaly_score, message
        elif z_score > 2:
            return False, 0.6, "Bandwidth slightly elevated"
        else:
            return False, 0.2, "Normal bandwidth"

    def detect_timing_anomaly(self, device_id: str) -> Tuple[bool, float, str]:
        """Detect unusual timing patterns."""
        if device_id not in self.historical_data:
            return False, 0.0, "No baseline data"

        history = self.historical_data[device_id]

        if len(history) < 10:
            return False, 0.0, "Insufficient data"

        # Check for activity outside normal hours
        timestamps = [h["timestamp"] for h in history[-100:] if "timestamp" in h]

        if not timestamps:
            return False, 0.0, "No timestamp data"

        # Get hours of activity
        active_hours = set(ts.hour for ts in timestamps)

        # Standard business hours (9-17)
        business_hours = set(range(9, 18))
        activity_outside_hours = active_hours - business_hours

        if len(activity_outside_hours) > 0:
            # Activity outside normal hours
            recent_activity = [ts for ts in timestamps if ts.hour in activity_outside_hours]

            if len(recent_activity) > len(timestamps) / 2:
                anomaly_score = 0.75
                message = f"Activity detected outside business hours: {activity_outside_hours}"
                is_anomaly = anomaly_score >= self.threshold
                return is_anomaly, anomaly_score, message

        return False, 0.2, "Normal activity hours"

    def detect_connection_anomaly(self, device_id: str, dest_ip: str, dest_port: int) -> Tuple[bool, float, str]:
        """Detect unusual connection patterns."""
        if device_id not in self.historical_data:
            return False, 0.0, "No baseline data"

        history = self.historical_data[device_id]

        # Get baseline connections
        baseline_destinations = set()
        for record in history:
            if "dest_ip" in record:
                baseline_destinations.add((record["dest_ip"], record.get("dest_port")))

        # Check if new destination
        connection_key = (dest_ip, dest_port)

        if connection_key not in baseline_destinations:
            # Check if destination is in suspicious ranges
            if self._is_suspicious_destination(dest_ip):
                anomaly_score = 0.85
                message = f"Connection to suspicious destination: {dest_ip}:{dest_port}"
                is_anomaly = anomaly_score >= self.threshold
                return is_anomaly, anomaly_score, message
            else:
                return False, 0.3, "New destination (not suspicious)"

        return False, 0.1, "Known destination"

    def detect_protocol_anomaly(self, device_id: str, protocol: str) -> Tuple[bool, float, str]:
        """Detect unusual protocol usage."""
        if device_id not in self.historical_data:
            return False, 0.0, "No baseline data"

        history = self.historical_data[device_id]

        # Get baseline protocols
        baseline_protocols = {}
        for record in history:
            prot = record.get("protocol", "unknown")
            baseline_protocols[prot] = baseline_protocols.get(prot, 0) + 1

        # Check if protocol is unusual
        if protocol not in baseline_protocols:
            # Suspicious protocols
            suspicious = ["ssh", "vnc", "rdp"] if device_id.startswith("iot_") else []

            if protocol in suspicious:
                anomaly_score = 0.8
                message = f"Suspicious protocol {protocol} detected"
                is_anomaly = anomaly_score >= self.threshold
                return is_anomaly, anomaly_score, message
            else:
                return False, 0.2, "New protocol (not suspicious)"

        return False, 0.1, "Known protocol"

    def analyze_traffic_pattern(self, device_id: str) -> Dict[str, Any]:
        """Analyze overall traffic pattern."""
        if device_id not in self.historical_data:
            return {"status": "no_data"}

        history = self.historical_data[device_id]

        if not history:
            return {"status": "no_data"}

        # Analyze patterns
        protocols = {}
        ports = {}
        bandwidth_samples = []

        for record in history[-1000:]:  # Last 1000 records
            if "protocol" in record:
                prot = record["protocol"]
                protocols[prot] = protocols.get(prot, 0) + 1

            if "port" in record:
                port = record["port"]
                ports[port] = ports.get(port, 0) + 1

            if "bandwidth" in record:
                bandwidth_samples.append(record["bandwidth"])

        # Calculate stats
        avg_bandwidth = statistics.mean(bandwidth_samples) if bandwidth_samples else 0
        max_bandwidth = max(bandwidth_samples) if bandwidth_samples else 0

        return {
            "device_id": device_id,
            "total_records": len(history),
            "unique_protocols": len(protocols),
            "unique_ports": len(ports),
            "most_common_protocol": max(protocols.items(), key=lambda x: x[1])[0] if protocols else None,
            "most_common_port": max(ports.items(), key=lambda x: x[1])[0] if ports else None,
            "average_bandwidth": avg_bandwidth,
            "max_bandwidth": max_bandwidth,
        }

    def get_anomalies(self, device_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get detected anomalies for device."""
        device_anomalies = [a for a in self.anomalies if a.get("device_id") == device_id]

        return sorted(
            device_anomalies,
            key=lambda x: x.get("anomaly_score", 0),
            reverse=True
        )[:limit]

    @staticmethod
    def _get_baseline_ports(history: List[Dict[str, Any]]) -> set:
        """Extract baseline ports from history."""
        ports = set()

        for record in history:
            if "ports" in record and isinstance(record["ports"], list):
                ports.update(record["ports"])
            elif "port" in record:
                ports.add(record["port"])

        return ports

    @staticmethod
    def _is_suspicious_destination(ip: str) -> bool:
        """Check if destination is suspicious."""
        # Suspicious IP ranges (example)
        suspicious_ranges = [
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",  # Localhost redirects
        ]

        if ip in suspicious_ranges:
            return True

        # Check for reserved ranges
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                first_octet = int(parts[0])
                if first_octet in [0, 10, 127, 255]:
                    return True
            except:
                pass

        return False

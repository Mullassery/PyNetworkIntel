"""Device behavioral baseline learning."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import statistics
import logging

logger = logging.getLogger(__name__)


@dataclass
class DeviceBaseline:
    device_id: str
    device_type: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    port_patterns: Dict[int, int] = field(default_factory=dict)
    service_patterns: Dict[str, int] = field(default_factory=dict)
    time_based_patterns: Dict[str, int] = field(default_factory=dict)
    activity_history: List[Dict[str, Any]] = field(default_factory=list)
    baseline_confidence: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


class BehavioralBaseline:
    """Learn and track device behavioral baselines."""

    def __init__(self, min_samples: int = 10):
        """
        Initialize behavioral baseline tracker.

        Args:
            min_samples: Minimum samples needed to establish baseline
        """
        self.min_samples = min_samples
        self.baselines: Dict[str, DeviceBaseline] = {}
        self.activity_log: List[Dict[str, Any]] = []

    def record_device_activity(self, device_id: str, device_type: str, activity: Dict[str, Any]):
        """Record device activity."""
        if device_id not in self.baselines:
            self.baselines[device_id] = DeviceBaseline(
                device_id=device_id,
                device_type=device_type,
            )

        baseline = self.baselines[device_id]

        # Record activity
        activity_record = {
            "timestamp": datetime.now(),
            "device_id": device_id,
            **activity,
        }
        baseline.activity_history.append(activity_record)
        self.activity_log.append(activity_record)

        # Update baseline metrics
        self._update_baseline_metrics(baseline, activity)

    def record_port_activity(self, device_id: str, device_type: str, port: int, direction: str = "outbound"):
        """Record port activity."""
        self.record_device_activity(device_id, device_type, {
            "type": "port_activity",
            "port": port,
            "direction": direction,
        })

        if device_id in self.baselines:
            baseline = self.baselines[device_id]
            baseline.port_patterns[port] = baseline.port_patterns.get(port, 0) + 1

    def record_service_activity(self, device_id: str, device_type: str, service: str):
        """Record service access."""
        self.record_device_activity(device_id, device_type, {
            "type": "service_activity",
            "service": service,
        })

        if device_id in self.baselines:
            baseline = self.baselines[device_id]
            baseline.service_patterns[service] = baseline.service_patterns.get(service, 0) + 1

    def get_baseline_status(self, device_id: str) -> Dict[str, Any]:
        """Get baseline status for device."""
        if device_id not in self.baselines:
            return {"status": "not_established"}

        baseline = self.baselines[device_id]
        activity_count = len(baseline.activity_history)

        if activity_count < self.min_samples:
            confidence = (activity_count / self.min_samples) * 100
            return {
                "status": "establishing",
                "samples_collected": activity_count,
                "samples_needed": self.min_samples,
                "confidence_percentage": confidence,
            }
        else:
            return {
                "status": "established",
                "samples_collected": activity_count,
                "confidence_percentage": 100.0,
                "common_ports": self._get_top_ports(baseline, 5),
                "common_services": self._get_top_services(baseline, 5),
            }

    def detect_anomalies(self, device_id: str, current_activity: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies based on baseline."""
        if device_id not in self.baselines:
            return []

        baseline = self.baselines[device_id]
        anomalies = []

        # Can't detect anomalies without established baseline
        if len(baseline.activity_history) < self.min_samples:
            return []

        # Check for unusual ports
        if "port" in current_activity:
            port = current_activity["port"]
            if port not in baseline.port_patterns:
                anomaly_score = 0.8
                anomalies.append({
                    "type": "unusual_port",
                    "port": port,
                    "anomaly_score": anomaly_score,
                    "description": f"Port {port} not in device baseline",
                })

        # Check for unusual services
        if "service" in current_activity:
            service = current_activity["service"]
            if service not in baseline.service_patterns:
                anomaly_score = 0.7
                anomalies.append({
                    "type": "unusual_service",
                    "service": service,
                    "anomaly_score": anomaly_score,
                    "description": f"Service {service} not in device baseline",
                })

        return anomalies

    def get_device_fingerprint(self, device_id: str) -> Dict[str, Any]:
        """Get device fingerprint based on behavior."""
        if device_id not in self.baselines:
            return {}

        baseline = self.baselines[device_id]

        return {
            "device_id": device_id,
            "device_type": baseline.device_type,
            "port_profile": sorted(
                baseline.port_patterns.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "service_profile": sorted(
                baseline.service_patterns.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "activity_count": len(baseline.activity_history),
            "baseline_confidence": baseline.baseline_confidence,
        }

    def compare_baselines(self, device_id1: str, device_id2: str) -> Dict[str, Any]:
        """Compare baselines of two devices."""
        if device_id1 not in self.baselines or device_id2 not in self.baselines:
            return {"error": "One or both devices not found"}

        baseline1 = self.baselines[device_id1]
        baseline2 = self.baselines[device_id2]

        # Calculate similarity based on port and service patterns
        ports1 = set(baseline1.port_patterns.keys())
        ports2 = set(baseline2.port_patterns.keys())

        services1 = set(baseline1.service_patterns.keys())
        services2 = set(baseline2.service_patterns.keys())

        port_similarity = self._calculate_similarity(ports1, ports2)
        service_similarity = self._calculate_similarity(services1, services2)

        return {
            "device_id_1": device_id1,
            "device_id_2": device_id2,
            "port_similarity": port_similarity,
            "service_similarity": service_similarity,
            "overall_similarity": (port_similarity + service_similarity) / 2,
            "shared_ports": list(ports1 & ports2),
            "shared_services": list(services1 & services2),
        }

    def get_fleet_statistics(self) -> Dict[str, Any]:
        """Get statistics across device fleet."""
        if not self.baselines:
            return {"total_devices": 0}

        established = sum(
            1 for b in self.baselines.values()
            if len(b.activity_history) >= self.min_samples
        )

        all_ports = {}
        all_services = {}

        for baseline in self.baselines.values():
            for port, count in baseline.port_patterns.items():
                all_ports[port] = all_ports.get(port, 0) + count

            for service, count in baseline.service_patterns.items():
                all_services[service] = all_services.get(service, 0) + count

        return {
            "total_devices": len(self.baselines),
            "established_baselines": established,
            "establishing_baselines": len(self.baselines) - established,
            "most_common_ports": sorted(
                all_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "most_common_services": sorted(
                all_services.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "total_activities_recorded": len(self.activity_log),
        }

    @staticmethod
    def _update_baseline_metrics(baseline: DeviceBaseline, activity: Dict[str, Any]):
        """Update baseline metrics from activity."""
        timestamp = datetime.now()
        hour = timestamp.hour

        hour_key = f"hour_{hour}"
        baseline.time_based_patterns[hour_key] = baseline.time_based_patterns.get(hour_key, 0) + 1

        baseline.last_updated = timestamp
        baseline.baseline_confidence = min(
            len(baseline.activity_history) / 100,
            1.0
        )

    @staticmethod
    def _get_top_ports(baseline: DeviceBaseline, limit: int = 5) -> List[Dict[str, int]]:
        """Get top ports used by device."""
        sorted_ports = sorted(
            baseline.port_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {"port": port, "count": count}
            for port, count in sorted_ports[:limit]
        ]

    @staticmethod
    def _get_top_services(baseline: DeviceBaseline, limit: int = 5) -> List[Dict[str, int]]:
        """Get top services used by device."""
        sorted_services = sorted(
            baseline.service_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {"service": service, "count": count}
            for service, count in sorted_services[:limit]
        ]

    @staticmethod
    def _calculate_similarity(set1: set, set2: set) -> float:
        """Calculate Jaccard similarity between two sets."""
        if not set1 and not set2:
            return 1.0

        if not set1 or not set2:
            return 0.0

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

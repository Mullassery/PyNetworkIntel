"""Predictive analytics for vulnerability and risk forecasting."""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import statistics
import logging

logger = logging.getLogger(__name__)


class PredictiveAnalyzer:
    """Predict future security risks and vulnerabilities."""

    def __init__(self):
        """Initialize predictive analyzer."""
        self.historical_risks: Dict[str, List[Dict[str, Any]]] = {}
        self.predictions: Dict[str, List[Dict[str, Any]]] = {}

    def record_vulnerability(self, device_id: str, severity: str, vuln_type: str):
        """Record discovered vulnerability."""
        if device_id not in self.historical_risks:
            self.historical_risks[device_id] = []

        self.historical_risks[device_id].append({
            "timestamp": datetime.now(),
            "severity": severity,
            "type": vuln_type,
        })

    def predict_future_vulnerabilities(self, device_id: str, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Predict future vulnerabilities based on history."""
        if device_id not in self.historical_risks:
            return []

        history = self.historical_risks[device_id]

        if len(history) < 2:
            return []

        # Analyze vulnerability discovery rate
        discovery_rate = self._calculate_discovery_rate(history)

        # Project future vulnerabilities
        predictions = []

        if discovery_rate > 0:
            for day in range(1, days_ahead + 1):
                predicted_vulns = discovery_rate * day
                confidence = min(0.5 + (len(history) * 0.1), 0.95)

                predictions.append({
                    "day_ahead": day,
                    "predicted_vulnerabilities": predicted_vulns,
                    "confidence": confidence,
                    "risk_level": self._get_risk_from_count(predicted_vulns),
                })

        return predictions

    def predict_severity_trends(self, device_id: str) -> Dict[str, Any]:
        """Predict trends in vulnerability severity."""
        if device_id not in self.historical_risks:
            return {"status": "insufficient_data"}

        history = self.historical_risks[device_id]

        if len(history) < 2:
            return {"status": "insufficient_data"}

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vuln in history:
            severity = vuln.get("severity", "medium")
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate trend
        total = sum(severity_counts.values())

        return {
            "severity_distribution": severity_counts,
            "critical_percentage": (severity_counts["critical"] / total * 100) if total else 0,
            "high_percentage": (severity_counts["high"] / total * 100) if total else 0,
            "trend": self._analyze_severity_trend(history),
            "recommendation": self._get_severity_recommendation(severity_counts),
        }

    def predict_patch_urgency(self, device_id: str, cve_score: float) -> Dict[str, Any]:
        """Predict how urgently device needs patching."""
        if device_id not in self.historical_risks:
            base_score = cve_score
        else:
            history = self.historical_risks[device_id]
            recent_vulns = [v for v in history if self._is_recent(v["timestamp"])]
            base_score = cve_score * (1 + len(recent_vulns) * 0.1)

        urgency_score = min(base_score, 10.0)

        return {
            "device_id": device_id,
            "urgency_score": urgency_score,
            "urgency_level": self._get_urgency_level(urgency_score),
            "estimated_days_to_critical": self._estimate_days_to_critical(urgency_score),
            "recommendation": self._get_patch_recommendation(urgency_score),
        }

    def predict_device_risk_score(self, device_id: str, current_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Predict overall device risk score."""
        base_score = 0.0

        # Factor 1: Historical vulnerabilities
        if device_id in self.historical_risks:
            vuln_count = len(self.historical_risks[device_id])
            base_score += min(vuln_count * 5, 40)

        # Factor 2: Uptime (devices always on are higher risk)
        if "uptime_days" in current_metrics:
            uptime = current_metrics["uptime_days"]
            base_score += min(uptime / 10, 30)

        # Factor 3: Open ports
        if "open_ports" in current_metrics:
            port_count = current_metrics["open_ports"]
            base_score += min(port_count / 2, 20)

        # Factor 4: Services running
        if "services" in current_metrics:
            service_count = len(current_metrics["services"])
            base_score += min(service_count * 2, 30)

        # Normalize to 0-100
        risk_score = min(base_score, 100)

        return {
            "device_id": device_id,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "contributing_factors": self._get_risk_factors(base_score, current_metrics),
            "mitigation_priority": self._get_mitigation_priority(risk_score),
        }

    def forecast_attack_surface_growth(self, device_ids: List[str], days_ahead: int = 90) -> Dict[str, Any]:
        """Forecast how attack surface will grow."""
        current_surface = sum(
            len(self.historical_risks.get(device_id, []))
            for device_id in device_ids
        )

        if current_surface == 0:
            return {"current_surface": 0, "forecast": "insufficient_data"}

        # Calculate growth rate
        growth_rate = 0.05  # Default 5% monthly growth

        forecast = []

        for month in range(1, int(days_ahead / 30) + 1):
            projected_surface = current_surface * ((1 + growth_rate) ** month)
            forecast.append({
                "month": month,
                "projected_vulnerabilities": int(projected_surface),
                "estimated_critical": int(projected_surface * 0.1),
            })

        return {
            "current_surface": current_surface,
            "forecast_period_days": days_ahead,
            "growth_rate_percent": growth_rate * 100,
            "monthly_forecast": forecast,
            "recommendation": "Implement continuous patching program",
        }

    @staticmethod
    def _calculate_discovery_rate(history: List[Dict[str, Any]]) -> float:
        """Calculate vulnerability discovery rate per day."""
        if len(history) < 2:
            return 0.0

        # Get time span
        timestamps = [h["timestamp"] for h in history]
        time_span = (max(timestamps) - min(timestamps)).days

        if time_span == 0:
            return float(len(history))

        return len(history) / time_span

    @staticmethod
    def _get_risk_from_count(count: float) -> str:
        """Get risk level from vulnerability count."""
        if count >= 10:
            return "critical"
        elif count >= 5:
            return "high"
        elif count >= 2:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _is_recent(timestamp: datetime, days: int = 30) -> bool:
        """Check if timestamp is recent."""
        return datetime.now() - timestamp < timedelta(days=days)

    @staticmethod
    def _analyze_severity_trend(history: List[Dict[str, Any]]) -> str:
        """Analyze trend in severity."""
        if len(history) < 3:
            return "insufficient_data"

        recent = history[-3:]
        older = history[:-3]

        avg_recent = statistics.mean([1 if v.get("severity") == "critical" else 0 for v in recent])
        avg_older = statistics.mean([1 if v.get("severity") == "critical" else 0 for v in older]) if older else 0

        if avg_recent > avg_older * 1.5:
            return "worsening"
        elif avg_recent < avg_older * 0.5:
            return "improving"
        else:
            return "stable"

    @staticmethod
    def _get_severity_recommendation(severity_counts: Dict[str, int]) -> str:
        """Get recommendation based on severity distribution."""
        if severity_counts["critical"] > 0:
            return "Address critical vulnerabilities immediately"
        elif severity_counts["high"] > 2:
            return "Prioritize patching high-severity issues"
        else:
            return "Continue regular maintenance schedule"

    @staticmethod
    def _get_urgency_level(urgency_score: float) -> str:
        """Get urgency level from score."""
        if urgency_score >= 8:
            return "critical"
        elif urgency_score >= 6:
            return "high"
        elif urgency_score >= 4:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _estimate_days_to_critical(urgency_score: float) -> int:
        """Estimate days until device becomes critical."""
        # Linear interpolation
        if urgency_score >= 9:
            return 1
        elif urgency_score >= 7:
            return 3
        elif urgency_score >= 5:
            return 7
        else:
            return 30

    @staticmethod
    def _get_patch_recommendation(urgency_score: float) -> str:
        """Get patch recommendation."""
        if urgency_score >= 8:
            return "Patch immediately (same day)"
        elif urgency_score >= 6:
            return "Patch within 24-48 hours"
        elif urgency_score >= 4:
            return "Schedule patching within 1 week"
        else:
            return "Regular maintenance cycle acceptable"

    @staticmethod
    def _get_risk_level(risk_score: float) -> str:
        """Get risk level from score."""
        if risk_score >= 75:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 25:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _get_risk_factors(total_score: float, current_metrics: Dict[str, Any]) -> List[str]:
        """Get list of contributing risk factors."""
        factors = []

        if "uptime_days" in current_metrics and current_metrics["uptime_days"] > 90:
            factors.append("High uptime without patches")

        if "open_ports" in current_metrics and current_metrics["open_ports"] > 10:
            factors.append("Large number of open ports")

        if "services" in current_metrics and len(current_metrics["services"]) > 5:
            factors.append("Multiple services running")

        return factors

    @staticmethod
    def _get_mitigation_priority(risk_score: float) -> str:
        """Get mitigation priority."""
        if risk_score >= 75:
            return "P1 - Immediate action required"
        elif risk_score >= 50:
            return "P2 - High priority mitigation"
        elif risk_score >= 25:
            return "P3 - Medium priority mitigation"
        else:
            return "P4 - Monitor for changes"

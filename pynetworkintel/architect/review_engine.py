"""Architecture review and assessment."""
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class ReviewEngine:
    """Review architectures for best practices."""

    def review_reliability(self, architecture: Dict[str, Any]) -> Dict[str, Any]:
        """Review reliability aspects."""
        score = 0

        # Check redundancy
        if "redundancy" in architecture and architecture["redundancy"]:
            score += 30

        # Check failover
        if "failover" in architecture and architecture["failover"]:
            score += 25

        # Check monitoring
        if "monitoring" in architecture and architecture["monitoring"]:
            score += 25

        # Check backup
        if "backup" in architecture and architecture["backup"]:
            score += 20

        return {
            "category": "reliability",
            "score": min(score, 100),
            "rto": architecture.get("rto", 4),
            "rpo": architecture.get("rpo", 1),
            "recommendations": self._get_reliability_recommendations(score),
        }

    def review_security(self, architecture: Dict[str, Any]) -> Dict[str, Any]:
        """Review security aspects."""
        score = 0

        if "encryption" in architecture and architecture["encryption"]:
            score += 30

        if "authentication" in architecture and architecture["authentication"]:
            score += 25

        if "network_segmentation" in architecture and architecture["network_segmentation"]:
            score += 25

        if "audit_logging" in architecture and architecture["audit_logging"]:
            score += 20

        return {
            "category": "security",
            "score": min(score, 100),
            "recommendations": self._get_security_recommendations(score),
        }

    def review_scalability(self, architecture: Dict[str, Any]) -> Dict[str, Any]:
        """Review scalability aspects."""
        score = 0

        if "auto_scaling" in architecture and architecture["auto_scaling"]:
            score += 35

        if "load_balancing" in architecture and architecture["load_balancing"]:
            score += 35

        if "caching" in architecture and architecture["caching"]:
            score += 30

        return {
            "category": "scalability",
            "score": min(score, 100),
            "recommendations": self._get_scalability_recommendations(score),
        }

    def review_cost(self, architecture: Dict[str, Any]) -> Dict[str, Any]:
        """Review cost optimization."""
        score = 50  # Baseline

        # Adjust based on factors
        if "serverless" in architecture and architecture["serverless"]:
            score += 20

        if "reserved_instances" in architecture and architecture["reserved_instances"]:
            score += 15

        if "right_sizing" in architecture and architecture["right_sizing"]:
            score += 15

        return {
            "category": "cost",
            "score": min(score, 100),
            "estimated_monthly": architecture.get("estimated_monthly_cost", 5000),
            "recommendations": self._get_cost_recommendations(score),
        }

    def generate_overall_review(self, architecture: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive review."""
        reliability = self.review_reliability(architecture)
        security = self.review_security(architecture)
        scalability = self.review_scalability(architecture)
        cost = self.review_cost(architecture)

        avg_score = (
            reliability["score"] + security["score"] +
            scalability["score"] + cost["score"]
        ) / 4

        return {
            "overall_score": avg_score,
            "maturity_level": self._get_maturity_level(avg_score),
            "reviews": {
                "reliability": reliability,
                "security": security,
                "scalability": scalability,
                "cost": cost,
            },
            "critical_issues": self._identify_critical_issues(
                [reliability, security, scalability, cost]
            ),
        }

    @staticmethod
    def _get_reliability_recommendations(score: float) -> List[str]:
        if score < 50:
            return [
                "Implement redundancy for critical components",
                "Design automatic failover",
                "Add comprehensive monitoring",
            ]
        elif score < 80:
            return ["Improve backup strategy", "Add more monitoring"]
        else:
            return ["Good reliability posture"]

    @staticmethod
    def _get_security_recommendations(score: float) -> List[str]:
        if score < 50:
            return [
                "Enable encryption for data in transit and at rest",
                "Implement strong authentication",
                "Setup audit logging",
            ]
        return ["Continue security hardening"]

    @staticmethod
    def _get_scalability_recommendations(score: float) -> List[str]:
        if score < 50:
            return ["Implement auto-scaling", "Add load balancing", "Setup caching"]
        return ["Scalability well architected"]

    @staticmethod
    def _get_cost_recommendations(score: float) -> List[str]:
        if score < 60:
            return ["Consider serverless for cost reduction", "Use reserved instances"]
        return ["Cost optimized"]

    @staticmethod
    def _get_maturity_level(score: float) -> str:
        if score >= 80:
            return "mature"
        elif score >= 60:
            return "developing"
        else:
            return "initial"

    @staticmethod
    def _identify_critical_issues(reviews: List[Dict[str, Any]]) -> List[str]:
        issues = []

        for review in reviews:
            if review["score"] < 40:
                category = review["category"]
                issues.append(f"CRITICAL: {category} score is low ({review['score']}%)")

        return issues

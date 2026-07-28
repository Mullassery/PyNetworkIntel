"""Intelligent recommendation generation."""
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """Generate intelligent recommendations."""

    def generate_recommendations(self, architecture_review: Dict[str, Any], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate context-aware recommendations."""
        recommendations = []

        reviews = architecture_review.get("reviews", {})
        budget = context.get("budget", 10000)
        team_size = context.get("team_size", 5)
        time_horizon = context.get("time_horizon_months", 12)

        # Reliability recommendations
        if reviews.get("reliability", {}).get("score", 0) < 70:
            recommendations.append({
                "category": "reliability",
                "priority": "high",
                "action": "Implement multi-region deployment",
                "effort": "medium",
                "cost_impact": budget * 0.3,
                "timeline_weeks": 8,
            })

        # Security recommendations
        if reviews.get("security", {}).get("score", 0) < 70:
            recommendations.append({
                "category": "security",
                "priority": "high",
                "action": "Enable encryption and implement IAM",
                "effort": "medium",
                "cost_impact": budget * 0.2,
                "timeline_weeks": 6,
            })

        # Scalability recommendations
        if reviews.get("scalability", {}).get("score", 0) < 70:
            recommendations.append({
                "category": "scalability",
                "priority": "medium",
                "action": "Implement auto-scaling and caching",
                "effort": "high",
                "cost_impact": budget * 0.25,
                "timeline_weeks": 12,
            })

        # Cost optimization
        if reviews.get("cost", {}).get("score", 0) < 70:
            recommendations.append({
                "category": "cost",
                "priority": "medium",
                "action": "Migrate to serverless architecture",
                "effort": "high",
                "cost_impact": -budget * 0.2,  # Negative = cost savings
                "timeline_weeks": 16,
            })

        # Rank by ROI
        recommendations = self._rank_by_roi(recommendations, budget, time_horizon)

        return recommendations

    def generate_roi_analysis(self, recommendation: Dict[str, Any], timeframe_months: int) -> Dict[str, Any]:
        """Calculate ROI for recommendation."""
        cost_impact = recommendation.get("cost_impact", 0)
        annual_savings = -cost_impact if cost_impact < 0 else 0
        period_benefit = (annual_savings / 12) * timeframe_months

        payback_months = (
            -cost_impact / monthly_benefit if cost_impact > 0 and (cost_impact / 12) > 0 else 0
        )

        return {
            "recommendation": recommendation.get("action"),
            "upfront_cost": cost_impact if cost_impact > 0 else 0,
            "monthly_savings": annual_savings / 12,
            "total_benefit_period": period_benefit,
            "roi_percent": (period_benefit / cost_impact * 100) if cost_impact > 0 else 0,
            "payback_period_months": payback_months,
        }

    @staticmethod
    def _rank_by_roi(recommendations: List[Dict[str, Any]], budget: float, timeframe: int) -> List[Dict[str, Any]]:
        """Rank recommendations by ROI."""
        scored = []

        for rec in recommendations:
            cost = rec.get("cost_impact", 0)
            savings = -cost if cost < 0 else 0
            total_benefit = (savings / 12) * timeframe

            roi = (total_benefit / abs(cost)) if cost != 0 else 0

            scored.append({
                **rec,
                "roi_score": roi,
            })

        return sorted(scored, key=lambda x: x["roi_score"], reverse=True)

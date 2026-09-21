"""Tests for pynetworkintel.architect.recommendation_engine.

architect/ is not shipped in the distributed package (excluded from
pyproject.toml's packages list) but its source is still present in the
tree; this covers the specific NameError regression documented in
ROADMAP_HONEST.md (recommendation_engine.py:76 referenced an undefined
`monthly_benefit` variable).
"""

from pynetworkintel.architect.recommendation_engine import RecommendationEngine


class TestGenerateRoiAnalysis:
    def test_positive_cost_impact_with_no_modeled_savings_does_not_raise(self):
        """This is the exact path that used to raise NameError: monthly_benefit
        was referenced before it was ever assigned."""
        engine = RecommendationEngine()
        recommendation = {
            "category": "security",
            "action": "Enable encryption and implement IAM",
            "cost_impact": 2000,
        }

        result = engine.generate_roi_analysis(recommendation, timeframe_months=12)

        assert result["upfront_cost"] == 2000
        assert result["monthly_savings"] == 0
        # No savings modeled for a pure-cost recommendation -> no payback period.
        assert result["payback_period_months"] == 0

    def test_negative_cost_impact_computes_payback_from_savings(self):
        engine = RecommendationEngine()
        recommendation = {
            "category": "cost",
            "action": "Migrate to serverless architecture",
            "cost_impact": -1200,  # negative = annual savings
        }

        result = engine.generate_roi_analysis(recommendation, timeframe_months=12)

        assert result["upfront_cost"] == 0
        assert result["monthly_savings"] == 100
        assert result["payback_period_months"] == 0  # no upfront cost to pay back

    def test_zero_cost_impact_does_not_raise(self):
        result = RecommendationEngine().generate_roi_analysis(
            {"cost_impact": 0}, timeframe_months=6
        )
        assert result["payback_period_months"] == 0
        assert result["roi_percent"] == 0

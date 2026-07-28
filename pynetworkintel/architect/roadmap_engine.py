"""Roadmap generation and planning."""
from typing import Dict, List, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class RoadmapEngine:
    """Generate phased implementation roadmaps."""

    def generate_roadmap(self, current_state: Dict[str, Any], target_state: Dict[str, Any], timeframe_months: int = 12) -> Dict[str, Any]:
        """Generate implementation roadmap."""
        gaps = self._identify_gaps(current_state, target_state)
        phases = self._create_phases(gaps, timeframe_months)

        return {
            "current_state": current_state,
            "target_state": target_state,
            "timeframe_months": timeframe_months,
            "total_gap_items": len(gaps),
            "phases": phases,
            "critical_path": self._identify_critical_path(phases),
            "success_metrics": self._define_success_metrics(target_state),
        }

    def _identify_gaps(self, current_state: Dict[str, Any], target_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify gaps between current and target state."""
        gaps = []

        for key, target_value in target_state.items():
            current_value = current_state.get(key)

            if current_value != target_value:
                gaps.append({
                    "area": key,
                    "current": current_value,
                    "target": target_value,
                    "gap_size": self._estimate_gap_size(current_value, target_value),
                })

        return gaps

    def _create_phases(self, gaps: List[Dict[str, Any]], total_months: int) -> List[Dict[str, Any]]:
        """Create implementation phases."""
        phases = []

        # Sort gaps by priority
        sorted_gaps = sorted(gaps, key=lambda x: x.get("gap_size", 1), reverse=True)

        # Divide into phases
        gaps_per_phase = max(1, len(sorted_gaps) // 3)

        for phase_num in range(1, 4):
            start_gap = (phase_num - 1) * gaps_per_phase
            end_gap = start_gap + gaps_per_phase if phase_num < 3 else len(sorted_gaps)

            phase_gaps = sorted_gaps[start_gap:end_gap]
            start_date = datetime.now() + timedelta(months=(phase_num - 1) * (total_months // 3))
            end_date = start_date + timedelta(months=total_months // 3)

            phases.append({
                "phase": phase_num,
                "name": f"Phase {phase_num}: {self._get_phase_name(phase_num)}",
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "duration_weeks": 12,
                "objectives": phase_gaps,
                "milestones": self._create_milestones(phase_gaps),
            })

        return phases

    @staticmethod
    def _get_phase_name(phase_num: int) -> str:
        """Get phase name."""
        names = {
            1: "Foundation & Assessment",
            2: "Implementation & Integration",
            3: "Optimization & Hardening",
        }

        return names.get(phase_num, "Unknown")

    @staticmethod
    def _create_milestones(objectives: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create milestones from objectives."""
        milestones = []

        for i, obj in enumerate(objectives, 1):
            milestones.append({
                "week": i * 3,
                "objective": obj.get("area"),
                "deliverable": f"Implement {obj.get('area')}",
            })

        return milestones

    @staticmethod
    def _identify_critical_path(phases: List[Dict[str, Any]]) -> List[str]:
        """Identify critical path items."""
        critical = []

        for phase in phases:
            objectives = phase.get("objectives", [])
            for obj in objectives:
                if obj.get("gap_size", 1) > 0.7:
                    critical.append(f"Phase {phase['phase']}: {obj['area']}")

        return critical

    @staticmethod
    def _estimate_gap_size(current: Any, target: Any) -> float:
        """Estimate gap size (0-1)."""
        if current is None and target is not None:
            return 1.0
        elif current == target:
            return 0.0
        else:
            return 0.5

    @staticmethod
    def _define_success_metrics(target_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Define success metrics for roadmap."""
        return [
            {
                "metric": "Reliability Score",
                "target": 90,
                "unit": "percent",
            },
            {
                "metric": "Security Score",
                "target": 85,
                "unit": "percent",
            },
            {
                "metric": "Scalability Score",
                "target": 80,
                "unit": "percent",
            },
            {
                "metric": "Cost Optimization",
                "target": 30,
                "unit": "percent_reduction",
            },
        ]

"""Pattern recognition and matching."""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class PatternEngine:
    """Recognize and match architecture patterns."""

    def __init__(self):
        """Initialize pattern engine."""
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load known architecture patterns."""
        return {
            "serverless_web": {
                "components": ["api_gateway", "lambda", "dynamodb"],
                "benefits": ["cost", "scalability", "low_ops"],
                "best_for": ["rest_api", "microservices"],
            },
            "three_tier_app": {
                "components": ["load_balancer", "app_servers", "database"],
                "benefits": ["separation_of_concerns", "scalability"],
                "best_for": ["traditional_web_apps"],
            },
            "microservices_mesh": {
                "components": ["service_mesh", "kubernetes", "databases"],
                "benefits": ["resilience", "scalability", "independent_deployment"],
                "best_for": ["large_applications"],
            },
            "event_driven": {
                "components": ["event_bus", "consumers", "storage"],
                "benefits": ["loose_coupling", "scalability"],
                "best_for": ["real_time_systems"],
            },
        }

    def detect_patterns(self, components: List[str]) -> List[Dict[str, Any]]:
        """Detect which patterns match the architecture."""
        matches = []

        for pattern_name, pattern_info in self.patterns.items():
            pattern_components = set(pattern_info["components"])
            input_components = set(components)

            overlap = len(pattern_components & input_components)
            similarity = overlap / len(pattern_components)

            if similarity > 0.5:
                matches.append({
                    "pattern": pattern_name,
                    "match_score": similarity,
                    "benefits": pattern_info.get("benefits", []),
                })

        return sorted(matches, key=lambda x: x["match_score"], reverse=True)

    def suggest_patterns(self, requirements: List[str]) -> List[Dict[str, Any]]:
        """Suggest patterns based on requirements."""
        suggestions = []

        for pattern_name, pattern_info in self.patterns.items():
            best_for = pattern_info.get("best_for", [])

            match_count = sum(1 for req in requirements if req in best_for)

            if match_count > 0:
                suggestions.append({
                    "pattern": pattern_name,
                    "match_score": match_count / len(requirements),
                    "benefits": pattern_info.get("benefits"),
                })

        return sorted(suggestions, key=lambda x: x["match_score"], reverse=True)

    def analyze_anti_patterns(self, architecture: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify anti-patterns in architecture."""
        anti_patterns = []

        components = architecture.get("components", [])
        connections = architecture.get("connections", [])

        # Check for too many dependencies (monolith)
        if len(connections) > len(components) * 2:
            anti_patterns.append({
                "pattern": "monolithic_coupling",
                "severity": "high",
                "description": "Too many interconnections suggest tight coupling",
                "recommendation": "Refactor into independent services",
            })

        # Check for missing redundancy
        redundant = sum(1 for c in components if "replica" in str(c).lower())
        if redundant == 0 and len(components) > 3:
            anti_patterns.append({
                "pattern": "no_redundancy",
                "severity": "high",
                "description": "No redundancy for high availability",
                "recommendation": "Add replicas for critical components",
            })

        return anti_patterns

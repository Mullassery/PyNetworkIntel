"""Architecture graph engine and modeling."""
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ArchitectureComponent:
    id: str
    name: str
    component_type: str
    cloud: str
    layer: str
    depends_on: List[str] = None
    depends_on_type: List[str] = None
    replicas: int = 1
    region: str = "us-east-1"
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []
        if self.metadata is None:
            self.metadata = {}


class ArchitectureEngine:
    """Model and analyze cloud architecture."""

    def __init__(self):
        """Initialize architecture engine."""
        self.components: Dict[str, ArchitectureComponent] = {}
        self.connections: List[Tuple[str, str]] = []

    def add_component(self, component: ArchitectureComponent) -> bool:
        """Add component to architecture."""
        if component.id in self.components:
            logger.warning(f"Component {component.id} already exists")
            return False

        self.components[component.id] = component
        logger.info(f"Added component: {component.id} ({component.component_type})")

        return True

    def add_connection(self, from_id: str, to_id: str) -> bool:
        """Add connection between components."""
        if from_id not in self.components or to_id not in self.components:
            logger.error("One or both components not found")
            return False

        self.connections.append((from_id, to_id))

        # Update depends_on
        component = self.components[to_id]
        if from_id not in component.depends_on:
            component.depends_on.append(from_id)

        return True

    def detect_single_points_of_failure(self) -> List[Dict[str, Any]]:
        """Detect single points of failure (SPOFs)."""
        spofs = []

        for component_id, component in self.components.items():
            # Check if component is a bottleneck
            incoming = sum(1 for c in self.connections if c[1] == component_id)
            outgoing = sum(1 for c in self.connections if c[0] == component_id)

            # SPOF if high incoming traffic but no redundancy
            if incoming > 2 and component.replicas == 1:
                spofs.append({
                    "component_id": component_id,
                    "component_name": component.name,
                    "type": "single_replica_bottleneck",
                    "incoming_connections": incoming,
                    "recommendation": "Increase replicas for redundancy",
                })

            # SPOF if component has no redundancy in critical path
            if component.component_type in ["database", "message_queue"] and component.replicas == 1:
                spofs.append({
                    "component_id": component_id,
                    "component_name": component.name,
                    "type": "critical_component_single_replica",
                    "recommendation": "Configure replication and failover",
                })

        return spofs

    def analyze_complexity(self) -> Dict[str, Any]:
        """Analyze architecture complexity."""
        num_components = len(self.components)
        num_connections = len(self.connections)

        # Calculate average connections per component
        avg_connections = (
            num_connections / num_components if num_components > 0 else 0
        )

        # Calculate depth of architecture
        depth = self._calculate_depth()

        complexity_score = (
            num_components * 0.3 +
            num_connections * 0.4 +
            depth * 0.3
        )

        return {
            "total_components": num_components,
            "total_connections": num_connections,
            "average_connections": avg_connections,
            "depth": depth,
            "complexity_score": min(complexity_score, 100),
            "complexity_level": self._get_complexity_level(complexity_score),
        }

    def calculate_high_availability(self) -> Dict[str, Any]:
        """Calculate high availability score."""
        if not self.components:
            return {"ha_score": 0, "ha_level": "none"}

        redundant_components = sum(
            1 for c in self.components.values() if c.replicas > 1
        )

        ha_percentage = (redundant_components / len(self.components)) * 100

        return {
            "redundant_components": redundant_components,
            "total_components": len(self.components),
            "redundancy_percentage": ha_percentage,
            "ha_score": ha_percentage,
            "ha_level": "high" if ha_percentage > 70 else "medium" if ha_percentage > 30 else "low",
        }

    def suggest_improvements(self) -> List[Dict[str, Any]]:
        """Suggest architecture improvements."""
        suggestions = []

        # Check for SPOFs
        spofs = self.detect_single_points_of_failure()
        if spofs:
            suggestions.append({
                "category": "high_availability",
                "priority": "high",
                "count": len(spofs),
                "suggestion": "Add redundancy to eliminate single points of failure",
                "details": spofs[:3],
            })

        # Check complexity
        complexity = self.analyze_complexity()
        if complexity["complexity_score"] > 70:
            suggestions.append({
                "category": "simplification",
                "priority": "medium",
                "suggestion": "Consider simplifying architecture",
                "current_complexity": complexity["complexity_score"],
            })

        # Check distribution
        clouds = set(c.cloud for c in self.components.values())
        if len(clouds) > 1:
            suggestions.append({
                "category": "multi_cloud",
                "priority": "medium",
                "suggestion": "Multi-cloud strategy in place",
                "clouds": list(clouds),
            })

        return suggestions

    def export_architecture_diagram(self, format: str = "mermaid") -> str:
        """Export architecture as diagram."""
        if format == "mermaid":
            return self._generate_mermaid_diagram()
        else:
            return ""

    def _generate_mermaid_diagram(self) -> str:
        """Generate Mermaid diagram of architecture."""
        lines = ["graph TB"]

        for component_id, component in self.components.items():
            label = f"{component.name}<br/>({component.component_type})"
            lines.append(f'    {component_id}["{label}"]')

        for from_id, to_id in self.connections:
            lines.append(f"    {from_id} --> {to_id}")

        return "\n".join(lines)

    def _calculate_depth(self) -> int:
        """Calculate architecture depth (layers)."""
        if not self.components:
            return 0

        layers = set(c.layer for c in self.components.values())
        return len(layers)

    @staticmethod
    def _get_complexity_level(score: float) -> str:
        """Get complexity level from score."""
        if score > 70:
            return "complex"
        elif score > 40:
            return "moderate"
        else:
            return "simple"

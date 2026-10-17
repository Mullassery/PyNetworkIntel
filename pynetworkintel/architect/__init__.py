"""EXPERIMENTAL / UNSUPPORTED - not part of the distributed package.

A conversational "AI architecture advisor" is unrelated to this tool's
stated core purpose (network discovery, topology mapping, vulnerability
scanning) - it's general software-architecture guidance, not network
intelligence. Untested and NOT included in the pynetworkintel wheel/sdist
(see pyproject.toml [tool.setuptools] packages). Kept in the source tree
only in case it's spun out into a separate product later.
"""

from .architecture_engine import ArchitectureEngine
from .conversational_ai import ConversationalArchitect
from .knowledge_base import KnowledgeBase
from .pattern_engine import PatternEngine
from .recommendation_engine import RecommendationEngine
from .review_engine import ReviewEngine
from .roadmap_engine import RoadmapEngine

__all__ = [
    "ArchitectureEngine",
    "ConversationalArchitect",
    "KnowledgeBase",
    "PatternEngine",
    "RecommendationEngine",
    "ReviewEngine",
    "RoadmapEngine",
]

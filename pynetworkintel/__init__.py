"""PyNetworkIntel: AI-powered network intelligence platform."""

__version__ = "0.1.0"

from pynetworkintel.core import Scanner, Analyzer

# MCP 2.0 Support (v0.1+) — Network security intelligence
from pynetworkintel._mcp_connector import NetworkIntelligence

__all__ = ["Scanner", "Analyzer", "NetworkIntelligence"]

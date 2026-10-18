"""PyNetworkIntel: AI-powered network intelligence platform."""

__version__ = "1.6.0"

# Core scanning and analysis
# MCP 2.0 Support — Network security intelligence
from pynetworkintel._mcp_connector import NetworkIntelligence

# Alerting
from pynetworkintel.alerts import (
    AlertChannel,
    AlertManager,
    EmailAlertChannel,
    SlackAlertChannel,
    WebhookAlertChannel,
)

# Change detection and reporting
from pynetworkintel.changes import ChangeDetector, ChangeReporter

# Configuration
from pynetworkintel.config import (
    AnalysisConfig,
    AppConfig,
    OutputConfig,
    ScanConfig,
    SSHConfig,
)
from pynetworkintel.core import Analyzer, Pipeline, Scanner

# Dashboard and monitoring
from pynetworkintel.dashboard import Dashboard, DashboardClient, DashboardServer

# Models and data structures
from pynetworkintel.models import (
    ConfigFile,
    Device,
    FindingType,
    ScanResult,
    Service,
    Severity,
)

# Utilities
from pynetworkintel.progress import OutputFormatter, ProgressIndicator
from pynetworkintel.reporting import ReportGenerator
from pynetworkintel.scheduler import MonitoringScheduler

# Topology mapping
from pynetworkintel.topology import NetworkTopology, TopologyEdge, TopologyMapper, TopologyNode
from pynetworkintel.topology_export import export_topology, to_graphml, to_node_link_json

__all__ = [
    # Alerts
    "AlertChannel",
    "AlertManager",
    "AnalysisConfig",
    "Analyzer",
    "AppConfig",
    # Change detection
    "ChangeDetector",
    "ChangeReporter",
    "ConfigFile",
    # Dashboard
    "Dashboard",
    "DashboardClient",
    "DashboardServer",
    "Device",
    "EmailAlertChannel",
    "FindingType",
    # Scheduler
    "MonitoringScheduler",
    # MCP
    "NetworkIntelligence",
    "NetworkTopology",
    "OutputConfig",
    "OutputFormatter",
    "Pipeline",
    # Utilities
    "ProgressIndicator",
    # Reporting
    "ReportGenerator",
    # Config
    "SSHConfig",
    "ScanConfig",
    "ScanResult",
    # Core
    "Scanner",
    "Service",
    # Models
    "Severity",
    "SlackAlertChannel",
    "TopologyEdge",
    # Topology
    "TopologyMapper",
    "TopologyNode",
    "WebhookAlertChannel",
    "export_topology",
    "to_graphml",
    "to_node_link_json",
]

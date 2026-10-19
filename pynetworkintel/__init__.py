"""PyNetworkIntel: AI-powered network intelligence platform."""

__version__ = "1.9.0"

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
from pynetworkintel.discovery.nuclei import NucleiScanner, NucleiUnavailable, scan_with_nuclei
from pynetworkintel.integrations.netbox import NetBoxCsvExporter, devices_csv, prefixes_csv
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

__all__ = [  # noqa: RUF022
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
    "NetBoxCsvExporter",
    "devices_csv",
    "prefixes_csv",
    "NucleiScanner",
    "NucleiUnavailable",
    "scan_with_nuclei",
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

"""PyNetworkIntel: AI-powered network intelligence platform."""

__version__ = "1.2.0"

# Core scanning and analysis
from pynetworkintel.core import Scanner, Analyzer, Pipeline

# Models and data structures
from pynetworkintel.models import (
    Severity,
    FindingType,
    Service,
    ConfigFile,
    Device,
    ScanResult,
)

# Configuration
from pynetworkintel.config import (
    SSHConfig,
    ScanConfig,
    AnalysisConfig,
    OutputConfig,
    AppConfig,
)

# Alerting
from pynetworkintel.alerts import (
    AlertChannel,
    SlackAlertChannel,
    EmailAlertChannel,
    WebhookAlertChannel,
    AlertManager,
)

# Change detection and reporting
from pynetworkintel.changes import ChangeDetector, ChangeReporter
from pynetworkintel.reporting import ReportGenerator

# Dashboard and monitoring
from pynetworkintel.dashboard import Dashboard, DashboardServer, DashboardClient
from pynetworkintel.scheduler import MonitoringScheduler

# Utilities
from pynetworkintel.progress import ProgressIndicator, OutputFormatter

# MCP 2.0 Support — Network security intelligence
from pynetworkintel._mcp_connector import NetworkIntelligence

__all__ = [
    # Core
    "Scanner",
    "Analyzer",
    "Pipeline",
    # Models
    "Severity",
    "FindingType",
    "Service",
    "ConfigFile",
    "Device",
    "ScanResult",
    # Config
    "SSHConfig",
    "ScanConfig",
    "AnalysisConfig",
    "OutputConfig",
    "AppConfig",
    # Alerts
    "AlertChannel",
    "SlackAlertChannel",
    "EmailAlertChannel",
    "WebhookAlertChannel",
    "AlertManager",
    # Change detection
    "ChangeDetector",
    "ChangeReporter",
    # Reporting
    "ReportGenerator",
    # Dashboard
    "Dashboard",
    "DashboardServer",
    "DashboardClient",
    # Scheduler
    "MonitoringScheduler",
    # Utilities
    "ProgressIndicator",
    "OutputFormatter",
    # MCP
    "NetworkIntelligence",
]

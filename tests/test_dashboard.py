"""Tests for the stats dashboard module."""

import pytest
import time
import os
from pynetworkintel.dashboard import (
    StatsCollector,
    DashboardServer,
    Dashboard,
    TerminalLauncher,
)


def test_stats_collector_initialization():
    """Test StatsCollector initialization."""
    collector = StatsCollector()
    assert collector.target == ""
    assert collector.devices_discovered == 0
    assert collector.scan_status == "Idle"


def test_stats_collector_to_dict():
    """Test StatsCollector serialization."""
    collector = StatsCollector()
    collector.target = "192.168.1.0/24"
    collector.devices_discovered = 10
    collector.findings_critical = 2

    stats = collector.to_dict()
    assert stats["target"] == "192.168.1.0/24"
    assert stats["devices_discovered"] == 10
    assert stats["findings"]["critical"] == 2
    assert "timestamp" in stats


def test_stats_collector_elapsed_time():
    """Test elapsed time calculation."""
    collector = StatsCollector()
    collector.start_time = time.time()

    time.sleep(0.1)
    stats = collector.to_dict()

    assert stats["elapsed_seconds"] >= 0.1


def test_stats_collector_total_findings():
    """Test total findings calculation."""
    collector = StatsCollector()
    collector.findings_critical = 1
    collector.findings_high = 2
    collector.findings_medium = 3

    stats = collector.to_dict()
    assert stats["total_findings"] == 6


def test_dashboard_server_socket_path():
    """Test DashboardServer socket path generation."""
    collector = StatsCollector()
    server = DashboardServer(collector)

    assert server.socket_path is not None
    if os.name != "nt":  # Unix-like systems
        assert "/tmp/pynetworkintel_stats_" in server.socket_path
        assert server.socket_path.endswith(".sock")


def test_dashboard_initialization():
    """Test Dashboard initialization."""
    collector = StatsCollector()
    collector.target = "192.168.1.0/24"
    collector.devices_discovered = 5

    dashboard = Dashboard(socket_path=None)
    dashboard.stats = collector.to_dict()

    assert dashboard.stats["target"] == "192.168.1.0/24"
    assert dashboard.stats["devices_discovered"] == 5


def test_dashboard_format_duration():
    """Test duration formatting."""
    # Test seconds
    assert Dashboard._format_duration(30) == "30s"

    # Test minutes
    assert Dashboard._format_duration(90) == "1.5m"

    # Test hours
    assert Dashboard._format_duration(3600) == "1.0h"


def test_terminal_launcher_platform_detection():
    """Test platform detection."""
    platform = TerminalLauncher.get_platform()
    assert platform in ["darwin", "linux", "windows"]


def test_stats_collector_error_tracking():
    """Test error tracking in stats collector."""
    collector = StatsCollector()
    assert collector.errors == []

    collector.errors.append("Connection timeout")
    assert len(collector.errors) == 1
    assert "Connection timeout" in collector.errors


def test_stats_collector_phase_tracking():
    """Test current phase tracking."""
    collector = StatsCollector()
    assert collector.current_phase == "Initialization"

    collector.current_phase = "Device Discovery"
    stats = collector.to_dict()
    assert stats["current_phase"] == "Device Discovery"


def test_stats_collector_current_device():
    """Test current device tracking."""
    collector = StatsCollector()
    assert collector.current_device is None

    collector.current_device = "192.168.1.1"
    stats = collector.to_dict()
    assert stats["current_device"] == "192.168.1.1"


@pytest.mark.skipif(
    os.environ.get("SKIP_DASHBOARD_INTEGRATION") == "1",
    reason="Dashboard integration test skipped",
)
def test_dashboard_layout_building():
    """Test dashboard layout construction."""
    collector = StatsCollector()
    collector.target = "192.168.1.0/24"
    collector.devices_discovered = 42
    collector.devices_online = 38
    collector.findings_critical = 2
    collector.findings_high = 5

    dashboard = Dashboard(socket_path=None)
    dashboard.stats = collector.to_dict()

    # Test that we can build the layout (this doesn't actually render)
    layout = dashboard._build_layout()
    assert layout is not None

    # Test individual components
    header = dashboard._build_header()
    assert header is not None

    summary = dashboard._build_summary()
    assert summary is not None

    details = dashboard._build_details()
    assert details is not None

    footer = dashboard._build_footer()
    assert footer is not None

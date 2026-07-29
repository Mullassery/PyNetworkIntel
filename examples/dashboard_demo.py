#!/usr/bin/env python3
"""
Example: Using PyNetworkIntel Dashboard Programmatically

This example demonstrates how to use the dashboard in your own scripts
without going through the CLI.
"""

import time
import sys
from datetime import datetime
from threading import Thread

# Add parent directory to path
sys.path.insert(0, '/Users/georgimullassery/PyNetworkIntel')

from pynetworkintel.dashboard import StatsCollector, DashboardServer, Dashboard, TerminalLauncher


def simulate_scan():
    """Simulate a network scan with progressive stat updates."""

    # Create stats collector
    stats = StatsCollector()
    stats.target = "192.168.1.0/24"
    stats.start_time = time.time()

    # Create and start server
    server = DashboardServer(stats)
    server.start()

    # Launch dashboard in separate terminal
    print("Launching dashboard...")
    process = TerminalLauncher.launch_dashboard(server.socket_path)

    if process:
        print(f"Dashboard launched (PID: {process.pid})")
        print(f"Stats server socket: {server.socket_path}")
    else:
        print("Warning: Could not launch dashboard")

    # Give dashboard time to start
    time.sleep(2)

    try:
        # Simulate scan progression
        print("\n[Main Process] Starting scan simulation...")

        # Phase 1: Device Discovery (30 seconds)
        print("[Main Process] Phase 1: Device Discovery")
        stats.scan_status = "Scanning"
        stats.current_phase = "Device Discovery"

        for i in range(30):
            stats.devices_discovered = int(42 * (i / 30))
            stats.devices_online = int(38 * (i / 30))
            stats.current_device = f"192.168.1.{10 + (i % 40)}"
            time.sleep(1)

        stats.devices_discovered = 42
        stats.devices_online = 38

        # Phase 2: Config Grabbing (15 seconds)
        print("[Main Process] Phase 2: Config Grabbing")
        stats.current_phase = "Config Grabbing"

        for i in range(15):
            stats.configs_grabbed = int(15 * (i / 15))
            stats.current_device = f"192.168.1.{50 + (i % 38)}"
            time.sleep(1)

        stats.configs_grabbed = 15

        # Phase 3: Security Analysis (30 seconds)
        print("[Main Process] Phase 3: Security Analysis")
        stats.current_phase = "Security Analysis"

        finding_patterns = [
            (2, 5, 12, 0, 0),  # 2 critical, 5 high, 12 medium
            (2, 5, 12, 8, 0),  # 2 critical, 5 high, 12 medium, 8 low
            (2, 5, 12, 8, 3),  # 2 critical, 5 high, 12 medium, 8 low, 3 info
        ]

        for i, pattern in enumerate(finding_patterns):
            stats.findings_critical = pattern[0]
            stats.findings_high = pattern[1]
            stats.findings_medium = pattern[2]
            stats.findings_low = pattern[3]
            stats.findings_info = pattern[4]

            # Update current device
            if i < len(finding_patterns) - 1:
                stats.current_device = f"192.168.1.{int(10 + 40 * (i / len(finding_patterns)))}"

            # Show findings in main process
            total = sum(pattern)
            print(f"[Main Process] Found {total} findings (C:{pattern[0]} H:{pattern[1]} M:{pattern[2]} L:{pattern[3]} I:{pattern[4]})")

            time.sleep(10)

        # Completion
        print("[Main Process] Scan complete!")
        stats.scan_status = "Complete"
        stats.current_phase = "Analysis Complete"
        stats.current_device = None

        print("\nDashboard will continue running for 5 more seconds...")
        print("Press Ctrl+C to close the main process, then close the dashboard window.")
        time.sleep(5)

    except KeyboardInterrupt:
        print("\n[Main Process] Scan interrupted by user")
    finally:
        # Stop server
        print("[Main Process] Stopping stats server...")
        server.stop()


def standalone_dashboard_example():
    """Example of showing a static dashboard with mock data."""

    # Create mock stats
    stats = StatsCollector()
    stats.target = "192.168.1.0/24"
    stats.start_time = time.time() - 120  # Pretend scan ran for 2 minutes
    stats.devices_discovered = 42
    stats.devices_online = 38
    stats.configs_grabbed = 15
    stats.findings_critical = 2
    stats.findings_high = 5
    stats.findings_medium = 12
    stats.findings_low = 8
    stats.findings_info = 3
    stats.scan_status = "Complete"
    stats.current_phase = "Analysis Complete"

    # Create dashboard
    dashboard = Dashboard(socket_path=None)
    dashboard.stats = stats.to_dict()

    print("Displaying static dashboard (press Ctrl+C to exit)...")
    print("This shows what the dashboard looks like after a scan completes.\n")

    try:
        dashboard.run()
    except KeyboardInterrupt:
        print("\n[Standalone] Dashboard closed")


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "static":
        print("Running standalone dashboard example (static data)...")
        standalone_dashboard_example()
    else:
        print("Running scan simulation with live dashboard...")
        print("This will launch the dashboard in a separate terminal.\n")
        simulate_scan()


if __name__ == "__main__":
    main()

"""CLI stats dashboard that runs in a separate terminal window."""

import os
import sys
import json
import time
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from threading import Thread, Event
import socket

try:
    from rich.console import Console
    from rich.table import Table
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.live import Live
    from rich.progress import Progress, BarColumn, TextColumn, DownloadColumn
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class StatsCollector:
    """Collects and manages scan statistics."""

    def __init__(self):
        self.target = ""
        self.start_time = None
        self.devices_discovered = 0
        self.devices_online = 0
        self.configs_grabbed = 0
        self.findings_critical = 0
        self.findings_high = 0
        self.findings_medium = 0
        self.findings_low = 0
        self.findings_info = 0
        self.scan_status = "Idle"
        self.current_phase = "Initialization"
        self.errors = []
        self.current_device = None

    def to_dict(self) -> Dict[str, Any]:
        """Export stats as dictionary."""
        elapsed = 0
        if self.start_time:
            elapsed = time.time() - self.start_time

        return {
            "target": self.target,
            "elapsed_seconds": elapsed,
            "devices_discovered": self.devices_discovered,
            "devices_online": self.devices_online,
            "configs_grabbed": self.configs_grabbed,
            "findings": {
                "critical": self.findings_critical,
                "high": self.findings_high,
                "medium": self.findings_medium,
                "low": self.findings_low,
                "info": self.findings_info,
            },
            "total_findings": (
                self.findings_critical
                + self.findings_high
                + self.findings_medium
                + self.findings_low
                + self.findings_info
            ),
            "scan_status": self.scan_status,
            "current_phase": self.current_phase,
            "current_device": self.current_device,
            "errors": self.errors,
            "timestamp": datetime.now().isoformat(),
        }


class DashboardServer:
    """Local IPC server for dashboard stats updates."""

    def __init__(self, stats: StatsCollector, socket_path: Optional[str] = None):
        self.stats = stats
        self.socket_path = socket_path or self._get_socket_path()
        self.running = False

    def _get_socket_path(self) -> str:
        """Get platform-specific socket path."""
        if platform.system() == "Windows":
            # Windows named pipe
            return "\\\\.\\pipe\\pynetworkintel_stats"
        else:
            # Unix socket
            return f"/tmp/pynetworkintel_stats_{os.getpid()}.sock"

    def start(self):
        """Start the server in a background thread."""
        self.running = True
        thread = Thread(target=self._run_server, daemon=True)
        thread.start()

    def _run_server(self):
        """Run the stats server."""
        if platform.system() == "Windows":
            self._run_windows_server()
        else:
            self._run_unix_server()

    def _run_unix_server(self):
        """Run Unix socket-based stats server."""
        import socket as sock

        # Clean up old socket
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        try:
            server = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
            server.bind(self.socket_path)
            server.listen(1)

            while self.running:
                server.settimeout(1.0)
                try:
                    conn, _ = server.accept()
                    data = json.dumps(self.stats.to_dict()).encode()
                    conn.send(data)
                    conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break

            server.close()
        finally:
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)

    def _run_windows_server(self):
        """Run Windows named pipe-based stats server."""
        import pipetools

        try:
            while self.running:
                try:
                    with pipetools.PipeServer(self.socket_path) as pipe:
                        data = json.dumps(self.stats.to_dict()).encode()
                        pipe.write(data)
                        time.sleep(0.1)
                except Exception:
                    time.sleep(0.1)
        except Exception:
            pass

    def stop(self):
        """Stop the server."""
        self.running = False


class DashboardClient:
    """Client for connecting to dashboard stats server."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Fetch current stats from server."""
        if platform.system() == "Windows":
            return self._get_stats_windows()
        else:
            return self._get_stats_unix()

    def _get_stats_unix(self) -> Optional[Dict[str, Any]]:
        """Fetch stats via Unix socket."""
        import socket as sock

        try:
            client = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
            client.connect(self.socket_path)
            client.settimeout(2.0)
            data = client.recv(8192)
            client.close()
            return json.loads(data.decode())
        except Exception:
            return None

    def _get_stats_windows(self) -> Optional[Dict[str, Any]]:
        """Fetch stats via Windows named pipe."""
        import pipetools

        try:
            with pipetools.PipeClient(self.socket_path) as pipe:
                data = pipe.read()
                return json.loads(data.decode())
        except Exception:
            return None


class TerminalLauncher:
    """Launches the dashboard in a new terminal window."""

    @staticmethod
    def get_platform() -> str:
        """Get platform identifier."""
        return platform.system().lower()

    @staticmethod
    def launch_dashboard(socket_path: str) -> Optional[subprocess.Popen]:
        """
        Launch dashboard in a new terminal window.

        Args:
            socket_path: Path to stats server socket

        Returns:
            Popen process object or None if launch failed
        """
        platform_name = TerminalLauncher.get_platform()

        if platform_name == "darwin":
            return TerminalLauncher._launch_macos(socket_path)
        elif platform_name == "linux":
            return TerminalLauncher._launch_linux(socket_path)
        elif platform_name == "windows":
            return TerminalLauncher._launch_windows(socket_path)
        else:
            return None

    @staticmethod
    def _launch_macos(socket_path: str) -> Optional[subprocess.Popen]:
        """Launch dashboard in Terminal.app on macOS."""
        script = f"""
import subprocess
import sys
from pynetworkintel.dashboard import Dashboard

dashboard = Dashboard(socket_path="{socket_path}")
dashboard.run()
"""

        cmd = [
            "osascript",
            "-e",
            f'tell app "Terminal" to do script "python3 -c {repr(script)}"',
        ]

        try:
            return subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception:
            return None

    @staticmethod
    def _launch_linux(socket_path: str) -> Optional[subprocess.Popen]:
        """Launch dashboard in a new terminal on Linux."""
        script_content = f"""#!/bin/bash
python3 -c "from pynetworkintel.dashboard import Dashboard; Dashboard(socket_path='{socket_path}').run()"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False
        ) as f:
            f.write(script_content)
            script_path = f.name

        os.chmod(script_path, 0o755)

        # Try various terminal emulators in order of preference
        terminal_cmds = [
            ["gnome-terminal", "--", script_path],
            ["konsole", "-e", script_path],
            ["xterm", "-e", script_path],
            ["xfce4-terminal", "-e", script_path],
            ["terminator", "-e", script_path],
            ["rxvt", "-e", script_path],
        ]

        for cmd in terminal_cmds:
            try:
                return subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError:
                continue

        return None

    @staticmethod
    def _launch_windows(socket_path: str) -> Optional[subprocess.Popen]:
        """Launch dashboard in a new terminal on Windows."""
        script_content = f"""python -c "from pynetworkintel.dashboard import Dashboard; Dashboard(socket_path='{socket_path}').run()"
pause"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as f:
            f.write(script_content)
            script_path = f.name

        try:
            return subprocess.Popen(
                ["cmd", "/c", "start", "cmd", "/k", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception:
            return None


class Dashboard:
    """Rich terminal dashboard for displaying scan stats."""

    def __init__(self, socket_path: Optional[str] = None, refresh_rate: float = 1.0):
        if not RICH_AVAILABLE:
            raise RuntimeError("Rich library is required for dashboard")

        self.socket_path = socket_path
        self.refresh_rate = refresh_rate
        self.client = DashboardClient(socket_path) if socket_path else None
        self.console = Console()
        self.stats = {}

    def run(self):
        """Run the dashboard display loop."""
        try:
            with Live(
                self._build_layout(),
                refresh_per_second=1 / self.refresh_rate,
                screen=True,
                console=self.console,
            ) as live:
                while True:
                    if self.client:
                        new_stats = self.client.get_stats()
                        if new_stats:
                            self.stats = new_stats

                    live.update(self._build_layout())
                    time.sleep(self.refresh_rate)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Dashboard closed[/yellow]")

    def _build_layout(self) -> Layout:
        """Build the dashboard layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["header"].update(self._build_header())
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        layout["left"].update(self._build_summary())
        layout["right"].update(self._build_details())
        layout["footer"].update(self._build_footer())

        return layout

    def _build_header(self) -> Panel:
        """Build header panel."""
        target = self.stats.get("target", "None")
        status = self.stats.get("scan_status", "Idle")
        phase = self.stats.get("current_phase", "Initialization")

        header_text = Text.assemble(
            ("PyNetworkIntel ", "bold cyan"),
            ("Dashboard", "bold"),
            " | ",
            ("Target: ", "dim"),
            (target, "green"),
            " | ",
            ("Status: ", "dim"),
            (status, "yellow" if status != "Complete" else "green"),
            " | ",
            ("Phase: ", "dim"),
            (phase, "blue"),
        )

        return Panel(header_text, style="blue")

    def _build_summary(self) -> Panel:
        """Build summary stats panel."""
        table = Table(show_header=False, box=None)
        table.add_column(style="dim", width=20)
        table.add_column(style="bold", justify="right")

        elapsed = self.stats.get("elapsed_seconds", 0)
        elapsed_str = self._format_duration(elapsed)

        table.add_row("Elapsed Time", f"[cyan]{elapsed_str}[/cyan]")
        table.add_row(
            "Devices Discovered",
            f"[green]{self.stats.get('devices_discovered', 0)}[/green]",
        )
        table.add_row(
            "Devices Online",
            f"[green]{self.stats.get('devices_online', 0)}[/green]",
        )
        table.add_row(
            "Configs Grabbed",
            f"[yellow]{self.stats.get('configs_grabbed', 0)}[/yellow]",
        )

        return Panel(table, title="[bold]Summary[/bold]")

    def _build_details(self) -> Panel:
        """Build findings details panel."""
        findings = self.stats.get("findings", {})
        total_findings = self.stats.get("total_findings", 0)

        table = Table(show_header=False, box=None)
        table.add_column(style="dim", width=20)
        table.add_column(style="bold", justify="right")

        critical = findings.get("critical", 0)
        high = findings.get("high", 0)
        medium = findings.get("medium", 0)
        low = findings.get("low", 0)
        info = findings.get("info", 0)

        # Color code severity levels
        critical_style = "bold red" if critical > 0 else "dim red"
        high_style = "bold yellow" if high > 0 else "dim yellow"
        medium_style = "bold cyan" if medium > 0 else "dim cyan"

        table.add_row("Total Findings", f"[bold magenta]{total_findings}[/bold magenta]")
        table.add_row(f"Critical", f"[{critical_style}]{critical}[/{critical_style}]")
        table.add_row(f"High", f"[{high_style}]{high}[/{high_style}]")
        table.add_row(
            f"Medium", f"[{medium_style}]{medium}[/{medium_style}]"
        )
        table.add_row("Low", f"[dim green]{low}[/dim green]")
        table.add_row("Info", f"[dim blue]{info}[/dim blue]")

        current_device = self.stats.get("current_device")
        if current_device:
            table.add_row("Current Device", f"[bold white]{current_device}[/bold white]")

        return Panel(table, title="[bold]Findings[/bold]")

    def _build_footer(self) -> Panel:
        """Build footer panel."""
        errors = self.stats.get("errors", [])

        if errors:
            error_text = Text.assemble(
                ("[!] Errors: ", "bold red"),
                ("; ".join(errors[-3:]), "red"),  # Show last 3 errors
            )
        else:
            error_text = Text("[OK] Running smoothly", style="bold green")

        timestamp = self.stats.get("timestamp", "")
        if timestamp:
            ts_obj = datetime.fromisoformat(timestamp)
            timestamp_str = ts_obj.strftime("%H:%M:%S")
            error_text.append(f" | Last update: {timestamp_str}")

        return Panel(error_text, style="dim")

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"


def launch_stats_dashboard(target: str) -> Tuple[Optional[subprocess.Popen], Optional[DashboardServer]]:
    """
    Launch a stats dashboard in a separate terminal.

    Args:
        target: Network target being scanned

    Returns:
        Tuple of (dashboard_process, stats_server)
    """
    if not RICH_AVAILABLE:
        return None, None

    # Create stats collector and server
    stats = StatsCollector()
    stats.target = target
    stats.start_time = time.time()

    server = DashboardServer(stats)
    server.start()

    # Launch dashboard in separate terminal
    process = TerminalLauncher.launch_dashboard(server.socket_path)

    return process, server


if __name__ == "__main__":
    # For testing: create a mock dashboard
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        stats = StatsCollector()
        stats.target = "192.168.1.0/24"
        stats.start_time = time.time()
        stats.devices_discovered = 42
        stats.devices_online = 38
        stats.configs_grabbed = 15
        stats.findings_critical = 2
        stats.findings_high = 5
        stats.findings_medium = 12
        stats.scan_status = "Scanning"
        stats.current_phase = "Device Discovery"

        dashboard = Dashboard()
        dashboard.stats = stats.to_dict()
        dashboard.run()
    else:
        print("Dashboard client - provide socket path via environment or argument")

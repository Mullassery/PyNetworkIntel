"""Progress indicators and formatted output."""

import sys
import time
from typing import Optional, Iterable
from datetime import datetime

try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ProgressIndicator:
    """Simple progress indicator with fallback to basic output."""

    def __init__(self, use_rich: bool = True):
        self.use_rich = use_rich and RICH_AVAILABLE
        self.console = Console() if self.use_rich else None

    def progress(self, iterable: Iterable, total: Optional[int] = None, description: str = ""):
        """Progress bar for iteration."""
        if self.use_rich:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task(description, total=total)
                for item in iterable:
                    yield item
                    progress.update(task, advance=1)
        else:
            # Fallback: simple counter
            for i, item in enumerate(iterable, 1):
                if total:
                    print(f"{description} [{i}/{total}]", file=sys.stderr)
                else:
                    print(f"{description} [{i}]", file=sys.stderr)
                yield item

    def status(self, message: str):
        """Print status message."""
        if self.use_rich:
            self.console.print(f"[*] {message}")
        else:
            print(f"[*] {message}")

    def success(self, message: str):
        """Print success message."""
        if self.use_rich:
            self.console.print(f"[+] {message}")
        else:
            print(f"[+] {message}")

    def error(self, message: str):
        """Print error message."""
        if self.use_rich:
            self.console.print(f"[-] {message}")
        else:
            print(f"[-] {message}")

    def warning(self, message: str):
        """Print warning message."""
        if self.use_rich:
            self.console.print(f"[!] {message}")
        else:
            print(f"[!] {message}")

    def section(self, title: str):
        """Print section header."""
        if self.use_rich:
            self.console.print(f"\n[bold blue]{'='*60}[/bold blue]")
            self.console.print(f"[bold blue]{title}[/bold blue]")
            self.console.print(f"[bold blue]{'='*60}[/bold blue]\n")
        else:
            print(f"\n{'='*60}")
            print(title)
            print(f"{'='*60}\n")


class OutputFormatter:
    """Format scan and analysis results."""

    def __init__(self, use_color: bool = True):
        self.use_color = use_color
        self.console = Console() if use_color else Console(no_color=True)

    def format_summary_table(self, summary: dict):
        """Format summary statistics as table."""
        if RICH_AVAILABLE and self.use_color:
            from rich.table import Table

            table = Table(title="Scan Summary", show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Devices", str(summary.get("total_devices", 0)))
            table.add_row("Online Devices", str(summary.get("online_devices", 0)))
            table.add_row("Total Findings", str(summary.get("total_findings", 0)))
            table.add_row("Critical", str(summary.get("critical_findings", 0)))
            table.add_row("High Priority", str(summary.get("high_findings", 0)))

            self.console.print(table)
        else:
            print(f"Total Devices: {summary.get('total_devices', 0)}")
            print(f"Online Devices: {summary.get('online_devices', 0)}")
            print(f"Total Findings: {summary.get('total_findings', 0)}")
            print(f"Critical: {summary.get('critical_findings', 0)}")
            print(f"High Priority: {summary.get('high_findings', 0)}")

    def format_findings_table(self, findings: list, max_rows: int = 10):
        """Format findings as table."""
        if not findings:
            print("[OK] No security issues found!")
            return

        severity_map = {
            "critical": ("[C]", "red"),
            "high": ("[H]", "yellow"),
            "medium": ("[M]", "yellow"),
            "low": ("[L]", "green"),
            "info": ("[I]", "blue"),
        }

        if RICH_AVAILABLE and self.use_color:
            from rich.table import Table

            table = Table(title="Security Findings", show_header=True)
            table.add_column("Severity", style="bold")
            table.add_column("Finding")
            table.add_column("Device")
            table.add_column("Impact")

            for finding in findings[:max_rows]:
                severity = finding.get("severity", "unknown").lower()
                icon, style = severity_map.get(severity, ("❓", "white"))

                table.add_row(
                    f"{icon} {severity.upper()}",
                    finding.get("title", "Unknown"),
                    finding.get("device", "unknown"),
                    finding.get("business_impact", ""),
                    style=style,
                )

            self.console.print(table)
        else:
            for i, finding in enumerate(findings[:max_rows], 1):
                severity = finding.get("severity", "unknown").upper()
                print(f"\n{i}. [{severity}] {finding.get('title', 'Unknown')}")
                print(f"   Device: {finding.get('device', 'unknown')}")
                print(f"   Impact: {finding.get('business_impact', '')}")

        if len(findings) > max_rows:
            print(f"\n... and {len(findings) - max_rows} more findings")

    def format_scan_time(self, seconds: float) -> str:
        """Format scan duration."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"

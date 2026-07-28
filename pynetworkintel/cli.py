"""Command-line interface for PyNetworkIntel."""

import argparse
import json
import sys
import logging
import os
from typing import Optional

from pynetworkintel import Scanner, Analyzer
from pynetworkintel.core import Pipeline
from pynetworkintel.config import ConfigManager
from pynetworkintel.progress import ProgressIndicator, OutputFormatter

logger = logging.getLogger(__name__)

# Progress indicator (global)
progress = ProgressIndicator()
formatter = OutputFormatter()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AI-powered network intelligence and vulnerability discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a subnet
  pynetworkintel scan 192.168.1.0/24

  # Scan with config grabbing (requires SSH access)
  pynetworkintel scan 192.168.1.0/24 --ssh-user admin --ssh-key ~/.ssh/id_rsa

  # Run full pipeline with LLM summary
  pynetworkintel analyze 192.168.1.0/24 --summarize

  # Get findings in JSON format
  pynetworkintel scan 192.168.1.0/24 --output json

  # Save results to file
  pynetworkintel analyze 192.168.1.0/24 --output-file results.json

  # Use custom config file
  pynetworkintel scan 192.168.1.0/24 --config ~/.pynetworkintel/config.yaml

  # Initialize default config
  pynetworkintel init-config
""",
    )

    # Global options
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.2.0",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--config",
        help="Path to config file (default: ~/.pynetworkintel/config.yaml)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Init config command
    init_parser = subparsers.add_parser("init-config", help="Initialize default config")
    init_parser.set_defaults(func=handle_init_config)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan network for devices")
    scan_parser.add_argument("target", help="Target IP, CIDR range, or hostname")
    scan_parser.add_argument(
        "--no-config-grab",
        action="store_true",
        help="Skip SSH config grabbing",
    )
    scan_parser.add_argument(
        "--ssh-user",
        default="root",
        help="SSH username for config grabbing (default: root)",
    )
    scan_parser.add_argument(
        "--ssh-key",
        help="SSH private key path for authentication",
    )
    scan_parser.add_argument(
        "--ssh-password",
        help="SSH password (if not using key-based auth)",
    )
    scan_parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    scan_parser.add_argument(
        "--output-file",
        help="Save results to file (auto-detect format from extension)",
    )
    scan_parser.set_defaults(func=handle_scan)

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze", help="Scan and perform full analysis"
    )
    analyze_parser.add_argument("target", help="Target IP, CIDR range, or hostname")
    analyze_parser.add_argument(
        "--ssh-user",
        default="root",
        help="SSH username (default: root)",
    )
    analyze_parser.add_argument(
        "--ssh-key",
        help="SSH private key path",
    )
    analyze_parser.add_argument(
        "--ssh-password",
        help="SSH password",
    )
    analyze_parser.add_argument(
        "--summarize",
        action="store_true",
        help="Generate AI-powered summary of findings",
    )
    analyze_parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    analyze_parser.add_argument(
        "--api-key",
        help="Anthropic API key for AI summaries (or set ANTHROPIC_API_KEY env var)",
    )
    analyze_parser.add_argument(
        "--output-file",
        help="Save results to file",
    )
    analyze_parser.set_defaults(func=handle_analyze)

    args = parser.parse_args()

    # Setup logging
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    if not args.command:
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        progress.error("Scanning interrupted by user")
        return 1
    except Exception as e:
        progress.error(f"{e}")
        logger.exception("Unhandled error")
        return 1


def handle_init_config(args) -> int:
    """Handle init-config command."""
    config_manager = ConfigManager()
    config_manager.create_default_config()
    progress.success(f"Config created at {config_manager.config_file}")
    return 0


def handle_scan(args) -> int:
    """Handle scan command."""
    progress.section(f"Scanning {args.target}")

    scanner = Scanner(
        ssh_username=args.ssh_user,
        ssh_key_path=args.ssh_key,
        ssh_password=args.ssh_password,
    )

    progress.status(f"Starting scan of {args.target}...")

    scan_result = scanner.scan(
        args.target,
        grab_configs=not args.no_config_grab,
    )

    progress.success(f"Discovered {len(scan_result.devices)} devices in {scan_result.scan_duration_seconds:.1f}s")

    if args.output == "json":
        output = scan_result.to_dict()
        result_str = json.dumps(output, indent=2, default=str)
    else:
        result_str = format_scan_output(scan_result)

    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(result_str)
        progress.success(f"Results saved to {args.output_file}")
    else:
        print(result_str)

    return 0


def handle_analyze(args) -> int:
    """Handle analyze command."""
    api_key = getattr(args, 'api_key', None) or os.getenv("ANTHROPIC_API_KEY")

    progress.section(f"Analyzing {args.target}")

    pipeline = Pipeline(
        ssh_username=args.ssh_user,
        ssh_key_path=args.ssh_key,
        ssh_password=args.ssh_password,
        anthropic_api_key=api_key,
    )

    progress.status(f"Scanning network {args.target}...")

    result = pipeline.run(
        args.target,
        grab_configs=True,
        summarize=args.summarize,
    )

    if args.output == "json":
        result_str = json.dumps(result, indent=2, default=str)
    else:
        result_str = format_analysis_output(result, args.summarize)

    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(result_str)
        progress.success(f"Results saved to {args.output_file}")
    else:
        print(result_str)

    return 0


def format_scan_output(scan_result) -> str:
    """Format scan results in human-readable format."""
    output = []
    output.append("="*60)
    output.append("NETWORK SCAN RESULTS")
    output.append("="*60)
    output.append("")

    output.append(f"Devices Found: {len(scan_result.devices)}")
    output.append(f"Online Devices: {sum(1 for d in scan_result.devices if d.is_online)}")
    output.append(f"Scan Duration: {scan_result.scan_duration_seconds:.1f}s")
    output.append("")

    if scan_result.devices:
        output.append("Discovered Devices:")
        output.append("-" * 60)
        for device in scan_result.devices:
            status = "✓ ONLINE" if device.is_online else "✗ OFFLINE"
            hostname = device.hostname or "unknown"
            os_info = device.os or "unknown"

            output.append(f"\n{device.ip} ({hostname})")
            output.append(f"  Status: {status}")
            output.append(f"  OS: {os_info}")

            if device.services:
                output.append(f"  Services:")
                for service in device.services:
                    version = f" {service.version}" if service.version else ""
                    output.append(f"    - Port {service.port}: {service.name}{version}")

            if device.configs:
                output.append(f"  Configs: {len(device.configs)} files grabbed")

    return "\n".join(output)


def format_analysis_output(result: dict, show_summary: bool = False) -> str:
    """Format analysis results in human-readable format."""
    output = []
    output.append("="*60)
    output.append("NETWORK ANALYSIS RESULTS")
    output.append("="*60)
    output.append("")

    summary = result.get("summary", {})
    output.append(f"Devices Found: {summary.get('total_devices', 0)}")
    output.append(f"Online: {summary.get('online_devices', 0)}")
    output.append(f"Critical Findings: {summary.get('critical_findings', 0)}")
    output.append(f"High Priority Findings: {summary.get('high_findings', 0)}")
    output.append(f"Total Issues: {summary.get('total_findings', 0)}")
    output.append("")

    findings = result.get("findings", [])
    if findings:
        output.append("Security Findings (ordered by severity):")
        output.append("-" * 60)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity"), 5)
        )

        for i, finding in enumerate(sorted_findings[:10], 1):
            severity = finding.get("severity", "unknown").upper()
            title = finding.get("title", "Unknown")
            device = finding.get("device", "unknown")
            impact = finding.get("business_impact", "")
            rec = finding.get("recommendation", "")

            output.append(f"\n{i}. [{severity}] {title}")
            output.append(f"   Device: {device}")
            output.append(f"   Impact: {impact}")
            output.append(f"   Fix: {rec}")

        if len(findings) > 10:
            output.append(f"\n... and {len(findings) - 10} more findings")
    else:
        output.append("✓ No security issues found!")

    if show_summary and "ai_summary" in result:
        output.append("")
        output.append("="*60)
        output.append("AI ANALYSIS SUMMARY")
        output.append("="*60)
        output.append("")
        output.append(result["ai_summary"])

    return "\n".join(output)


if __name__ == "__main__":
    sys.exit(main())

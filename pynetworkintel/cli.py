"""Command-line interface for PyNetworkIntel."""

import argparse
import json
import sys
import logging
from typing import Optional

from pynetworkintel import Scanner, Analyzer
from pynetworkintel.core import Pipeline

logger = logging.getLogger(__name__)


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
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "scan":
            return handle_scan(args)
        elif args.command == "analyze":
            return handle_analyze(args)
    except KeyboardInterrupt:
        print("\nScanning interrupted by user")
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        logger.exception("Unhandled error")
        return 1

    return 0


def handle_scan(args) -> int:
    """Handle scan command."""
    scanner = Scanner(
        ssh_username=args.ssh_user,
        ssh_key_path=args.ssh_key,
        ssh_password=args.ssh_password,
    )

    print(f"Scanning {args.target}...")

    scan_result = scanner.scan(
        args.target,
        grab_configs=not args.no_config_grab,
    )

    if args.output == "json":
        output = scan_result.to_dict()
        print(json.dumps(output, indent=2, default=str))
    else:
        print_scan_results(scan_result)

    return 0


def handle_analyze(args) -> int:
    """Handle analyze command."""
    api_key = getattr(args, 'api_key', None)

    pipeline = Pipeline(
        ssh_username=args.ssh_user,
        ssh_key_path=args.ssh_key,
        ssh_password=args.ssh_password,
        anthropic_api_key=api_key,
    )

    print(f"Scanning and analyzing {args.target}...")

    result = pipeline.run(
        args.target,
        grab_configs=True,
        summarize=args.summarize,
    )

    if args.output == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print_analysis_results(result, args.summarize)

    return 0


def print_scan_results(scan_result):
    """Print scan results in human-readable format."""
    print(f"\n{'='*60}")
    print("NETWORK SCAN RESULTS")
    print(f"{'='*60}\n")

    print(f"Devices Found: {len(scan_result.devices)}")
    print(f"Online Devices: {sum(1 for d in scan_result.devices if d.is_online)}")
    print(f"Scan Duration: {scan_result.scan_duration_seconds:.1f}s\n")

    if scan_result.devices:
        print("Discovered Devices:")
        print("-" * 60)
        for device in scan_result.devices:
            status = "✓ ONLINE" if device.is_online else "✗ OFFLINE"
            hostname = device.hostname or "unknown"
            os_info = device.os or "unknown"

            print(f"\n{device.ip} ({hostname})")
            print(f"  Status: {status}")
            print(f"  OS: {os_info}")

            if device.services:
                print(f"  Services:")
                for service in device.services:
                    version = f" {service.version}" if service.version else ""
                    print(f"    - Port {service.port}: {service.name}{version}")

            if device.configs:
                print(f"  Configs: {len(device.configs)} files grabbed")


def print_analysis_results(result: dict, show_summary: bool = False):
    """Print analysis results in human-readable format."""
    print(f"\n{'='*60}")
    print("NETWORK ANALYSIS RESULTS")
    print(f"{'='*60}\n")

    summary = result.get("summary", {})
    print(f"Devices Found: {summary.get('total_devices', 0)}")
    print(f"Online: {summary.get('online_devices', 0)}")
    print(f"Critical Findings: {summary.get('critical_findings', 0)}")
    print(f"High Priority Findings: {summary.get('high_findings', 0)}")
    print(f"Total Issues: {summary.get('total_findings', 0)}\n")

    findings = result.get("findings", [])
    if findings:
        print("Security Findings (ordered by severity):")
        print("-" * 60)

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

            print(f"\n{i}. [{severity}] {title}")
            print(f"   Device: {device}")
            print(f"   Impact: {impact}")
            print(f"   Fix: {rec}")

        if len(findings) > 10:
            print(f"\n... and {len(findings) - 10} more findings")
    else:
        print("✓ No security issues found!")

    if show_summary and "ai_summary" in result:
        print(f"\n{'='*60}")
        print("AI ANALYSIS SUMMARY")
        print(f"{'='*60}\n")
        print(result["ai_summary"])


if __name__ == "__main__":
    sys.exit(main())

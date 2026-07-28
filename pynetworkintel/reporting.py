"""Reporting engine for scan results and trends."""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from pynetworkintel.db import Database, ScanSession, Finding as DBFinding, Device as DBDevice, DeviceChange

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate reports from scan data."""

    def __init__(self, db: Database):
        self.db = db

    def generate_summary_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate summary report for last N hours."""
        session = self.db.get_session()

        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Get scan sessions
            scans = session.query(ScanSession).filter(ScanSession.scan_time >= since).all()

            # Get findings in period
            findings = session.query(DBFinding).filter(DBFinding.found_at >= since).all()

            # Group by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.severity
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Get unique devices
            devices = session.query(DBDevice.ip).distinct().filter(DBDevice.last_seen >= since).all()

            report = {
                "period": f"Last {hours} hours",
                "generated_at": datetime.utcnow().isoformat(),
                "scan_count": len(scans),
                "total_findings": len(findings),
                "findings_by_severity": severity_counts,
                "unique_devices": len(devices),
                "critical_findings": severity_counts.get("critical", 0),
                "high_findings": severity_counts.get("high", 0),
            }

            return report

        finally:
            session.close()

    def generate_device_inventory_report(self) -> Dict[str, Any]:
        """Generate current device inventory report."""
        session = self.db.get_session()

        try:
            devices = session.query(DBDevice).distinct(DBDevice.ip).all()

            inventory = {
                "total_devices": len(devices),
                "devices_by_type": {},
                "devices_by_os": {},
                "devices": [],
            }

            for device in devices:
                device_type = device.device_type or "unknown"
                os_type = device.os or "unknown"

                inventory["devices_by_type"][device_type] = inventory["devices_by_type"].get(device_type, 0) + 1
                inventory["devices_by_os"][os_type] = inventory["devices_by_os"].get(os_type, 0) + 1

                inventory["devices"].append({
                    "ip": device.ip,
                    "hostname": device.hostname,
                    "os": device.os,
                    "type": device_type,
                    "status": "online" if device.is_online else "offline",
                    "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                })

            return inventory

        finally:
            session.close()

    def generate_vulnerability_report(self) -> Dict[str, Any]:
        """Generate vulnerability report."""
        session = self.db.get_session()

        try:
            # Get latest findings
            findings = session.query(DBFinding).filter(DBFinding.cve_id.isnot(None)).order_by(DBFinding.found_at.desc()).all()

            cves_by_severity = {}
            cves_by_device = {}

            for finding in findings:
                severity = finding.severity
                cves_by_severity[severity] = cves_by_severity.get(severity, 0) + 1

                device_ip = finding.device_ip
                if device_ip not in cves_by_device:
                    cves_by_device[device_ip] = []

                if finding.cve_id not in [c["cve_id"] for c in cves_by_device[device_ip]]:
                    cves_by_device[device_ip].append({
                        "cve_id": finding.cve_id,
                        "severity": severity,
                        "title": finding.title,
                        "cvss_score": finding.cvss_score,
                    })

            report = {
                "total_cves": len(set(f.cve_id for f in findings if f.cve_id)),
                "cves_by_severity": cves_by_severity,
                "most_affected_devices": sorted(
                    cves_by_device.items(),
                    key=lambda x: len(x[1]),
                    reverse=True,
                )[:10],
            }

            return report

        finally:
            session.close()

    def generate_change_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate changes report."""
        session = self.db.get_session()

        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            changes = session.query(DeviceChange).filter(DeviceChange.detected_at >= since).all()

            discovered = [c for c in changes if c.change_type == "discovered"]
            removed = [c for c in changes if c.change_type == "removed"]

            report = {
                "period": f"Last {hours} hours",
                "total_changes": len(changes),
                "devices_discovered": len(discovered),
                "devices_removed": len(removed),
                "discovered": [{"ip": c.ip, "hostname": c.hostname} for c in discovered[:10]],
                "removed": [{"ip": c.ip} for c in removed[:10]],
            }

            return report

        finally:
            session.close()

    def generate_markdown_report(self, hours: int = 24) -> str:
        """Generate complete report in Markdown format."""
        summary = self.generate_summary_report(hours)
        inventory = self.generate_device_inventory_report()
        vulnerabilities = self.generate_vulnerability_report()
        changes = self.generate_change_report(hours)

        md = []
        md.append(f"# Network Security Report")
        md.append(f"\nGenerated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append(f"Period: {summary['period']}\n")

        # Summary Section
        md.append("## Executive Summary\n")
        md.append(f"- **Total Devices**: {inventory['total_devices']}")
        md.append(f"- **Scans Performed**: {summary['scan_count']}")
        md.append(f"- **Total Findings**: {summary['total_findings']}")
        md.append(f"- **Critical Issues**: {summary['critical_findings']}")
        md.append(f"- **High Priority Issues**: {summary['high_findings']}\n")

        # Findings by Severity
        md.append("## Findings by Severity\n")
        for severity, count in summary.get("findings_by_severity", {}).items():
            md.append(f"- **{severity.upper()}**: {count}")
        md.append("")

        # Device Inventory
        md.append("## Device Inventory\n")
        md.append(f"**Total Unique Devices**: {inventory['total_devices']}\n")

        if inventory.get("devices_by_type"):
            md.append("**Devices by Type**:")
            for dtype, count in inventory["devices_by_type"].items():
                md.append(f"- {dtype}: {count}")
            md.append("")

        if inventory.get("devices_by_os"):
            md.append("**Devices by Operating System**:")
            for os, count in inventory["devices_by_os"].items():
                md.append(f"- {os}: {count}")
            md.append("")

        # Vulnerabilities
        md.append("## Vulnerability Status\n")
        md.append(f"**Total Unique CVEs**: {vulnerabilities.get('total_cves', 0)}\n")

        if vulnerabilities.get("cves_by_severity"):
            md.append("**CVEs by Severity**:")
            for severity, count in vulnerabilities["cves_by_severity"].items():
                md.append(f"- {severity.upper()}: {count}")
            md.append("")

        # Most Affected Devices
        if vulnerabilities.get("most_affected_devices"):
            md.append("**Most Affected Devices**:\n")
            for device_ip, cves in vulnerabilities["most_affected_devices"][:5]:
                md.append(f"- {device_ip}: {len(cves)} vulnerabilities")
            md.append("")

        # Recent Changes
        md.append("## Recent Changes\n")
        md.append(f"**Total Changes**: {changes.get('total_changes', 0)}\n")
        md.append(f"- **Devices Discovered**: {changes.get('devices_discovered', 0)}")
        md.append(f"- **Devices Removed**: {changes.get('devices_removed', 0)}\n")

        if changes.get("discovered"):
            md.append("**Recently Discovered Devices**:")
            for device in changes["discovered"][:5]:
                md.append(f"- {device['ip']} ({device.get('hostname', 'unknown')})")
            md.append("")

        md.append("---")
        md.append("*Generated by PyNetworkIntel*")

        return "\n".join(md)

    def export_to_file(self, filename: str, report_format: str = "markdown"):
        """Export report to file."""
        if report_format == "markdown":
            report = self.generate_markdown_report()
        elif report_format == "json":
            import json

            summary = self.generate_summary_report()
            inventory = self.generate_device_inventory_report()
            vulnerabilities = self.generate_vulnerability_report()
            changes = self.generate_change_report()

            data = {
                "summary": summary,
                "inventory": inventory,
                "vulnerabilities": vulnerabilities,
                "changes": changes,
            }

            report = json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unknown format: {report_format}")

        with open(filename, "w") as f:
            f.write(report)

        logger.info(f"Report exported to {filename}")

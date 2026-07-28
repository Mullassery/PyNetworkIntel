"""Device and vulnerability change detection."""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from pynetworkintel.models import Device, ScanResult
from pynetworkintel.db import (
    Database, DeviceChange, VulnerabilityChange, Finding,
    Device as DBDevice, Finding as DBFinding
)

logger = logging.getLogger(__name__)


class ChangeDetector:
    """Detect changes in network state."""

    def __init__(self, db: Database):
        self.db = db

    def detect_device_changes(self, current_devices: List[Device], scan_id: int) -> List[Dict[str, Any]]:
        """
        Detect device additions, removals, and status changes.

        Returns:
            List of change dictionaries
        """
        changes = []
        session = self.db.get_session()

        try:
            current_ips = {d.ip for d in current_devices}

            # Find previously seen devices
            previous_ips = set(
                ip[0] for ip in session.query(DBDevice.ip).distinct().all()
            )

            # New devices
            for ip in current_ips - previous_ips:
                device = next(d for d in current_devices if d.ip == ip)
                change = {
                    "type": "device_discovered",
                    "ip": ip,
                    "hostname": device.hostname,
                    "os": device.os,
                    "timestamp": datetime.utcnow(),
                }
                changes.append(change)
                self._record_device_change(session, ip, "discovered", device.hostname, device.os)

            # Removed devices (were online, now offline)
            for ip in previous_ips - current_ips:
                change = {
                    "type": "device_removed",
                    "ip": ip,
                    "timestamp": datetime.utcnow(),
                }
                changes.append(change)
                self._record_device_change(session, ip, "removed", None, None)

            session.commit()

        finally:
            session.close()

        return changes

    def detect_vulnerability_changes(self, current_findings: List, previous_findings_by_ip: Dict) -> List[Dict[str, Any]]:
        """
        Detect new vulnerabilities and resolved vulnerabilities.

        Returns:
            List of change dictionaries
        """
        changes = []
        session = self.db.get_session()

        try:
            # Group current findings by device IP and CVE
            current_by_ip_cve = {}
            for finding in current_findings:
                if finding.cve_id:
                    key = (finding.device, finding.cve_id)
                    current_by_ip_cve[key] = finding

            # Check for new vulnerabilities
            for (device_ip, cve_id), finding in current_by_ip_cve.items():
                previous = previous_findings_by_ip.get((device_ip, cve_id))
                if not previous:
                    change = {
                        "type": "vulnerability_discovered",
                        "device_ip": device_ip,
                        "cve_id": cve_id,
                        "severity": finding.severity.value,
                        "title": finding.title,
                        "timestamp": datetime.utcnow(),
                    }
                    changes.append(change)
                    self._record_vulnerability_change(
                        session,
                        device_ip,
                        cve_id,
                        finding.title,
                        finding.severity.value,
                    )

            # Check for resolved vulnerabilities
            for (device_ip, cve_id), previous_finding in previous_findings_by_ip.items():
                if (device_ip, cve_id) not in current_by_ip_cve:
                    change = {
                        "type": "vulnerability_resolved",
                        "device_ip": device_ip,
                        "cve_id": cve_id,
                        "timestamp": datetime.utcnow(),
                    }
                    changes.append(change)
                    self._mark_vulnerability_resolved(session, device_ip, cve_id)

            session.commit()

        finally:
            session.close()

        return changes

    def get_previous_scan_findings(self) -> Dict[tuple, Any]:
        """Get findings from previous scan grouped by (device_ip, cve_id)."""
        session = self.db.get_session()

        try:
            findings = session.query(DBFinding).order_by(DBFinding.found_at.desc()).all()

            # Keep only the most recent findings for each device
            grouped = {}
            for finding in findings:
                key = (finding.device_ip, finding.cve_id)
                if key not in grouped:
                    grouped[key] = finding

            return grouped

        finally:
            session.close()

    def _record_device_change(self, session: Session, ip: str, change_type: str, hostname: Optional[str], os: Optional[str]):
        """Record a device change in database."""
        change = DeviceChange(
            ip=ip,
            hostname=hostname,
            change_type=change_type,
            details={"os": os} if os else None,
        )
        session.add(change)

    def _record_vulnerability_change(self, session: Session, device_ip: str, cve_id: str, title: str, severity: str):
        """Record a vulnerability discovery."""
        vuln_change = VulnerabilityChange(
            device_ip=device_ip,
            cve_id=cve_id,
            title=title,
            severity=severity,
        )
        session.add(vuln_change)

    def _mark_vulnerability_resolved(self, session: Session, device_ip: str, cve_id: str):
        """Mark a vulnerability as resolved."""
        change = session.query(VulnerabilityChange).filter(
            VulnerabilityChange.device_ip == device_ip,
            VulnerabilityChange.cve_id == cve_id,
            VulnerabilityChange.resolved_at.is_(None),
        ).first()

        if change:
            change.resolved_at = datetime.utcnow()
            session.add(change)


class ChangeReporter:
    """Report detected changes in human-readable format."""

    @staticmethod
    def summarize_changes(changes: List[Dict[str, Any]]) -> str:
        """Generate summary of detected changes."""
        if not changes:
            return "No changes detected since last scan."

        summary = ["Changes Detected Since Previous Scan:\n"]

        device_discovered = [c for c in changes if c["type"] == "device_discovered"]
        device_removed = [c for c in changes if c["type"] == "device_removed"]
        vuln_discovered = [c for c in changes if c["type"] == "vulnerability_discovered"]
        vuln_resolved = [c for c in changes if c["type"] == "vulnerability_resolved"]

        if device_discovered:
            summary.append(f"+ New Devices: {len(device_discovered)}")
            for change in device_discovered[:3]:
                summary.append(f"  - {change['ip']} ({change.get('hostname', 'unknown')})")
            if len(device_discovered) > 3:
                summary.append(f"  ... and {len(device_discovered) - 3} more")

        if device_removed:
            summary.append(f"- Removed Devices: {len(device_removed)}")
            for change in device_removed[:3]:
                summary.append(f"  - {change['ip']}")
            if len(device_removed) > 3:
                summary.append(f"  ... and {len(device_removed) - 3} more")

        if vuln_discovered:
            summary.append(f"! New Vulnerabilities: {len(vuln_discovered)}")
            for change in vuln_discovered[:3]:
                summary.append(f"  - {change['cve_id']} ({change['severity'].upper()}): {change['title'][:50]}")
            if len(vuln_discovered) > 3:
                summary.append(f"  ... and {len(vuln_discovered) - 3} more")

        if vuln_resolved:
            summary.append(f"✓ Resolved Vulnerabilities: {len(vuln_resolved)}")

        return "\n".join(summary)

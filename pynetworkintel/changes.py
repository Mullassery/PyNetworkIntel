"""Device and vulnerability change detection."""

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from pynetworkintel.db import (
    Database,
    DeviceChange,
    ScanSession,
    VulnerabilityChange,
)
from pynetworkintel.db import (
    Device as DBDevice,
)
from pynetworkintel.db import (
    Finding as DBFinding,
)
from pynetworkintel.models import Device

logger = logging.getLogger(__name__)


class ChangeDetector:
    """Detect changes in network state."""

    def __init__(self, db: Database):
        self.db = db

    def detect_device_changes(
        self,
        current_devices: list[Device],
        scan_id: int,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Detect device additions, removals, and status changes.

        Comparison is against the previous scans of the *same* target only
        (so scanning unrelated targets never flips this target's devices to
        "removed"), and the scan being compared (`scan_id`) is excluded --
        its devices are already persisted when this runs.

        Returns:
            List of change dictionaries
        """
        changes = []
        session = self.db.get_session()

        try:
            if target is None:
                current_scan = session.query(ScanSession).filter_by(id=scan_id).first()
                target = current_scan.target if current_scan else None

            current_ips = {d.ip for d in current_devices}

            # IPs seen in previous scans of this target (never the current one).
            prev_q = (
                session.query(DBDevice.ip)
                .join(ScanSession, ScanSession.id == DBDevice.scan_id)
                .filter(DBDevice.scan_id != scan_id)
            )
            if target is not None:
                prev_q = prev_q.filter(ScanSession.target == target)
            previous_ips = {ip[0] for ip in prev_q.distinct().all()}

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

    def detect_vulnerability_changes(self, current_findings: list, previous_findings_by_ip: dict) -> list[dict[str, Any]]:
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
            for (device_ip, cve_id) in previous_findings_by_ip:
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

    def get_previous_scan_findings(
        self,
        exclude_scan_id: int | None = None,
        target: str | None = None,
    ) -> dict[tuple, Any]:
        """Get findings from previous scans grouped by (device_ip, cve_id).

        Optionally excludes one scan id (the current scan, whose findings
        are already persisted) and scopes to a single target so scans of
        unrelated networks don't leak into the comparison.
        """
        session = self.db.get_session()

        try:
            query = session.query(
                DBFinding, ScanSession.target
            ).join(ScanSession, ScanSession.id == DBFinding.scan_id)
            query = query.order_by(DBFinding.found_at.desc())

            if exclude_scan_id is not None:
                query = query.filter(DBFinding.scan_id != exclude_scan_id)
            if target is not None:
                query = query.filter(ScanSession.target == target)

            rows = query.all()

            # Keep only the most recent finding for each (device, cve_id)
            grouped = {}
            for finding, _target in rows:
                key = (finding.device_ip, finding.cve_id)
                if key not in grouped:
                    grouped[key] = finding

            return grouped

        finally:
            session.close()

    def _record_device_change(self, session: Session, ip: str, change_type: str, hostname: str | None, os: str | None):
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
    def summarize_changes(changes: list[dict[str, Any]]) -> str:
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
            summary.extend(
                f"  - {change['ip']} ({change.get('hostname', 'unknown')})"
                for change in device_discovered[:3]
            )
            if len(device_discovered) > 3:
                summary.append(f"  ... and {len(device_discovered) - 3} more")

        if device_removed:
            summary.append(f"- Removed Devices: {len(device_removed)}")
            summary.extend(f"  - {change['ip']}" for change in device_removed[:3])
            if len(device_removed) > 3:
                summary.append(f"  ... and {len(device_removed) - 3} more")

        if vuln_discovered:
            summary.append(f"! New Vulnerabilities: {len(vuln_discovered)}")
            summary.extend(
                f"  - {change['cve_id']} ({change['severity'].upper()}): {change['title'][:50]}"
                for change in vuln_discovered[:3]
            )
            if len(vuln_discovered) > 3:
                summary.append(f"  ... and {len(vuln_discovered) - 3} more")

        if vuln_resolved:
            summary.append(f"✓ Resolved Vulnerabilities: {len(vuln_resolved)}")

        return "\n".join(summary)

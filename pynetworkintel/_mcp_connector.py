"""Network security intelligence built on real scan data.

`NetworkIntelligence` previously fabricated its output: every method
returned literal hardcoded values (``"src_ip": "192.168.1.100"``,
``"anomaly_score": 0.15``, ...) regardless of input, and the MCP connector
depended on an external ``statguardian`` package and a ``dab`` CLI binary
that are not dependencies of this project. This version computes real
answers from the data this project actually has -- the SQLAlchemy scan
history database (`Device`/`Finding`/`Service` rows) and the topology
derived from discovered devices -- and raises `NotImplementedError` (never
returns fabricated data) for capabilities that require infrastructure this
project does not provide (packet capture, geolocation databases, external
threat-intel feeds, live traffic baselines).
"""

import ipaddress
import itertools
import logging
import math
import socket
from datetime import timedelta
from typing import Any

from pynetworkintel.changes import ChangeDetector
from pynetworkintel.db import Database, ScanSession, get_db
from pynetworkintel.reporting import ReportGenerator
from pynetworkintel.topology import TopologyMapper

logger = logging.getLogger(__name__)

NOT_IMPLEMENTED = "not implemented in this build"


class NetworkIntelligence:
    """Network security intelligence and analysis over stored scan history.

    Args:
        db: A `Database` instance. Defaults to the module-global database
            (`pynetworkintel.db.get_db()`).
    """

    def __init__(self, db: Database | None = None):
        self.db = db or get_db()

    # ------------------------------------------------------------------ helpers

    def _latest_scan(self, subnet_or_target: str) -> ScanSession | None:
        session = self.db.get_session()
        try:
            return (
                session.query(ScanSession)
                .filter(ScanSession.target == subnet_or_target)
                .order_by(ScanSession.scan_time.desc())
                .first()
            )
        finally:
            session.close()

    def _devices_for_target(self, target: str, limit_to_subnet: str | None = None) -> list[dict[str, Any]]:
        """Devices from the most recent scan of `target`, optionally clipped
        to an `ipaddress`-interpretable subnet."""
        from pynetworkintel.db import Device as DBDevice

        session = self.db.get_session()
        try:
            latest = self._latest_scan(target)
            if latest is None:
                return []

            net = ipaddress.ip_network(limit_to_subnet, strict=False) if limit_to_subnet else None

            devices = (
                session.query(DBDevice)
                .filter(DBDevice.scan_id == latest.id)
                .order_by(DBDevice.ip)
                .all()
            )
            out = []
            for dev in devices:
                if net is not None:
                    try:
                        if ipaddress.ip_address(dev.ip) not in net:
                            continue
                    except ValueError:
                        continue
                out.append(
                    {
                        "ip": dev.ip,
                        "hostname": dev.hostname,
                        "os": dev.os,
                        "device_type": dev.device_type,
                        "is_online": dev.is_online,
                        "services": [
                            {
                                "port": s.port,
                                "name": s.name,
                                "version": s.version,
                                "protocol": s.protocol,
                                "state": s.state,
                            }
                            for s in dev.services
                        ],
                    }
                )
            return out
        finally:
            session.close()

    # ------------------------------------------------------------------ public API

    def analyze_network_flow(
        self,
        flow_id: str,
        time_window_seconds: int = 300,
        include_geolocation: bool = False,
    ) -> dict[str, Any]:
        """Analyze reachability for a discovered target from stored scan
        topology. This project has no packet-flow capture, so this reports
        the real connectivity graph inferred from the latest scan."""
        if include_geolocation:
            raise NotImplementedError(
                f"{NOT_IMPLEMENTED}: no geolocation data source; "
                "pass include_geolocation=False"
            )

        devices = self._devices_for_target(flow_id)
        if not devices:
            return {"target": flow_id, "reachable_networks": [], "nodes": [], "edges": []}

        from pynetworkintel.models import Device

        model_devices = [
            Device(
                ip=d["ip"],
                hostname=d["hostname"],
                os=d["os"],
                device_type=d["device_type"],
                is_online=d["is_online"],
            )
            for d in devices
        ]
        topology = TopologyMapper().build(model_devices)
        return {
            "target": flow_id,
            "reachable_networks": topology.subnets,
            "nodes": [n.to_dict() for n in topology.nodes],
            "edges": [e.to_dict() for e in topology.edges],
        }

    def detect_anomalies(
        self,
        sensor_id: str,
        anomaly_type: str | None = None,
        sensitivity: float = 0.7,
    ) -> dict[str, Any]:
        """Detect baseline-drift anomalies by diffing the two most recent
        scans of a target (new/removed devices, new/resolved CVEs). This
        build has no live-traffic sensing, so attack-class anomaly types
        (ddos, exfiltration, ...) are reported as unavailable rather than
        guessed."""
        from pynetworkintel.models import Device

        session = self.db.get_session()
        try:
            scans = (
                session.query(ScanSession)
                .filter(ScanSession.target == sensor_id)
                .order_by(ScanSession.scan_time.desc())
                .limit(2)
                .all()
            )
        finally:
            session.close()

        if len(scans) < 2:
            return {
                "sensor_id": sensor_id,
                "anomalies_detected": 0,
                "anomalies": [],
                "note": "Need at least two scans of this target to diff.",
            }

        detector = ChangeDetector(self.db)
        current = scans[0]
        devices = [
            Device(
                ip=d["ip"],
                hostname=d.get("hostname"),
                os=d.get("os"),
                device_type=d.get("device_type", "linux"),
                is_online=d.get("is_online", True),
            )
            for d in self._devices_for_target(sensor_id)
        ]
        device_changes = detector.detect_device_changes(
            devices, scan_id=current.id, target=sensor_id
        )
        prev_findings = detector.get_previous_scan_findings(
            exclude_scan_id=current.id, target=sensor_id
        )

        # Re-use the vulnerability diff machinery with the current scan's CVE findings.
        from pynetworkintel.models import FindingType, SecurityFinding, Severity

        session = self.db.get_session()
        try:
            from pynetworkintel.db import Finding as DBFinding

            current_findings = (
                session.query(DBFinding)
                .filter(DBFinding.scan_id == current.id, DBFinding.cve_id.isnot(None))
                .all()
            )
            model_findings = [
                SecurityFinding(
                    device=f.device_ip,
                    finding_type=FindingType(f.finding_type),
                    severity=Severity(f.severity),
                    title=f.title,
                    description=f.description,
                    evidence=f.evidence,
                    recommendation=f.recommendation,
                    business_impact=f.business_impact,
                    cve_id=f.cve_id,
                    cvss_score=f.cvss_score,
                    exploit_available=f.exploit_available,
                )
                for f in current_findings
            ]
        finally:
            session.close()

        vuln_changes = detector.detect_vulnerability_changes(model_findings, prev_findings)

        anomalies = []
        for idx, change in enumerate(device_changes + vuln_changes):
            if anomaly_type and change.get("type") != anomaly_type:
                continue
            anomalies.append(
                {
                    "id": f"anom_{idx:03d}",
                    "type": change.get("type"),
                    "severity": change.get("severity", "info"),
                    "device_ip": change.get("ip", change.get("device_ip")),
                    "cve_id": change.get("cve_id"),
                }
            )

        if anomaly_type and anomaly_type not in {
            "device_discovered", "device_removed", "vulnerability_discovered",
            "vulnerability_resolved",
        }:
            return {
                "sensor_id": sensor_id,
                "anomalies_detected": 0,
                "anomalies": [],
                "note": f"Anomaly type '{anomaly_type}' cannot be detected from scan "
                "history in this build (no live-traffic sensing).",
            }

        return {
            "sensor_id": sensor_id,
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
        }

    def threat_correlation(
        self,
        indicators: list[str],
        threat_intel_sources: list[str] | None = None,
    ) -> dict[str, Any]:
        """Correlate indicators (IPs/hostnames) against stored scan findings
        -- the CVEs tied to each indicator across scan history. No external
        threat-intel feeds are configured, so sources are scan-history only."""
        return self._match_indicator_findings(indicators)

    def _match_indicator_findings(self, indicators: list[str]) -> dict[str, Any]:
        from pynetworkintel.db import Finding as DBFinding

        session = self.db.get_session()
        try:
            all_findings = (
                session.query(DBFinding)
                .filter(DBFinding.cve_id.isnot(None))
                .all()
            )
        finally:
            session.close()

        groups: dict[str, dict[str, Any]] = {}
        for indicator in indicators:
            ind = indicator.strip()
            if not ind:
                continue
            matched = [
                f
                for f in all_findings
                if f.device_ip == ind or (f.device_hostname or "") == ind
            ]
            if not matched:
                groups[ind] = {"threats": [], "correlation_count": 0}
                continue
            by_cve: dict[str, dict[str, Any]] = {}
            for f in matched:
                key = f.cve_id
                entry = by_cve.setdefault(
                    key,
                    {
                        "cve_id": key,
                        "severity": f.severity,
                        "title": f.title,
                        "affected_device_count": 0,
                        "devices": [],
                        "recommendation": f.recommendation,
                    },
                )
                entry["affected_device_count"] += 1
                if f.device_ip not in entry["devices"]:
                    entry["devices"].append(f.device_ip)
            by_severity: dict[str, int] = {}
            for entry in by_cve.values():
                by_severity[entry["severity"]] = by_severity.get(entry["severity"], 0) + 1
            groups[ind] = {
                "threats": list(by_cve.values()),
                "correlation_count": len(by_cve),
                "severity_breakdown": by_severity,
            }

        highest = None
        for group in groups.values():
            for entry in group.get("threats", []):
                sev = entry.get("severity", "info")
                if sev in ("critical", "high") and (highest is None or sev == "critical"):
                    highest = sev
        return {
            "indicators": list(groups.keys()),
            "correlated": groups,
            "threat_level": highest or "low",
            "sources": ["scan_history"],
        }

    def get_asset_inventory(
        self,
        subnet: str,
        include_vulnerabilities: bool = False,
        vulnerability_severity: str | None = None,
    ) -> dict[str, Any]:
        """Real inventory from the latest scan of `subnet` (treated as the
        monitored target)."""
        devices = self._devices_for_target(subnet)
        if not devices:
            return {"subnet": subnet, "total_assets": 0, "responsive_hosts": 0,
                    "os_breakdown": {}, "vulnerabilities": []}

        os_breakdown: dict[str, int] = {}
        for d in devices:
            os = d.get("os") or "unknown"
            os_breakdown[os] = os_breakdown.get(os, 0) + 1

        vulnerabilities = []
        if include_vulnerabilities:
            for d in devices:
                for f in self._findings_for_device(d["ip"]):
                    if vulnerability_severity and f.severity != vulnerability_severity:
                        continue
                    vulnerabilities.append(
                        {
                            "host": d["ip"],
                            "hostname": d.get("hostname"),
                            "cve": f.cve_id,
                            "severity": f.severity,
                        }
                    )

        return {
            "subnet": subnet,
            "total_assets": len(devices),
            "responsive_hosts": sum(1 for d in devices if d.get("is_online", True)),
            "os_breakdown": os_breakdown,
            "vulnerabilities": vulnerabilities,
        }

    def _findings_for_device(self, ip: str) -> list[Any]:
        from pynetworkintel.db import Finding as DBFinding

        session = self.db.get_session()
        try:
            return (
                session.query(DBFinding)
                .filter(DBFinding.device_ip == ip, DBFinding.cve_id.isnot(None))
                .all()
            )
        finally:
            session.close()

    def check_port_exposure(
        self,
        host: str,
        port_range: str | None = None,
        check_services: bool = True,
    ) -> dict[str, Any]:
        """Report which ports/services were observed open on `host` in the
        latest scan that includes it."""
        devices = []
        from pynetworkintel.db import Device as DBDevice
        from pynetworkintel.db import ScanSession

        session = self.db.get_session()
        try:
            latest_scan = (
                session.query(ScanSession)
                .join(DBDevice, DBDevice.scan_id == ScanSession.id)
                .filter(DBDevice.ip == host)
                .order_by(ScanSession.scan_time.desc())
                .first()
            )
            if latest_scan is not None:
                device = (
                    session.query(DBDevice)
                    .filter(DBDevice.scan_id == latest_scan.id, DBDevice.ip == host)
                    .first()
                )
                if device is not None:
                    devices = [
                        {
                            "port": s.port,
                            "name": s.name,
                            "version": s.version,
                            "protocol": s.protocol,
                            "state": s.state,
                        }
                        for s in device.services
                    ]
        finally:
            session.close()

        ports = self._filter_ports(devices, port_range)
        return {
            "host": host,
            "exposed_ports": [str(p["port"]) for p in ports],
            "port_count": len(ports),
            "services": ports if check_services else [],
        }

    @staticmethod
    def _filter_ports(services: list[dict[str, Any]], port_range: str | None) -> list[dict[str, Any]]:
        if not port_range:
            return list(services)

        wanted = set()
        for chunk in port_range.replace(" ", "").split(","):
            if not chunk:
                continue
            if "-" in chunk:
                lo, hi = chunk.split("-", 1)
                wanted.update(range(int(lo), int(hi) + 1))
            else:
                wanted.add(int(chunk))
        return [s for s in services if s["port"] in wanted]

    def analyze_dns_records(
        self,
        domain: str,
        include_dns_history: bool = False,
        check_dga: bool = False,
    ) -> dict[str, Any]:
        """Resolve real A/AAAA/CNAME records for `domain` via the system
        resolver. DNS history requires a provider this project does not
        use, so it is reported as unavailable (empty) rather than fake."""
        records: list[dict[str, str]] = []
        seen = set()
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                family = info[0]
                sockaddr = info[4][0]
                rtype = "A" if family == socket.AF_INET else "AAAA"
                key = (rtype, sockaddr)
                if key not in seen:
                    seen.add(key)
                    records.append({"type": rtype, "value": sockaddr})
        except socket.gaierror as e:
            return {
                "domain": domain,
                "records": [],
                "resolution_error": str(e),
                "is_dga": None,
                "dns_history": [],
            }

        is_dga = None
        if check_dga:
            # DGA heuristic: high character entropy + length, computed on
            # the actual resolved name (label before the final dot).
            label = domain.split(".")[0]
            if len(label) > 8:
                counts = {}
                for ch in label:
                    counts[ch] = counts.get(ch, 0) + 1
                entropy = -sum(
                    (c / len(label)) * math.log2(c / len(label)) for c in counts.values()
                )
                is_dga = entropy > 3.5 and any(ch.isdigit() for ch in label)
            else:
                is_dga = False

        return {
            "domain": domain,
            "records": records,
            "is_dga": is_dga,
            "dns_history": [],  # no history provider configured
        }

    def get_geolocation_analysis(
        self,
        ip_addresses: list[str],
        time_window_hours: int = 24,
        detect_vpn_proxies: bool = False,
    ) -> dict[str, Any]:
        """Classify IPs as private/public/reserved via `ipaddress` -- the
        only genuinely available signal, since this project bundles no
        geolocation database. Country-level mapping is not performed."""
        classification = {"private": [], "public": [], "reserved": []}
        for ip_str in ip_addresses:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                classification.setdefault("invalid", []).append(ip_str)
                continue
            if ip.is_private:
                classification["private"].append(ip_str)
            elif ip.is_global:
                classification["public"].append(ip_str)
            else:
                classification["reserved"].append(ip_str)

        if detect_vpn_proxies:
            return {
                "ips": ip_addresses,
                "geographic_distribution": {},
                "suspicious_locations": 0,
                "vpn_proxies_detected": [],
                "note": "VPN/proxy/heuristics require a geolocation data "
                "source not bundled with this project.",
                "classification": classification,
            }
        return {
            "ips": ip_addresses,
            "geographic_distribution": {},
            "suspicious_locations": 0,
            "classification": classification,
            "note": "IP classification only -- no geolocation database bundled.",
        }

    def protocol_analysis(self, pcap_id: str, protocols: list[str] | None = None) -> dict[str, Any]:
        raise NotImplementedError(
            f"{NOT_IMPLEMENTED}: requires packet capture infrastructure "
            f"(no pcap_id '{pcap_id}' exists in this project)."
        )

    def behavioral_profiling(
        self,
        entity_id: str,
        entity_type: str,
        time_window_days: int = 30,
    ) -> dict[str, Any]:
        """Profile `entity_id` from scan history: when it was first/last
        seen, how many scans included it, and which services were observed."""
        from pynetworkintel.db import Device as DBDevice

        session = self.db.get_session()
        try:
            devices = (
                session.query(DBDevice)
                .filter(DBDevice.ip == entity_id)
                .order_by(DBDevice.last_seen)
                .all()
            )
            # Materialize relationship data (services) while the session is
            # still open; lazy-loading after close would raise
            # DetachedInstanceError.
            rows = [
                (
                    dev.first_seen,
                    dev.last_seen,
                    dev.device_type,
                    sorted({s.port for s in dev.services}),
                )
                for dev in devices
            ]
        finally:
            session.close()

        if not rows:
            return {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "profile": {},
                "deviations_detected": 0,
            }

        all_ports = set()
        device_types = set()
        for _first_seen, _last_seen, device_type, ports in rows:
            device_types.add(device_type)
            all_ports.update(ports)

        profile = {
            "first_seen": rows[0][0].isoformat(),
            "last_seen": rows[-1][1].isoformat(),
            "scan_count": len(rows),
            "device_types_seen": sorted(device_types),
            "ports_observed": sorted(all_ports),
        }
        # Deviation heuristic: seen again today after a gap > the window.
        gaps = 0
        for prev, cur in itertools.pairwise(rows):
            if (cur[1] - prev[1]) > timedelta(days=time_window_days):
                gaps += 1
        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "profile": profile,
            "deviations_detected": gaps,
        }

    def get_threat_intelligence(
        self,
        indicator: str,
        threat_level: str = "any",
    ) -> dict[str, Any]:
        """Return the real CVEs tied to `indicator` (IP/hostname) in scan
        history. No external threat-intel feeds are configured; the result
        is local scan intelligence only."""
        from pynetworkintel.db import Finding as DBFinding

        session = self.db.get_session()
        try:
            findings = (
                session.query(DBFinding)
                .filter(DBFinding.cve_id.isnot(None))
                .all()
            )
        finally:
            session.close()

        matched = [
            f
            for f in findings
            if f.device_ip == indicator
            or (f.device_hostname or "") == indicator
            or f.cve_id == indicator
        ]
        if threat_level != "any":
            matched = [f for f in matched if f.severity == threat_level]

        grouped: dict[str, dict[str, Any]] = {}
        for f in matched:
            entry = grouped.setdefault(
                f.cve_id,
                {
                    "cve_id": f.cve_id,
                    "severity": f.severity,
                    "title": f.title,
                    "first_seen": f.found_at.isoformat(),
                    "last_seen": f.found_at.isoformat(),
                    "cvss_score": f.cvss_score,
                    "sources": ["scan_history"],
                },
            )
            if f.found_at.isoformat() < entry["first_seen"]:
                entry["first_seen"] = f.found_at.isoformat()
            if f.found_at.isoformat() > entry["last_seen"]:
                entry["last_seen"] = f.found_at.isoformat()

        sevs = [e["severity"] for e in grouped.values()]
        total = len(sevs)
        level = "low"
        if total and any(s == "critical" for s in sevs):
            level = "critical"
        elif total and any(s == "high" for s in sevs):
            level = "high"
        elif total and any(s == "medium" for s in sevs):
            level = "medium"

        return {
            "indicator": indicator,
            "threat_level": level,
            "threat_names": list(grouped.keys()),
            "first_seen": min((e["first_seen"] for e in grouped.values()), default=None),
            "last_seen": max((e["last_seen"] for e in grouped.values()), default=None),
            "sources": 1 if grouped else 0,
            "findings": list(grouped.values()),
        }

    def remediation_recommendations(
        self,
        threat_id: str,
        remediation_priority: str = "high",
    ) -> dict[str, Any]:
        """Real remediation guidance derived from a stored vulnerability
        (by CVE id) matched against the scan history."""
        from pynetworkintel.db import Finding as DBFinding

        session = self.db.get_session()
        try:
            finding = (
                session.query(DBFinding)
                .filter(DBFinding.cve_id == threat_id)
                .order_by(DBFinding.found_at.desc())
                .first()
            )
        finally:
            session.close()

        if finding is None:
            return {
                "threat_id": threat_id,
                "priority": remediation_priority,
                "recommendations": [],
                "note": f"No vulnerability with id '{threat_id}' in scan history.",
            }

        severity = finding.severity
        recommendations = [
            finding.recommendation,
        ] if finding.recommendation else []
        recommendations = [r for r in recommendations if r]
        if severity == "critical":
            recommendations.append("Isolate affected device(s) immediately.")
            recommendations.append("Revoke any credentials exposed on the affected host.")
        elif severity == "high":
            recommendations.append("Schedule remediation before the next maintenance window.")
        if finding.exploit_available:
            recommendations.append("Public exploit is available -- prioritize this CVE.")
        recommendations.append("Re-scan the affected device to confirm remediation.")

        return {
            "threat_id": threat_id,
            "priority": remediation_priority,
            "severity": severity,
            "recommendations": recommendations,
            "estimated_remediation_time_minutes": None,  # no estimator, honest
        }

    def network_segmentation_analysis(
        self,
        network_id: str,
        check_microsegmentation: bool = False,
        security_zone: str | None = None,
    ) -> dict[str, Any]:
        """Segment the discovered topology of `network_id` into its real
        inferred subnets. The segmentation score is a transparent heuristic
        over the derived graph, not a claim of switch-level isolation."""
        devices = self._devices_for_target(network_id)
        if not devices:
            return {
                "network_id": network_id,
                "segmentation_score": None,
                "security_zones": 0,
                "microsegmentation_enabled": False,
                "zones": [],
            }

        from pynetworkintel.models import Device

        model_devices = [
            Device(
                ip=d["ip"],
                hostname=d["hostname"],
                os=d["os"],
                device_type=d["device_type"],
                is_online=d["is_online"],
            )
            for d in devices
        ]
        topology = TopologyMapper().build(model_devices)
        zones = topology.devices_by_subnet()

        if security_zone:
            zones = {k: v for k, v in zones.items() if k == security_zone}

        # Heuristic: proportion of distinct placement zones given the node
        # count. More subnets = more segmentation (with real graph data).
        node_count = len(topology.nodes) or 1
        score = min(1.0, len(zones) / node_count) if node_count else None

        return {
            "network_id": network_id,
            "segmentation_score": round(score, 4) if score is not None else None,
            "security_zones": len(zones),
            "microsegmentation_enabled": check_microsegmentation,
            "zones": zones,
            "heuristic_note": "Score is % of distinct inferred subnets / nodes; "
            "subnets are derived from the /24 grouping heuristic.",
        }

    def export_security_report(
        self,
        report_type: str,
        time_period: str = "last_7d",
        format: str = "markdown",
    ) -> dict[str, Any]:
        """Generate a real report from scan history via `ReportGenerator`.

        `report_type` maps: executive_summary -> summary report,
        threat_assessment / vulnerability_scan -> vulnerability report,
        forensics -> change report. Only markdown/json are supported (the
        ReportGenerator doesn't emit PDFs).
        """
        hours = {"last_24h": 24, "last_7d": 7 * 24, "last_30d": 30 * 24}.get(time_period, 24)
        if format not in ("markdown", "json"):
            raise NotImplementedError(
                f"{NOT_IMPLEMENTED}: {format} output requires a PDF renderer"
            )

        generator = ReportGenerator(self.db)
        if report_type == "executive_summary":
            body = generator.generate_summary_report(hours)
        elif report_type in ("threat_assessment", "vulnerability_scan"):
            body = generator.generate_vulnerability_report()
        elif report_type == "forensics":
            body = generator.generate_change_report(hours)
        else:
            raise NotImplementedError(f"{NOT_IMPLEMENTED}: report_type '{report_type}'")

        if format == "json":
            import json as _json

            content = _json.dumps(body, indent=2, default=str)
        else:
            content = generator.generate_markdown_report(hours)

        return {
            "report_type": report_type,
            "time_period": time_period,
            "format": format,
            "content": content,
            "size_bytes": len(content.encode("utf-8")),
        }

    def start_mcp_connector(self, port: int = 8773) -> str:
        """Return an endpoint for an external MCP gateway.

        The previous implementation launched a `dab` subprocess (a binary
        that is not a dependency of this project). That is no longer
        attempted. Tools/handlers are available directly via
        `pynetworkintel._mcp_tools`; spawning an MCP-over-HTTP gateway is
        not implemented in this build.
        """
        raise NotImplementedError(
            f"{NOT_IMPLEMENTED}: MCP gateway server. Use the "
            "PyNetworkIntelMCPHandler tools directly instead."
        )

    def stop_mcp_connector(self):
        """No-op companion to `start_mcp_connector` (nothing to stop)."""

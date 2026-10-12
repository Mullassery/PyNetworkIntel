"""Tests for the real scan-history-backed `NetworkIntelligence` and its MCP
handler surface.

These pin down the replacement of the previous hardcoded-fake MCP layer:
every former handler returned fabricated literal values regardless of
input. Now the outputs are computed from the SQLAlchemy scan database and
the derived topology, and capabilities with no backing infrastructure
raise `NotImplementedError` (surfaced by the MCP handler as an explicit
`not_implemented` result) instead of returning invented data.
"""

import asyncio
from datetime import datetime, timedelta

import pytest

from pynetworkintel._mcp_connector import NetworkIntelligence
from pynetworkintel._mcp_tools import PyNetworkIntelMCPHandler, PyNetworkIntelMCPTools
from pynetworkintel.changes import ChangeDetector
from pynetworkintel.db import (
    Database,
    Device as DBDevice,
    Finding as DBFinding,
    ScanSession,
    Service as DBService,
)
from pynetworkintel.models import Device, SecurityFinding, Severity, FindingType


def _seed_db(db: Database):
    """Seed two scans of the same target for change/anomaly detection."""
    now = datetime.utcnow()
    session = db.get_session()

    scan1 = ScanSession(target="10.0.0.0/24", scan_time=now - timedelta(hours=2),
                        device_count=2, finding_count=1, status="completed")
    session.add(scan1)
    session.flush()

    session.add_all([
        DBDevice(scan_id=scan1.id, ip="10.0.0.1", hostname="gw", os="linux",
                 device_type="linux", is_online=True),
        DBDevice(scan_id=scan1.id, ip="10.0.0.2", hostname="printer", os="linux",
                 device_type="linux", is_online=True),
    ])
    session.flush()

    session.add(DBFinding(scan_id=scan1.id, device_ip="10.0.0.1", device_hostname="gw",
                          finding_type="cve", severity="high", title="Old RCE",
                          description="", evidence="", recommendation="patch",
                          business_impact="", cve_id="CVE-2024-0001", cvss_score=7.5))
    session.commit()

    scan2 = ScanSession(target="10.0.0.0/24", scan_time=now,
                        device_count=2, finding_count=2, status="completed")
    session.add(scan2)
    session.flush()

    session.add_all([
        DBDevice(scan_id=scan2.id, ip="10.0.0.1", hostname="gw", os="linux",
                 device_type="linux", is_online=True),
        DBDevice(scan_id=scan2.id, ip="10.0.0.3", hostname="newhost", os="windows",
                 device_type="windows", is_online=True),
    ])
    session.flush()

    dev2b = session.query(DBDevice).filter(DBDevice.ip == "10.0.0.3").one()
    session.add(DBService(device_id=dev2b.id, port=80, name="http", version="nginx 1.24",
                          protocol="tcp", state="open"))
    session.commit()

    session.add_all([
        DBFinding(scan_id=scan2.id, device_ip="10.0.0.1", device_hostname="gw",
                  finding_type="cve", severity="high", title="Old RCE",
                  description="", evidence="", recommendation="patch",
                  business_impact="", cve_id="CVE-2024-0001", cvss_score=7.5),
        DBFinding(scan_id=scan2.id, device_ip="10.0.0.3", device_hostname="newhost",
                  finding_type="cve", severity="critical", title="Critical RCE",
                  description="", evidence="", recommendation="isolate",
                  business_impact="", cve_id="CVE-2024-0002", cvss_score=9.8,
                  exploit_available=True),
    ])
    session.commit()
    session.close()


@pytest.fixture()
def intel():
    db = Database("sqlite:///:memory:")
    db.create_all()
    _seed_db(db)
    return NetworkIntelligence(db=db)


def test_asset_inventory_is_real(intel):
    inv = intel.get_asset_inventory("10.0.0.0/24", include_vulnerabilities=True)
    assert inv["total_assets"] == 2
    assert "10.0.0.1" in {v["host"] for v in inv["vulnerabilities"]}
    assert "10.0.0.3" in {v["host"] for v in inv["vulnerabilities"]}
    assert inv["os_breakdown"] == {"linux": 1, "windows": 1}


def test_port_exposure_is_real(intel):
    result = intel.check_port_exposure("10.0.0.3")
    assert result["exposed_ports"] == ["80"]
    filtered = intel.check_port_exposure("10.0.0.3", port_range="22,80")
    assert filtered["port_count"] == 1
    nope = intel.check_port_exposure("10.0.0.3", port_range="443")
    assert nope["port_count"] == 0


def test_threat_correlation_groups_real_cves(intel):
    result = intel.threat_correlation(["10.0.0.3"])
    assert result["correlated"]["10.0.0.3"]["correlation_count"] == 1
    assert result["threat_level"] == "critical"


def test_threat_intelligence_from_scan_history(intel):
    result = intel.get_threat_intelligence("10.0.0.3")
    assert "CVE-2024-0002" in result["threat_names"]
    assert result["threat_level"] == "critical"


def test_remediation_recommendations_real(intel):
    result = intel.remediation_recommendations("CVE-2024-0002")
    assert "isolate" in " ".join(result["recommendations"]).lower()
    missing = intel.remediation_recommendations("CVE-2024-9999")
    assert missing["recommendations"] == []


def test_behavioral_profiling_from_scan_history(intel):
    result = intel.behavioral_profiling("10.0.0.1", "host")
    assert result["profile"]["scan_count"] == 2
    assert result["profile"]["ports_observed"] == []


def test_detect_anomalies_diffs_two_scans(intel):
    result = intel.detect_anomalies("10.0.0.0/24")
    types = {a["type"] for a in result["anomalies"]}
    assert "vulnerability_discovered" in types
    assert "device_discovered" in types


def test_detect_anomalies_unknown_type_is_honest(intel):
    result = intel.detect_anomalies("10.0.0.0/24", anomaly_type="ddos")
    assert result["anomalies_detected"] == 0
    assert "cannot be detected" in result["note"]


def test_flow_analysis_from_topology(intel):
    result = intel.analyze_network_flow("10.0.0.0/24")
    assert result["reachable_networks"]
    assert all(isinstance(n, dict) for n in result["nodes"])


def test_segmentation_analysis_real(intel):
    result = intel.network_segmentation_analysis("10.0.0.0/24")
    assert result["security_zones"] >= 1
    assert result["segmentation_score"] is not None
    assert "heuristic_note" in result


def test_protocol_analysis_not_implemented_not_fake(intel):
    with pytest.raises(NotImplementedError):
        intel.protocol_analysis("pc_1")


def test_start_mcp_connector_not_implemented(intel):
    with pytest.raises(NotImplementedError):
        intel.start_mcp_connector()


def test_geolocation_classifies_ips(intel):
    result = intel.get_geolocation_analysis(["10.0.0.1", "8.8.8.8"])
    assert "10.0.0.1" in result["classification"]["private"]
    assert "8.8.8.8" in result["classification"]["public"]
    assert result["geographic_distribution"] == {}


def test_dns_records_unresolvable_is_honest(intel):
    result = intel.analyze_dns_records("nonexistent-host.invalid-suffix.example")
    assert "resolution_error" in result
    assert result["records"] == []


def test_export_security_report_real(intel, tmp_path):
    result = intel.export_security_report("threat_assessment", time_period="last_24h",
                                          format="json")
    assert "CVE-2024-0002" in result["content"]
    assert result["size_bytes"] > 0

    md = intel.export_security_report("threat_assessment", time_period="last_24h")
    assert "Total Unique CVEs" in md["content"]
    assert md["size_bytes"] > 0


def test_mcp_handler_delegates_and_maps_not_implemented(intel):
    handler = PyNetworkIntelMCPHandler(intel)
    result = asyncio.run(handler.protocol_analysis("pc_1"))
    assert result["not_implemented"] is True
    assert "error" in result

    inventory = asyncio.run(handler.get_asset_inventory("10.0.0.0/24"))
    assert inventory["total_assets"] == 2


def test_mcp_tools_descriptions_no_longer_overclaim():
    tools = PyNetworkIntelMCPTools.get_tools()
    joined = " ".join(
        t["description"] for t in tools.values()
    ).lower()
    assert "deep packet inspection" not in joined
    assert "live threat feeds" not in joined
    assert "packet-flow capture" in tools["analyze_network_flow"]["description"]


def test_change_detector_scopes_to_target_and_excludes_current_scan():
    db = Database("sqlite:///:memory:")
    db.create_all()
    _seed_db(db)

    intel = NetworkIntelligence(db=db)
    detector = ChangeDetector(db)

    # Devices from latest scan (10.0.0.1, 10.0.0.3)
    devices = [
        Device(ip="10.0.0.1", hostname="gw", os="linux", device_type="linux"),
        Device(ip="10.0.0.3", hostname="newhost", os="windows", device_type="windows"),
    ]
    changes = detector.detect_device_changes(devices, scan_id=intel._latest_scan("10.0.0.0/24").id,
                                             target="10.0.0.0/24")
    types = {c["type"] for c in changes}
    assert "device_discovered" in types
    assert "device_removed" in types

    # An unrelated target scan must not disturb this target's previous set.
    session = db.get_session()
    other = ScanSession(target="192.168.1.0/24", scan_time=datetime.utcnow(),
                        device_count=1, finding_count=0, status="completed")
    session.add(other)
    session.commit()
    other_dev = DBDevice(scan_id=other.id, ip="192.168.1.5", hostname="other",
                         os="linux", device_type="linux", is_online=True)
    session.add(other_dev)
    session.commit()
    changes = detector.detect_device_changes(devices, scan_id=intel._latest_scan("10.0.0.0/24").id,
                                             target="10.0.0.0/24")
    assert "192.168.1.5" not in {c["ip"] for c in changes}
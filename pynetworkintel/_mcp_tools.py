"""MCP 2.0 tools for PyNetworkIntel.

The handlers previously returned hardcoded, fabricated data regardless of
their inputs (e.g. `analyze_network_flow` always reported `"src_ip":
"192.168.1.100"`, `"anomaly_score": 0.15`, ...). They now delegate to
`NetworkIntelligence`, which computes real answers from stored scan
history and raises `NotImplementedError` for capabilities this project has
no infrastructure for (packet capture, geolocation databases, external
threat-intel feeds). The tool descriptions below describe what the tools
actually do; removed all "deep packet inspection", "live threat feeds" and
similar claims that never backed a real implementation.
"""

import logging
from typing import Any, Dict, List, Optional

from pynetworkintel._mcp_connector import NetworkIntelligence

logger = logging.getLogger(__name__)


def _with_error_result(func):
    """Run `func` and convert NotImplementedError into an explicit
    `not_implemented` result instead of letting it crash the caller with
    no explanation."""

    async def wrapped(self, *args, **kwargs):
        try:
            return await func(self, *args, **kwargs)
        except NotImplementedError as exc:
            return {
                "error": str(exc),
                "not_implemented": True,
            }

    return wrapped


class PyNetworkIntelMCPTools:
    """13 MCP tools for network analysis, threat detection, anomaly detection"""

    @staticmethod
    def get_tools() -> Dict[str, Any]:
        return {
            "analyze_network_flow": {
                "name": "analyze_network_flow",
                "description": "Analyze the inferred reachability/connectivity graph "
                "of a scanned target from stored topology (no packet-flow capture exists)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "flow_id": {"type": "string", "description": "Scanned target (IP, CIDR, or hostname)"},
                        "time_window_seconds": {"type": "integer"},
                        "include_geolocation": {"type": "boolean"},
                    },
                    "required": ["flow_id"],
                },
            },
            "detect_anomalies": {
                "name": "detect_anomalies",
                "description": "Diff the two most recent scans of a target to detect "
                "baseline drift (new/removed devices, new/resolved CVEs)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Monitored target to diff"},
                        "anomaly_type": {
                            "type": "string",
                            "enum": ["device_discovered", "device_removed",
                                     "vulnerability_discovered", "vulnerability_resolved"],
                        },
                        "sensitivity": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    },
                    "required": ["sensor_id"],
                },
            },
            "threat_correlation": {
                "name": "threat_correlation",
                "description": "Correlate indicators (IPs/hostnames) against CVEs found "
                "in scan history for those devices",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IPs or hostnames to correlate against scan findings"
                        },
                        "threat_intel_sources": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["indicators"],
                },
            },
            "get_asset_inventory": {
                "name": "get_asset_inventory",
                "description": "Get real network asset inventory from the latest scan "
                "of the target, with optional vulnerability status",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subnet": {"type": "string", "description": "Scanned target (CIDR or hostname)"},
                        "include_vulnerabilities": {"type": "boolean"},
                        "vulnerability_severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                    },
                    "required": ["subnet"],
                },
            },
            "check_port_exposure": {
                "name": "check_port_exposure",
                "description": "Report which ports/services were observed open on a host "
                "in the latest scan that included it",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port_range": {"type": "string", "description": "e.g., 1-1024 or 22,80,443"},
                        "check_services": {"type": "boolean"},
                    },
                    "required": ["host"],
                },
            },
            "analyze_dns_records": {
                "name": "analyze_dns_records",
                "description": "Resolve A/AAAA records for a domain via the system "
                "resolver and optionally apply a DGA heuristic",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"},
                        "include_dns_history": {"type": "boolean",
                                                "description": "No history provider exists; always empty"},
                        "check_dga": {"type": "boolean",
                                      "description": "Real entropy+length DGA heuristic"},
                    },
                    "required": ["domain"],
                },
            },
            "get_geolocation_analysis": {
                "name": "get_geolocation_analysis",
                "description": "Classify IPs as private/public/reserved via ipaddress "
                "(no geolocation database is bundled)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip_addresses": {"type": "array", "items": {"type": "string"}},
                        "time_window_hours": {"type": "integer"},
                        "detect_vpn_proxies": {"type": "boolean"},
                    },
                    "required": ["ip_addresses"],
                },
            },
            "protocol_analysis": {
                "name": "protocol_analysis",
                "description": "Not available: requires packet-capture infrastructure "
                "this project does not provide",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pcap_id": {"type": "string"},
                        "protocols": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["pcap_id"],
                },
            },
            "behavioral_profiling": {
                "name": "behavioral_profiling",
                "description": "Build a behavioral profile of a host from scan history "
                "(first/last seen, scan count, ports observed)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entity_id": {"type": "string", "description": "IP address"},
                        "entity_type": {"type": "string", "enum": ["host"]},
                        "time_window_days": {"type": "integer"},
                    },
                    "required": ["entity_id", "entity_type"],
                },
            },
            "get_threat_intelligence": {
                "name": "get_threat_intelligence",
                "description": "Return the real CVEs tied to an indicator (IP/hostname/CVE) "
                "in scan history (no external feeds)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "indicator": {"type": "string", "description": "IP, hostname, or CVE id"},
                        "threat_level": {
                            "type": "string",
                            "enum": ["any", "critical", "high", "medium", "low"],
                        },
                    },
                    "required": ["indicator"],
                },
            },
            "remediation_recommendations": {
                "name": "remediation_recommendations",
                "description": "Get remediation guidance for a CVE found in scan history",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threat_id": {"type": "string", "description": "CVE id"},
                        "remediation_priority": {
                            "type": "string",
                            "enum": ["immediate", "urgent", "high", "standard"],
                        },
                    },
                    "required": ["threat_id"],
                },
            },
            "network_segmentation_analysis": {
                "name": "network_segmentation_analysis",
                "description": "Segment the discovered topology of a target into its "
                "inferred subnets and score placement diversity",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "network_id": {"type": "string", "description": "Scanned target"},
                        "check_microsegmentation": {"type": "boolean"},
                        "security_zone": {"type": "string"},
                    },
                    "required": ["network_id"],
                },
            },
            "export_security_report": {
                "name": "export_security_report",
                "description": "Generate a real report from scan history (markdown or json)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "report_type": {
                            "type": "string",
                            "enum": ["executive_summary", "threat_assessment",
                                     "vulnerability_scan", "forensics"],
                        },
                        "time_period": {"type": "string", "enum": ["last_24h", "last_7d", "last_30d"]},
                        "format": {"type": "string", "enum": ["markdown", "json"]},
                    },
                    "required": ["report_type"],
                },
            },
        }


class PyNetworkIntelMCPHandler:
    """Async handlers for PyNetworkIntel MCP tools, backed by
    `NetworkIntelligence` real scan-history analysis."""

    def __init__(self, network_intel: NetworkIntelligence):
        self.intel = network_intel

    @_with_error_result
    async def analyze_network_flow(self, flow_id: str, time_window_seconds: int = 300,
                                  include_geolocation: bool = False) -> Dict[str, Any]:
        return self.intel.analyze_network_flow(
            flow_id, time_window_seconds=time_window_seconds,
            include_geolocation=include_geolocation,
        )

    @_with_error_result
    async def detect_anomalies(self, sensor_id: str, anomaly_type: Optional[str] = None,
                              sensitivity: float = 0.7) -> Dict[str, Any]:
        return self.intel.detect_anomalies(sensor_id, anomaly_type=anomaly_type,
                                           sensitivity=sensitivity)

    @_with_error_result
    async def threat_correlation(self, indicators: List[str],
                                threat_intel_sources: Optional[List[str]] = None) -> Dict[str, Any]:
        return self.intel.threat_correlation(indicators, threat_intel_sources=threat_intel_sources)

    @_with_error_result
    async def get_asset_inventory(self, subnet: str, include_vulnerabilities: bool = False,
                                 vulnerability_severity: Optional[str] = None) -> Dict[str, Any]:
        return self.intel.get_asset_inventory(
            subnet,
            include_vulnerabilities=include_vulnerabilities,
            vulnerability_severity=vulnerability_severity,
        )

    @_with_error_result
    async def check_port_exposure(self, host: str, port_range: Optional[str] = None,
                                 check_services: bool = True) -> Dict[str, Any]:
        return self.intel.check_port_exposure(
            host, port_range=port_range, check_services=check_services
        )

    @_with_error_result
    async def analyze_dns_records(self, domain: str, include_dns_history: bool = False,
                                 check_dga: bool = False) -> Dict[str, Any]:
        return self.intel.analyze_dns_records(
            domain, include_dns_history=include_dns_history, check_dga=check_dga
        )

    @_with_error_result
    async def get_geolocation_analysis(self, ip_addresses: List[str],
                                      time_window_hours: int = 24,
                                      detect_vpn_proxies: bool = False) -> Dict[str, Any]:
        return self.intel.get_geolocation_analysis(
            ip_addresses,
            time_window_hours=time_window_hours,
            detect_vpn_proxies=detect_vpn_proxies,
        )

    @_with_error_result
    async def protocol_analysis(self, pcap_id: str,
                               protocols: Optional[List[str]] = None) -> Dict[str, Any]:
        return self.intel.protocol_analysis(pcap_id, protocols=protocols)

    @_with_error_result
    async def behavioral_profiling(self, entity_id: str, entity_type: str,
                                  time_window_days: int = 30) -> Dict[str, Any]:
        return self.intel.behavioral_profiling(
            entity_id, entity_type, time_window_days=time_window_days
        )

    @_with_error_result
    async def get_threat_intelligence(self, indicator: str,
                                     threat_level: str = "any") -> Dict[str, Any]:
        return self.intel.get_threat_intelligence(indicator, threat_level=threat_level)

    @_with_error_result
    async def remediation_recommendations(self, threat_id: str,
                                         remediation_priority: str = "high") -> Dict[str, Any]:
        return self.intel.remediation_recommendations(
            threat_id, remediation_priority=remediation_priority
        )

    @_with_error_result
    async def network_segmentation_analysis(self, network_id: str,
                                           check_microsegmentation: bool = False,
                                           security_zone: Optional[str] = None) -> Dict[str, Any]:
        return self.intel.network_segmentation_analysis(
            network_id,
            check_microsegmentation=check_microsegmentation,
            security_zone=security_zone,
        )

    @_with_error_result
    async def export_security_report(self, report_type: str,
                                    time_period: str = "last_7d",
                                    format: str = "markdown") -> Dict[str, Any]:
        return self.intel.export_security_report(
            report_type, time_period=time_period, format=format
        )
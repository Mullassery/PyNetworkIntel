"""Data models for devices, services, and security findings."""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    CONFIGURATION = "configuration"
    CVE = "cve"
    EXPOSURE = "exposure"
    PERFORMANCE = "performance"


@dataclass
class Service:
    port: int
    name: str
    version: Optional[str] = None
    protocol: str = "tcp"
    state: str = "open"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfigFile:
    path: str
    content: str
    device_type: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Device:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    device_type: str = "linux"
    services: List[Service] = field(default_factory=list)
    configs: List[ConfigFile] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    is_online: bool = True

    def add_service(self, port: int, name: str, version: Optional[str] = None):
        self.services.append(Service(port=port, name=name, version=version))

    def add_config(self, path: str, content: str, device_type: str):
        self.configs.append(ConfigFile(path=path, content=content, device_type=device_type))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "device_type": self.device_type,
            "services": [s.to_dict() for s in self.services],
            "configs": [c.to_dict() for c in self.configs],
            "last_seen": self.last_seen.isoformat(),
            "is_online": self.is_online,
        }


@dataclass
class SecurityFinding:
    device: str
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    business_impact: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["finding_type"] = self.finding_type.value
        data["severity"] = self.severity.value
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class ScanResult:
    devices: List[Device] = field(default_factory=list)
    findings: List[SecurityFinding] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "devices": [d.to_dict() for d in self.devices],
            "findings": [f.to_dict() for f in self.findings],
            "scan_time": self.scan_time.isoformat(),
            "scan_duration_seconds": self.scan_duration_seconds,
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "total_devices": len(self.devices),
            "online_devices": sum(1 for d in self.devices if d.is_online),
            "total_findings": len(self.findings),
            "critical_findings": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high_findings": sum(1 for f in self.findings if f.severity == Severity.HIGH),
        }

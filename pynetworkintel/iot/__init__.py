"""IoT/OT device discovery, protocol analysis, and vulnerability checks.

Real, working code and squarely core - "everything connected to your
network" explicitly includes IoT/industrial devices, and this module uses
plain sockets (no external SDK) to probe for them. Lighter test coverage
than the primary nmap-based discovery path - see tests/test_iot.py for
protocol/vulnerability logic coverage (live socket probing against real
devices is not exercised in CI).
"""

from .discovery import IoTDeviceDiscovery
from .protocols import ProtocolAnalyzer
from .vulnerabilities import IoTVulnerabilityAnalyzer

__all__ = [
    "IoTDeviceDiscovery",
    "ProtocolAnalyzer",
    "IoTVulnerabilityAnalyzer",
]

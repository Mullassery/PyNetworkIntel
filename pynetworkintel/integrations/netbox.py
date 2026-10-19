"""NetBox import helpers.

NetBox (Apache-2.0) is the de-facto OSS network source of truth. Its UI/API
accepts CSV imports, which avoids embedding Django or requiring a live token.
This adapter produces NetBox-shaped device and prefix CSVs from a scan result;
site/device-type/device-role values are the NetBox slugs you already maintain.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass

from pynetworkintel.models import ScanResult


@dataclass
class NetBoxCsvExporter:
    site: str
    device_type: str
    device_role: str
    status: str = "active"

    def devices_csv(self, scan_result: ScanResult) -> str:
        return devices_csv(
            scan_result,
            site=self.site,
            device_type=self.device_type,
            device_role=self.device_role,
            status=self.status,
        )

    def prefixes_csv(self, scan_result: ScanResult, *, prefix_length: int = 24) -> str:
        return prefixes_csv(scan_result, prefix_length=prefix_length)


def devices_csv(
    scan_result: ScanResult,
    *,
    site: str,
    device_type: str,
    device_role: str,
    status: str = "active",
) -> str:
    """Return a NetBox device-import CSV (one row per discovered device)."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["name", "device_type", "device_role", "site", "status", "comments"])
    for device in scan_result.devices:
        name = device.hostname or f"host-{device.ip.replace('.', '-').replace(':', '-')}"
        services = ", ".join(
            f"{service.port}/{service.protocol}"
            for service in device.services
            if service.state == "open"
        )
        comments = f"discovered by PyNetworkIntel; ip={device.ip}"
        if services:
            comments += f"; open={services}"
        writer.writerow([name, device_type, device_role, site, status, comments])
    return output.getvalue()


def prefixes_csv(scan_result: ScanResult, *, prefix_length: int = 24) -> str:
    """Return a NetBox prefix-import CSV derived from device IPv4 addresses."""
    import ipaddress

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["prefix", "status", "description"])
    seen: set[str] = set()
    for device in scan_result.devices:
        try:
            network = ipaddress.ip_network(f"{device.ip}/{prefix_length}", strict=False)
        except ValueError:
            continue
        prefix = str(network)
        if prefix in seen:
            continue
        seen.add(prefix)
        writer.writerow([prefix, "active", "discovered by PyNetworkIntel"])
    return output.getvalue()


__all__ = ["NetBoxCsvExporter", "devices_csv", "prefixes_csv"]

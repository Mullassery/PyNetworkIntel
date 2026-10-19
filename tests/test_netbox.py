"""NetBox CSV export tests."""

from __future__ import annotations

from pynetworkintel.integrations.netbox import devices_csv, prefixes_csv
from pynetworkintel.models import Device, ScanResult, Service


def test_devices_csv_includes_services_and_name():
    result = ScanResult(
        devices=[
            Device(
                ip="10.0.0.5",
                hostname="edge-1",
                services=[Service(port=443, name="https", state="open")],
            )
        ]
    )
    text = devices_csv(result, site="lab", device_type="server", device_role="edge")
    assert "edge-1,server,edge,lab,active" in text
    assert "443/tcp" in text


def test_prefixes_are_deduplicated(tmp_path):
    result = ScanResult(devices=[Device(ip="10.0.0.5"), Device(ip="10.0.0.6")])
    text = prefixes_csv(result)
    assert text.count("10.0.0.0/24") == 1

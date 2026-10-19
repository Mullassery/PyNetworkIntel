"""Nuclei adapter tests use a fake executable, so no network or real Nuclei
binary is required. The fake emits the documented JSONL contract."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from pynetworkintel.discovery.nuclei import NucleiScanner, NucleiUnavailable
from pynetworkintel.models import Device, ScanResult, Severity


def _fake_nuclei(tmp_path: Path) -> Path:
    script = tmp_path / "nuclei"
    script.write_text(
        """#!/usr/bin/env python3
import json, sys
args = sys.argv
target_file = args[args.index('-l') + 1]
targets = [l.strip() for l in open(target_file) if l.strip()]
records = [
    {
        "template-id": "CVE-2024-0001",
        "info": {
            "name": "Example verified exposure",
            "severity": "high",
            "description": "A verified issue.",
            "remediation": "Upgrade the service.",
            "classification": {"cve-id": ["CVE-2024-0001"], "cvss-score": 8.1},
        },
        "host": targets[0],
        "matched-at": targets[0] + "/admin",
        "ip": "10.0.0.5",
    }
]
for r in records:
    print(json.dumps(r))
"""
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def test_targets_from_scan_include_web_services():
    result = ScanResult(
        devices=[
            Device(
                ip="10.0.0.5",
                services=[
                    __import__("pynetworkintel.models", fromlist=["Service"]).Service(
                        port=8080, name="http", state="open"
                    )
                ],
            )
        ]
    )
    assert NucleiScanner.targets_from_scan(result) == ["http://10.0.0.5:8080"]


def test_nuclei_jsonl_maps_to_security_finding(tmp_path):
    binary = _fake_nuclei(tmp_path)
    result = ScanResult(devices=[Device(ip="10.0.0.5")])
    findings = NucleiScanner(nuclei_path=str(binary)).scan_scan_result(result)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.device == "10.0.0.5"
    assert finding.cve_id == "CVE-2024-0001"
    assert finding.severity == Severity.HIGH
    assert finding.cvss_score == 8.1
    assert "template" in finding.evidence


def test_missing_binary_raises_actionable_error(tmp_path):
    scanner = NucleiScanner(nuclei_path=str(tmp_path / "missing-nuclei"))
    with pytest.raises(NucleiUnavailable, match="nuclei was not found"):
        scanner.scan_targets(["http://127.0.0.1"])

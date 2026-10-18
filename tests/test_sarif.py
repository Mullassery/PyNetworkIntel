"""SARIF export tests."""

import json

from pynetworkintel.sarif import build_sarif


def _findings():
    return [
        {
            "device": "192.0.2.10 (db)",
            "finding_type": "cve",
            "severity": "high",
            "title": "OpenSSH 8.2 - CVE-2021-41617",
            "description": "Known vulnerability",
            "evidence": "port 22",
            "recommendation": "Upgrade OpenSSH",
            "business_impact": "Remote attack",
            "cve_id": "CVE-2021-41617",
            "cvss_score": 7.0,
        },
        {
            "device": "192.0.2.20",
            "finding_type": "config",
            "severity": "medium",
            "title": "Telnet exposed",
            "description": "Telnet is enabled",
            "evidence": "port 23",
            "recommendation": "Disable telnet",
            "business_impact": "Cleartext credentials",
            "cve_id": None,
            "cvss_score": None,
        },
    ]


def test_sarif_shape_rules_and_levels():
    sarif = build_sarif(_findings(), tool_version="1.7.0")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["version"] == "1.7.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {
        "pynetworkintel/cve",
        "pynetworkintel/config",
    }
    assert [r["level"] for r in run["results"]] == ["error", "warning"]
    assert run["results"][0]["properties"]["cve_id"] == "CVE-2021-41617"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "network://192.0.2.10 (db)"
    )


def test_sarif_empty_findings_is_valid():
    sarif = build_sarif([])
    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []

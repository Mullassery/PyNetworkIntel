"""SARIF 2.1.0 export for scan findings.

One result per finding, with the device represented as a `network://` artifact
URI and CVE score/type/recommendation preserved in result properties. This is
intended for GitHub code scanning or any SARIF viewer; it is an additional
export, not a replacement for the JSON report.
"""

from __future__ import annotations

from typing import Any, Dict, List

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_sarif(findings: List[Dict[str, Any]], tool_version: str = "") -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        finding_type = str(finding.get("finding_type", "finding"))
        rule_id = f"pynetworkintel/{finding_type}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding_type,
                "shortDescription": {
                    "text": "PyNetworkIntel %s finding" % finding_type
                },
                "properties": {"security-severity": _security_severity(finding)},
            },
        )
        device = str(finding.get("device", "unknown"))
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL.get(str(finding.get("severity", "")).lower(), "warning"),
                "message": {
                    "text": "%s: %s"
                    % (finding.get("title", "finding"), finding.get("description", ""))
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "network://" + device},
                        }
                    }
                ],
                "properties": {
                    "finding_type": finding_type,
                    "severity": finding.get("severity"),
                    "device": device,
                    "cve_id": finding.get("cve_id"),
                    "cvss_score": finding.get("cvss_score"),
                    "recommendation": finding.get("recommendation"),
                    "business_impact": finding.get("business_impact"),
                    "evidence": finding.get("evidence"),
                },
            }
        )

    driver: Dict[str, Any] = {
        "name": "PyNetworkIntel",
        "informationUri": "https://github.com/Mullassery/PyNetworkIntel",
        "rules": [rules[key] for key in sorted(rules)],
    }
    if tool_version:
        driver["version"] = tool_version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def _security_severity(finding: Dict[str, Any]) -> str:
    score = finding.get("cvss_score")
    if isinstance(score, (int, float)):
        return f"{float(score):.1f}"
    return {
        "critical": "9.0",
        "high": "7.0",
        "medium": "4.0",
        "low": "1.0",
    }.get(str(finding.get("severity", "")).lower(), "0.0")

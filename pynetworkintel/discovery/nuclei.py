"""Optional Nuclei verification adapter.

Nuclei is a separate MIT-licensed Go binary.  We deliberately do **not**
vendor or fork it: this module builds a target list from devices discovered by
nmap, runs the installed ``nuclei`` binary with JSONL output, and maps
findings into PyNetworkIntel's :class:`SecurityFinding` model.

If the binary is not installed the adapter raises ``NucleiUnavailable`` with
an actionable message rather than silently returning "no findings".
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pynetworkintel.models import (
    FindingType,
    ScanResult,
    SecurityFinding,
    Severity,
)

logger = logging.getLogger(__name__)

# Ports that are commonly HTTP(S) even when nmap cannot identify the service.
WEB_PORTS = {
    80,
    81,
    443,
    3000,
    5000,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
    9090,
    9443,
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiUnavailable(RuntimeError):
    """Raised when the nuclei binary cannot be found."""


@dataclass
class NucleiResult:
    """Normalized Nuclei finding plus the raw record for evidence/debugging."""

    template_id: str
    name: str
    severity: str
    matched_at: str
    host: str
    ip: str | None = None
    description: str = ""
    remediation: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class NucleiScanner:
    """Run Nuclei templates against hosts discovered by PyNetworkIntel."""

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates: Iterable[str] | None = None,
        severity: str | None = None,
        timeout: int = 300,
        extra_args: Iterable[str] | None = None,
    ):
        self.nuclei_path = nuclei_path
        self.templates = list(templates or [])
        self.severity = severity
        self.timeout = timeout
        self.extra_args = list(extra_args or [])

    def is_available(self) -> bool:
        return shutil.which(self.nuclei_path) is not None

    def _require_binary(self) -> str:
        resolved = shutil.which(self.nuclei_path)
        if resolved is None:
            raise NucleiUnavailable(
                "nuclei was not found on PATH. Install the MIT-licensed "
                "binary from https://github.com/projectdiscovery/nuclei "
                "(e.g. `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`) "
                "or pass nuclei_path=..."
            )
        return resolved

    @staticmethod
    def targets_from_scan(scan_result: ScanResult) -> list[str]:
        """Build HTTP(S) targets from discovered open services."""
        targets: list[str] = []
        seen: set[str] = set()

        def add(value: str) -> None:
            value = value.strip().rstrip("/")
            if value and value not in seen:
                seen.add(value)
                targets.append(value)

        for device in scan_result.devices:
            if not getattr(device, "is_online", True):
                continue
            seen_ports = {s.port for s in device.services if s.state == "open"}
            for service in device.services:
                if service.state != "open":
                    continue
                name = (service.name or "").lower()
                port = service.port
                if port in WEB_PORTS or "http" in name:
                    scheme = "https" if port in {443, 8443, 9443} or "https" in name else "http"
                    add(f"{scheme}://{device.ip}:{port}")
            # If nmap found a host but no service, still try the two default
            # web ports; Nuclei filters non-matching templates itself.
            if not seen_ports:
                add(f"http://{device.ip}")
                add(f"https://{device.ip}")
        return targets

    def scan_scan_result(self, scan_result: ScanResult) -> list[SecurityFinding]:
        targets = self.targets_from_scan(scan_result)
        if not targets:
            logger.info("Nuclei: no HTTP targets discovered; skipping")
            return []
        return self._run(targets)

    def scan_targets(self, targets: Iterable[str]) -> list[SecurityFinding]:
        cleaned = [t.strip() for t in targets if t and t.strip()]
        if not cleaned:
            return []
        return self._run(cleaned)

    def _run(self, targets: list[str]) -> list[SecurityFinding]:
        binary = self._require_binary()

        with tempfile.TemporaryDirectory(prefix="pynetworkintel-nuclei-") as tmp:
            target_file = Path(tmp) / "targets.txt"
            target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

            cmd = [binary, "-l", str(target_file), "-jsonl", "-silent", "-nc", "-duc"]
            if self.severity:
                cmd.extend(["-severity", self.severity])
            for template in self.templates:
                cmd.extend(["-t", template])
            cmd.extend(self.extra_args)

            logger.info("Running Nuclei against %d target(s)", len(targets))
            try:
                completed = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"nuclei timed out after {self.timeout}s") from exc

            if completed.returncode not in (0, 1):
                detail = (completed.stderr or "").strip()
                raise RuntimeError(f"nuclei exited with {completed.returncode}: {detail[:500]}")

            findings: list[SecurityFinding] = []
            for line in (completed.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Nuclei emitted non-JSON line: %s", line[:200])
                    continue
                normalized = self._normalize(record)
                if normalized is not None:
                    findings.extend(self._to_findings(normalized, scan_result=None))

            return findings

    @staticmethod
    def _normalize(record: dict[str, Any]) -> NucleiResult | None:
        info = record.get("info") or {}
        template_id = record.get("template-id") or info.get("template-id") or ""
        name = info.get("name") or template_id or "Nuclei finding"
        severity = str(info.get("severity") or "unknown").lower()
        matched_at = record.get("matched-at") or record.get("host") or ""
        host = record.get("host") or matched_at
        if not matched_at:
            return None

        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cvss = classification.get("cvss-score")
        try:
            cvss_score = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_score = None

        return NucleiResult(
            template_id=template_id,
            name=name,
            severity=severity,
            matched_at=matched_at,
            host=host,
            ip=record.get("ip"),
            description=info.get("description") or "",
            remediation=info.get("remediation") or "",
            cve_ids=[str(c) for c in cve_ids],
            cvss_score=cvss_score,
            raw=record,
        )

    @staticmethod
    def _to_findings(
        result: NucleiResult,
        scan_result: ScanResult | None = None,
    ) -> list[SecurityFinding]:
        device = result.ip or result.host
        if not device:
            device = result.matched_at
        # Strip scheme/port for the device key when a URL was matched.
        device = device.replace("https://", "").replace("http://", "").split("/")[0]
        device = device.rsplit(":", 1)[0] if device.count(":") == 1 else device

        cve_id = result.cve_ids[0] if result.cve_ids else None
        evidence = f"{result.matched_at} (template: {result.template_id})"
        description = result.description or result.name
        recommendation = result.remediation or (
            "Review the matched Nuclei template and remediate the exposed service or configuration."
        )
        return [
            SecurityFinding(
                device=device,
                finding_type=FindingType.CVE if cve_id else FindingType.EXPOSURE,
                severity=_SEVERITY_MAP.get(result.severity, Severity.INFO),
                title=result.name,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                business_impact=(
                    "Verified exploitable/exposed condition on a discovered asset; "
                    "triage against asset criticality."
                ),
                cve_id=cve_id,
                cvss_score=result.cvss_score,
                exploit_available=bool(cve_id),
            )
        ]


def scan_with_nuclei(
    scan_result: ScanResult,
    nuclei_path: str = "nuclei",
    templates: Iterable[str] | None = None,
    severity: str | None = None,
    timeout: int = 300,
) -> list[SecurityFinding]:
    """Convenience wrapper: verify discovered services with Nuclei."""
    return NucleiScanner(
        nuclei_path=nuclei_path,
        templates=templates,
        severity=severity,
        timeout=timeout,
    ).scan_scan_result(scan_result)


__all__ = [
    "NucleiResult",
    "NucleiScanner",
    "NucleiUnavailable",
    "scan_with_nuclei",
]

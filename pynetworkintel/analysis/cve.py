"""CVE database integration and vulnerability checking."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import requests

from pynetworkintel.models import Device, FindingType, SecurityFinding, Service, Severity

logger = logging.getLogger(__name__)

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Service name to CVE search keywords
SERVICE_KEYWORDS = {
    "ssh": "OpenSSH",
    "http": "Apache HTTP",
    "https": "Apache HTTP",
    "apache": "Apache HTTP",
    "nginx": "Nginx",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "python": "Python",
    "nodejs": "Node.js",
    "java": "Java",
}


class CVEChecker:
    """Check services for known vulnerabilities via NVD API."""

    def __init__(
        self,
        rate_limit_delay: float = 6.0,
        cache_path: str | None = None,
        cache_ttl: int | None = None,
        offline: bool | None = None,
    ):
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0.0
        self._cache = {}
        self.cache_path = Path(
            cache_path
            or os.getenv("PYNETWORKINTEL_CVE_CACHE")
            or (Path.home() / ".pynetworkintel" / "cve_cache.json")
        )
        self.cache_ttl = int(
            cache_ttl
            if cache_ttl is not None
            else os.getenv("PYNETWORKINTEL_CVE_CACHE_TTL", "86400")
        )
        self.offline = (
            offline
            if offline is not None
            else os.getenv("PYNETWORKINTEL_OFFLINE", "").lower() in ("1", "true", "yes")
        )
        self._disk_cache = self._load_disk_cache()

    def check_device(self, device: Device) -> list[SecurityFinding]:
        """
        Check all services on device for known vulnerabilities.

        Args:
            device: Device to check

        Returns:
            List of CVE-based security findings
        """
        findings = []

        for service in device.services:
            if service.version:
                cves = self.get_cves_for_service(service.name, service.version)
                for cve in cves:
                    finding = self._create_finding(device, service, cve)
                    findings.append(finding)

        return findings

    def get_cves_for_service(self, service_name: str, version: str) -> list[dict[str, Any]]:
        """
        Get CVEs for a specific service and version.

        Args:
            service_name: Name of the service (e.g., 'Apache', 'OpenSSH')
            version: Version string

        Returns:
            List of CVE dictionaries
        """
        cache_key = f"{service_name}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        cached = self._disk_cache.get(cache_key)
        if isinstance(cached, dict):
            age = time.time() - float(cached.get("timestamp", 0))
            if age <= self.cache_ttl:
                cves = cached.get("cves", [])
                self._cache[cache_key] = cves
                return cves

        if self.offline:
            logger.warning(
                "Offline mode and no fresh CVE cache entry for %s; skipping NVD lookup",
                cache_key,
            )
            return []

        keyword = SERVICE_KEYWORDS.get(service_name.lower(), service_name)
        search_query = f"{keyword} {version}"

        try:
            cves = self._query_nvd(search_query)
            self._cache[cache_key] = cves
            self._disk_cache[cache_key] = {
                "timestamp": time.time(),
                "cves": cves,
            }
            self._save_disk_cache()
            return cves
        except Exception as e:
            logger.warning(f"Failed to query CVEs for {service_name}: {e}")
            return []

    def _query_nvd(self, keyword: str) -> list[dict[str, Any]]:
        """Query NVD API for CVEs matching keyword."""
        if self.offline:
            logger.warning("Offline mode: skipping NVD request for %r", keyword)
            return []
        self._respect_rate_limit()

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
        }

        try:
            response = requests.get(NVD_API_URL, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            cves = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                # NVD can return a CVE with an explicitly empty "descriptions"
                # list (e.g. reserved/rejected CVEs) - `.get(..., [{}])` only
                # covers the *missing* key case, not an empty-list value, so
                # `or [{}]` is needed to avoid an IndexError on `[0]`.
                descriptions = cve_data.get("descriptions") or [{}]
                description = descriptions[0].get("value", "")
                cvss_score = self._extract_cvss_score(cve_data)

                if cve_id:
                    cves.append(
                        {
                            "id": cve_id,
                            "description": description,
                            "cvss_score": cvss_score,
                        }
                    )

            return cves

        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []

    def _load_disk_cache(self) -> dict[str, Any]:
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_disk_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._disk_cache, indent=2), encoding="utf-8")
            os.replace(tmp, self.cache_path)
        except OSError as exc:
            logger.warning("Could not write CVE cache %s: %s", self.cache_path, exc)

    def _extract_cvss_score(self, cve_data: dict[str, Any]) -> float | None:
        """Extract CVSS score from CVE data."""
        metrics = cve_data.get("metrics", {})

        # Try CVSS 3.1 first (more recent)
        cvss31 = metrics.get("cvssMetricV31", [{}])[0]
        if cvss31 and "cvssData" in cvss31:
            return cvss31["cvssData"].get("baseScore")

        # Fall back to CVSS 2.0
        cvss20 = metrics.get("cvssMetricV20", [{}])[0]
        if cvss20 and "cvssData" in cvss20:
            return cvss20["cvssData"].get("baseScore")

        return None

    def _respect_rate_limit(self):
        """Respect NVD API rate limit (1 request per 6 seconds)."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def _create_finding(
        self, device: Device, service: Service, cve: dict[str, Any]
    ) -> SecurityFinding:
        """Create security finding from CVE information."""
        severity = self._cvss_to_severity(cve.get("cvss_score"))

        return SecurityFinding(
            device=f"{device.ip} ({device.hostname or 'unknown'})",
            finding_type=FindingType.CVE,
            severity=severity,
            title=f"{service.name} {service.version} - {cve['id']}",
            description=cve.get("description", "Known vulnerability"),
            evidence=f"Service: {service.name}, Version: {service.version}, Port: {service.port}",
            recommendation=f"Upgrade {service.name} to a patched version",
            business_impact=f"Known vulnerability in {service.name} could allow remote attack",
            cve_id=cve["id"],
            cvss_score=cve.get("cvss_score"),
        )

    @staticmethod
    def _cvss_to_severity(cvss_score: float | None) -> Severity:
        """Convert CVSS score to severity level."""
        if cvss_score is None:
            return Severity.MEDIUM

        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW

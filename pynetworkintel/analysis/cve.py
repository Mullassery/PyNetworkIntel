"""CVE database integration and vulnerability checking."""

import logging
import requests
import time
from typing import List, Optional, Dict, Any
from functools import lru_cache
from datetime import datetime, timedelta

from pynetworkintel.models import Device, Service, SecurityFinding, Severity, FindingType

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

    def __init__(self, rate_limit_delay: float = 0.6):
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0.0
        self._cache = {}

    def check_device(self, device: Device) -> List[SecurityFinding]:
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

    def get_cves_for_service(self, service_name: str, version: str) -> List[Dict[str, Any]]:
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

        keyword = SERVICE_KEYWORDS.get(service_name.lower(), service_name)
        search_query = f"{keyword} {version}"

        try:
            cves = self._query_nvd(search_query)
            self._cache[cache_key] = cves
            return cves
        except Exception as e:
            logger.warning(f"Failed to query CVEs for {service_name}: {e}")
            return []

    def _query_nvd(self, keyword: str) -> List[Dict[str, Any]]:
        """Query NVD API for CVEs matching keyword."""
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
                description = cve_data.get("descriptions", [{}])[0].get("value", "")
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

    def _extract_cvss_score(self, cve_data: Dict[str, Any]) -> Optional[float]:
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
        self, device: Device, service: Service, cve: Dict[str, Any]
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
    def _cvss_to_severity(cvss_score: Optional[float]) -> Severity:
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

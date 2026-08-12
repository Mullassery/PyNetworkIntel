"""Tests for CVEChecker's NVD API integration, using mocked HTTP responses.

The pre-existing test suite explicitly avoided exercising `_query_nvd` /
`get_cves_for_service` ("won't actually query NVD due to rate limiting").
These tests mock `requests.get` so the actual query/parsing/caching logic
gets real coverage without hitting the network or being rate-limited.
"""

import time
from unittest.mock import patch, MagicMock

import pytest
import requests

from pynetworkintel.analysis.cve import CVEChecker
from pynetworkintel.models import Device, Severity, FindingType


def make_nvd_response(cve_id="CVE-2021-41617", score=7.0, description="Test vuln"):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "vectorString": "..."}}
                        ]
                    },
                }
            }
        ]
    }


@pytest.fixture
def checker():
    # rate_limit_delay=0 so tests don't actually sleep
    return CVEChecker(rate_limit_delay=0)


class TestQueryNVD:
    def test_query_nvd_parses_cves_from_response(self, checker):
        mock_response = MagicMock()
        mock_response.json.return_value = make_nvd_response()
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response) as mock_get:
            cves = checker._query_nvd("OpenSSH 8.2p1")

        assert len(cves) == 1
        assert cves[0]["id"] == "CVE-2021-41617"
        assert cves[0]["cvss_score"] == 7.0
        assert cves[0]["description"] == "Test vuln"

        mock_get.assert_called_once()
        called_args, called_kwargs = mock_get.call_args
        assert called_kwargs["params"]["keywordSearch"] == "OpenSSH 8.2p1"

    def test_query_nvd_handles_multiple_results(self, checker):
        response_data = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2021-0001", "descriptions": [{"value": "a"}], "metrics": {}}},
                {"cve": {"id": "CVE-2021-0002", "descriptions": [{"value": "b"}], "metrics": {}}},
            ]
        }
        mock_response = MagicMock()
        mock_response.json.return_value = response_data
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response):
            cves = checker._query_nvd("Apache")

        assert {c["id"] for c in cves} == {"CVE-2021-0001", "CVE-2021-0002"}

    def test_query_nvd_skips_entries_without_cve_id(self, checker):
        response_data = {"vulnerabilities": [{"cve": {"descriptions": [], "metrics": {}}}]}
        mock_response = MagicMock()
        mock_response.json.return_value = response_data
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response):
            cves = checker._query_nvd("something")

        assert cves == []

    def test_query_nvd_empty_vulnerabilities(self, checker):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response):
            cves = checker._query_nvd("NoSuchService 1.0")

        assert cves == []

    def test_query_nvd_request_exception_returns_empty_list(self, checker):
        with patch("requests.get", side_effect=requests.RequestException("network down")):
            cves = checker._query_nvd("OpenSSH")

        assert cves == []

    def test_query_nvd_http_error_returns_empty_list(self, checker):
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("500")

        with patch("requests.get", return_value=mock_response):
            cves = checker._query_nvd("OpenSSH")

        assert cves == []

    def test_query_nvd_falls_back_to_cvss_v2(self, checker):
        response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2010-0001",
                        "descriptions": [{"value": "old vuln"}],
                        "metrics": {
                            "cvssMetricV20": [{"cvssData": {"baseScore": 5.0}}]
                        },
                    }
                }
            ]
        }
        mock_response = MagicMock()
        mock_response.json.return_value = response_data
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response):
            cves = checker._query_nvd("legacy service")

        assert cves[0]["cvss_score"] == 5.0

    def test_respects_rate_limit(self):
        checker = CVEChecker(rate_limit_delay=0.2)
        checker.last_request_time = time.time()

        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status.return_value = None

        start = time.time()
        with patch("requests.get", return_value=mock_response):
            checker._query_nvd("anything")
        elapsed = time.time() - start

        assert elapsed >= 0.15  # allow small scheduling slack


class TestGetCVEsForService:
    def test_get_cves_uses_service_keyword_mapping(self, checker):
        mock_response = MagicMock()
        mock_response.json.return_value = make_nvd_response()
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response) as mock_get:
            checker.get_cves_for_service("ssh", "8.2p1")

        called_kwargs = mock_get.call_args.kwargs
        assert called_kwargs["params"]["keywordSearch"] == "OpenSSH 8.2p1"

    def test_get_cves_caches_result(self, checker):
        mock_response = MagicMock()
        mock_response.json.return_value = make_nvd_response()
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response) as mock_get:
            first = checker.get_cves_for_service("nginx", "1.18.0")
            second = checker.get_cves_for_service("nginx", "1.18.0")

        assert first == second
        # Only one real HTTP call should have been made; the second call hits the cache
        assert mock_get.call_count == 1

    def test_get_cves_unknown_service_uses_name_as_keyword(self, checker):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response) as mock_get:
            checker.get_cves_for_service("some-custom-daemon", "3.1")

        called_kwargs = mock_get.call_args.kwargs
        assert called_kwargs["params"]["keywordSearch"] == "some-custom-daemon 3.1"

    def test_get_cves_swallows_exceptions_and_returns_empty(self, checker):
        with patch.object(checker, "_query_nvd", side_effect=RuntimeError("boom")):
            result = checker.get_cves_for_service("ssh", "1.0")
        assert result == []


class TestCheckDevice:
    def test_check_device_creates_findings_from_cves(self, checker):
        device = Device(ip="10.0.0.5", hostname="db1")
        device.add_service(port=5432, name="postgresql", version="12.1")

        mock_response = MagicMock()
        mock_response.json.return_value = make_nvd_response(
            cve_id="CVE-2022-1234", score=9.1, description="Critical RCE"
        )
        mock_response.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_response):
            findings = checker.check_device(device)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.cve_id == "CVE-2022-1234"
        assert finding.severity == Severity.CRITICAL
        assert finding.finding_type == FindingType.CVE
        assert "10.0.0.5" in finding.device

    def test_check_device_skips_services_without_version(self, checker):
        device = Device(ip="10.0.0.6")
        device.add_service(port=80, name="http", version=None)

        with patch("requests.get") as mock_get:
            findings = checker.check_device(device)

        mock_get.assert_not_called()
        assert findings == []

    def test_check_device_no_services(self, checker):
        device = Device(ip="10.0.0.7")
        assert checker.check_device(device) == []

"""Core scanner and analyzer classes."""

import logging
import time
from typing import Optional, List
from datetime import datetime

from pynetworkintel.models import ScanResult, Device
from pynetworkintel.discovery import DeviceScanner, SSHConfigGrabber
from pynetworkintel.analysis import RuleChecker, CVEChecker, LLMAnalyzer

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


class Scanner:
    """High-level device discovery scanner."""

    def __init__(
        self,
        nmap_path: str = "nmap",
        ssh_username: str = "root",
        ssh_key_path: Optional[str] = None,
        ssh_password: Optional[str] = None,
    ):
        self.device_scanner = DeviceScanner(nmap_path)
        self.ssh_grabber = SSHConfigGrabber(ssh_username, ssh_key_path, ssh_password)

    def scan(self, target: str, grab_configs: bool = True) -> ScanResult:
        """
        Scan network for devices and gather configuration.

        Args:
            target: IP address, CIDR range, or hostname
            grab_configs: Whether to attempt SSH config grab (requires credentials)

        Returns:
            ScanResult with discovered devices
        """
        start_time = time.time()

        logger.info(f"Starting network scan for {target}")
        devices = self.device_scanner.discover(target)

        if grab_configs and devices:
            logger.info(f"Attempting to grab configs from {len(devices)} devices")
            for device in devices:
                if self.ssh_grabber.grab_configs(device):
                    logger.debug(f"Successfully grabbed configs from {device.ip}")
                else:
                    logger.debug(f"Could not grab configs from {device.ip}")

        duration = time.time() - start_time

        result = ScanResult(devices=devices, scan_duration_seconds=duration)

        logger.info(
            f"Scan complete: {len(devices)} devices in {duration:.1f} seconds"
        )

        return result


class Analyzer:
    """Security analyzer for scan results."""

    def __init__(self, anthropic_api_key: Optional[str] = None):
        self.rule_checker = RuleChecker()
        self.cve_checker = CVEChecker()
        self.llm_analyzer = LLMAnalyzer(anthropic_api_key)

    def analyze(self, scan_result: ScanResult) -> ScanResult:
        """
        Perform full security analysis on scan results.

        Args:
            scan_result: Results from scanner

        Returns:
            Updated ScanResult with findings
        """
        logger.info("Starting security analysis")

        for device in scan_result.devices:
            logger.debug(f"Analyzing device {device.ip}")

            # Check configuration rules
            rule_findings = self.rule_checker.check_device(device)
            scan_result.findings.extend(rule_findings)

            # Check for known CVEs
            cve_findings = self.cve_checker.check_device(device)
            scan_result.findings.extend(cve_findings)

        logger.info(f"Analysis complete: {len(scan_result.findings)} findings")

        return scan_result

    def summarize(self, scan_result: ScanResult) -> str:
        """
        Generate plain English summary of findings.

        Args:
            scan_result: Analyzed scan results

        Returns:
            Plain English summary
        """
        logger.info("Generating AI summary")
        return self.llm_analyzer.summarize_findings(scan_result)

    def get_summary(self, scan_result: ScanResult) -> dict:
        """Get structured summary of findings."""
        return scan_result.summary()


class Pipeline:
    """Full scanning and analysis pipeline."""

    def __init__(
        self,
        nmap_path: str = "nmap",
        ssh_username: str = "root",
        ssh_key_path: Optional[str] = None,
        ssh_password: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
    ):
        self.scanner = Scanner(nmap_path, ssh_username, ssh_key_path, ssh_password)
        self.analyzer = Analyzer(anthropic_api_key)

    def run(self, target: str, grab_configs: bool = True, summarize: bool = False) -> dict:
        """
        Run complete scan and analysis pipeline.

        Args:
            target: Network target to scan
            grab_configs: Whether to grab device configs
            summarize: Whether to generate LLM summary

        Returns:
            Dictionary with results
        """
        logger.info("Starting PyNetworkIntel pipeline")

        # Scan
        scan_result = self.scanner.scan(target, grab_configs)

        # Analyze
        scan_result = self.analyzer.analyze(scan_result)

        result = {
            "devices": [d.to_dict() for d in scan_result.devices],
            "findings": [f.to_dict() for f in scan_result.findings],
            "summary": self.analyzer.get_summary(scan_result),
            "scan_time": scan_result.scan_time.isoformat(),
            "scan_duration_seconds": scan_result.scan_duration_seconds,
        }

        # Generate summary if requested
        if summarize:
            result["ai_summary"] = self.analyzer.summarize(scan_result)

        logger.info("Pipeline complete")

        return result

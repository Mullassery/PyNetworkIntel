"""Configuration rule engine for security analysis."""

import logging
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from pynetworkintel.models import Device, SecurityFinding, Severity, FindingType

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    name: str
    device_type: str
    severity: Severity
    description: str
    recommendation: str
    business_impact: str
    checks: List[Dict[str, Any]]


class RuleChecker:
    """Evaluate configuration rules against devices."""

    def __init__(self):
        self.rules = self._load_default_rules()

    def _load_default_rules(self) -> List[Rule]:
        """Load default security rules."""
        return [
            Rule(
                name="SSH with password authentication enabled",
                device_type="linux",
                severity=Severity.HIGH,
                description="SSH allows password-based login instead of key-only authentication",
                recommendation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, require SSH keys only",
                business_impact="Brute-force attack vulnerability on critical infrastructure",
                checks=[
                    {
                        "config_key": "/etc/ssh/sshd_config",
                        "regex": r"PasswordAuthentication\s+yes",
                    }
                ],
            ),
            Rule(
                name="SSH with weak cipher algorithms",
                device_type="linux",
                severity=Severity.MEDIUM,
                description="SSH is configured with weak encryption ciphers below recommended standards",
                recommendation="Configure strong ciphers in sshd_config: aes256-gcm, aes256-ctr, or stronger",
                business_impact="Encrypted connection could be compromised with advanced attack methods",
                checks=[
                    {
                        "config_key": "/etc/ssh/sshd_config",
                        "regex": r"Ciphers.*aes128",
                    }
                ],
            ),
            Rule(
                name="SSH root login enabled",
                device_type="linux",
                severity=Severity.HIGH,
                description="Direct SSH login as root is allowed, increasing compromise risk",
                recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config, use sudo for elevated access",
                business_impact="Attacker can directly access system with highest privilege if SSH is compromised",
                checks=[
                    {
                        "config_key": "/etc/ssh/sshd_config",
                        "regex": r"PermitRootLogin\s+yes",
                    }
                ],
            ),
            Rule(
                name="Telnet service is accessible",
                device_type="linux",
                severity=Severity.CRITICAL,
                description="Telnet is an unencrypted remote access protocol that transmits passwords in plaintext",
                recommendation="Disable Telnet immediately, use SSH for encrypted remote access",
                business_impact="Credentials and all communication visible to anyone on the network",
                checks=[
                    {
                        "config_key": "/etc/iptables/rules",
                        "regex": r"ACCEPT.*port 23",
                    }
                ],
            ),
            Rule(
                name="FTP service is accessible",
                device_type="linux",
                severity=Severity.CRITICAL,
                description="FTP is an unencrypted file transfer protocol that transmits credentials in plaintext",
                recommendation="Disable FTP, use SFTP or SCP for secure file transfer",
                business_impact="Credentials and file transfers visible to anyone on the network",
                checks=[
                    {
                        "config_key": "/etc/iptables/rules",
                        "regex": r"ACCEPT.*port 21",
                    }
                ],
            ),
            Rule(
                name="Database port exposed to subnet",
                device_type="linux",
                severity=Severity.HIGH,
                description="Database port (MySQL/PostgreSQL) accessible from internal network, not just app servers",
                recommendation="Restrict database access using firewall rules to specific application server IPs only",
                business_impact="Lateral movement risk - any compromised device in subnet can access database",
                checks=[
                    {
                        "config_key": "/etc/iptables/rules",
                        "regex": r"ACCEPT.*sport (3306|5432)",
                    }
                ],
            ),
            Rule(
                name="HTTP access without HTTPS redirect",
                device_type="linux",
                severity=Severity.MEDIUM,
                description="HTTP (port 80) is accessible without automatic redirect to HTTPS",
                recommendation="Configure web server to redirect all HTTP traffic to HTTPS (port 443)",
                business_impact="User credentials or session data could be intercepted if not redirected",
                checks=[
                    {
                        "config_key": "/etc/iptables/rules",
                        "regex": r"ACCEPT.*dport 80",
                    }
                ],
            ),
            Rule(
                name="Firewall allows wide open access",
                device_type="linux",
                severity=Severity.CRITICAL,
                description="Firewall rule allows access from all sources (0.0.0.0/0) to sensitive port",
                recommendation="Restrict firewall rules to specific source IPs or networks only",
                business_impact="Any attacker on the internet can attempt to exploit this port",
                checks=[
                    {
                        "config_key": "/etc/iptables/rules",
                        "regex": r"ACCEPT.*0\.0\.0\.0\/0.*dport (22|3306|5432)",
                    }
                ],
            ),
            Rule(
                name="SNMP with default community string",
                device_type="linux",
                severity=Severity.HIGH,
                description="SNMP is configured with default community strings (public/private)",
                recommendation="Change SNMP community strings to strong, unique values or disable if not needed",
                business_impact="Attackers can query device for system information and configuration details",
                checks=[
                    {
                        "config_key": "/etc/snmp/snmpd.conf",
                        "regex": r"rocommunity\s+(public|private)",
                    }
                ],
            ),
            Rule(
                name="No SSH key-based authentication enforcement",
                device_type="linux",
                severity=Severity.MEDIUM,
                description="SSH allows multiple authentication methods, not strictly key-based",
                recommendation="Configure SSH to use only key-based authentication, disable passwords and other methods",
                business_impact="Reduces effectiveness of SSH key security if weaker auth methods are available",
                checks=[
                    {
                        "config_key": "/etc/ssh/sshd_config",
                        "regex": r"PubkeyAuthentication\s+no|AuthenticationMethods\s+password",
                    }
                ],
            ),
        ]

    def check_device(self, device: Device) -> List[SecurityFinding]:
        """
        Check device against all applicable rules.

        Args:
            device: Device to check

        Returns:
            List of security findings
        """
        findings = []

        for rule in self.rules:
            if rule.device_type not in ("any", device.device_type):
                continue

            if self._rule_matches(device, rule):
                finding = SecurityFinding(
                    device=f"{device.ip} ({device.hostname or 'unknown'})",
                    finding_type=FindingType.CONFIGURATION,
                    severity=rule.severity,
                    title=rule.name,
                    description=rule.description,
                    evidence=self._extract_evidence(device, rule),
                    recommendation=rule.recommendation,
                    business_impact=rule.business_impact,
                )
                findings.append(finding)

        return findings

    def _rule_matches(self, device: Device, rule: Rule) -> bool:
        """Check if device violates any condition in rule."""
        for check in rule.checks:
            if self._check_matches(device, check):
                return True
        return False

    def _check_matches(self, device: Device, check: Dict[str, Any]) -> bool:
        """Evaluate a single check condition against device."""
        config_key = check.get("config_key")
        regex = check.get("regex")

        if not config_key or not regex:
            return False

        for config in device.configs:
            if config.path == config_key:
                if re.search(regex, config.content, re.MULTILINE | re.IGNORECASE):
                    return True

        return False

    def _extract_evidence(self, device: Device, rule: Rule) -> str:
        """Extract matching evidence from device configuration."""
        for check in rule.checks:
            config_key = check.get("config_key")
            regex = check.get("regex")

            if not config_key or not regex:
                continue

            for config in device.configs:
                if config.path == config_key:
                    matches = re.finditer(regex, config.content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        return f"Found in {config_key}: {match.group(0)}"

        return f"Check failed for {rule.name}"

    def add_rule(self, rule: Rule):
        """Add custom rule to checker."""
        self.rules.append(rule)

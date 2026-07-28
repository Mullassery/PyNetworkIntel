"""Compliance framework mapping and reporting."""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ComplianceMapper:
    """Map findings to compliance frameworks."""

    def __init__(self):
        """Initialize compliance mapper."""
        self.compliance_mappings = self._load_compliance_mappings()

    def map_to_pci_dss(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map finding to PCI-DSS requirements."""
        mapped = []

        finding_type = finding.get("type", "").lower()
        severity = finding.get("severity", "").lower()

        if "unencrypted" in finding_type:
            mapped.append({
                "requirement": "PCI-DSS 3.4",
                "control": "Encryption of cardholder data",
                "status": "non_compliant" if severity in ["critical", "high"] else "needs_review",
            })

        if "default_credentials" in finding_type or "weak_auth" in finding_type:
            mapped.append({
                "requirement": "PCI-DSS 2.1",
                "control": "Default security parameters",
                "status": "non_compliant",
            })
            mapped.append({
                "requirement": "PCI-DSS 8.1",
                "control": "User identification",
                "status": "non_compliant",
            })

        if "access_control" in finding_type or "permission" in finding_type:
            mapped.append({
                "requirement": "PCI-DSS 7.1",
                "control": "Limit access to cardholder data",
                "status": "needs_review" if severity == "medium" else "non_compliant",
            })

        return mapped

    def map_to_hipaa(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map finding to HIPAA requirements."""
        mapped = []

        finding_type = finding.get("type", "").lower()
        severity = finding.get("severity", "").lower()

        if "unencrypted" in finding_type:
            mapped.append({
                "requirement": "HIPAA 164.312(a)(2)(i)",
                "control": "Encryption and decryption",
                "status": "non_compliant",
            })

        if "access_control" in finding_type:
            mapped.append({
                "requirement": "HIPAA 164.308(a)(4)(i)",
                "control": "Access management",
                "status": "non_compliant" if severity in ["critical", "high"] else "needs_review",
            })

        if "audit" in finding_type or "logging" in finding_type:
            mapped.append({
                "requirement": "HIPAA 164.312(b)",
                "control": "Audit controls",
                "status": "non_compliant",
            })

        if "malware" in finding_type or "vulnerability" in finding_type:
            mapped.append({
                "requirement": "HIPAA 164.308(a)(5)(ii)(B)",
                "control": "Malware protection",
                "status": "non_compliant",
            })

        return mapped

    def map_to_iso27001(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map finding to ISO 27001 controls."""
        mapped = []

        finding_type = finding.get("type", "").lower()
        severity = finding.get("severity", "").lower()

        if "unencrypted" in finding_type:
            mapped.append({
                "requirement": "ISO 27001 A.10.1.1",
                "control": "Cryptographic controls",
                "status": "non_compliant",
            })

        if "access_control" in finding_type or "authentication" in finding_type:
            mapped.append({
                "requirement": "ISO 27001 A.9.1.1",
                "control": "Access control policy",
                "status": "non_compliant" if severity in ["critical", "high"] else "needs_review",
            })

        if "patch" in finding_type or "vulnerability" in finding_type:
            mapped.append({
                "requirement": "ISO 27001 A.12.6.1",
                "control": "Management of technical vulnerabilities",
                "status": "non_compliant",
            })

        return mapped

    def map_to_cis_controls(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map finding to CIS Controls."""
        mapped = []

        finding_type = finding.get("type", "").lower()

        if "inventory" in finding_type:
            mapped.append({
                "control": "CIS 1",
                "description": "Inventory of Authorized and Unauthorized Devices",
                "status": "needs_action",
            })

        if "vulnerability" in finding_type:
            mapped.append({
                "control": "CIS 7",
                "description": "Continuous Vulnerability Management",
                "status": "needs_action",
            })

        if "access_control" in finding_type or "authentication" in finding_type:
            mapped.append({
                "control": "CIS 5",
                "description": "Account Access Management",
                "status": "needs_action",
            })

        return mapped

    def generate_compliance_report(self, findings: List[Dict[str, Any]], framework: str) -> Dict[str, Any]:
        """Generate compliance report for findings."""
        mapped_findings = []
        compliance_status = {"compliant": 0, "non_compliant": 0, "needs_review": 0}

        for finding in findings:
            if framework.upper() == "PCI-DSS":
                mappings = self.map_to_pci_dss(finding)
            elif framework.upper() == "HIPAA":
                mappings = self.map_to_hipaa(finding)
            elif framework.upper() == "ISO27001":
                mappings = self.map_to_iso27001(finding)
            elif framework.upper() == "CIS":
                mappings = self.map_to_cis_controls(finding)
            else:
                mappings = []

            for mapping in mappings:
                mapped_findings.append({
                    "finding": finding.get("description"),
                    "severity": finding.get("severity"),
                    **mapping,
                })

                status = mapping.get("status", "needs_review")
                compliance_status[status] += 1

        total_issues = sum(compliance_status.values())
        compliance_percentage = (
            (compliance_status["compliant"] / total_issues * 100)
            if total_issues > 0
            else 0
        )

        return {
            "framework": framework,
            "total_mapped_findings": len(mapped_findings),
            "compliance_percentage": compliance_percentage,
            "status_breakdown": compliance_status,
            "recommendations": self._get_framework_recommendations(framework),
            "findings": mapped_findings[:20],  # Return first 20
        }

    def get_remediation_timeline(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate remediation timeline based on severity and compliance."""
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]

        return {
            "immediate_30_days": {
                "critical_findings": len(critical),
                "action": "Address all critical findings",
                "target_date": "Within 30 days",
            },
            "short_term_90_days": {
                "high_findings": len(high),
                "action": "Address all high-severity findings",
                "target_date": "Within 90 days",
            },
            "medium_term_6_months": {
                "medium_findings": len(medium),
                "action": "Address all medium-severity findings",
                "target_date": "Within 6 months",
            },
        }

    @staticmethod
    def _load_compliance_mappings() -> Dict[str, Dict[str, List[str]]]:
        """Load compliance framework mappings."""
        return {
            "pci_dss": {
                "encryption": ["3.4", "4.1"],
                "access_control": ["7.1", "7.2"],
                "authentication": ["2.1", "8.1"],
            },
            "hipaa": {
                "encryption": ["164.312(a)(2)(i)"],
                "access_control": ["164.308(a)(4)(i)"],
                "audit": ["164.312(b)"],
            },
            "iso27001": {
                "encryption": ["A.10.1.1"],
                "access_control": ["A.9.1.1"],
                "vulnerability": ["A.12.6.1"],
            },
        }

    @staticmethod
    def _get_framework_recommendations(framework: str) -> List[str]:
        """Get recommendations for compliance framework."""
        recommendations = {
            "pci_dss": [
                "Implement encryption for data in transit and at rest",
                "Maintain secure authentication mechanisms",
                "Conduct regular security assessments",
                "Implement and maintain a firewall",
                "Protect cardholder data",
            ],
            "hipaa": [
                "Implement HIPAA-compliant encryption",
                "Maintain audit logs for all access",
                "Implement workforce security measures",
                "Conduct periodic risk assessments",
                "Document all security policies",
            ],
            "iso27001": [
                "Establish information security governance",
                "Implement access control policies",
                "Maintain asset inventory",
                "Conduct vulnerability assessments",
                "Implement incident response procedures",
            ],
            "cis": [
                "Maintain inventory of authorized assets",
                "Implement secure configurations",
                "Conduct regular vulnerability scans",
                "Implement access control measures",
                "Monitor and respond to security events",
            ],
        }

        return recommendations.get(framework.lower(), [
            "Review framework requirements",
            "Conduct gap analysis",
            "Implement remediation plan",
        ])

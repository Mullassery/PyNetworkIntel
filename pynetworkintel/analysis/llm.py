"""LLM-powered analysis and summarization using Claude."""

import logging
import json
from typing import Optional
from anthropic import Anthropic

from pynetworkintel.models import ScanResult, SecurityFinding, Severity

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """Use Claude to synthesize findings and provide business-focused analysis."""

    def __init__(self, api_key: Optional[str] = None):
        self.client = Anthropic(api_key=api_key)
        self.model = "claude-3-5-sonnet-20241022"

    def summarize_findings(self, scan_result: ScanResult) -> str:
        """
        Synthesize security findings into plain English summary.

        Args:
            scan_result: Scan results with devices and findings

        Returns:
            AI-generated plain English summary
        """
        if not scan_result.findings:
            return self._generate_empty_summary(scan_result)

        prompt = self._build_summary_prompt(scan_result)

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"LLM summarization failed: {e}")
            return self._generate_fallback_summary(scan_result)

    def _build_summary_prompt(self, scan_result: ScanResult) -> str:
        """Build prompt for LLM analysis."""
        findings_json = json.dumps(
            [f.to_dict() for f in scan_result.findings],
            indent=2,
            default=str,
        )

        devices_json = json.dumps(
            [d.to_dict() for d in scan_result.devices],
            indent=2,
        )

        return f"""You are a network security analyst explaining findings to an electronics/IoT engineer who doesn't understand networking jargon.

NETWORK SCAN RESULTS:
{devices_json}

SECURITY FINDINGS:
{findings_json}

Please provide a clear, non-technical summary:

1. **OVERVIEW** (1-2 sentences): Is the network generally healthy or are there problems?

2. **TOP 3 THINGS TO FIX** (in priority order):
   - For each: What is it? Why does it matter? How to fix it? Time required?

3. **WHAT'S GOOD** (if anything):
   - List positive findings

4. **QUESTIONS TO ASK YOUR TEAM**:
   - What questions should they investigate?

Keep language simple. Use analogies to hardware/electronics when possible. No networking jargon. Explain WHY each issue matters for business/security/reliability."""

    def _generate_empty_summary(self, scan_result: ScanResult) -> str:
        """Generate summary when no findings detected."""
        summary = f"""✅ NETWORK HEALTH CHECK - NO ISSUES DETECTED

Devices Found: {scan_result.summary()['total_devices']}
Online: {scan_result.summary()['online_devices']}
Critical Issues: 0
High Priority Issues: 0

Good news! Your network scan didn't find any major security problems. Everything looks secure and properly configured.

However, you should:
- Continue monitoring regularly (weekly or monthly scans)
- Keep software updated when new versions are released
- Review access rules periodically
"""
        return summary

    def _generate_fallback_summary(self, scan_result: ScanResult) -> str:
        """Fallback summary if LLM fails."""
        summary = scan_result.summary()
        critical = summary["critical_findings"]
        high = summary["high_findings"]

        output = f"""NETWORK SECURITY SUMMARY

Devices Discovered: {summary['total_devices']}
Online Devices: {summary['online_devices']}

ISSUES FOUND:
- Critical Issues: {critical}
- High Priority Issues: {high}
- Total Issues: {summary['total_findings']}

TOP ISSUES:
"""

        # Sort findings by severity
        sorted_findings = sorted(
            scan_result.findings,
            key=lambda f: (
                0 if f.severity == Severity.CRITICAL
                else 1 if f.severity == Severity.HIGH
                else 2 if f.severity == Severity.MEDIUM
                else 3
            ),
        )

        for i, finding in enumerate(sorted_findings[:3], 1):
            output += f"""
{i}. {finding.title}
   Device: {finding.device}
   Why it matters: {finding.business_impact}
   How to fix: {finding.recommendation}
"""

        return output

    def explain_finding(self, finding: SecurityFinding) -> str:
        """
        Explain a single finding in plain English.

        Args:
            finding: Security finding to explain

        Returns:
            Plain English explanation
        """
        prompt = f"""Explain this security finding to an electronics engineer in simple terms.
No networking jargon. Use hardware/electronics analogies when helpful.

FINDING: {finding.title}
DEVICE: {finding.device}
DESCRIPTION: {finding.description}
EVIDENCE: {finding.evidence}
IMPACT: {finding.business_impact}
RECOMMENDATION: {finding.recommendation}

Please explain:
1. What is this in simple terms?
2. Why should they care?
3. How to fix it (step by step if possible)?
4. How long does it take to fix?"""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return (
                f"{finding.title}\n\n"
                f"Why it matters: {finding.business_impact}\n\n"
                f"How to fix: {finding.recommendation}"
            )

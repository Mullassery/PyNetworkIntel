"""CI/CD pipeline security scanning."""
from typing import Dict, List, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)


class CICDPipelineScanner:
    """Scan CI/CD pipelines for security issues."""

    def __init__(self):
        """Initialize CI/CD scanner."""
        self.pipelines: List[Dict[str, Any]] = []

    def scan_github_actions(self, workflow_content: str) -> Dict[str, Any]:
        """Scan GitHub Actions workflow for security issues."""
        issues = []

        # Check for unsafe use of secrets
        if re.search(r'secrets\.\w+.*echo|print|log', workflow_content):
            issues.append({
                "type": "secret_exposure",
                "severity": "critical",
                "description": "Secrets may be logged to console",
                "line": self._find_line_number(workflow_content, r'secrets\.\w+'),
            })

        # Check for untrusted input in shell commands
        if re.search(r'\$\{\{\s*github\.event\.pull_request\.title', workflow_content):
            issues.append({
                "type": "command_injection",
                "severity": "high",
                "description": "User input from PR title may be used in shell command",
            })

        # Check for pinned actions (unpinned = security risk)
        if re.search(r'uses:\s*[\w-]+/[\w-]+@main|@master', workflow_content):
            issues.append({
                "type": "unpinned_action",
                "severity": "medium",
                "description": "Actions should be pinned to specific commits, not branches",
            })

        # Check for permissions
        if not re.search(r'permissions:', workflow_content):
            issues.append({
                "type": "overly_permissive",
                "severity": "high",
                "description": "Workflow does not specify permissions (defaults to all)",
            })

        return {
            "workflow": "GitHub Actions",
            "total_issues": len(issues),
            "issues": issues,
            "recommendations": self._get_cicd_recommendations(),
        }

    def scan_gitlab_ci(self, gitlab_ci_content: str) -> Dict[str, Any]:
        """Scan GitLab CI configuration for security issues."""
        issues = []

        # Check for exposed variables
        if "expose_as_env_vars: true" in gitlab_ci_content:
            issues.append({
                "type": "exposed_variables",
                "severity": "high",
                "description": "Environment variables exposed as artifacts",
            })

        # Check for artifacts containing sensitive files
        if re.search(r'artifacts:.*\.env|\.config|credentials', gitlab_ci_content):
            issues.append({
                "type": "sensitive_artifacts",
                "severity": "critical",
                "description": "Artifacts may contain sensitive configuration files",
            })

        # Check for unprotected deployments
        if not re.search(r'environment:\s*name:\s*\w+', gitlab_ci_content):
            issues.append({
                "type": "no_environment_protection",
                "severity": "medium",
                "description": "Deployments should target protected environments",
            })

        return {
            "pipeline": "GitLab CI",
            "total_issues": len(issues),
            "issues": issues,
            "recommendations": self._get_cicd_recommendations(),
        }

    def scan_jenkins_pipeline(self, jenkinsfile_content: str) -> Dict[str, Any]:
        """Scan Jenkinsfile for security issues."""
        issues = []

        # Check for hardcoded credentials
        if re.search(r'password\s*=\s*["\']', jenkinsfile_content):
            issues.append({
                "type": "hardcoded_credentials",
                "severity": "critical",
                "description": "Credentials hardcoded in Jenkinsfile",
            })

        # Check for unsafe shell steps
        if re.search(r'sh\s+["\'].*\$\{BUILD_', jenkinsfile_content):
            issues.append({
                "type": "build_variable_injection",
                "severity": "high",
                "description": "Build variables may be subject to injection attacks",
            })

        # Check for missing credential binding
        if "withCredentials" not in jenkinsfile_content and "credentials" in jenkinsfile_content:
            issues.append({
                "type": "missing_credential_binding",
                "severity": "high",
                "description": "Credentials not properly bound to steps",
            })

        return {
            "pipeline": "Jenkins",
            "total_issues": len(issues),
            "issues": issues,
            "recommendations": self._get_cicd_recommendations(),
        }

    def detect_supply_chain_risks(self, pipeline_config: Dict[str, Any]) -> Dict[str, Any]:
        """Detect supply chain attack risks."""
        risks = []

        # Check for external dependencies
        dependencies = pipeline_config.get("dependencies", [])
        for dep in dependencies:
            if not self._is_trusted_package(dep):
                risks.append({
                    "type": "untrusted_dependency",
                    "dependency": dep,
                    "severity": "high",
                    "recommendation": "Verify package source and maintainer",
                })

        # Check for external container images
        images = pipeline_config.get("container_images", [])
        for image in images:
            if not self._is_official_image(image):
                risks.append({
                    "type": "untrusted_image",
                    "image": image,
                    "severity": "high",
                    "recommendation": "Use official or trusted registry images",
                })

        return {
            "supply_chain_risks": len(risks),
            "risks": risks,
            "recommendation": "Implement artifact attestation and SBOM verification",
        }

    def generate_hardening_recommendations(self) -> List[str]:
        """Generate CI/CD hardening recommendations."""
        return [
            "Enable branch protection rules",
            "Require signed commits for merges",
            "Implement automated security scanning",
            "Use short-lived credentials with automatic rotation",
            "Enable audit logging for all pipeline executions",
            "Implement approval gates for production deployments",
            "Scan container images before deployment",
            "Implement infrastructure as code scanning",
            "Enable SAST (static application security testing)",
            "Use dependency scanning tools",
        ]

    @staticmethod
    def _find_line_number(content: str, pattern: str) -> int:
        """Find line number of pattern in content."""
        for i, line in enumerate(content.split('\n'), 1):
            if re.search(pattern, line):
                return i
        return 0

    @staticmethod
    def _get_cicd_recommendations() -> List[str]:
        """Get CICD security recommendations."""
        return [
            "Use hardened runner images with minimal attack surface",
            "Implement secret scanning to prevent credential leaks",
            "Require MFA for deployments",
            "Use OIDC for cloud authentication (no long-lived credentials)",
            "Implement SBOM (Software Bill of Materials) generation",
            "Scan all artifacts for vulnerabilities",
            "Use minimal container base images",
        ]

    @staticmethod
    def _is_trusted_package(package_name: str) -> bool:
        """Check if package is from trusted source."""
        trusted_sources = ["official", "verified", "signed"]
        return any(source in package_name.lower() for source in trusted_sources)

    @staticmethod
    def _is_official_image(image_name: str) -> bool:
        """Check if container image is official."""
        official_registries = ["docker.io/library", "gcr.io/distroless", "amazon/aws-lambda"]
        return any(reg in image_name for reg in official_registries)

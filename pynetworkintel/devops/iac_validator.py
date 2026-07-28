"""Infrastructure as Code validation and security scanning."""
from typing import Dict, List, Any, Optional
import json
import logging
import re

logger = logging.getLogger(__name__)


class IaCValidator:
    """Validate Infrastructure as Code for security misconfigurations."""

    def __init__(self):
        """Initialize IaC validator."""
        self.findings: List[Dict[str, Any]] = []

    def validate_terraform(self, tf_content: str) -> Dict[str, Any]:
        """Validate Terraform configuration."""
        issues = []

        # Check for exposed database passwords
        if re.search(r'password\s*=\s*["\']{1}[^"\']*["\']{1}', tf_content):
            issues.append({
                "type": "hardcoded_secret",
                "severity": "critical",
                "resource": "database",
                "description": "Database password is hardcoded",
                "recommendation": "Use Terraform variables or secrets management",
            })

        # Check for public S3 buckets
        if re.search(r'acl\s*=\s*"public-read"', tf_content):
            issues.append({
                "type": "public_bucket",
                "severity": "critical",
                "resource": "S3",
                "description": "S3 bucket is publicly readable",
                "recommendation": "Use 'private' ACL and implement bucket policies",
            })

        # Check for unencrypted storage
        if re.search(r'encrypted\s*=\s*false', tf_content):
            issues.append({
                "type": "unencrypted_storage",
                "severity": "high",
                "resource": "storage",
                "description": "Storage is not encrypted",
                "recommendation": "Enable encryption at rest",
            })

        # Check for security group with 0.0.0.0/0
        if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', tf_content):
            issues.append({
                "type": "overly_permissive_sg",
                "severity": "high",
                "resource": "security_group",
                "description": "Security group allows all ingress traffic",
                "recommendation": "Restrict to specific CIDR blocks",
            })

        # Check for missing MFA
        if re.search(r'mfa_delete\s*=\s*false', tf_content):
            issues.append({
                "type": "missing_mfa",
                "severity": "medium",
                "resource": "S3",
                "description": "MFA delete is not enabled",
                "recommendation": "Enable MFA delete for critical buckets",
            })

        return {
            "iac_tool": "Terraform",
            "total_issues": len(issues),
            "issues": issues,
            "compliance_score": 100 - (len(issues) * 10),
        }

    def validate_cloudformation(self, cf_content: str) -> Dict[str, Any]:
        """Validate CloudFormation template."""
        issues = []

        try:
            if cf_content.startswith('{'):
                template = json.loads(cf_content)
            else:
                import yaml
                template = yaml.safe_load(cf_content)
        except:
            return {"error": "Failed to parse CloudFormation template"}

        resources = template.get("Resources", {})

        for resource_name, resource_config in resources.items():
            resource_type = resource_config.get("Type", "")
            properties = resource_config.get("Properties", {})

            # Check RDS for encryption
            if "RDS" in resource_type and not properties.get("StorageEncrypted"):
                issues.append({
                    "type": "unencrypted_database",
                    "severity": "high",
                    "resource": resource_name,
                    "description": "RDS instance is not encrypted",
                })

            # Check S3 for public access
            if "S3" in resource_type and properties.get("PublicAccessBlockConfiguration", {}).get("BlockPublicAcls") is False:
                issues.append({
                    "type": "public_s3_bucket",
                    "severity": "critical",
                    "resource": resource_name,
                    "description": "S3 bucket allows public ACLs",
                })

            # Check for ingress from 0.0.0.0/0
            if "SecurityGroup" in resource_type:
                ingress_rules = properties.get("SecurityGroupIngress", [])
                for rule in ingress_rules:
                    if rule.get("CidrIp") == "0.0.0.0/0":
                        issues.append({
                            "type": "overly_permissive_sg",
                            "severity": "high",
                            "resource": resource_name,
                            "description": "Security group allows all ingress",
                        })

        return {
            "iac_tool": "CloudFormation",
            "total_issues": len(issues),
            "issues": issues,
            "compliance_score": 100 - (len(issues) * 10),
        }

    def validate_kubernetes_manifests(self, manifest_content: str) -> Dict[str, Any]:
        """Validate Kubernetes manifests."""
        issues = []

        try:
            import yaml
            manifests = list(yaml.safe_load_all(manifest_content))
        except:
            return {"error": "Failed to parse Kubernetes manifests"}

        for manifest in manifests:
            if not manifest:
                continue

            kind = manifest.get("kind", "")
            spec = manifest.get("spec", {})

            # Check Pod Security Policy
            if kind == "Pod":
                containers = spec.get("containers", [])
                for container in containers:
                    # Check for privileged mode
                    sec_context = container.get("securityContext", {})
                    if sec_context.get("privileged"):
                        issues.append({
                            "type": "privileged_container",
                            "severity": "critical",
                            "resource": manifest.get("metadata", {}).get("name"),
                            "description": "Container runs in privileged mode",
                        })

                    # Check for read-only filesystem
                    if not sec_context.get("readOnlyRootFilesystem"):
                        issues.append({
                            "type": "writable_filesystem",
                            "severity": "medium",
                            "resource": container.get("name"),
                            "description": "Root filesystem is writable",
                        })

                    # Check for resource limits
                    if not container.get("resources", {}).get("limits"):
                        issues.append({
                            "type": "no_resource_limits",
                            "severity": "medium",
                            "resource": container.get("name"),
                            "description": "No resource limits defined",
                        })

            # Check for NetworkPolicy
            if kind == "Deployment" and not self._has_network_policy(manifest_content):
                issues.append({
                    "type": "missing_network_policy",
                    "severity": "medium",
                    "resource": manifest.get("metadata", {}).get("name"),
                    "description": "No network policy defined",
                })

        return {
            "iac_tool": "Kubernetes",
            "total_issues": len(issues),
            "issues": issues,
            "compliance_score": 100 - (len(issues) * 10),
        }

    def validate_docker_compose(self, compose_content: str) -> Dict[str, Any]:
        """Validate Docker Compose configuration."""
        issues = []

        try:
            import yaml
            compose = yaml.safe_load(compose_content)
        except:
            return {"error": "Failed to parse Docker Compose"}

        services = compose.get("services", {})

        for service_name, service_config in services.items():
            # Check for privileged mode
            if service_config.get("privileged"):
                issues.append({
                    "type": "privileged_container",
                    "severity": "critical",
                    "service": service_name,
                    "description": "Service runs in privileged mode",
                })

            # Check for host port binding
            ports = service_config.get("ports", [])
            for port in ports:
                if isinstance(port, str) and ":" in port:
                    host_port = port.split(":")[0]
                    if host_port == "0.0.0.0" or not host_port.startswith("127"):
                        issues.append({
                            "type": "public_port_binding",
                            "severity": "high",
                            "service": service_name,
                            "port": port,
                            "description": "Service exposes port publicly",
                        })

            # Check for environment secrets
            environment = service_config.get("environment", {})
            for key, value in environment.items():
                if any(secret in key.lower() for secret in ["password", "secret", "token", "key"]):
                    issues.append({
                        "type": "hardcoded_secret",
                        "severity": "critical",
                        "service": service_name,
                        "variable": key,
                        "description": "Secret hardcoded in environment",
                    })

        return {
            "iac_tool": "Docker Compose",
            "total_issues": len(issues),
            "issues": issues,
            "compliance_score": 100 - (len(issues) * 10),
        }

    def generate_remediation_plan(self, validation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate remediation plan from validation results."""
        issues = validation_results.get("issues", [])

        # Group by severity
        critical = [i for i in issues if i.get("severity") == "critical"]
        high = [i for i in issues if i.get("severity") == "high"]
        medium = [i for i in issues if i.get("severity") == "medium"]

        plan = []

        if critical:
            plan.append({
                "priority": 1,
                "severity": "Critical",
                "count": len(critical),
                "action": "Fix immediately before deployment",
                "issues": critical,
            })

        if high:
            plan.append({
                "priority": 2,
                "severity": "High",
                "count": len(high),
                "action": "Fix before production deployment",
                "issues": high,
            })

        if medium:
            plan.append({
                "priority": 3,
                "severity": "Medium",
                "count": len(medium),
                "action": "Fix in next update cycle",
                "issues": medium,
            })

        return plan

    @staticmethod
    def _has_network_policy(manifest_content: str) -> bool:
        """Check if manifest includes NetworkPolicy."""
        return "kind: NetworkPolicy" in manifest_content or "kind: NetworkPolicy" in manifest_content

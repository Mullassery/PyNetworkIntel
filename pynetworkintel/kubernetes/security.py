"""Container and workload security analysis for Kubernetes."""
from typing import Dict, List, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)


class ContainerSecurityAnalyzer:
    """Analyze container security configurations in Kubernetes workloads."""

    def __init__(self):
        """Initialize container security analyzer."""
        try:
            from kubernetes import client
            self.client = client
            self._initialized = False
        except ImportError:
            self._initialized = False

    def _initialize_client(self):
        """Initialize Kubernetes client."""
        if self._initialized:
            return

        try:
            self.v1 = self.client.CoreV1Api()
            self.apps_v1 = self.client.AppsV1Api()
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")

    def analyze_pod_security(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Analyze pod security contexts."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        security_issues = []
        try:
            if namespace:
                pod_list = self.v1.list_namespaced_pod(namespace)
            else:
                pod_list = self.v1.list_pod_for_all_namespaces()

            for pod in pod_list.items:
                issues = self._check_pod_security(pod)
                if issues:
                    security_issues.append({
                        "namespace": pod.metadata.namespace,
                        "pod_name": pod.metadata.name,
                        "issues": issues,
                        "risk_score": self._calculate_pod_risk(issues),
                    })
        except Exception as e:
            logger.error(f"Failed to analyze pod security: {e}")

        return security_issues

    def scan_container_images(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan container images for vulnerabilities."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        images = []
        try:
            if namespace:
                pod_list = self.v1.list_namespaced_pod(namespace)
            else:
                pod_list = self.v1.list_pod_for_all_namespaces()

            seen_images = set()

            for pod in pod_list.items:
                for container in (pod.spec.containers or []):
                    image = container.image
                    if image not in seen_images:
                        seen_images.add(image)
                        images.append({
                            "image": image,
                            "issues": self._check_image(image),
                            "risk_level": self._assess_image_risk(image),
                        })
        except Exception as e:
            logger.error(f"Failed to scan container images: {e}")

        return images

    def find_privileged_containers(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Find privileged containers."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        privileged = []
        try:
            if namespace:
                pod_list = self.v1.list_namespaced_pod(namespace)
            else:
                pod_list = self.v1.list_pod_for_all_namespaces()

            for pod in pod_list.items:
                for i, container in enumerate(pod.spec.containers or []):
                    if container.security_context and container.security_context.privileged:
                        privileged.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": container.image,
                        })
        except Exception as e:
            logger.error(f"Failed to find privileged containers: {e}")

        return privileged

    def find_containers_running_as_root(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Find containers running as root."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        root_containers = []
        try:
            if namespace:
                pod_list = self.v1.list_namespaced_pod(namespace)
            else:
                pod_list = self.v1.list_pod_for_all_namespaces()

            for pod in pod_list.items:
                for container in (pod.spec.containers or []):
                    sec_ctx = container.security_context
                    runs_as_root = True

                    if sec_ctx and sec_ctx.run_as_user is not None:
                        runs_as_root = sec_ctx.run_as_user == 0

                    if runs_as_root:
                        root_containers.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": container.image,
                        })
        except Exception as e:
            logger.error(f"Failed to find root containers: {e}")

        return root_containers

    def check_resource_limits(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check if containers have resource limits defined."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        issues = []
        try:
            if namespace:
                pod_list = self.v1.list_namespaced_pod(namespace)
            else:
                pod_list = self.v1.list_pod_for_all_namespaces()

            for pod in pod_list.items:
                for container in (pod.spec.containers or []):
                    if not container.resources or not container.resources.limits:
                        issues.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "issue": "No resource limits defined",
                        })
        except Exception as e:
            logger.error(f"Failed to check resource limits: {e}")

        return issues

    def get_security_summary(self) -> Dict[str, Any]:
        """Get comprehensive security summary."""
        pod_issues = self.analyze_pod_security()
        images = self.scan_container_images()
        privileged = self.find_privileged_containers()
        root_containers = self.find_containers_running_as_root()
        resource_issues = self.check_resource_limits()

        critical_issues = 0
        critical_issues += len(privileged)
        critical_issues += len(root_containers)
        critical_issues += sum(1 for img in images if img.get('risk_level') == 'critical')

        return {
            "total_pods_analyzed": len(pod_issues),
            "total_images_scanned": len(images),
            "critical_issues": critical_issues,
            "privileged_containers": len(privileged),
            "root_containers": len(root_containers),
            "missing_resource_limits": len(resource_issues),
            "recommendations": [
                "Remove privileged mode unless absolutely necessary",
                "Run containers as non-root users",
                "Define resource requests and limits",
                "Use read-only file systems where possible",
                "Implement network policies",
                "Scan images for vulnerabilities",
            ],
        }

    @staticmethod
    def _check_pod_security(pod) -> List[str]:
        """Check pod security context."""
        issues = []
        spec = pod.spec

        if spec.security_context is None or not spec.security_context.fs_group:
            issues.append("No fsGroup defined in pod security context")

        if spec.security_context and spec.security_context.run_as_user == 0:
            issues.append("Pod runs as root")

        for container in (spec.containers or []):
            if not container.security_context:
                issues.append(f"Container {container.name} has no security context")
            elif not container.security_context.read_only_root_filesystem:
                issues.append(f"Container {container.name} has writable root filesystem")

        return issues

    @staticmethod
    def _calculate_pod_risk(issues: List[str]) -> float:
        """Calculate risk score for a pod."""
        risk_score = 0.0

        for issue in issues:
            if "root" in issue.lower():
                risk_score += 30
            elif "writable" in issue.lower():
                risk_score += 20
            elif "security context" in issue.lower():
                risk_score += 15

        return min(risk_score, 100)

    @staticmethod
    def _check_image(image: str) -> List[str]:
        """Check container image for security issues."""
        issues = []

        # Check for 'latest' tag (risky)
        if image.endswith(":latest") or ":" not in image:
            issues.append("Image uses 'latest' or no version tag")

        # Check for official images
        if "/" not in image or image.startswith("docker.io"):
            issues.append("Using official/public image without company registry")

        # Check for old images
        if "ubuntu:14" in image or "centos:6" in image or "debian:7" in image:
            issues.append("Image uses outdated base OS")

        return issues

    @staticmethod
    def _assess_image_risk(image: str) -> str:
        """Assess risk level of container image."""
        risk_score = 0

        if image.endswith(":latest") or ":" not in image:
            risk_score += 30

        if "ubuntu:14" in image or "centos:6" in image or "debian:7" in image:
            risk_score += 40

        if "/" not in image or image.startswith("docker.io"):
            risk_score += 20

        if risk_score >= 50:
            return "high"
        elif risk_score >= 20:
            return "medium"
        else:
            return "low"

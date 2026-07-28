"""Kubernetes RBAC (Role-Based Access Control) analysis."""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class RBACAnalyzer:
    """Analyze Kubernetes RBAC policies and identify security issues."""

    def __init__(self):
        """Initialize RBAC analyzer."""
        try:
            from kubernetes import client
            self.client = client
            self._initialized = False
        except ImportError:
            self._initialized = False
            logger.warning("Kubernetes client not installed")

    def _initialize_client(self):
        """Initialize Kubernetes RBAC client."""
        if self._initialized:
            return

        try:
            self.rbac_v1 = self.client.RbacAuthorizationV1Api()
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize RBAC client: {e}")

    def analyze_roles(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Analyze roles and identify overprivileged roles."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        roles = []
        try:
            if namespace:
                role_list = self.rbac_v1.list_namespaced_role(namespace)
            else:
                role_list = self.rbac_v1.list_role_for_all_namespaces()

            for role in role_list.items:
                permissions = self._extract_permissions(role.rules)
                risk_score = self._calculate_role_risk(permissions)

                roles.append({
                    "name": role.metadata.name,
                    "namespace": role.metadata.namespace,
                    "permissions": permissions,
                    "risk_score": risk_score,
                    "risk_level": self._get_risk_level(risk_score),
                    "recommendations": self._get_role_recommendations(permissions),
                })
        except Exception as e:
            logger.error(f"Failed to analyze roles: {e}")

        return roles

    def analyze_cluster_roles(self) -> List[Dict[str, Any]]:
        """Analyze cluster-wide roles."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        roles = []
        try:
            for role in self.rbac_v1.list_cluster_role().items:
                permissions = self._extract_permissions(role.rules)
                risk_score = self._calculate_role_risk(permissions)

                roles.append({
                    "name": role.metadata.name,
                    "type": "cluster_role",
                    "permissions": permissions,
                    "risk_score": risk_score,
                    "risk_level": self._get_risk_level(risk_score),
                    "recommendations": self._get_role_recommendations(permissions),
                })
        except Exception as e:
            logger.error(f"Failed to analyze cluster roles: {e}")

        return roles

    def analyze_role_bindings(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Analyze role bindings and identify risky assignments."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        bindings = []
        try:
            if namespace:
                binding_list = self.rbac_v1.list_namespaced_role_binding(namespace)
            else:
                binding_list = self.rbac_v1.list_role_binding_for_all_namespaces()

            for binding in binding_list.items:
                subjects = []
                for subject in (binding.subjects or []):
                    subjects.append({
                        "kind": subject.kind,
                        "name": subject.name,
                        "namespace": subject.namespace,
                    })

                bindings.append({
                    "name": binding.metadata.name,
                    "namespace": binding.metadata.namespace,
                    "role": binding.role_ref.name,
                    "subjects": subjects,
                    "risk_level": self._assess_binding_risk(subjects),
                })
        except Exception as e:
            logger.error(f"Failed to analyze role bindings: {e}")

        return bindings

    def analyze_cluster_role_bindings(self) -> List[Dict[str, Any]]:
        """Analyze cluster-wide role bindings."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        bindings = []
        try:
            for binding in self.rbac_v1.list_cluster_role_binding().items:
                subjects = []
                for subject in (binding.subjects or []):
                    subjects.append({
                        "kind": subject.kind,
                        "name": subject.name,
                        "namespace": subject.namespace,
                    })

                bindings.append({
                    "name": binding.metadata.name,
                    "role": binding.role_ref.name,
                    "subjects": subjects,
                    "risk_level": self._assess_binding_risk(subjects),
                })
        except Exception as e:
            logger.error(f"Failed to analyze cluster role bindings: {e}")

        return bindings

    def find_overprivileged_service_accounts(self) -> List[Dict[str, Any]]:
        """Find service accounts with excessive permissions."""
        # This would combine role analysis and binding analysis
        # Implementation depends on gathering all roles and bindings first
        return []

    def get_rbac_summary(self) -> Dict[str, Any]:
        """Get RBAC security summary."""
        roles = self.analyze_roles()
        cluster_roles = self.analyze_cluster_roles()

        high_risk = sum(1 for r in roles if r.get('risk_level') == 'high')
        high_risk += sum(1 for r in cluster_roles if r.get('risk_level') == 'high')

        return {
            "total_roles": len(roles),
            "total_cluster_roles": len(cluster_roles),
            "high_risk_roles": high_risk,
            "recommendations": [
                "Review roles with wildcard permissions",
                "Implement least privilege principle",
                "Audit service account permissions",
                "Use network policies alongside RBAC",
            ],
        }

    @staticmethod
    def _extract_permissions(rules) -> List[Dict[str, Any]]:
        """Extract permissions from role rules."""
        permissions = []

        for rule in (rules or []):
            permission = {
                "api_groups": rule.api_groups or ["*"],
                "resources": rule.resources or [],
                "verbs": rule.verbs or [],
                "resource_names": rule.resource_names or [],
            }
            permissions.append(permission)

        return permissions

    @staticmethod
    def _calculate_role_risk(permissions: List[Dict]) -> float:
        """Calculate risk score for a role (0-100)."""
        risk_score = 0.0

        for perm in permissions:
            # Wildcard resources
            if "*" in perm.get("resources", []):
                risk_score += 30

            # Wildcard verbs
            if "*" in perm.get("verbs", []):
                risk_score += 30

            # Wildcard API groups
            if "*" in perm.get("api_groups", []):
                risk_score += 20

            # Critical resources
            critical = ["secrets", "clusterroles", "clusterrolebindings", "configmaps"]
            if any(r in critical for r in perm.get("resources", [])):
                risk_score += 15

            # Dangerous verbs
            dangerous = ["*", "create", "delete", "deletecollection"]
            if any(v in dangerous for v in perm.get("verbs", [])):
                risk_score += 10

        return min(risk_score, 100)

    @staticmethod
    def _get_risk_level(risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 70:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 30:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _get_role_recommendations(permissions: List[Dict]) -> List[str]:
        """Get recommendations for role improvements."""
        recommendations = []

        for perm in permissions:
            if "*" in perm.get("resources", []):
                recommendations.append("Specify specific resources instead of wildcards")

            if "*" in perm.get("verbs", []):
                recommendations.append("Limit verbs to only what's necessary (get, list, watch, etc.)")

            if "secrets" in perm.get("resources", []):
                recommendations.append("Restrict access to secrets - consider using sealed-secrets or external-secrets")

        return list(set(recommendations))[:3]  # Return top 3 unique recommendations

    @staticmethod
    def _assess_binding_risk(subjects: List[Dict]) -> str:
        """Assess risk of role binding based on subjects."""
        for subject in subjects:
            # system:unauthenticated is extremely risky
            if subject.get("name") == "system:unauthenticated":
                return "critical"

            # system:anonymous is also risky
            if subject.get("name") == "system:anonymous":
                return "high"

            # Default service account
            if subject.get("name") == "default":
                return "medium"

        return "low"

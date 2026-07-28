"""Kubernetes network policy analysis."""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class NetworkPolicyAnalyzer:
    """Analyze Kubernetes network policies and identify gaps."""

    def __init__(self):
        """Initialize network policy analyzer."""
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
            self.networking_v1 = self.client.NetworkingV1Api()
            self.v1 = self.client.CoreV1Api()
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")

    def analyze_network_policies(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Analyze network policies."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        policies = []
        try:
            if namespace:
                policy_list = self.networking_v1.list_namespaced_network_policy(namespace)
            else:
                policy_list = self.networking_v1.list_network_policy_for_all_namespaces()

            for policy in policy_list.items:
                ingress_rules = self._extract_ingress_rules(policy.spec.ingress)
                egress_rules = self._extract_egress_rules(policy.spec.egress)

                policies.append({
                    "namespace": policy.metadata.namespace,
                    "name": policy.metadata.name,
                    "pod_selector": policy.spec.pod_selector.match_labels if policy.spec.pod_selector else {},
                    "ingress_rules": ingress_rules,
                    "egress_rules": egress_rules,
                    "policy_types": policy.spec.policy_types or ["Ingress"],
                })
        except Exception as e:
            logger.error(f"Failed to analyze network policies: {e}")

        return policies

    def find_namespaces_without_policies(self) -> List[Dict[str, Any]]:
        """Find namespaces without network policies."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        vulnerable_namespaces = []
        try:
            for namespace in self.v1.list_namespace().items:
                ns_name = namespace.metadata.name

                # Skip kube-system and other system namespaces
                if ns_name.startswith("kube-"):
                    continue

                try:
                    policy_list = self.networking_v1.list_namespaced_network_policy(ns_name)
                    if not policy_list.items:
                        vulnerable_namespaces.append({
                            "namespace": ns_name,
                            "policies": 0,
                            "risk": "high",
                            "recommendation": "Implement network policies for pod-to-pod communication control",
                        })
                except:
                    pass
        except Exception as e:
            logger.error(f"Failed to find unprotected namespaces: {e}")

        return vulnerable_namespaces

    def find_overly_permissive_policies(self) -> List[Dict[str, Any]]:
        """Find network policies that are overly permissive."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return []

        permissive_policies = []
        try:
            policies = self.analyze_network_policies()

            for policy in policies:
                issues = []

                # Check for empty pod selector (matches all pods)
                if not policy.get('pod_selector'):
                    issues.append("Policy selector matches all pods")

                # Check for empty ingress/egress rules (allow all)
                if not policy.get('ingress_rules'):
                    issues.append("Policy allows all ingress")

                if "Egress" in policy.get('policy_types', []):
                    if not policy.get('egress_rules'):
                        issues.append("Policy allows all egress")

                if issues:
                    permissive_policies.append({
                        "namespace": policy['namespace'],
                        "name": policy['name'],
                        "issues": issues,
                        "recommendation": "Restrict policy to specific pods and ports",
                    })
        except Exception as e:
            logger.error(f"Failed to find permissive policies: {e}")

        return permissive_policies

    def get_network_policy_coverage(self) -> Dict[str, Any]:
        """Get network policy coverage summary."""
        if not self._initialized:
            self._initialize_client()
        if not self._initialized:
            return {}

        try:
            all_policies = self.analyze_network_policies()
            unprotected = self.find_namespaces_without_policies()
            permissive = self.find_overly_permissive_policies()

            total_namespaces = len(list(self.v1.list_namespace().items))
            protected_namespaces = total_namespaces - len(unprotected)

            return {
                "total_namespaces": total_namespaces,
                "protected_namespaces": protected_namespaces,
                "coverage_percentage": (protected_namespaces / total_namespaces * 100) if total_namespaces > 0 else 0,
                "total_policies": len(all_policies),
                "unprotected_namespaces": len(unprotected),
                "permissive_policies": len(permissive),
                "recommendation": "Implement network policies in all namespaces" if len(unprotected) > 0 else "Good coverage, review permissive policies",
            }
        except Exception as e:
            logger.error(f"Failed to get network policy coverage: {e}")
            return {}

    @staticmethod
    def _extract_ingress_rules(ingress_rules) -> List[Dict[str, Any]]:
        """Extract ingress rules."""
        rules = []

        for rule in (ingress_rules or []):
            rule_data = {
                "from": [],
                "ports": [],
            }

            # Extract 'from' selectors
            for from_selector in (rule.from_ or []):
                if from_selector.pod_selector:
                    rule_data['from'].append({
                        "type": "pod_selector",
                        "labels": from_selector.pod_selector.match_labels or {},
                    })
                if from_selector.namespace_selector:
                    rule_data['from'].append({
                        "type": "namespace_selector",
                        "labels": from_selector.namespace_selector.match_labels or {},
                    })
                if from_selector.ip_block:
                    rule_data['from'].append({
                        "type": "ip_block",
                        "cidr": from_selector.ip_block.cidr,
                        "except": from_selector.ip_block.except_ or [],
                    })

            # Extract ports
            for port in (rule.ports or []):
                rule_data['ports'].append({
                    "protocol": port.protocol or "TCP",
                    "port": port.port,
                })

            rules.append(rule_data)

        return rules

    @staticmethod
    def _extract_egress_rules(egress_rules) -> List[Dict[str, Any]]:
        """Extract egress rules."""
        rules = []

        for rule in (egress_rules or []):
            rule_data = {
                "to": [],
                "ports": [],
            }

            # Extract 'to' selectors
            for to_selector in (rule.to or []):
                if to_selector.pod_selector:
                    rule_data['to'].append({
                        "type": "pod_selector",
                        "labels": to_selector.pod_selector.match_labels or {},
                    })
                if to_selector.namespace_selector:
                    rule_data['to'].append({
                        "type": "namespace_selector",
                        "labels": to_selector.namespace_selector.match_labels or {},
                    })
                if to_selector.ip_block:
                    rule_data['to'].append({
                        "type": "ip_block",
                        "cidr": to_selector.ip_block.cidr,
                        "except": to_selector.ip_block.except_ or [],
                    })

            # Extract ports
            for port in (rule.ports or []):
                rule_data['ports'].append({
                    "protocol": port.protocol or "TCP",
                    "port": port.port,
                })

            rules.append(rule_data)

        return rules

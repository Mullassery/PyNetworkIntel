"""Kubernetes cluster/workload discovery and security analysis.

Real, working code - clusters are network infrastructure, so this is a
natural extension of "network intelligence." The `kubernetes` Python client
is lazy-imported and NOT part of the core install; the `kubernetes` extra
(`pip install pynetworkintel[kubernetes]`) pulls it in. Lighter test
coverage than the core discovery/analysis path - see
tests/test_kubernetes.py (pure-logic helpers only; live cluster calls are
not exercised).
"""

from .discovery import KubernetesDiscovery
from .rbac import RBACAnalyzer
from .security import ContainerSecurityAnalyzer
from .network_policy import NetworkPolicyAnalyzer

__all__ = [
    "KubernetesDiscovery",
    "RBACAnalyzer",
    "ContainerSecurityAnalyzer",
    "NetworkPolicyAnalyzer",
]

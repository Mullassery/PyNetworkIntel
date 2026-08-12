"""Basic coverage for the kubernetes/ module.

The `kubernetes` python client is lazy-imported and typically not installed
in this test environment, so these tests focus on the graceful-degradation
behavior (no client -> empty results, not a crash) rather than live cluster
calls.
"""

import pytest

from pynetworkintel.kubernetes.rbac import RBACAnalyzer
from pynetworkintel.kubernetes.security import ContainerSecurityAnalyzer
from pynetworkintel.kubernetes.discovery import K8sResource


class TestK8sResource:
    def test_defaults_are_independent_dicts(self):
        a = K8sResource(resource_id="a", resource_type="pod", namespace="default", name="a", state="Running")
        b = K8sResource(resource_id="b", resource_type="pod", namespace="default", name="b", state="Running")
        a.labels["app"] = "foo"
        assert b.labels == {}

    def test_to_dict(self):
        res = K8sResource(resource_id="a", resource_type="pod", namespace="default", name="a", state="Running")
        data = res.to_dict()
        assert data["resource_id"] == "a"
        assert data["namespace"] == "default"


class TestRBACAnalyzerWithoutClient:
    def test_analyze_roles_returns_empty_without_k8s_client(self):
        analyzer = RBACAnalyzer()
        # Without a real cluster/kubeconfig, this must degrade gracefully
        # rather than raising.
        assert analyzer.analyze_roles() == []


class TestContainerSecurityAnalyzerWithoutClient:
    def test_analyze_pod_security_returns_empty_without_k8s_client(self):
        analyzer = ContainerSecurityAnalyzer()
        assert analyzer.analyze_pod_security() == []

"""Kubernetes cluster discovery and resource enumeration."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class K8sResource:
    resource_id: str
    resource_type: str
    namespace: str
    name: str
    state: str
    labels: Dict[str, str] = None
    annotations: Dict[str, str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = {}
        if self.annotations is None:
            self.annotations = {}
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self):
        return asdict(self)


class KubernetesDiscovery:
    """Discover and enumerate Kubernetes resources."""

    def __init__(self, config_path: Optional[str] = None, context: Optional[str] = None):
        """
        Initialize Kubernetes discovery.

        Args:
            config_path: Path to kubeconfig file
            context: Kubernetes context to use
        """
        self.config_path = config_path
        self.context = context
        self.resources: List[K8sResource] = []

        try:
            from kubernetes import client, config, watch
            self.client = client
            self.config = config
            self.watch = watch
            self._initialized = False
        except ImportError:
            self._initialized = False
            logger.warning("Kubernetes client not installed. Install with: pip install kubernetes")

    def _initialize(self):
        """Initialize Kubernetes client."""
        if not hasattr(self, 'config') or self._initialized:
            return

        try:
            if self.config_path:
                self.config.load_kube_config(config_file=self.config_path, context=self.context)
            else:
                self.config.load_kube_config(context=self.context)

            self.v1 = self.client.CoreV1Api()
            self.apps_v1 = self.client.AppsV1Api()
            self.batch_v1 = self.client.BatchV1Api()
            self.rbac_v1 = self.client.RbacAuthorizationV1Api()
            self.networking_v1 = self.client.NetworkingV1Api()
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            self._initialized = False

    def discover_nodes(self) -> List[K8sResource]:
        """Discover Kubernetes nodes."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return []

        nodes = []
        try:
            for node in self.v1.list_node().items:
                addresses = {}
                for addr in node.status.addresses:
                    addresses[addr.type] = addr.address

                resource = K8sResource(
                    resource_id=node.metadata.name,
                    resource_type="node",
                    namespace="cluster",
                    name=node.metadata.name,
                    state=self._get_node_status(node.status),
                    labels=node.metadata.labels or {},
                    metadata={
                        "capacity": dict(node.status.capacity) if node.status.capacity else {},
                        "allocatable": dict(node.status.allocatable) if node.status.allocatable else {},
                        "kernel_version": node.status.node_info.kernel_version if node.status.node_info else None,
                        "addresses": addresses,
                    }
                )
                nodes.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover nodes: {e}")

        return nodes

    def discover_pods(self, namespace: Optional[str] = None) -> List[K8sResource]:
        """Discover Kubernetes pods."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return []

        pods = []
        try:
            if namespace:
                pod_list = self.v1.list_namespaced_pod(namespace)
            else:
                pod_list = self.v1.list_pod_for_all_namespaces()

            for pod in pod_list.items:
                containers = [c.image for c in pod.spec.containers] if pod.spec.containers else []

                resource = K8sResource(
                    resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                    resource_type="pod",
                    namespace=pod.metadata.namespace,
                    name=pod.metadata.name,
                    state=pod.status.phase,
                    labels=pod.metadata.labels or {},
                    annotations=pod.metadata.annotations or {},
                    metadata={
                        "node_name": pod.spec.node_name,
                        "containers": containers,
                        "restart_count": sum(
                            c.restart_count for c in (pod.status.container_statuses or [])
                        ),
                        "pod_ip": pod.status.pod_ip,
                    }
                )
                pods.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover pods: {e}")

        return pods

    def discover_deployments(self, namespace: Optional[str] = None) -> List[K8sResource]:
        """Discover Kubernetes deployments."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return []

        deployments = []
        try:
            if namespace:
                deploy_list = self.apps_v1.list_namespaced_deployment(namespace)
            else:
                deploy_list = self.apps_v1.list_deployment_for_all_namespaces()

            for deployment in deploy_list.items:
                resource = K8sResource(
                    resource_id=f"{deployment.metadata.namespace}/{deployment.metadata.name}",
                    resource_type="deployment",
                    namespace=deployment.metadata.namespace,
                    name=deployment.metadata.name,
                    state="active" if deployment.status.ready_replicas else "inactive",
                    labels=deployment.metadata.labels or {},
                    metadata={
                        "replicas": deployment.spec.replicas,
                        "ready_replicas": deployment.status.ready_replicas or 0,
                        "updated_replicas": deployment.status.updated_replicas or 0,
                        "image": deployment.spec.template.spec.containers[0].image if deployment.spec.template.spec.containers else None,
                    }
                )
                deployments.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover deployments: {e}")

        return deployments

    def discover_services(self, namespace: Optional[str] = None) -> List[K8sResource]:
        """Discover Kubernetes services."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return []

        services = []
        try:
            if namespace:
                svc_list = self.v1.list_namespaced_service(namespace)
            else:
                svc_list = self.v1.list_service_for_all_namespaces()

            for service in svc_list.items:
                ports = []
                for port in (service.spec.ports or []):
                    ports.append({
                        "name": port.name,
                        "port": port.port,
                        "target_port": port.target_port,
                        "protocol": port.protocol,
                    })

                resource = K8sResource(
                    resource_id=f"{service.metadata.namespace}/{service.metadata.name}",
                    resource_type="service",
                    namespace=service.metadata.namespace,
                    name=service.metadata.name,
                    state="active",
                    labels=service.metadata.labels or {},
                    metadata={
                        "type": service.spec.type,
                        "cluster_ip": service.spec.cluster_ip,
                        "external_ips": service.spec.external_i_ps or [],
                        "load_balancer_ip": service.spec.load_balancer_source_ranges or [],
                        "ports": ports,
                    }
                )
                services.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover services: {e}")

        return services

    def discover_namespaces(self) -> List[K8sResource]:
        """Discover Kubernetes namespaces."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return []

        namespaces = []
        try:
            for namespace in self.v1.list_namespace().items:
                resource = K8sResource(
                    resource_id=namespace.metadata.name,
                    resource_type="namespace",
                    namespace="cluster",
                    name=namespace.metadata.name,
                    state=namespace.status.phase,
                    labels=namespace.metadata.labels or {},
                )
                namespaces.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover namespaces: {e}")

        return namespaces

    def discover_secrets(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover secrets (information only, not values)."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return []

        secrets = []
        try:
            if namespace:
                secret_list = self.v1.list_namespaced_secret(namespace)
            else:
                secret_list = self.v1.list_secret_for_all_namespaces()

            for secret in secret_list.items:
                secrets.append({
                    "namespace": secret.metadata.namespace,
                    "name": secret.metadata.name,
                    "type": secret.type,
                    "keys": list(secret.data.keys()) if secret.data else [],
                })
        except Exception as e:
            logger.error(f"Failed to discover secrets: {e}")

        return secrets

    def discover_all(self) -> Dict[str, List]:
        """Discover all Kubernetes resources."""
        return {
            "namespaces": self.discover_namespaces(),
            "nodes": self.discover_nodes(),
            "pods": self.discover_pods(),
            "deployments": self.discover_deployments(),
            "services": self.discover_services(),
            "secrets": self.discover_secrets(),
        }

    def get_cluster_info(self) -> Dict[str, Any]:
        """Get basic cluster information."""
        if not self._initialized:
            self._initialize()
        if not self._initialized:
            return {}

        try:
            version = self.client.VersionApi().get_code()
            return {
                "git_version": version.git_version,
                "git_commit": version.git_commit,
                "platform": version.platform,
            }
        except:
            return {}

    def get_resources_summary(self) -> Dict[str, Any]:
        """Get summary of discovered resources."""
        by_type = {}
        by_namespace = {}

        for resource in self.resources:
            by_type[resource.resource_type] = by_type.get(resource.resource_type, 0) + 1
            if resource.namespace != "cluster":
                by_namespace[resource.namespace] = by_namespace.get(resource.namespace, 0) + 1

        return {
            "total_resources": len(self.resources),
            "by_type": by_type,
            "by_namespace": by_namespace,
        }

    @staticmethod
    def _get_node_status(status) -> str:
        """Determine node status from conditions."""
        if not status.conditions:
            return "unknown"

        for condition in status.conditions:
            if condition.type == "Ready":
                return "ready" if condition.status == "True" else "not_ready"

        return "unknown"

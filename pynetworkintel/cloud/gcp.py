"""Google Cloud Platform discovery and inventory management."""
import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class GCPResource:
    resource_id: str
    resource_type: str
    region: str
    name: str
    state: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    tags: Dict[str, str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = {}
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self):
        return asdict(self)


class GCPDiscovery:
    """Discover and enumerate Google Cloud Platform resources."""

    def __init__(self, project_id: str, credentials_path: Optional[str] = None):
        """
        Initialize GCP discovery client.

        Args:
            project_id: GCP project ID
            credentials_path: Path to GCP service account JSON file
        """
        self.project_id = project_id
        self.credentials_path = credentials_path
        self.resources: List[GCPResource] = []

        # Lazy import Google Cloud libraries
        try:
            from google.cloud import compute_v1
            from google.cloud import sql_v1
            from google.cloud import storage
            from google.auth import default as auth_default

            self.compute_v1 = compute_v1
            self.sql_v1 = sql_v1
            self.storage = storage
            self.auth_default = auth_default
            self._initialized = False
        except ImportError:
            self._initialized = False
            logger.warning("Google Cloud libraries not installed. Install with: pip install google-cloud-compute google-cloud-sql google-cloud-storage")

    def _get_credentials(self):
        """Get GCP credentials."""
        if not hasattr(self, 'auth_default'):
            return None

        try:
            if self.credentials_path:
                import os
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.credentials_path

            credentials, _ = self.auth_default()
            return credentials
        except Exception as e:
            logger.error(f"Failed to get GCP credentials: {e}")
            return None

    def discover_compute_instances(self) -> List[GCPResource]:
        """Discover Google Compute Engine instances."""
        if not hasattr(self, 'compute_v1'):
            return []

        instances = []
        try:
            credentials = self._get_credentials()
            if not credentials:
                return []

            client = self.compute_v1.InstancesClient(credentials=credentials)
            request = self.compute_v1.AggregatedListInstancesRequest(
                project=self.project_id
            )

            for zone, instances_data in client.aggregated_list(request=request).items():
                zone_name = zone.split('/')[-1]

                for instance in instances_data.instances:
                    # Extract network interface info
                    public_ip = None
                    private_ip = None

                    if instance.network_interfaces:
                        nic = instance.network_interfaces[0]
                        private_ip = nic.network_ip

                        if nic.access_configs:
                            public_ip = nic.access_configs[0].nat_i_p

                    resource = GCPResource(
                        resource_id=instance.id,
                        resource_type="compute",
                        region=zone_name,
                        name=instance.name,
                        state=instance.status,
                        public_ip=public_ip,
                        private_ip=private_ip,
                        tags=dict(instance.labels or {}),
                        metadata={
                            "machine_type": instance.machine_type.split('/')[-1] if instance.machine_type else None,
                            "boot_disk": instance.disks[0].source.split('/')[-1] if instance.disks else None,
                            "creation_timestamp": str(instance.creation_timestamp),
                        }
                    )
                    instances.append(resource)
                    self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover GCP compute instances: {e}")

        return instances

    def discover_cloud_sql_instances(self) -> List[GCPResource]:
        """Discover Google Cloud SQL instances."""
        if not hasattr(self, 'sql_v1'):
            return []

        databases = []
        try:
            credentials = self._get_credentials()
            if not credentials:
                return []

            client = self.sql_v1.SqlInstancesServiceClient(credentials=credentials)
            request = self.sql_v1.SqlInstancesListRequest(project=self.project_id)

            for instance in client.list(request=request):
                resource = GCPResource(
                    resource_id=instance.name,
                    resource_type="cloudsql",
                    region=instance.region,
                    name=instance.name,
                    state=instance.state.name if instance.state else "unknown",
                    metadata={
                        "database_version": instance.database_version,
                        "tier": instance.settings.tier if instance.settings else None,
                        "ip_addresses": [ip.ip_address for ip in (instance.ip_addresses or [])],
                    }
                )
                databases.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover Cloud SQL instances: {e}")

        return databases

    def discover_cloud_storage_buckets(self) -> List[GCPResource]:
        """Discover Google Cloud Storage buckets."""
        if not hasattr(self, 'storage'):
            return []

        buckets = []
        try:
            credentials = self._get_credentials()
            if not credentials:
                return []

            client = self.storage.Client(project=self.project_id, credentials=credentials)

            for bucket in client.list_buckets():
                resource = GCPResource(
                    resource_id=bucket.name,
                    resource_type="storage",
                    region=bucket.location,
                    name=bucket.name,
                    state="active",
                    tags=dict(bucket.labels or {}),
                    metadata={
                        "creation_time": str(bucket.time_created),
                        "storage_class": bucket.storage_class,
                        "versioning_enabled": bucket.versioning_enabled,
                    }
                )
                buckets.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover Cloud Storage buckets: {e}")

        return buckets

    def discover_firewall_rules(self) -> List[Dict[str, Any]]:
        """Discover firewall rules."""
        if not hasattr(self, 'compute_v1'):
            return []

        rules = []
        try:
            credentials = self._get_credentials()
            if not credentials:
                return []

            client = self.compute_v1.FirewallsClient(credentials=credentials)
            request = self.compute_v1.ListFirewallsRequest(project=self.project_id)

            for firewall in client.list(request=request):
                rules.append({
                    "name": firewall.name,
                    "direction": firewall.direction,
                    "priority": firewall.priority,
                    "source_ranges": list(firewall.source_ranges or []),
                    "allowed": [
                        {"protocol": rule.i_p_protocol, "ports": rule.ports}
                        for rule in (firewall.allowed or [])
                    ],
                    "denied": [
                        {"protocol": rule.i_p_protocol, "ports": rule.ports}
                        for rule in (firewall.denied or [])
                    ],
                })
        except Exception as e:
            logger.error(f"Failed to discover firewall rules: {e}")

        return rules

    def discover_networks(self) -> List[Dict[str, Any]]:
        """Discover VPC networks."""
        if not hasattr(self, 'compute_v1'):
            return []

        networks = []
        try:
            credentials = self._get_credentials()
            if not credentials:
                return []

            client = self.compute_v1.NetworksClient(credentials=credentials)
            request = self.compute_v1.ListNetworksRequest(project=self.project_id)

            for network in client.list(request=request):
                networks.append({
                    "name": network.name,
                    "auto_create_subnetworks": network.auto_create_subnetworks,
                    "ipv4_range": network.ipv4_range,
                    "subnetworks": list(network.subnetworks or []),
                })
        except Exception as e:
            logger.error(f"Failed to discover networks: {e}")

        return networks

    def discover_all(self) -> Dict[str, List]:
        """Discover all GCP resources."""
        return {
            "compute_instances": self.discover_compute_instances(),
            "cloud_sql": self.discover_cloud_sql_instances(),
            "storage_buckets": self.discover_cloud_storage_buckets(),
            "firewall_rules": self.discover_firewall_rules(),
            "networks": self.discover_networks(),
        }

    def get_resources_summary(self) -> Dict[str, Any]:
        """Get summary of discovered resources."""
        by_type = {}
        by_region = {}

        for resource in self.resources:
            by_type[resource.resource_type] = by_type.get(resource.resource_type, 0) + 1
            by_region[resource.region] = by_region.get(resource.region, 0) + 1

        return {
            "total_resources": len(self.resources),
            "by_type": by_type,
            "by_region": by_region,
        }

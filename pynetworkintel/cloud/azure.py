"""Azure cloud platform discovery and inventory management."""
import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class AzureResource:
    resource_id: str
    resource_type: str
    region: str
    name: str
    resource_group: str
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


class AzureDiscovery:
    """Discover and enumerate Azure resources."""

    def __init__(self, subscription_id: str, client_id: str, client_secret: str, tenant_id: str):
        """
        Initialize Azure discovery client.

        Args:
            subscription_id: Azure subscription ID
            client_id: Azure service principal client ID
            client_secret: Azure service principal client secret
            tenant_id: Azure tenant ID
        """
        self.subscription_id = subscription_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.resources: List[AzureResource] = []

        # Lazy import Azure SDK
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.network import NetworkManagementClient

            self.ClientSecretCredential = ClientSecretCredential
            self.ComputeManagementClient = ComputeManagementClient
            self.PostgreSQLManagementClient = PostgreSQLManagementClient
            self.StorageManagementClient = StorageManagementClient
            self.NetworkManagementClient = NetworkManagementClient
            self._initialized = False
        except ImportError:
            self._initialized = False
            logger.warning("Azure SDK not installed. Install with: pip install azure-identity azure-mgmt-compute azure-mgmt-storage")

    def _get_credential(self):
        """Get Azure credential."""
        if not hasattr(self, 'ClientSecretCredential'):
            return None
        return self.ClientSecretCredential(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id
        )

    def discover_virtual_machines(self) -> List[AzureResource]:
        """Discover Azure virtual machines."""
        if not hasattr(self, 'ComputeManagementClient'):
            return []

        vms = []
        try:
            credential = self._get_credential()
            if not credential:
                return []

            compute_client = self.ComputeManagementClient(credential, self.subscription_id)

            for vm in compute_client.virtual_machines.list_all():
                resource = AzureResource(
                    resource_id=vm.id,
                    resource_type="vm",
                    region=vm.location,
                    name=vm.name,
                    resource_group=self._extract_resource_group(vm.id),
                    state="active",
                    tags=vm.tags or {},
                    metadata={
                        "vm_id": vm.vm_id,
                        "os_type": vm.storage_profile.os_disk.os_type if vm.storage_profile else None,
                    }
                )
                vms.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover Azure VMs: {e}")

        return vms

    def discover_databases(self) -> List[AzureResource]:
        """Discover Azure databases (PostgreSQL, MySQL, SQL Server)."""
        databases = []
        try:
            credential = self._get_credential()
            if not credential:
                return []

            # PostgreSQL
            if hasattr(self, 'PostgreSQLManagementClient'):
                try:
                    pg_client = self.PostgreSQLManagementClient(credential, self.subscription_id)
                    for server in pg_client.servers.list():
                        resource = AzureResource(
                            resource_id=server.id,
                            resource_type="postgresql",
                            region=server.location,
                            name=server.name,
                            resource_group=self._extract_resource_group(server.id),
                            state="active",
                            tags=server.tags or {},
                            metadata={
                                "version": server.version,
                                "admin_username": server.administrator_login,
                                "sku": str(server.sku),
                            }
                        )
                        databases.append(resource)
                        self.resources.append(resource)
                except Exception as e:
                    logger.error(f"Failed to discover PostgreSQL servers: {e}")
        except Exception as e:
            logger.error(f"Failed to discover Azure databases: {e}")

        return databases

    def discover_storage_accounts(self) -> List[AzureResource]:
        """Discover Azure storage accounts."""
        if not hasattr(self, 'StorageManagementClient'):
            return []

        storage = []
        try:
            credential = self._get_credential()
            if not credential:
                return []

            storage_client = self.StorageManagementClient(credential, self.subscription_id)

            for account in storage_client.storage_accounts.list():
                resource = AzureResource(
                    resource_id=account.id,
                    resource_type="storage",
                    region=account.location,
                    name=account.name,
                    resource_group=self._extract_resource_group(account.id),
                    state="active",
                    tags=account.tags or {},
                    metadata={
                        "kind": account.kind,
                        "sku": str(account.sku),
                        "access_tier": account.access_tier,
                    }
                )
                storage.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover storage accounts: {e}")

        return storage

    def discover_resource_groups(self) -> List[Dict[str, Any]]:
        """Discover resource groups."""
        if not hasattr(self, 'ComputeManagementClient'):
            return []

        groups = []
        try:
            from azure.mgmt.resource import ResourceManagementClient

            credential = self._get_credential()
            if not credential:
                return []

            resource_client = ResourceManagementClient(credential, self.subscription_id)

            for group in resource_client.resource_groups.list():
                groups.append({
                    "name": group.name,
                    "location": group.location,
                    "tags": group.tags or {},
                })
        except Exception as e:
            logger.error(f"Failed to discover resource groups: {e}")

        return groups

    def discover_network_interfaces(self) -> List[Dict[str, Any]]:
        """Discover network interfaces and IP configurations."""
        if not hasattr(self, 'NetworkManagementClient'):
            return []

        interfaces = []
        try:
            credential = self._get_credential()
            if not credential:
                return []

            network_client = self.NetworkManagementClient(credential, self.subscription_id)

            for nic in network_client.network_interfaces.list_all():
                ip_configs = []
                for ip_config in nic.ip_configurations or []:
                    ip_configs.append({
                        "name": ip_config.name,
                        "private_ip": ip_config.private_ip_address,
                        "public_ip_id": ip_config.public_ip_address.id if ip_config.public_ip_address else None,
                    })

                interfaces.append({
                    "nic_id": nic.id,
                    "name": nic.name,
                    "region": nic.location,
                    "mac_address": nic.mac_address,
                    "ip_configurations": ip_configs,
                })
        except Exception as e:
            logger.error(f"Failed to discover network interfaces: {e}")

        return interfaces

    def discover_all(self) -> Dict[str, List]:
        """Discover all Azure resources."""
        return {
            "virtual_machines": self.discover_virtual_machines(),
            "databases": self.discover_databases(),
            "storage_accounts": self.discover_storage_accounts(),
            "resource_groups": self.discover_resource_groups(),
            "network_interfaces": self.discover_network_interfaces(),
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

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract resource group from Azure resource ID."""
        try:
            parts = resource_id.split('/')
            rg_index = parts.index('resourceGroups')
            return parts[rg_index + 1]
        except:
            return "unknown"

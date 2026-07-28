"""Multi-tenant architecture and isolation."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)


@dataclass
class TenantConfig:
    tenant_id: str
    name: str
    owner_email: str
    created_at: datetime = field(default_factory=datetime.now)
    quota_devices: int = 100
    quota_storage_gb: int = 100
    quota_api_calls_daily: int = 10000
    is_active: bool = True
    features: List[str] = field(default_factory=list)
    encryption_key: str = ""


class TenantManager:
    """Manage multi-tenant environments."""

    def __init__(self):
        """Initialize tenant manager."""
        self.tenants: Dict[str, TenantConfig] = {}
        self.tenant_data_isolation: Dict[str, Dict[str, Any]] = {}
        self.api_keys: Dict[str, str] = {}  # api_key -> tenant_id

    def create_tenant(self, name: str, owner_email: str, features: Optional[List[str]] = None) -> Optional[str]:
        """Create a new tenant."""
        tenant_id = self._generate_tenant_id(name, owner_email)

        if tenant_id in self.tenants:
            logger.warning(f"Tenant {tenant_id} already exists")
            return None

        encryption_key = self._generate_encryption_key(tenant_id)

        tenant = TenantConfig(
            tenant_id=tenant_id,
            name=name,
            owner_email=owner_email,
            encryption_key=encryption_key,
            features=features or ["basic"],
        )

        self.tenants[tenant_id] = tenant
        self.tenant_data_isolation[tenant_id] = {}

        logger.info(f"Created tenant: {tenant_id} ({name})")

        return tenant_id

    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant and all associated data."""
        if tenant_id not in self.tenants:
            logger.error(f"Tenant {tenant_id} not found")
            return False

        # Delete all tenant data
        if tenant_id in self.tenant_data_isolation:
            del self.tenant_data_isolation[tenant_id]

        # Delete tenant config
        del self.tenants[tenant_id]

        # Delete API keys
        keys_to_delete = [k for k, v in self.api_keys.items() if v == tenant_id]
        for key in keys_to_delete:
            del self.api_keys[key]

        logger.info(f"Deleted tenant: {tenant_id}")

        return True

    def generate_api_key(self, tenant_id: str) -> Optional[str]:
        """Generate API key for tenant."""
        if tenant_id not in self.tenants:
            return None

        api_key = self._generate_api_key(tenant_id)
        self.api_keys[api_key] = tenant_id

        logger.info(f"Generated API key for tenant: {tenant_id}")

        return api_key

    def validate_api_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return tenant ID."""
        return self.api_keys.get(api_key)

    def get_tenant_quota(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant quota."""
        if tenant_id not in self.tenants:
            return None

        tenant = self.tenants[tenant_id]

        return {
            "tenant_id": tenant_id,
            "quota_devices": tenant.quota_devices,
            "quota_storage_gb": tenant.quota_storage_gb,
            "quota_api_calls_daily": tenant.quota_api_calls_daily,
        }

    def check_quota(self, tenant_id: str, resource: str, amount: int = 1) -> bool:
        """Check if tenant has quota for resource."""
        if tenant_id not in self.tenants:
            return False

        tenant = self.tenants[tenant_id]

        if resource == "devices":
            return amount <= tenant.quota_devices
        elif resource == "storage":
            return amount <= tenant.quota_storage_gb
        elif resource == "api_calls":
            return amount <= tenant.quota_api_calls_daily

        return False

    def isolate_data(self, tenant_id: str, data_key: str, data: Dict[str, Any]) -> bool:
        """Store tenant-isolated data."""
        if tenant_id not in self.tenant_data_isolation:
            return False

        self.tenant_data_isolation[tenant_id][data_key] = data

        return True

    def retrieve_tenant_data(self, tenant_id: str, data_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve tenant-isolated data."""
        if tenant_id not in self.tenant_data_isolation:
            return None

        if data_key:
            return self.tenant_data_isolation[tenant_id].get(data_key)
        else:
            return self.tenant_data_isolation[tenant_id]

    def get_row_level_security_filter(self, tenant_id: str) -> Dict[str, Any]:
        """Get RLS filter for tenant data queries."""
        return {
            "tenant_id": tenant_id,
            "column": "tenant_id",
            "operator": "equals",
        }

    def update_encryption_key(self, tenant_id: str) -> Optional[str]:
        """Rotate encryption key for tenant."""
        if tenant_id not in self.tenants:
            return None

        new_key = self._generate_encryption_key(tenant_id)
        self.tenants[tenant_id].encryption_key = new_key

        logger.info(f"Rotated encryption key for tenant: {tenant_id}")

        return new_key

    def enable_feature(self, tenant_id: str, feature: str) -> bool:
        """Enable a feature for tenant."""
        if tenant_id not in self.tenants:
            return False

        tenant = self.tenants[tenant_id]
        if feature not in tenant.features:
            tenant.features.append(feature)

        return True

    def disable_feature(self, tenant_id: str, feature: str) -> bool:
        """Disable a feature for tenant."""
        if tenant_id not in self.tenants:
            return False

        tenant = self.tenants[tenant_id]
        if feature in tenant.features:
            tenant.features.remove(feature)

        return True

    def get_tenant_info(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant information."""
        if tenant_id not in self.tenants:
            return None

        tenant = self.tenants[tenant_id]

        return {
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
            "owner_email": tenant.owner_email,
            "created_at": tenant.created_at.isoformat(),
            "is_active": tenant.is_active,
            "features": tenant.features,
            "quota": {
                "devices": tenant.quota_devices,
                "storage_gb": tenant.quota_storage_gb,
                "api_calls_daily": tenant.quota_api_calls_daily,
            },
        }

    @staticmethod
    def _generate_tenant_id(name: str, email: str) -> str:
        """Generate unique tenant ID."""
        import uuid
        unique_str = f"{name}-{email}-{uuid.uuid4()}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:16]

    @staticmethod
    def _generate_api_key(tenant_id: str) -> str:
        """Generate API key for tenant."""
        import uuid
        import base64
        key_material = f"{tenant_id}-{uuid.uuid4()}"
        return base64.b64encode(key_material.encode()).decode()[:32]

    @staticmethod
    def _generate_encryption_key(tenant_id: str) -> str:
        """Generate encryption key for tenant."""
        import secrets
        return secrets.token_hex(32)

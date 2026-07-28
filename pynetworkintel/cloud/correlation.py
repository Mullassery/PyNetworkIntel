"""Multi-cloud asset correlation and network path analysis."""
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class AssetMapping:
    """Represents a cross-cloud asset mapping."""
    asset_id: str
    asset_name: str
    asset_type: str
    cloud_sources: Dict[str, str]  # cloud_platform -> resource_id
    primary_ip: Optional[str] = None
    backup_ips: List[str] = None
    related_assets: List[str] = None

    def __post_init__(self):
        if self.backup_ips is None:
            self.backup_ips = []
        if self.related_assets is None:
            self.related_assets = []


class CloudCorrelationEngine:
    """Correlate assets across multiple cloud platforms."""

    def __init__(self):
        """Initialize correlation engine."""
        self.assets: Dict[str, AssetMapping] = {}
        self.ip_to_asset: Dict[str, str] = {}
        self.name_to_asset: Dict[str, List[str]] = {}

    def add_aws_resource(self, resource: Dict[str, Any]):
        """Add AWS resource to correlation engine."""
        resource_id = resource.get('resource_id', '')
        resource_type = resource.get('resource_type', '')
        name = resource.get('name', '')
        public_ip = resource.get('public_ip')
        private_ip = resource.get('private_ip')

        asset_key = self._get_asset_key(name, private_ip, public_ip)

        if asset_key not in self.assets:
            self.assets[asset_key] = AssetMapping(
                asset_id=asset_key,
                asset_name=name,
                asset_type=resource_type,
                cloud_sources={'aws': resource_id},
                primary_ip=public_ip or private_ip,
            )
        else:
            self.assets[asset_key].cloud_sources['aws'] = resource_id

        # Track IP mappings
        if public_ip:
            self.ip_to_asset[public_ip] = asset_key
        if private_ip:
            self.ip_to_asset[private_ip] = asset_key

        # Track name mappings
        if name not in self.name_to_asset:
            self.name_to_asset[name] = []
        if asset_key not in self.name_to_asset[name]:
            self.name_to_asset[name].append(asset_key)

    def add_azure_resource(self, resource: Dict[str, Any]):
        """Add Azure resource to correlation engine."""
        resource_id = resource.get('resource_id', '')
        resource_type = resource.get('resource_type', '')
        name = resource.get('name', '')
        public_ip = resource.get('public_ip')
        private_ip = resource.get('private_ip')

        asset_key = self._get_asset_key(name, private_ip, public_ip)

        if asset_key not in self.assets:
            self.assets[asset_key] = AssetMapping(
                asset_id=asset_key,
                asset_name=name,
                asset_type=resource_type,
                cloud_sources={'azure': resource_id},
                primary_ip=public_ip or private_ip,
            )
        else:
            self.assets[asset_key].cloud_sources['azure'] = resource_id

        if public_ip:
            self.ip_to_asset[public_ip] = asset_key
        if private_ip:
            self.ip_to_asset[private_ip] = asset_key

        if name not in self.name_to_asset:
            self.name_to_asset[name] = []
        if asset_key not in self.name_to_asset[name]:
            self.name_to_asset[name].append(asset_key)

    def add_gcp_resource(self, resource: Dict[str, Any]):
        """Add GCP resource to correlation engine."""
        resource_id = resource.get('resource_id', '')
        resource_type = resource.get('resource_type', '')
        name = resource.get('name', '')
        public_ip = resource.get('public_ip')
        private_ip = resource.get('private_ip')

        asset_key = self._get_asset_key(name, private_ip, public_ip)

        if asset_key not in self.assets:
            self.assets[asset_key] = AssetMapping(
                asset_id=asset_key,
                asset_name=name,
                asset_type=resource_type,
                cloud_sources={'gcp': resource_id},
                primary_ip=public_ip or private_ip,
            )
        else:
            self.assets[asset_key].cloud_sources['gcp'] = resource_id

        if public_ip:
            self.ip_to_asset[public_ip] = asset_key
        if private_ip:
            self.ip_to_asset[private_ip] = asset_key

        if name not in self.name_to_asset:
            self.name_to_asset[name] = []
        if asset_key not in self.name_to_asset[name]:
            self.name_to_asset[name].append(asset_key)

    def find_duplicate_assets(self) -> List[Dict[str, Any]]:
        """Find assets that exist in multiple cloud platforms."""
        duplicates = []

        for asset_key, asset in self.assets.items():
            if len(asset.cloud_sources) > 1:
                duplicates.append({
                    "asset_id": asset_key,
                    "asset_name": asset.asset_name,
                    "asset_type": asset.asset_type,
                    "clouds": list(asset.cloud_sources.keys()),
                    "resources": asset.cloud_sources,
                    "primary_ip": asset.primary_ip,
                })

        return duplicates

    def find_asset_by_ip(self, ip_address: str) -> Optional[AssetMapping]:
        """Find asset by IP address."""
        asset_key = self.ip_to_asset.get(ip_address)
        if asset_key:
            return self.assets.get(asset_key)
        return None

    def find_assets_by_name(self, name: str) -> List[AssetMapping]:
        """Find assets by name."""
        asset_keys = self.name_to_asset.get(name, [])
        return [self.assets.get(key) for key in asset_keys if key in self.assets]

    def get_multi_cloud_inventory(self) -> Dict[str, Any]:
        """Get complete multi-cloud inventory."""
        by_cloud = {'aws': 0, 'azure': 0, 'gcp': 0}
        by_type = {}
        multi_cloud_assets = 0

        for asset in self.assets.values():
            for cloud in asset.cloud_sources.keys():
                by_cloud[cloud] += 1

            if len(asset.cloud_sources) > 1:
                multi_cloud_assets += 1

            asset_type = asset.asset_type
            by_type[asset_type] = by_type.get(asset_type, 0) + 1

        return {
            "total_unique_assets": len(self.assets),
            "multi_cloud_assets": multi_cloud_assets,
            "by_cloud": by_cloud,
            "by_type": by_type,
            "cloud_distribution": {
                k: v for k, v in by_cloud.items() if v > 0
            },
        }

    def analyze_network_paths(self) -> Dict[str, Any]:
        """Analyze network paths between cloud platforms."""
        cloud_pairs = set()
        path_analysis = {}

        for asset in self.assets.values():
            clouds = sorted(list(asset.cloud_sources.keys()))
            if len(clouds) >= 2:
                for i in range(len(clouds)):
                    for j in range(i + 1, len(clouds)):
                        pair = f"{clouds[i]}-{clouds[j]}"
                        cloud_pairs.add(pair)

        for pair in cloud_pairs:
            path_analysis[pair] = {
                "assets_spanning_clouds": 0,
                "connectivity_points": [],
            }

        for asset in self.assets.values():
            clouds = sorted(list(asset.cloud_sources.keys()))
            if len(clouds) >= 2:
                for i in range(len(clouds)):
                    for j in range(i + 1, len(clouds)):
                        pair = f"{clouds[i]}-{clouds[j]}"
                        path_analysis[pair]["assets_spanning_clouds"] += 1
                        if asset.primary_ip:
                            path_analysis[pair]["connectivity_points"].append(asset.primary_ip)

        return {
            "cloud_pairs": list(cloud_pairs),
            "path_analysis": path_analysis,
            "total_cross_cloud_connections": len(cloud_pairs),
        }

    def detect_resource_clusters(self) -> List[Dict[str, Any]]:
        """Detect clusters of related resources."""
        clusters = []
        visited = set()

        for asset_key, asset in self.assets.items():
            if asset_key in visited:
                continue

            # Start new cluster
            cluster = {
                "cluster_id": asset_key,
                "assets": [asset_key],
                "clouds": set(asset.cloud_sources.keys()),
                "ips": [asset.primary_ip] if asset.primary_ip else [],
            }

            # Find related assets
            queue = [asset_key]
            while queue:
                current_key = queue.pop(0)
                if current_key in visited:
                    continue

                visited.add(current_key)
                current_asset = self.assets.get(current_key)

                if current_asset:
                    cluster["clouds"].update(current_asset.cloud_sources.keys())
                    if current_asset.primary_ip:
                        cluster["ips"].append(current_asset.primary_ip)

                    # Add related assets to queue
                    for related_key in (current_asset.related_assets or []):
                        if related_key not in visited:
                            queue.append(related_key)
                            cluster["assets"].append(related_key)

            if len(cluster["assets"]) > 1 or len(cluster["clouds"]) > 1:
                cluster["clouds"] = list(cluster["clouds"])
                clusters.append(cluster)

        return clusters

    @staticmethod
    def _get_asset_key(name: str, private_ip: Optional[str], public_ip: Optional[str]) -> str:
        """Generate unique asset key."""
        if private_ip:
            return f"{name}:{private_ip}"
        elif public_ip:
            return f"{name}:{public_ip}"
        else:
            return name

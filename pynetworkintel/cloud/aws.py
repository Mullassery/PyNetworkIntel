"""AWS cloud platform discovery and inventory management."""
import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class AWSResource:
    resource_id: str
    resource_type: str
    region: str
    name: str
    state: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    security_groups: List[str] = None
    subnet_id: Optional[str] = None
    vpc_id: Optional[str] = None
    tags: Dict[str, str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.security_groups is None:
            self.security_groups = []
        if self.tags is None:
            self.tags = {}
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self):
        return asdict(self)


class AWSDiscovery:
    """Discover and enumerate AWS resources across regions."""

    def __init__(self, access_key_id: str, secret_access_key: str, regions: Optional[List[str]] = None):
        """
        Initialize AWS discovery client.

        Args:
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            regions: List of regions to scan (None = all)
        """
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.regions = regions or self._get_all_regions()
        self.resources: List[AWSResource] = []
        self.vpc_mappings: Dict[str, List[str]] = {}

        # Lazy import boto3 only if available
        try:
            import boto3
            self.boto3 = boto3
            self.ec2 = None
            self.rds = None
            self.s3 = None
            self._initialized = False
        except ImportError:
            self.boto3 = None
            self._initialized = False
            logger.warning("boto3 not installed. Install with: pip install boto3")

    def _initialize_clients(self):
        """Lazy initialize boto3 clients."""
        if not self.boto3 or self._initialized:
            return

        try:
            session = self.boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key
            )
            self.ec2_resource = session.resource('ec2')
            self.ec2_client = session.client('ec2')
            self.rds_client = session.client('rds')
            self.s3_client = session.client('s3')
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            self._initialized = False

    def _get_all_regions(self) -> List[str]:
        """Get all available AWS regions."""
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-central-1", "eu-north-1",
            "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            "ca-central-1", "sa-east-1"
        ]

    def discover_ec2_instances(self, region: Optional[str] = None) -> List[AWSResource]:
        """Discover EC2 instances."""
        if not self._initialized:
            self._initialize_clients()
        if not self._initialized:
            return []

        regions = [region] if region else self.regions
        instances = []

        for reg in regions:
            try:
                ec2 = self.boto3.resource('ec2', region_name=reg)
                for instance in ec2.instances.all():
                    resource = AWSResource(
                        resource_id=instance.id,
                        resource_type="ec2",
                        region=reg,
                        name=self._get_tag(instance.tags, 'Name') or instance.id,
                        state=instance.state['Name'],
                        public_ip=instance.public_ip_address,
                        private_ip=instance.private_ip_address,
                        security_groups=[sg['GroupId'] for sg in instance.security_groups],
                        subnet_id=instance.subnet_id,
                        vpc_id=instance.vpc_id,
                        tags=self._tags_to_dict(instance.tags),
                        metadata={
                            "instance_type": instance.instance_type,
                            "launch_time": str(instance.launch_time),
                            "availability_zone": instance.placement['AvailabilityZone'],
                            "key_name": instance.key_name,
                        }
                    )
                    instances.append(resource)
                    self.resources.append(resource)
            except Exception as e:
                logger.error(f"Failed to discover EC2 instances in {reg}: {e}")

        return instances

    def discover_rds_instances(self, region: Optional[str] = None) -> List[AWSResource]:
        """Discover RDS database instances."""
        if not self._initialized:
            self._initialize_clients()
        if not self._initialized:
            return []

        regions = [region] if region else self.regions
        databases = []

        for reg in regions:
            try:
                rds = self.boto3.client('rds', region_name=reg)
                response = rds.describe_db_instances()

                for db in response.get('DBInstances', []):
                    resource = AWSResource(
                        resource_id=db['DBInstanceIdentifier'],
                        resource_type="rds",
                        region=reg,
                        name=db['DBInstanceIdentifier'],
                        state=db['DBInstanceStatus'],
                        metadata={
                            "engine": db.get('Engine'),
                            "engine_version": db.get('EngineVersion'),
                            "instance_class": db.get('DBInstanceClass'),
                            "multi_az": db.get('MultiAZ', False),
                            "endpoint": db.get('Endpoint', {}).get('Address'),
                            "port": db.get('Endpoint', {}).get('Port'),
                        }
                    )
                    databases.append(resource)
                    self.resources.append(resource)
            except Exception as e:
                logger.error(f"Failed to discover RDS instances in {reg}: {e}")

        return databases

    def discover_s3_buckets(self) -> List[AWSResource]:
        """Discover S3 buckets."""
        if not self._initialized:
            self._initialize_clients()
        if not self._initialized:
            return []

        buckets = []
        try:
            s3 = self.boto3.client('s3')
            response = s3.list_buckets()

            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']

                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get('LocationConstraint', 'us-east-1') or 'us-east-1'
                except:
                    region = 'us-east-1'

                resource = AWSResource(
                    resource_id=bucket_name,
                    resource_type="s3",
                    region=region,
                    name=bucket_name,
                    state="active",
                    metadata={
                        "creation_date": str(bucket.get('CreationDate')),
                    }
                )
                buckets.append(resource)
                self.resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to discover S3 buckets: {e}")

        return buckets

    def discover_security_groups(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover security group configurations."""
        if not self._initialized:
            self._initialize_clients()
        if not self._initialized:
            return []

        regions = [region] if region else self.regions
        sgs = []

        for reg in regions:
            try:
                ec2 = self.boto3.client('ec2', region_name=reg)
                response = ec2.describe_security_groups()

                for sg in response.get('SecurityGroups', []):
                    sg_data = {
                        "group_id": sg['GroupId'],
                        "group_name": sg['GroupName'],
                        "region": reg,
                        "vpc_id": sg.get('VpcId'),
                        "inbound_rules": sg.get('IpPermissions', []),
                        "outbound_rules": sg.get('IpPermissionsEgress', []),
                    }
                    sgs.append(sg_data)
            except Exception as e:
                logger.error(f"Failed to discover security groups in {reg}: {e}")

        return sgs

    def discover_vpc_networks(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover VPC networks and subnets."""
        if not self._initialized:
            self._initialize_clients()
        if not self._initialized:
            return []

        regions = [region] if region else self.regions
        vpcs = []

        for reg in regions:
            try:
                ec2 = self.boto3.client('ec2', region_name=reg)

                vpc_response = ec2.describe_vpcs()
                for vpc in vpc_response.get('Vpcs', []):
                    vpc_id = vpc['VpcId']

                    subnet_response = ec2.describe_subnets(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )

                    vpc_data = {
                        "vpc_id": vpc_id,
                        "region": reg,
                        "cidr_block": vpc['CidrBlock'],
                        "state": vpc['State'],
                        "subnets": [
                            {
                                "subnet_id": subnet['SubnetId'],
                                "cidr_block": subnet['CidrBlock'],
                                "availability_zone": subnet['AvailabilityZone'],
                                "available_ips": subnet['AvailableIpAddressCount'],
                            }
                            for subnet in subnet_response.get('Subnets', [])
                        ]
                    }
                    vpcs.append(vpc_data)
                    self.vpc_mappings[vpc_id] = [s['subnet_id'] for s in vpc_data['subnets']]
            except Exception as e:
                logger.error(f"Failed to discover VPCs in {reg}: {e}")

        return vpcs

    def discover_all(self) -> Dict[str, List]:
        """Discover all AWS resources."""
        return {
            "ec2_instances": self.discover_ec2_instances(),
            "rds_databases": self.discover_rds_instances(),
            "s3_buckets": self.discover_s3_buckets(),
            "security_groups": self.discover_security_groups(),
            "vpcs": self.discover_vpc_networks(),
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
            "regions_scanned": len(self.regions),
        }

    @staticmethod
    def _get_tag(tags, key: str, default=None):
        """Extract tag value by key."""
        if not tags:
            return default
        for tag in tags:
            if tag.get('Key') == key:
                return tag.get('Value')
        return default

    @staticmethod
    def _tags_to_dict(tags) -> Dict[str, str]:
        """Convert AWS tags list to dict."""
        if not tags:
            return {}
        return {tag.get('Key', ''): tag.get('Value', '') for tag in tags}

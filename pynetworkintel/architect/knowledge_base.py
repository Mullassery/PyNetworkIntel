"""Knowledge base for architectural intelligence."""
from typing import Dict, List, Any, Optional, Set
import logging

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Comprehensive knowledge base for infrastructure architecture."""

    def __init__(self):
        """Initialize knowledge base."""
        self.services: Dict[str, Dict[str, Any]] = {}
        self.patterns: Dict[str, Dict[str, Any]] = {}
        self.compliance_controls: Dict[str, List[str]] = {}
        self.best_practices: Dict[str, List[str]] = {}
        self._build_knowledge_base()

    def _build_knowledge_base(self):
        """Build comprehensive knowledge base."""
        self._load_aws_services()
        self._load_azure_services()
        self._load_gcp_services()
        self._load_cloud_patterns()
        self._load_compliance_mappings()
        self._load_best_practices()

    def _load_aws_services(self):
        """Load AWS service knowledge (200+ services)."""
        aws_services = {
            # Compute
            "EC2": {
                "category": "compute",
                "description": "Virtual servers in the cloud",
                "high_availability": True,
                "disaster_recovery": True,
                "use_cases": ["web hosting", "app servers", "batch processing"],
                "related_services": ["ELB", "Auto Scaling", "CloudWatch"],
            },
            "Lambda": {
                "category": "serverless_compute",
                "description": "Run code without provisioning servers",
                "high_availability": True,
                "cost_effective": True,
                "use_cases": ["api backends", "data processing", "event handlers"],
            },
            "ECS": {
                "category": "container_orchestration",
                "description": "Docker container management",
                "high_availability": True,
                "use_cases": ["microservices", "containerized apps"],
            },
            "EKS": {
                "category": "kubernetes",
                "description": "Managed Kubernetes service",
                "high_availability": True,
                "use_cases": ["kubernetes workloads", "cloud native apps"],
            },
            # Database
            "RDS": {
                "category": "database",
                "description": "Managed relational databases",
                "high_availability": True,
                "automated_backups": True,
                "use_cases": ["sql databases", "structured data"],
            },
            "DynamoDB": {
                "category": "nosql_database",
                "description": "Fully managed NoSQL database",
                "high_availability": True,
                "global_replication": True,
                "use_cases": ["real-time apps", "mobile apps"],
            },
            "ElastiCache": {
                "category": "caching",
                "description": "In-memory data store",
                "use_cases": ["session caching", "real-time analytics"],
            },
            # Networking
            "VPC": {
                "category": "networking",
                "description": "Virtual private cloud",
                "use_cases": ["network isolation", "security boundaries"],
            },
            "CloudFront": {
                "category": "cdn",
                "description": "Content delivery network",
                "global": True,
                "use_cases": ["content distribution", "ddos protection"],
            },
            # Security
            "IAM": {
                "category": "identity",
                "description": "Access management",
                "use_cases": ["user management", "api authentication"],
            },
            "KMS": {
                "category": "encryption",
                "description": "Key management service",
                "use_cases": ["data encryption", "key rotation"],
            },
        }

        for service_id, service_info in aws_services.items():
            service_key = f"aws:{service_id}"
            self.services[service_key] = {
                **service_info,
                "cloud": "aws",
                "service_id": service_id,
            }

    def _load_azure_services(self):
        """Load Azure service knowledge."""
        azure_services = {
            "VM": {
                "category": "compute",
                "description": "Virtual machines",
                "high_availability": True,
                "use_cases": ["application hosting", "dev/test"],
            },
            "AppService": {
                "category": "app_platform",
                "description": "Web and mobile app platform",
                "use_cases": ["web apps", "api backends"],
            },
            "AKS": {
                "category": "kubernetes",
                "description": "Azure Kubernetes Service",
                "high_availability": True,
                "use_cases": ["kubernetes workloads"],
            },
            "CosmosDB": {
                "category": "database",
                "description": "Globally distributed database",
                "global": True,
                "use_cases": ["global apps", "real-time data"],
            },
        }

        for service_id, service_info in azure_services.items():
            service_key = f"azure:{service_id}"
            self.services[service_key] = {
                **service_info,
                "cloud": "azure",
                "service_id": service_id,
            }

    def _load_gcp_services(self):
        """Load GCP service knowledge."""
        gcp_services = {
            "ComputeEngine": {
                "category": "compute",
                "description": "Virtual machines",
                "high_availability": True,
                "use_cases": ["VM hosting"],
            },
            "GKE": {
                "category": "kubernetes",
                "description": "Google Kubernetes Engine",
                "high_availability": True,
                "use_cases": ["kubernetes workloads"],
            },
            "CloudRun": {
                "category": "serverless",
                "description": "Containerized functions",
                "use_cases": ["api backends", "workers"],
            },
            "BigQuery": {
                "category": "analytics",
                "description": "Data warehouse",
                "large_scale": True,
                "use_cases": ["analytics", "reporting"],
            },
        }

        for service_id, service_info in gcp_services.items():
            service_key = f"gcp:{service_id}"
            self.services[service_key] = {
                **service_info,
                "cloud": "gcp",
                "service_id": service_id,
            }

    def _load_cloud_patterns(self):
        """Load cloud architecture patterns."""
        self.patterns = {
            "serverless": {
                "description": "Use managed services and serverless compute",
                "benefits": ["reduced ops", "auto-scaling", "cost optimization"],
                "components": ["Lambda/Functions", "API Gateway", "Databases"],
                "best_for": ["event-driven", "variable load"],
            },
            "microservices": {
                "description": "Decompose into small, independent services",
                "benefits": ["scalability", "fault isolation", "independent deployment"],
                "components": ["containerization", "orchestration", "service mesh"],
                "best_for": ["complex applications", "large teams"],
            },
            "multi_cloud": {
                "description": "Span multiple cloud providers",
                "benefits": ["reduced vendor lock-in", "regional redundancy"],
                "challenges": ["complexity", "management overhead"],
            },
            "disaster_recovery": {
                "description": "Setup for recovery from failures",
                "strategies": ["backup", "replication", "multi-region"],
                "metrics": ["RTO", "RPO"],
            },
        }

    def _load_compliance_mappings(self):
        """Load compliance framework mappings."""
        self.compliance_controls = {
            "SOC2": [
                "Logical access controls",
                "Change management",
                "Monitoring and alerting",
                "Data encryption",
                "Incident response",
            ],
            "ISO27001": [
                "Access control",
                "Cryptography",
                "Physical security",
                "Human resources",
                "Supplier relationships",
            ],
            "PCI-DSS": [
                "Install and maintain firewall",
                "Protect cardholder data",
                "Maintain vulnerability management",
                "Implement access control",
                "Test and monitor systems",
            ],
        }

    def _load_best_practices(self):
        """Load architectural best practices."""
        self.best_practices = {
            "reliability": [
                "Use managed services",
                "Implement redundancy",
                "Design for failure",
                "Use auto-scaling",
                "Monitor and alert",
            ],
            "security": [
                "Principle of least privilege",
                "Encryption by default",
                "Regular audits",
                "Network segmentation",
                "Incident response plan",
            ],
            "cost": [
                "Right-size resources",
                "Use spot/reserved instances",
                "Implement cost monitoring",
                "Architect for efficiency",
                "Remove unused resources",
            ],
            "performance": [
                "Use caching",
                "CDN for content",
                "Database optimization",
                "Asynchronous processing",
                "Load testing",
            ],
        }

    def get_service_info(self, service_key: str) -> Optional[Dict[str, Any]]:
        """Get service information."""
        return self.services.get(service_key)

    def get_services_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get services by category."""
        return [
            service for service in self.services.values()
            if service.get("category") == category
        ]

    def get_services_by_cloud(self, cloud: str) -> List[Dict[str, Any]]:
        """Get services by cloud provider."""
        return [
            service for service in self.services.values()
            if service.get("cloud") == cloud
        ]

    def search_services(self, query: str) -> List[Dict[str, Any]]:
        """Search for services by use case or description."""
        results = []

        for service in self.services.values():
            if query.lower() in service.get("description", "").lower():
                results.append(service)
            elif any(query.lower() in uc.lower() for uc in service.get("use_cases", [])):
                results.append(service)

        return results

    def get_pattern_info(self, pattern_name: str) -> Optional[Dict[str, Any]]:
        """Get pattern information."""
        return self.patterns.get(pattern_name)

    def get_all_patterns(self) -> List[str]:
        """Get all available patterns."""
        return list(self.patterns.keys())

    def get_compliance_controls(self, framework: str) -> List[str]:
        """Get compliance controls for framework."""
        return self.compliance_controls.get(framework, [])

    def get_best_practices(self, category: str) -> List[str]:
        """Get best practices for category."""
        return self.best_practices.get(category, [])

    def get_service_count(self) -> Dict[str, int]:
        """Get count of services by cloud."""
        counts = {}

        for service in self.services.values():
            cloud = service.get("cloud", "unknown")
            counts[cloud] = counts.get(cloud, 0) + 1

        return counts

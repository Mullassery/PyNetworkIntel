"""Cloud asset discovery (AWS/Azure/GCP).

Real, working code - a natural extension of "network intelligence" into
hybrid/cloud infrastructure. Cloud SDKs (boto3, azure-mgmt-*,
google-cloud-*) are lazy-imported and NOT part of the core install; the
`cloud` extra (`pip install pynetworkintel[cloud]`) pulls them in. Lighter
test coverage than the core discovery/analysis path - see tests/test_cloud.py
for what's covered (dataclass/correlation logic; live-API calls are not
exercised since they require real cloud credentials).
"""

from .aws import AWSDiscovery
from .azure import AzureDiscovery
from .gcp import GCPDiscovery
from .credentials import CloudCredentialManager
from .correlation import CloudCorrelationEngine

__all__ = [
    "AWSDiscovery",
    "AzureDiscovery",
    "GCPDiscovery",
    "CloudCredentialManager",
    "CloudCorrelationEngine",
]

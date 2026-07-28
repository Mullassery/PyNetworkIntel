"""Cloud platform credential management."""
import os
import json
from typing import Dict, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CloudCredentialManager:
    """Manage credentials for cloud platforms (AWS, Azure, GCP)."""

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize credential manager.

        Args:
            config_dir: Directory to store credentials (default: ~/.pynetworkintel/cloud)
        """
        self.config_dir = Path(config_dir or Path.home() / ".pynetworkintel" / "cloud")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials = {}

    def store_aws_credentials(self, profile_name: str, access_key_id: str, secret_access_key: str, regions: Optional[list] = None):
        """Store AWS credentials."""
        aws_file = self.config_dir / "aws.json"

        try:
            existing = {}
            if aws_file.exists():
                with open(aws_file, 'r') as f:
                    existing = json.load(f)
        except:
            existing = {}

        existing[profile_name] = {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "regions": regions or [],
        }

        with open(aws_file, 'w') as f:
            json.dump(existing, f, indent=2)

        os.chmod(aws_file, 0o600)
        logger.info(f"Stored AWS credentials for profile: {profile_name}")

    def store_azure_credentials(self, profile_name: str, subscription_id: str, client_id: str, client_secret: str, tenant_id: str):
        """Store Azure credentials."""
        azure_file = self.config_dir / "azure.json"

        try:
            existing = {}
            if azure_file.exists():
                with open(azure_file, 'r') as f:
                    existing = json.load(f)
        except:
            existing = {}

        existing[profile_name] = {
            "subscription_id": subscription_id,
            "client_id": client_id,
            "client_secret": client_secret,
            "tenant_id": tenant_id,
        }

        with open(azure_file, 'w') as f:
            json.dump(existing, f, indent=2)

        os.chmod(azure_file, 0o600)
        logger.info(f"Stored Azure credentials for profile: {profile_name}")

    def store_gcp_credentials(self, profile_name: str, project_id: str, credentials_path: str):
        """Store GCP credentials reference."""
        gcp_file = self.config_dir / "gcp.json"

        try:
            existing = {}
            if gcp_file.exists():
                with open(gcp_file, 'r') as f:
                    existing = json.load(f)
        except:
            existing = {}

        existing[profile_name] = {
            "project_id": project_id,
            "credentials_path": credentials_path,
        }

        with open(gcp_file, 'w') as f:
            json.dump(existing, f, indent=2)

        os.chmod(gcp_file, 0o600)
        logger.info(f"Stored GCP credentials for profile: {profile_name}")

    def load_aws_credentials(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Load AWS credentials."""
        aws_file = self.config_dir / "aws.json"

        if not aws_file.exists():
            logger.warning(f"AWS credentials file not found at {aws_file}")
            return None

        try:
            with open(aws_file, 'r') as f:
                credentials = json.load(f)
                return credentials.get(profile_name)
        except Exception as e:
            logger.error(f"Failed to load AWS credentials: {e}")
            return None

    def load_azure_credentials(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Load Azure credentials."""
        azure_file = self.config_dir / "azure.json"

        if not azure_file.exists():
            logger.warning(f"Azure credentials file not found at {azure_file}")
            return None

        try:
            with open(azure_file, 'r') as f:
                credentials = json.load(f)
                return credentials.get(profile_name)
        except Exception as e:
            logger.error(f"Failed to load Azure credentials: {e}")
            return None

    def load_gcp_credentials(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Load GCP credentials."""
        gcp_file = self.config_dir / "gcp.json"

        if not gcp_file.exists():
            logger.warning(f"GCP credentials file not found at {gcp_file}")
            return None

        try:
            with open(gcp_file, 'r') as f:
                credentials = json.load(f)
                return credentials.get(profile_name)
        except Exception as e:
            logger.error(f"Failed to load GCP credentials: {e}")
            return None

    def get_aws_profiles(self) -> list:
        """Get list of stored AWS profiles."""
        aws_file = self.config_dir / "aws.json"

        if not aws_file.exists():
            return []

        try:
            with open(aws_file, 'r') as f:
                credentials = json.load(f)
                return list(credentials.keys())
        except:
            return []

    def get_azure_profiles(self) -> list:
        """Get list of stored Azure profiles."""
        azure_file = self.config_dir / "azure.json"

        if not azure_file.exists():
            return []

        try:
            with open(azure_file, 'r') as f:
                credentials = json.load(f)
                return list(credentials.keys())
        except:
            return []

    def get_gcp_profiles(self) -> list:
        """Get list of stored GCP profiles."""
        gcp_file = self.config_dir / "gcp.json"

        if not gcp_file.exists():
            return []

        try:
            with open(gcp_file, 'r') as f:
                credentials = json.load(f)
                return list(credentials.keys())
        except:
            return []

    def delete_aws_profile(self, profile_name: str):
        """Delete AWS profile."""
        aws_file = self.config_dir / "aws.json"

        if not aws_file.exists():
            return

        try:
            with open(aws_file, 'r') as f:
                credentials = json.load(f)

            if profile_name in credentials:
                del credentials[profile_name]

                with open(aws_file, 'w') as f:
                    json.dump(credentials, f, indent=2)

                logger.info(f"Deleted AWS profile: {profile_name}")
        except Exception as e:
            logger.error(f"Failed to delete AWS profile: {e}")

    def delete_azure_profile(self, profile_name: str):
        """Delete Azure profile."""
        azure_file = self.config_dir / "azure.json"

        if not azure_file.exists():
            return

        try:
            with open(azure_file, 'r') as f:
                credentials = json.load(f)

            if profile_name in credentials:
                del credentials[profile_name]

                with open(azure_file, 'w') as f:
                    json.dump(credentials, f, indent=2)

                logger.info(f"Deleted Azure profile: {profile_name}")
        except Exception as e:
            logger.error(f"Failed to delete Azure profile: {e}")

    def delete_gcp_profile(self, profile_name: str):
        """Delete GCP profile."""
        gcp_file = self.config_dir / "gcp.json"

        if not gcp_file.exists():
            return

        try:
            with open(gcp_file, 'r') as f:
                credentials = json.load(f)

            if profile_name in credentials:
                del credentials[profile_name]

                with open(gcp_file, 'w') as f:
                    json.dump(credentials, f, indent=2)

                logger.info(f"Deleted GCP profile: {profile_name}")
        except Exception as e:
            logger.error(f"Failed to delete GCP profile: {e}")

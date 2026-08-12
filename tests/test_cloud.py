"""Basic coverage for the cloud/ module (multi-cloud asset discovery).

Live SDK calls (boto3/azure-mgmt/google-cloud) require real credentials and
are lazy-imported by design, so they're not exercised here. These tests
cover the parts that don't need a live cloud account: dataclasses and the
cross-cloud correlation engine.
"""

import pytest

from pynetworkintel.cloud.correlation import CloudCorrelationEngine, AssetMapping


class TestCloudCorrelationEngine:
    def test_add_aws_resource_creates_asset(self):
        engine = CloudCorrelationEngine()
        engine.add_aws_resource(
            {
                "resource_id": "i-0123456789",
                "resource_type": "ec2_instance",
                "name": "web-1",
                "public_ip": "203.0.113.10",
                "private_ip": "10.0.1.5",
            }
        )
        assert len(engine.assets) == 1
        asset = next(iter(engine.assets.values()))
        assert asset.cloud_sources["aws"] == "i-0123456789"
        assert asset.primary_ip == "203.0.113.10"

    def test_ip_lookup_tracks_public_and_private(self):
        engine = CloudCorrelationEngine()
        engine.add_aws_resource(
            {
                "resource_id": "i-1",
                "resource_type": "ec2_instance",
                "name": "web-1",
                "public_ip": "203.0.113.10",
                "private_ip": "10.0.1.5",
            }
        )
        assert "203.0.113.10" in engine.ip_to_asset
        assert "10.0.1.5" in engine.ip_to_asset

    def test_same_name_and_ip_reuses_asset_across_calls(self):
        engine = CloudCorrelationEngine()
        resource = {
            "resource_id": "i-1",
            "resource_type": "ec2_instance",
            "name": "web-1",
            "public_ip": "203.0.113.10",
            "private_ip": "10.0.1.5",
        }
        engine.add_aws_resource(resource)
        engine.add_aws_resource(resource)
        # adding the identical resource twice should not create two assets
        assert len(engine.assets) == 1


class TestAssetMapping:
    def test_defaults_are_independent_lists(self):
        a = AssetMapping(asset_id="a1", asset_name="a", asset_type="ec2", cloud_sources={})
        b = AssetMapping(asset_id="b1", asset_name="b", asset_type="ec2", cloud_sources={})
        a.backup_ips.append("1.2.3.4")
        assert b.backup_ips == []

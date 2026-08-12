"""Basic coverage for the devops/ module (CI/CD & IaC static scanning).

Real, self-contained regex-based analysis - no external services needed to
test it, so this gets straightforward unit coverage.
"""

import pytest

from pynetworkintel.devops.cicd_scanner import CICDPipelineScanner
from pynetworkintel.devops.iac_validator import IaCValidator


class TestCICDPipelineScanner:
    def test_detects_unpinned_action(self):
        scanner = CICDPipelineScanner()
        workflow = """
        jobs:
          build:
            steps:
              - uses: actions/checkout@main
        """
        result = scanner.scan_github_actions(workflow)
        assert any(i["type"] == "unpinned_action" for i in result["issues"])

    def test_detects_missing_permissions(self):
        scanner = CICDPipelineScanner()
        workflow = "jobs:\n  build:\n    steps:\n      - run: echo hi\n"
        result = scanner.scan_github_actions(workflow)
        assert any(i["type"] == "overly_permissive" for i in result["issues"])

    def test_clean_workflow_flags_fewer_issues(self):
        scanner = CICDPipelineScanner()
        workflow = """
        permissions:
          contents: read
        jobs:
          build:
            steps:
              - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        """
        result = scanner.scan_github_actions(workflow)
        assert not any(i["type"] == "overly_permissive" for i in result["issues"])
        assert not any(i["type"] == "unpinned_action" for i in result["issues"])

    def test_result_shape(self):
        scanner = CICDPipelineScanner()
        result = scanner.scan_github_actions("jobs: {}")
        assert set(result.keys()) == {"workflow", "total_issues", "issues", "recommendations"}
        assert result["total_issues"] == len(result["issues"])


class TestIaCValidator:
    def test_detects_hardcoded_password(self):
        validator = IaCValidator()
        tf = 'resource "aws_db_instance" "default" {\n  password = "hunter2"\n}\n'
        result = validator.validate_terraform(tf)
        assert any(i["type"] == "hardcoded_secret" for i in result["issues"])

    def test_detects_public_s3_bucket(self):
        validator = IaCValidator()
        tf = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
        result = validator.validate_terraform(tf)
        assert any(i["type"] == "public_bucket" for i in result["issues"])

    def test_detects_open_security_group(self):
        validator = IaCValidator()
        tf = 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        result = validator.validate_terraform(tf)
        assert any(i["type"] == "overly_permissive_sg" for i in result["issues"])

    def test_clean_config_has_no_findings_of_those_types(self):
        validator = IaCValidator()
        tf = 'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n}\n'
        result = validator.validate_terraform(tf)
        flagged_types = {i["type"] for i in result["issues"]}
        assert "hardcoded_secret" not in flagged_types
        assert "public_bucket" not in flagged_types

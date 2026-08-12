"""Static security scanning for CI/CD pipelines and Infrastructure-as-Code.

Real, working regex/pattern-based static analysis (GitHub Actions workflows,
Terraform, SIEM export formatting) - a reasonable extension of "vulnerability
scanning" into the infrastructure that provisions the network being scanned,
and fully self-contained (no external services/credentials needed). Lighter
test coverage than the core discovery/analysis path - see
tests/test_devops.py.
"""

from .cicd_scanner import CICDPipelineScanner
from .iac_validator import IaCValidator
from .siem_integrator import SIEMIntegrator
from .compliance import ComplianceMapper

__all__ = [
    "CICDPipelineScanner",
    "IaCValidator",
    "SIEMIntegrator",
    "ComplianceMapper",
]

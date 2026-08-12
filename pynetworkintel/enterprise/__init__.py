"""EXPERIMENTAL / UNSUPPORTED - not part of the distributed package.

Multitenancy, HA/leader-election, auth, and a REST API server are
enterprise-platform building blocks, not network discovery/topology
mapping/vulnerability scanning - this tool's stated core purpose. They are
untested, not covered by any security review, and NOT included in the
pynetworkintel wheel/sdist (see pyproject.toml [tool.setuptools] packages).
This code is kept in the source tree only as a starting point for a
possible future SaaS/multi-user deployment mode; do not rely on it for
anything security-sensitive (e.g. AuthenticationManager) without a real
audit first.
"""

from .ha import HAArchitecture
from .multitenancy import TenantManager
from .authentication import AuthenticationManager
from .api import RESTAPIServer
from .observability import ObservabilityManager
from .compliance import ComplianceAuditor

__all__ = [
    "HAArchitecture",
    "TenantManager",
    "AuthenticationManager",
    "RESTAPIServer",
    "ObservabilityManager",
    "ComplianceAuditor",
]

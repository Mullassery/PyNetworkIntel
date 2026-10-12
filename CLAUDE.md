# PyNetworkIntel: Network Discovery, Topology Mapping & Vulnerability Scanning

**Status:** v1.4.0 | **License:** Apache License 2.0

This file documents what the codebase actually does, for engineers (human
or AI) working on it. Previous versions of this file made claims that did
not match the implementation (a "Type-safe Rust scanning engine" - there is
no Rust anywhere in this repo; fictional classes like `ContinuousMonitor`
and `AlertConfig` with APIs that don't exist). This version has been
corrected to describe the real, current implementation.

## What this actually is

A pure-Python CLI/library that wraps `nmap` (via `subprocess`) for host/
service discovery, optionally grabs config files from discovered devices
over SSH (`paramiko`), matches discovered service versions against rule-
based checks and the NVD CVE database, derives a simple subnet/gateway
topology graph from the results, and can produce a plain-English summary of
findings via the Anthropic API.

There is no Rust, no bundled ML models, and no cloud-hosted service - this
is a local tool you run against a target you specify.

## Real architecture: Discovery -> Analysis -> Reporting

```
target (IP / CIDR / hostname)
    |
[pynetworkintel.discovery]
  - NmapScanner: subprocess wrapper around `nmap -sV --script=smb-os-discovery
    -oX -`, parses the XML into Device/Service objects
    (pynetworkintel/discovery/scanner.py)
  - SSHConfigGrabber: paramiko SSH connection per device, reads a small
    fixed list of config files (sshd_config, sysctl.conf, hostname,
    os-release) and firewall rule dumps (pynetworkintel/discovery/ssh_config.py)
    - runs across devices concurrently via a bounded ThreadPoolExecutor
    |
[pynetworkintel.analysis]
  - RuleChecker: pattern-matches grabbed config content against a fixed
    rule list (e.g. PasswordAuthentication yes, telnet open)
    (pynetworkintel/analysis/rules.py)
  - CVEChecker: queries the public NVD REST API (services.nvd.nist.gov) by
    service name + version keyword, rate-limited, in-memory cached
    (pynetworkintel/analysis/cve.py) - this is a live network call, not
    offline/bundled data, despite earlier docs claiming "offline-first"
  - LLMAnalyzer: optional Anthropic API call to turn structured findings
    into a plain-English summary (pynetworkintel/analysis/llm.py)
    |
[pynetworkintel.topology]
  - TopologyMapper: groups devices into inferred subnets via `ipaddress`
    and derives gateway-style edges heuristically (no networkx dependency,
    no active route discovery/traceroute)
    |
[pynetworkintel.reporting / pynetworkintel.alerts / pynetworkintel.dashboard]
  - ReportGenerator: Markdown/JSON reports from the SQLAlchemy-backed
    scan history DB (pynetworkintel/db.py)
  - AlertManager: chat-webhook/email/generic webhook notification channels
  - Dashboard: terminal (Rich-based) live-scan viewer over a Unix socket
```

## `pynetworkintel.NetworkIntelligence` / `_mcp_connector.py` / `_mcp_tools.py`

`pynetworkintel/_mcp_connector.py` and `pynetworkintel/_mcp_tools.py` are
real, shipped, and exported in `__init__.py.__all__` (`NetworkIntelligence`).

`NetworkIntelligence` is **DB-backed** (defaults to `pynetworkintel.db.get_db()`)
and computes everything from scan history and the derived topology graph:
`analyze_network_flow` (topology reachability), `detect_anomalies` (diffs the
two most recent scans of a target via `ChangeDetector`),
`threat_correlation`/`get_threat_intelligence` (CVEs matched per indicator),
`get_asset_inventory`, `check_port_exposure` (observed ports/services),
`analyze_dns_records` (system resolver A/AAAA + DGA entropy heuristic),
`get_geolocation_analysis` (RFC 1918/public/reserved classification via
`ipaddress` only - no bundled geo DB), `behavioral_profiling`,
`remediation_recommendations`, `network_segmentation_analysis`
(`TopologyMapper` subnets), and `export_security_report`
(`ReportGenerator` markdown/json).

Capabilities without backing infrastructure raise `NotImplementedError`
instead of returning fabricated data: packet-flow `protocol_analysis`, the
`start_mcp_connector`/`stop_mcp_connector` MCP gateway (the old `dab`
subprocess is gone - use `PyNetworkIntelMCPHandler` directly),
geolocation/VPN lookups, and PDF output. The MCP handlers in `_mcp_tools.py`
delegate to `NetworkIntelligence` and surface `NotImplementedError` as an
explicit `not_implemented: true` result via `_with_error_result`. There are
**no external threat-intel, geolocation, or packet-flow data sources** in
this project - anything that would need one is either computed from local
scan data or refused.

Tested in `tests/test_mcp.py` (18 tests). The root `pynetworkintel.toml`
MCP-to-toole configuration file is not referenced by any code (see
`ROADMAP_HONEST.md` section 4).

## Entry points

- CLI: `pynetworkintel scan <target>` / `pynetworkintel analyze <target>`
  (`pynetworkintel/cli.py`)
- Library: `pynetworkintel.core.Scanner` (discovery only) and
  `pynetworkintel.core.Pipeline` (discovery + analysis, optional AI summary)
- `pynetworkintel.core.Analyzer` sits between them if you already have a
  `ScanResult` and just want analysis.

## Security-relevant behavior (as of v1.3.0)

- **Scan authorization**: `scan`/`analyze` refuse to run against a target
  without either `--i-am-authorized`, `PYNETWORKINTEL_I_AM_AUTHORIZED=1`, or
  an interactive "yes" at a confirmation prompt. See
  `cli.py:confirm_authorization`.
- **No default SSH user.** `--ssh-user` must be passed explicitly (was
  `root` by default before v1.3.0). If unset, SSH config grabbing is skipped
  with a warning rather than silently connecting as root.
- **No `--ssh-password` CLI flag.** Only `--ssh-key` and the
  `PYNETWORKINTEL_SSH_PASSWORD` env var are supported, to avoid credentials
  showing up in shell history / `ps` output.
- **SSH passwords are never persisted to disk.** `ConfigManager.save_config`
  excludes the password field entirely; the config file is chmod'd 0600.
- **SSH host key verification uses `paramiko.WarningPolicy`** (log a warning
  and proceed) rather than the previous `AutoAddPolicy` (silently accept) or
  a strict known-hosts-only policy (which would break on first contact with
  nearly every scanned device). See the docstring on
  `SSHConfigGrabber._connect` for the tradeoff.
- **Scan targets are validated** (`discovery/scanner.py:validate_target`)
  before reaching the `nmap` argv, rejecting anything that isn't a
  plausible IP/CIDR/hostname (in particular, anything starting with `-`,
  which would otherwise be interpreted as an nmap flag).

## Module status (see README.md "Module status" for the full table with coverage numbers)

Coverage varies a lot within what earlier docs lumped together as "the
tested core" - measured with `pytest --cov` during the 2026-09
standardization pass:

- `models.py`, `topology.py`, `topology_export.py`, `analysis/cve.py`,
  `analysis/rules.py`, `db.py`, `config.py`: 83-100% - genuinely
  well-tested.
- `discovery/scanner.py`: 64%.
- `core.py`, `discovery/ssh_config.py`, `analysis/llm.py`: 34-48% (the
  security-relevant paths in these are covered by `tests/test_security.py`
  specifically; general code paths have real gaps).
- `cli.py`, `dashboard.py`, `scheduler.py`, `alerts.py`, `changes.py`,
  `reporting.py`: 10-52% - thin. `reporting.py` is 10%.

`cloud/`, `kubernetes/`, `iot/`, `ml/`, `devops/` are real, working, but
lighter-tested extensions shipped in the package (11-45% coverage) - see
their module docstrings for what's covered.

`enterprise/` and `architect/` are **not shipped** in the distributed
package (excluded in `pyproject.toml`'s `[tool.setuptools] packages`) - see
their module docstrings for why.

## Development

- Tests: `pytest tests/ -v` (see `tests/`)
- CI: `.github/workflows/tests.yml` runs `pytest tests/ -v` on 3.10/3.11/3.12
  and fails the build on any test failure (previously it swallowed all
  failures with `|| echo "No tests"` - fixed).
- Build: `python -m build`; publish: `python -m twine upload dist/*`
  (`pyproject.toml` is the sole source of build metadata - `setup.py` was
  removed as a stale, contradictory duplicate).

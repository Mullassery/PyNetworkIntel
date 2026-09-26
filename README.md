# PyNetworkIntel

**Discover what's on your network. Map how it's connected. Find what's vulnerable.**

PyNetworkIntel scans a network target with `nmap`, optionally pulls
configuration from reachable devices over SSH, checks discovered services
against known vulnerability rules and the NVD CVE database, and derives a
subnet/gateway topology graph from the results - in plain Python, with no
hidden network calls beyond nmap/SSH/NVD/(optional) Anthropic.

[![Tests](https://github.com/Mullassery/PyNetworkIntel/actions/workflows/tests.yml/badge.svg)](https://github.com/Mullassery/PyNetworkIntel/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/pynetworkintel)](https://pypi.org/project/pynetworkintel)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

---

## Before you scan anything

This tool actively probes network hosts. **Only scan networks and devices
you own or have explicit written permission to test.** Unauthorized network
scanning may be illegal in your jurisdiction. Both the CLI and the
underlying commands require you to confirm authorization before a scan
runs (see [Security](#security) below) - this isn't a formality, it's there
so the tool never scans a target silently just because it was handed one.

---

## 30-Second Start

```bash
pip install pynetworkintel
# nmap must also be installed and on PATH (brew install nmap / apt install nmap / etc.)

pynetworkintel scan 192.168.1.0/24
# -> prompts to confirm you're authorized to scan this target, then runs
```

```python
from pynetworkintel import Scanner

scanner = Scanner()  # no SSH by default - see "SSH config grabbing" below
result = scanner.scan("192.168.1.0/24")

for device in result.devices:
    print(f"{device.ip} ({device.hostname or 'unknown'})")
    for service in device.services:
        print(f"  - {service.name} {service.version or ''} on port {service.port}")

print(result.topology().to_dict())  # subnet groupings + inferred gateway edges
```

---

## Use cases

- **A one-off network inventory** — `pynetworkintel scan <subnet>` for
  "what's actually on this network right now," with a real topology graph,
  not a flat list.
- **Recurring drift/change detection** — repeated scans against the same
  SQLite history to catch new/removed devices between runs.
- **Pairing discovery with vulnerability triage** — `analyze` cross-checks
  discovered services against config-based rules and live NVD CVE lookups
  in one pass.
- **Not yet a good fit for:** enterprise multitenancy/HA/auth/REST API, or
  a conversational architecture advisor — both are explicitly excluded
  from the package (see [Module status](#module-status)), not partially
  built.

## Key Features

- **Device discovery** - `nmap -sV` based host/port/service discovery
  (`pynetworkintel.discovery`)
- **Topology mapping** - a real graph (nodes/edges), not just a flat device
  list: devices are grouped into inferred subnets, with gateway-style edges
  derived from IP addressing (`pynetworkintel.topology`)
- **Vulnerability detection** - config-based rule checks (weak SSH settings,
  telnet exposure, etc.) plus live NVD CVE lookups by service/version
  (`pynetworkintel.analysis`)
- **Optional SSH config grabbing** - pulls `sshd_config`, firewall rules,
  etc. from devices you have credentials for, concurrently across devices
- **Change tracking** - detects new/removed devices across scans, backed by
  a local SQLite/SQLAlchemy history (`pynetworkintel.changes`, `pynetworkintel.db`)
- **Reports & alerts** - Markdown/JSON reports, chat-webhook/email/generic
  webhook alert channels (`pynetworkintel.reporting`, `pynetworkintel.alerts`)
- **Optional AI summary** - plain-English findings summary via the
  Anthropic API, only when `--summarize` / `summarize=True` is used

---

## vs nmap

PyNetworkIntel doesn't replace nmap - its own discovery step *is* an
`nmap -sV` subprocess call (`pynetworkintel/discovery/scanner.py`). The
honest comparison isn't "who scans faster," it's "what do you get beyond
raw nmap output for roughly the same scan time."

Measured live against this machine's own local `/24` (2026-09-22, 2 hosts
up: a gateway router and this laptop - a small real network, not a lab
fixture):

| | `nmap -sV 192.168.1.0/24` (raw) | `pynetworkintel scan 192.168.1.0/24` |
|---|---|---|
| Hosts found | 2 | 2 (identical) |
| Scan time | 134.4s | 146.1s (+~9%, parsing/topology/DB overhead) |
| Output | Text/XML port+service list | Structured JSON: devices, services, topology graph, scan history |
| Topology graph | No (traceroute is separate, manual) | Yes - inferred gateway/subnet edges, `--output graphml`/`d3-json` for Gephi/yEd/D3 |
| CVE cross-referencing | No (NSE `--script vuln` exists but is a separate manual step, offline rule set) | Yes - live NVD REST lookups by service+version, plus config-based rule checks (weak SSH, telnet exposure) via optional SSH grab |
| Change tracking across runs | No (external diffing required) | Yes - SQLite-backed history, detects new/removed devices |
| Scan-authorization gate | No | Yes - refuses to run without `--i-am-authorized` or interactive confirmation |

On this run, neither tool recovered version strings for the services found
(router's `https`/`pharos` ports, laptop's `postgresql`/`rtsp`/`http-proxy`
ports all fingerprinted as bare service names by nmap's own `-sV` probe) -
so the live NVD CVE check correctly returned 0 findings rather than
guessing. That's a real limitation of this specific network's service
fingerprints, not a PyNetworkIntel bug - worth knowing before expecting CVE
hits on a quiet home network.

**Bottom line:** if you just want "what's listening where," raw nmap is
lighter-weight and has no Python dependency. PyNetworkIntel is worth it
when you want the same scan turned into a structured, versioned,
CVE-annotated, graphable asset inventory instead of scrollback text - at
roughly a 9% time cost on top of the nmap call it already makes.

---

## Installation

```bash
pip install pynetworkintel
```

Requires the `nmap` binary to be installed separately and on `PATH`
(the Python package wraps it via `subprocess`; without it, discovery
returns no results but the rest of the API still works, e.g. for testing).

Optional extras for the lighter-tested cloud/kubernetes asset-discovery
modules (see [Module status](#module-status)):

```bash
pip install "pynetworkintel[cloud]"       # boto3, azure-mgmt-*, google-cloud-*
pip install "pynetworkintel[kubernetes]"  # kubernetes python client
```

---

## CLI Usage

```bash
# Scan a subnet (prompts for scan authorization the first time)
pynetworkintel scan 192.168.1.0/24

# Scan and grab SSH config from reachable devices (explicit --ssh-user required;
# there is no default user, on purpose - see Security below)
pynetworkintel scan 192.168.1.0/24 --ssh-user admin --ssh-key ~/.ssh/id_rsa

# Non-interactive / CI use: skip the confirmation prompt explicitly
pynetworkintel scan 192.168.1.0/24 --i-am-authorized

# Full pipeline: scan + vulnerability analysis + AI summary
pynetworkintel analyze 192.168.1.0/24 --summarize

# JSON output (includes devices, findings, and the topology graph)
pynetworkintel scan 192.168.1.0/24 --output json

# Save results to a file
pynetworkintel analyze 192.168.1.0/24 --output-file results.json
```

SSH passwords are **never** accepted as a CLI flag (they'd end up in shell
history and process listings). Use `--ssh-key` or set
`PYNETWORKINTEL_SSH_PASSWORD` in the environment instead.

---

## Python API

```python
from pynetworkintel import Pipeline

pipeline = Pipeline(
    ssh_username="admin",       # optional; omit to skip SSH config grabbing
    ssh_key_path="~/.ssh/id_rsa",
)
result = pipeline.run("192.168.1.0/24", summarize=False)

print(result["summary"])   # counts: devices, findings by severity, subnets
print(result["topology"])  # {"nodes": [...], "edges": [...], "subnets": [...]}
for finding in result["findings"]:
    print(finding["severity"], finding["title"])
```

---

## Security

PyNetworkIntel is a dual-use network scanning tool, and the security
posture of the tool itself is treated as a first-class concern, not an
afterthought:

- **Scan authorization is required.** `scan`/`analyze` will not run without
  `--i-am-authorized`, `PYNETWORKINTEL_I_AM_AUTHORIZED=1`, or an interactive
  confirmation.
- **No default SSH user.** You must pass `--ssh-user` explicitly; the tool
  will not assume `root` (or anything else) on your behalf.
- **No `--ssh-password` flag.** Use `--ssh-key` or the
  `PYNETWORKINTEL_SSH_PASSWORD` environment variable.
- **SSH passwords are never written to disk**, including in the persisted
  config file (`~/.pynetworkintel/config.yaml`, which is chmod'd `0600`).
- **SSH host key verification** uses `paramiko.WarningPolicy` (logs loudly
  on an unknown/changed host key rather than silently trusting it). See
  `pynetworkintel/discovery/ssh_config.py` for the documented tradeoff -
  first-contact scanning of arbitrary devices is fundamentally in tension
  with strict known-hosts verification.
- **Scan targets are validated** before reaching the `nmap` command line,
  rejecting anything that isn't a plausible IP/CIDR/hostname (in particular
  anything starting with `-`, which would otherwise be parsed as an nmap
  flag).
- Dependency versions are pinned with upper bounds in `pyproject.toml`.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

---

## Module status

Being direct about what's tested and what's real-but-lighter-tested vs. not
shipped at all:

| Module | Status | Notes |
|---|---|---|
| `models`, `topology`, `topology_export`, `analysis/cve`, `analysis/rules`, `db`, `config` | **Core, well-tested** | 83-100% line coverage (measured with `pytest --cov`); this is where the primary, meaningful test coverage lives |
| `discovery/scanner` | **Core, tested** | 64% line coverage; XML parsing, target validation, and per-record error isolation are covered, some subprocess edge cases aren't |
| `core`, `discovery/ssh_config`, `analysis/llm` | **Core, partially tested** | 34-48% line coverage - the security-relevant paths (auth gate, SSH defaults, no-password-flag) are well covered by `tests/test_security.py`, but general code paths in these files have real gaps |
| `cli`, `dashboard`, `scheduler`, `alerts`, `changes`, `reporting` | **Core, thin test coverage** | 10-52% line coverage measured directly - previous versions of this README called these "tested" alongside the 90-100%-covered modules above; that conflated very different actual coverage levels. `reporting.py` in particular is 10% covered. |
| `cloud` (major cloud provider asset discovery) | Shipped, lighter-tested | Real code, lazy-imports SDKs (boto3, azure-mgmt-*, google-cloud-*) via the `cloud` extra; 12-34% line coverage |
| `kubernetes` (cluster/RBAC/pod security) | Shipped, lighter-tested | Real code, lazy-imports the `kubernetes` client via the `kubernetes` extra; 11-25% line coverage |
| `iot` (MQTT/CoAP/Modbus/S7comm discovery) | Shipped, lighter-tested | Real socket-based probing; 19-41% line coverage |
| `ml` (statistical baselines/anomaly detection) | Shipped, lighter-tested | Real `statistics`-based logic, not a trained model - "ML" in the name overstates it; 38-45% line coverage |
| `devops` (CI/CD & IaC static scanning) | Shipped, lighter-tested | Real regex-based Terraform/GitHub Actions scanning, self-contained; 18-44% line coverage |
| `enterprise` (multitenancy, HA, auth, REST API) | **Not shipped** | Excluded from the package entirely - enterprise-platform scope, unrelated to network discovery, untested |
| `architect` (conversational architecture advisor) | **Not shipped** | Excluded from the package entirely - unrelated to network discovery |
| `_mcp_connector.py` / `_mcp_tools.py` (`NetworkIntelligence`, exported from `pynetworkintel.__init__`) | **Shipped but fake - do not use** | Every method returns hardcoded fake data (e.g. a hardcoded `"src_ip": "192.168.1.100"`), not real analysis. Untested, undocumented until this pass, references a `dab` binary and `statguardian` package this project does not depend on. See `ROADMAP_HONEST.md`. |

---

## Requirements

- Python 3.10+
- `nmap` installed and on `PATH` for live scanning
- SSH access (key or password) to a device, only if you want config grabbing
- An Anthropic API key, only if you use `--summarize`

---

## Documentation

- [Dashboard](docs/DASHBOARD.md) - the live terminal stats viewer (`--dashboard`)
- [CLAUDE.md](CLAUDE.md) - accurate architecture description for engineers
  (human or AI) working on this codebase
- [ROADMAP_HONEST.md](ROADMAP_HONEST.md) - current honest status: what's
  fixed, what's broken, what's a fake stub, what's genuinely pending, and
  technical debt with file:line specifics
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md),
  [SECURITY.md](SECURITY.md)

`docs/ARCHITECTURE.md`, `docs/PRODUCT_VISION.md`, and `docs/ROADMAP.md` are
stale/placeholder documents from earlier planning and are not kept in sync
with the implementation (each now has an in-file banner saying so); refer
to [CLAUDE.md](CLAUDE.md) and [ROADMAP_HONEST.md](ROADMAP_HONEST.md)
instead. `docs/VERSION_MANAGEMENT.md` was corrected in this pass and is
accurate.

---

## Known Issues

- **Fake stub shipped in the public API**: `pynetworkintel.NetworkIntelligence`
  (`_mcp_connector.py`/`_mcp_tools.py`) returns hardcoded fake data, not real
  analysis - see [Module status](#module-status) and `ROADMAP_HONEST.md`.
- **Lighter-tested modules**: `cloud`, `kubernetes`, `iot`, `ml`, and
  `devops` are real, shipped code but have less test coverage than the
  core scan -> analyze -> topology path; see [Module status](#module-status).
- **Stale planning docs**: `docs/ARCHITECTURE.md`, `docs/PRODUCT_VISION.md`,
  and `docs/ROADMAP.md` predate the current implementation and are not kept
  in sync - each now carries an in-file banner saying so; use
  [CLAUDE.md](CLAUDE.md) and `ROADMAP_HONEST.md` for accurate descriptions
  instead.
- **Misleading git tag**: the local `v2.0.0` tag points at a commit older
  and less complete than `v1.4.0` (an out-of-order/mislabeled tag from
  earlier history) - don't trust tag names as a version indicator; see
  `ROADMAP_HONEST.md`.
- **`paramiko` 3.5.1 has an open advisory** (PYSEC-2026-2858, SHA-1 allowed
  in `rsakey.py`) with no fixed release available yet as of this pass; see
  `ROADMAP_HONEST.md` for tracking.
- **No committed performance benchmarks.** There is no benchmark script or
  results file in this repo, so no throughput/latency numbers are claimed
  anywhere in this README.
- **No open GitHub issues** and no `TODO`/`FIXME` markers in `pynetworkintel/`
  as of this pass (though there is real lint debt - 23 bare `except:`
  clauses and ~48 files not `black`-formatted; see `ROADMAP_HONEST.md`).
- `pynetworkintel/__init__.py`'s `__version__` had drifted to `1.3.1` while
  `pyproject.toml` moved on to `1.4.0` - fixed in this pass, and
  `scripts/check-version-sync.sh` now checks both files so it won't
  silently recur.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).

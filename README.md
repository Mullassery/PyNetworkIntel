# PyNetworkIntel

Discover what's on your network, map how it's connected, and triage vulnerabilities — a pure-Python wrapper around `nmap`, SSH config grabs, rule checks, and live NVD lookups.

[![Tests](https://github.com/Mullassery/PyNetworkIntel/actions/workflows/tests.yml/badge.svg)](https://github.com/Mullassery/PyNetworkIntel/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/pynetworkintel)](https://pypi.org/project/pynetworkintel/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Before you scan anything:** this tool actively probes network hosts. Only
> scan networks and devices you own or have explicit written permission to test.
> Unauthorized scanning may be illegal in your jurisdiction. `scan`/`analyze`
> refuse to run without `--i-am-authorized`, `PYNETWORKINTEL_I_AM_AUTHORIZED=1`,
> or an interactive confirmation.

> **Not to be confused with [PyAPICheck](https://github.com/Mullassery/PyAPICheck):** PyNetworkIntel maps devices, services, and vulnerabilities on a network; PyAPICheck focuses on API security and policy.

## Which project do I need?

Part of the Mullassery open-source family. These tools have similar names — here is the short version of who does what:

| If you need to… | Use |
| --- | --- |
| Build a repository's dependency graph and match it against vulnerability advisories (Python, Rust, Node, containers) | [PyDeepMesh](https://github.com/Mullassery/PyDeepMesh) |
| Understand *why* a Python dependency exists, who added it, and whether it is actually used | [PyDependencyCheck](https://github.com/Mullassery/PyDependencyCheck) |
| Statically analyze a **dbt** project (risky tests, test blast radius, cost) | [PyDBTGuard](https://github.com/Mullassery/PyDBTGuard) |
| Statically analyze **Apache Beam / Dataflow** pipelines (cost, hot keys, reliability) | [PyBeamGuard](https://github.com/Mullassery/PyBeamGuard) |
| Validate **Airflow** DAGs and dbt runs | [PyAirflowTester](https://github.com/Mullassery/PyAirflowTester) |
| Simulate cascading-failure **blast radius** across infrastructure, data pipelines, and AI systems | [PyBlastRadius](https://github.com/Mullassery/PyBlastRadius) |
| Check the **quality of the data itself** at runtime (schema, drift, anomalies) | [StatGuardian](https://github.com/Mullassery/StatGuardian) |
| Discover **devices, services, and vulnerabilities on a network** | [PyNetworkIntel](https://github.com/Mullassery/PyNetworkIntel) |
| Discover and score **API security** risk (real traffic, agent/MCP, Cedar policy) | [PyAPICheck](https://github.com/Mullassery/PyAPICheck) |
| Trace and root-cause **AI agent** failures | [PyAgentHound](https://github.com/Mullassery/PyAgentHound) |
| Diagnose **RAG retrieval** failures | [PyVectorHound](https://github.com/Mullassery/PyVectorHound) |
| Orchestrate **local, dependency-aware tasks** (DAG scheduler + content-addressed cache) | [PyTaskWireCheck](https://github.com/Mullassery/PyTaskWireCheck) |

[Browse all projects →](https://github.com/Mullassery?tab=repositories)

## What it is

PyNetworkIntel is a CLI and library that runs `nmap -sV` against a target, parses
the results into devices and services, optionally grabs configuration files from
reachable devices over SSH, checks discovered services against rule-based checks
and the NVD CVE database, and derives a subnet/gateway topology graph from the
results. An optional `--summarize` step produces a plain-English findings summary
via the Anthropic API.

It is pure Python with no bundled Rust engine, no trained ML models, and no
cloud-hosted service. Beyond `nmap`, SSH, NVD, and (only if you opt in) Anthropic,
it makes no hidden network calls.

## Features / Highlights

- **Device discovery** — `nmap -sV`-based host/port/service discovery
  (`pynetworkintel.discovery`).
- **Topology mapping** — a real nodes/edges graph, not a flat list: devices are
  grouped into inferred subnets with gateway-style edges derived from IP
  addressing (`pynetworkintel.topology`); export to GraphML or d3-json.
- **Vulnerability detection** — config-based rule checks (weak SSH settings,
  telnet exposure, etc.) plus live NVD CVE lookups by service/version
  (`pynetworkintel.analysis`).
- **Optional SSH config grabbing** — pulls `sshd_config`, firewall rules, and
  similar from devices you have credentials for, concurrently across hosts.
- **Change tracking** — detects new/removed devices across scans, backed by a
  local SQLite/SQLAlchemy history (`pynetworkintel.changes`, `pynetworkintel.db`).
- **Reports & alerts** — Markdown/JSON reports and chat-webhook/email/generic
  webhook alert channels (`pynetworkintel.reporting`, `pynetworkintel.alerts`).
- **Optional AI summary** — a plain-English findings summary via the Anthropic
  API, only when `--summarize` / `summarize=True` is used.
- **Shipped extensions** — cloud, Kubernetes, IoT, statistical-baseline ("ml"),
  and DevOps/IaC static-scanning modules (real, but lighter-tested — see
  [Module status](#module-status)).

## Who it's for / Use cases

- **A one-off network inventory** — `pynetworkintel scan <subnet>` for "what's
  actually on this network right now," with a real topology graph.
- **Recurring drift/change detection** — repeated scans against the same SQLite
  history to catch new/removed devices between runs.
- **Pairing discovery with vulnerability triage** — `analyze` cross-checks
  discovered services against config rules and live NVD CVEs in one pass.
- **Homelab, lab, and small-office operators** who want a structured,
  versioned, CVE-annotated, graphable asset inventory instead of scrollback text.

## What it is not

- **Not a replacement for `nmap`.** Its discovery step *is* an `nmap -sV`
  subprocess call. Raw nmap is lighter-weight if all you want is "what's
  listening where."
- **Not an enterprise platform.** Multitenancy, HA, auth, and a REST API
  (`enterprise`) and a conversational architecture advisor (`architect`) are
  **not shipped** — excluded from the package entirely.
- **Not offline-first CVE data.** CVE checks are live NVD REST calls, and the
  optional summary is a live Anthropic call. Neither is used unless enabled.
- **Not benchmarked.** There is no committed benchmark script or results file,
  so no throughput/latency numbers are claimed here.
- **Not uniformly hardened.** Several shipped modules have thin test coverage
  (see [Module status](#module-status)); the core scan → analyze → topology path
  is where the meaningful coverage lives.

## Project status

**Beta (v1.5.0).** The core discovery → analysis → topology → reporting path is
implemented and tested. The `cloud`, `kubernetes`, `iot`, `ml`, and `devops`
extensions ship but are lighter-tested. `enterprise` and `architect` are excluded
from the distributed package. See [ROADMAP_HONEST.md](ROADMAP_HONEST.md) for the
current honest status and [CLAUDE.md](CLAUDE.md) for an accurate architecture
description.

## Installation

```bash
pip install pynetworkintel
```

The `nmap` binary must be installed separately and on `PATH` (the package wraps
it via `subprocess`). Without it, discovery returns no results, but the rest of
the API still works.

Optional extras for the lighter-tested cloud/Kubernetes asset-discovery modules:

```bash
pip install "pynetworkintel[cloud]"       # boto3, azure-mgmt-*, google-cloud-*
pip install "pynetworkintel[kubernetes]"  # kubernetes python client
```

## Quick start

```bash
pip install pynetworkintel
# nmap must also be installed and on PATH (brew install nmap / apt install nmap / etc.)

pynetworkintel scan 192.168.1.0/24
# -> prompts to confirm you're authorized to scan this target, then runs
```

```python
from pynetworkintel import Scanner

scanner = Scanner()  # no SSH by default
result = scanner.scan("192.168.1.0/24")

for device in result.devices:
    print(f"{device.ip} ({device.hostname or 'unknown'})")
    for service in device.services:
        print(f"  - {service.name} {service.version or ''} on port {service.port}")

print(result.topology().to_dict())  # subnet groupings + inferred gateway edges
```

## Usage

CLI:

```bash
# Scan a subnet (prompts for scan authorization the first time)
pynetworkintel scan 192.168.1.0/24

# Grab SSH config from reachable devices (explicit --ssh-user required)
pynetworkintel scan 192.168.1.0/24 --ssh-user admin --ssh-key ~/.ssh/id_rsa

# Non-interactive / CI use: skip the confirmation prompt explicitly
pynetworkintel scan 192.168.1.0/24 --i-am-authorized

# Full pipeline: scan + vulnerability analysis + AI summary
pynetworkintel analyze 192.168.1.0/24 --summarize

# JSON output (devices, findings, and the topology graph)
pynetworkintel scan 192.168.1.0/24 --output json

# Save results to a file
pynetworkintel analyze 192.168.1.0/24 --output-file results.json
```

SSH passwords are **never** accepted as a CLI flag. Use `--ssh-key` or set
`PYNETWORKINTEL_SSH_PASSWORD` in the environment.

Python pipeline API:

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

## Module status

Being direct about what is tested vs. real-but-lighter-tested vs. not shipped:

| Module | Status | Notes |
|---|---|---|
| `models`, `topology`, `topology_export`, `analysis/cve`, `analysis/rules`, `db`, `config` | **Core, well-tested** | 83–100% line coverage (`pytest --cov`); primary meaningful coverage lives here. |
| `discovery/scanner` | **Core, tested** | ~64% coverage; XML parsing, target validation, per-record error isolation covered. |
| `core`, `discovery/ssh_config`, `analysis/llm` | **Core, partially tested** | 34–48% coverage; security-relevant paths covered by `tests/test_security.py`. |
| `cli`, `dashboard`, `scheduler`, `alerts`, `changes`, `reporting` | **Core, thin coverage** | 10–52% coverage; `reporting.py` is ~10%. |
| `cloud`, `kubernetes`, `iot`, `ml`, `devops` | Shipped, lighter-tested | Real code, lazy-imported SDKs; 11–45% coverage. The `ml` module is `statistics`-based, not a trained model. |
| `enterprise`, `architect` | **Not shipped** | Excluded from the package in `pyproject.toml`; enterprise-platform scope, unrelated to network discovery. |

## Security

- **Scan authorization is required** — `--i-am-authorized`,
  `PYNETWORKINTEL_I_AM_AUTHORIZED=1`, or interactive confirmation.
- **No default SSH user** — `--ssh-user` must be passed explicitly.
- **No `--ssh-password` flag** — use `--ssh-key` or the
  `PYNETWORKINTEL_SSH_PASSWORD` environment variable.
- **SSH passwords are never persisted to disk** — the config file
  (`~/.pynetworkintel/config.yaml`) is chmod'd `0600`.
- **SSH host key verification** uses `paramiko.WarningPolicy`.
- **Scan targets are validated** before reaching the `nmap` argv.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Documentation

- [docs/DASHBOARD.md](docs/DASHBOARD.md) — the live terminal stats viewer
  (`--dashboard`).
- [CLAUDE.md](CLAUDE.md) — accurate architecture description for engineers
  working on the codebase.
- [ROADMAP_HONEST.md](ROADMAP_HONEST.md) — current honest status and technical
  debt with file:line specifics.
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md),
  [SECURITY.md](SECURITY.md).

`docs/ARCHITECTURE.md`, `docs/PRODUCT_VISION.md`, and `docs/ROADMAP.md` are
stale/placeholder documents from earlier planning, each carrying an in-file
banner saying so — refer to `CLAUDE.md` and `ROADMAP_HONEST.md` instead.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Development
workflow:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

CI (`.github/workflows/tests.yml`) runs `pytest tests/ -v` on Python 3.10/3.11/3.12
and fails the build on any test failure.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

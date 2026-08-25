# PyNetworkIntel

**Discover what's on your network. Map how it's connected. Find what's vulnerable.**

PyNetworkIntel scans a network target with `nmap`, optionally pulls
configuration from reachable devices over SSH, checks discovered services
against known vulnerability rules and the NVD CVE database, and derives a
subnet/gateway topology graph from the results - in plain Python, with no
hidden network calls beyond nmap/SSH/NVD/(optional) Anthropic.

[![PyPI](https://img.shields.io/pypi/v/pynetworkintel)](https://pypi.org/project/pynetworkintel)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-blue.svg)](./LICENSE)

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
| `discovery`, `analysis`, `models`, `topology`, `core`, `cli`, `config` | **Core, tested** | The scan -> analyze -> topology path; primary test coverage lives here |
| `reporting`, `alerts`, `changes`, `dashboard`, `scheduler`, `db` | **Core, tested** | Report generation, change tracking, live terminal dashboard |
| `cloud` (major cloud provider asset discovery) | Shipped, lighter-tested | Real code, lazy-imports SDKs (boto3, azure-mgmt-*, google-cloud-*) via the `cloud` extra |
| `kubernetes` (cluster/RBAC/pod security) | Shipped, lighter-tested | Real code, lazy-imports the `kubernetes` client via the `kubernetes` extra |
| `iot` (MQTT/CoAP/Modbus/S7comm discovery) | Shipped, lighter-tested | Real socket-based probing; arguably core to "everything connected to your network," just less exercised |
| `ml` (statistical baselines/anomaly detection) | Shipped, lighter-tested | Real `statistics`-based logic, not a trained model - "ML" in the name overstates it |
| `devops` (CI/CD & IaC static scanning) | Shipped, lighter-tested | Real regex-based Terraform/GitHub Actions scanning, self-contained |
| `enterprise` (multitenancy, HA, auth, REST API) | **Not shipped** | Excluded from the package entirely - enterprise-platform scope, unrelated to network discovery, untested |
| `architect` (conversational architecture advisor) | **Not shipped** | Excluded from the package entirely - unrelated to network discovery |

---

## Requirements

- Python 3.10+
- `nmap` installed and on `PATH` for live scanning
- SSH access (key or password) to a device, only if you want config grabbing
- An Anthropic API key, only if you use `--summarize`

---

## Documentation

- [Dashboard](docs/DASHBOARD.md) - the live terminal stats viewer (`--dashboard`)

`docs/ARCHITECTURE.md`, `docs/PRODUCT_VISION.md`, and `docs/ROADMAP.md` are
stale/placeholder documents from earlier planning and are not kept in sync
with the implementation; refer to [CLAUDE.md](CLAUDE.md) for an accurate
architecture description instead.

---

## Known Issues

- **Lighter-tested modules**: `cloud`, `kubernetes`, `iot`, `ml`, and
  `devops` are real, shipped code but have less test coverage than the
  core scan -> analyze -> topology path; see [Module status](#module-status).
- **Stale planning docs**: `docs/ARCHITECTURE.md`, `docs/PRODUCT_VISION.md`,
  and `docs/ROADMAP.md` predate the current implementation and are not kept
  in sync - use [CLAUDE.md](CLAUDE.md) for an accurate description instead.
- **No committed performance benchmarks.** There is no benchmark script or
  results file in this repo, so no throughput/latency numbers are claimed
  anywhere in this README.
- **No open GitHub issues** and no `TODO`/`FIXME` markers in `pynetworkintel/`
  as of this pass.
- Published version on PyPI (`1.3.1`) matches this repo's `pyproject.toml`;
  no version drift.

---

## License

Proprietary License - free to use with explicit attribution. See [LICENSE](LICENSE).

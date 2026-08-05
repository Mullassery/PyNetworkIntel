# PyNetworkIntel

**Know what's on your network. Find everything. Automatically.**

Discover every device, service, and vulnerability on your network in minutes. Map network topology, inventory services, analyze security risks. Works on homelabs, enterprises, and everything in between.

[![PyPI](https://img.shields.io/pypi/v/pynetworkintel)](https://pypi.org/project/pynetworkintel)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![Tests Passing](https://img.shields.io/badge/tests-passing-success)](./tests)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-blue.svg)](./LICENSE)

---

## 30-Second Start

```python
from pynetworkintel import Scan

# Discover everything on your network
scan = Scan()
devices = scan.discover("192.168.1.0/24")

# See what's running
for device in devices:
    print(f"{device.hostname} ({device.ip})")
    for service in device.services:
        print(f"  - {service.name}: {service.port}")
```

---

## Why PyNetworkIntel?

**The Problem:**
- Your network is a black box. What's actually connected?
- Manual discovery is tedious and error-prone
- Security threats hiding in plain sight
- No map of what talks to what

**The Solution:**
- Automatic device discovery and service inventory
- Visual network topology mapping
- Security vulnerability detection
- Change tracking (what's new?)

---

## Key Features

- **Device Discovery:** Automatically find all computers, servers, IoT devices
- **Service Inventory:** Know what's running on every device
- **Topology Mapping:** Visualize connections between devices
- **Vulnerability Detection:** Identify open ports, old software, misconfigurations
- **Change Tracking:** Alert when new devices appear or services change
- **Export Reports:** Generate compliance and audit reports
- **API Access:** Query network data programmatically

---

## Real-World Use Cases

**Home Lab Security:**
```python
# Find all devices on your network
scan = Scan("192.168.1.0/24")
devices = scan.discover()

# Alert if anything new appears
for device in devices:
    if device.is_new:
        print(f"New device found: {device.hostname}")
```

**Enterprise Network Audit:**
```python
# Generate compliance report
scan = Scan("10.0.0.0/16")
report = scan.generate_report(format="pdf")
print(f"Report: {report.devices_found} devices")
```

**Security Assessment:**
```python
# Find vulnerable services
scan = Scan()
vulnerabilities = scan.find_vulnerabilities()
for vuln in vulnerabilities:
    print(f"{vuln.service}: {vuln.risk_level}")
```

---

## What You Get

- **Network Map:** Visual diagram of all devices and connections
- **Device Inventory:** Every device with hostname, OS, services
- **Service List:** Every open port and what's listening
- **Vulnerability Report:** Security risks ranked by severity
- **Change Log:** What's new since last scan
- **Historical Data:** Track changes over time

---

## Installation

```bash
pip install pynetworkintel
# or with uv
uv pip install pynetworkintel
```

---

## Documentation

- [Quick Start](docs/QUICKSTART.md) — Scan your first network
- [Network Mapping](docs/MAPPING.md) — Understand topology
- [Security Analysis](docs/SECURITY.md) — Find vulnerabilities
- [Examples](examples/) — Real-world scans

---

## License

Proprietary License - Free to use with explicit attribution. See [LICENSE](LICENSE).

---

**PyNetworkIntel v2.0.0** | Network discovery & mapping | Python 3.10+

## License

MIT

---

**MCP 2.0 Mega-Platform | v2.0.0 | Wheels-Only Distribution**

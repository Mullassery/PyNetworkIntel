# PyNetworkIntel

AI-powered network intelligence and vulnerability discovery platform.

Automatically discovers devices, detects security misconfigurations, checks for known vulnerabilities, and provides plain-English explanations of findings.

## Installation

```bash
pip install pynetworkintel
```

## Quick Start

### Basic Network Scan

```bash
pynetworkintel scan 192.168.1.0/24
```

### Full Analysis with AI Summary

```bash
pynetworkintel analyze 192.168.1.0/24 --summarize
```

### With SSH Config Grabbing

```bash
pynetworkintel scan 192.168.1.0/24 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa
```

## Python API

```python
from pynetworkintel import Scanner, Analyzer

# Scan for devices
scanner = Scanner()
scan_result = scanner.scan("192.168.1.0/24")

# Analyze for vulnerabilities
analyzer = Analyzer()
scan_result = analyzer.analyze(scan_result)

# Get plain English summary
summary = analyzer.summarize(scan_result)
print(summary)
```

## What It Does

### 1. Device Discovery
Automatically finds all devices on your network:
- IP addresses
- Hostnames
- Operating systems
- Running services and versions

### 2. Configuration Analysis
Checks device configurations for security issues:
- SSH weak authentication
- Unencrypted protocols (Telnet, FTP)
- Firewall misconfigurations
- Exposed database ports
- Default credentials

### 3. Vulnerability Detection
Checks services against known vulnerabilities (CVE database):
- Service versions with known exploits
- CVSS scores and severity ratings
- Patch recommendations

### 4. AI-Powered Summaries
Claude synthesizes findings into plain English:
- Why each issue matters
- How to fix it
- Priority order
- Business impact

## Features

✅ Automated device discovery (nmap)  
✅ SSH configuration grabbing  
✅ Configuration vulnerability rules  
✅ CVE database integration (NVD)  
✅ LLM-powered analysis (Claude)  
✅ Plain English explanations  
✅ JSON or text output  
✅ Python API and CLI  

## Architecture

- **Discovery**: Nmap + SSH for device and config retrieval
- **Analysis**: Configuration rules engine + CVE checker
- **Synthesis**: Claude API for plain English summaries
- **Models**: Clean data models (Device, Service, Finding, etc.)

## Requirements

- Python 3.10+
- nmap installed on system
- SSH access to devices (for config grabbing, optional)
- Anthropic API key (for AI summaries)

## Setup

### Install nmap

**macOS:**
```bash
brew install nmap
```

**Ubuntu/Debian:**
```bash
sudo apt-get install nmap
```

**Fedora/RHEL:**
```bash
sudo dnf install nmap
```

### Set API Key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Or pass to Python:

```python
from pynetworkintel import Analyzer

analyzer = Analyzer(anthropic_api_key="sk-ant-...")
```

## License

Proprietary. All rights reserved.

## Support

For issues and questions, contact: mullassery@gmail.com

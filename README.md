# PyNetworkIntel

**AI-Powered Network Intelligence & Vulnerability Discovery Platform**

Automatically discovers devices on your network, detects configuration vulnerabilities, checks for known CVEs, and provides plain-English explanations with business context using Claude AI.

**Status**: v0.2.0 (Phase 1-4 Complete)  
**License**: Proprietary  
**Distribution**: Wheels Only (No Source on PyPI)

## Installation

```bash
# Install from PyPI (wheels only)
pip install pynetworkintel

# Or install from wheel file directly
pip install pynetworkintel-0.2.0-py3-none-any.whl
```

**Requirements**:
- Python 3.10+
- nmap installed (`brew install nmap` on macOS, `apt-get install nmap` on Ubuntu)
- Anthropic API key for AI summaries (optional, fallback available)

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

## Phase 1-4 Features

### ✅ Phase 1: Device Discovery
- Nmap-based network scanning
- SSH configuration grabbing (sshd_config, iptables, firewall rules)
- Service enumeration with version detection
- OS and hostname identification
- Support for Linux, Windows, macOS, BSD, embedded systems

### ✅ Phase 2: Security Analysis
- **10+ Built-in Rules**: SSH weak auth, Telnet, FTP, firewall misconfigs, default credentials, exposed databases
- **CVE Integration**: NVD API queries with CVSS scoring
- **LLM Summarization**: Claude API explains findings in plain English
- **Business Impact**: Each finding includes "why it matters"

### ✅ Phase 3: CLI & Distribution
- YAML-based configuration management
- Progress indicators with colored output
- Docker containerization
- Wheel-only distribution (no source on PyPI)
- Multiple output formats (text, JSON)

### ✅ Phase 4: Continuous Monitoring
- SQLite/PostgreSQL database persistence
- Change detection (new devices, new CVEs)
- Multi-channel alerting (Slack, Email, Webhooks)
- Background scheduling (hourly, daily, weekly scans)
- Automated report generation (Markdown, JSON)

## Commands

```bash
# Initialize configuration
pynetworkintel init-config

# Simple network scan
pynetworkintel scan 192.168.1.0/24

# Full analysis with AI summary
pynetworkintel analyze 192.168.1.0/24 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --summarize

# Scan with output to file
pynetworkintel scan 192.168.1.0/24 --output-file results.json

# Help and version
pynetworkintel --help
pynetworkintel --version
```

## Docker

```bash
# Build image
docker build -t pynetworkintel:0.2.0 .

# Run scan
docker run -it pynetworkintel:0.2.0 scan 192.168.1.0/24

# With SSH credentials mounted
docker run -v ~/.ssh:/root/.ssh:ro pynetworkintel:0.2.0 \
  scan 192.168.1.0/24 --ssh-key ~/.ssh/id_rsa
```

## Architecture

```
Discovery Engine          Analysis Engine           Output
    ↓                            ↓                     ↓
Nmap Scanner    ──→  Rule Checker   ──→  LLM  ──→  CLI/JSON
SSH Config      ──→  CVE Checker    ──→  Reports
Grabber         ──→  Scoring        ──→  Alerts
                        ↓
                    Database (SQLite/PostgreSQL)
                        ↓
                    Scheduler (APScheduler)
                        ↓
                    Change Detection & Alerting
```

## System Requirements

**Required**:
- Python 3.10+ (tested on 3.10, 3.11, 3.12, 3.13)
- nmap (for network scanning)
- ~100 MB disk space

**Optional**:
- SSH access to target devices (for config grabbing)
- Anthropic API key (for Claude summaries; fallback available)
- PostgreSQL (production deployments; SQLite works for testing)

### Install Dependencies

**nmap**:
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Fedora/RHEL
sudo dnf install nmap

# Alpine
apk add nmap

# Windows
# Option 1: Chocolatey
choco install nmap

# Option 2: Download installer from https://nmap.org/download.html
# Then add nmap to PATH

# Verify installation (all platforms)
nmap -version
```

**Python Dependencies**:
Automatically installed with `pip install pynetworkintel`:
- paramiko (SSH)
- netaddr (IP utilities)
- requests (HTTP)
- anthropic (Claude API)
- rich (UI/progress)
- sqlalchemy (database)
- apscheduler (scheduling)

## Configuration

### Quick Start

```bash
# Create default config file
pynetworkintel init-config

# Edit configuration (use your preferred editor)
# Linux/macOS: nano, vim, or VSCode
nano ~/.pynetworkintel/config.yaml

# Windows: PowerShell or Notepad
notepad $env:USERPROFILE\.pynetworkintel\config.yaml
```

### Environment Variables

**Linux/macOS**:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export PYNETWORKINTEL_SSH_USER="admin"
export PYNETWORKINTEL_SSH_KEY="~/.ssh/id_rsa"
```

**Windows (PowerShell)**:
```powershell
$env:ANTHROPIC_API_KEY="sk-ant-..."
$env:PYNETWORKINTEL_SSH_USER="admin"
$env:PYNETWORKINTEL_SSH_KEY="$env:USERPROFILE\.ssh\id_rsa"
```

**Windows (Command Prompt)**:
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
set PYNETWORKINTEL_SSH_USER=admin
set PYNETWORKINTEL_SSH_KEY=%USERPROFILE%\.ssh\id_rsa
```

### Configuration File Example

```yaml
ssh:
  username: root
  key_path: ~/.ssh/id_rsa
  password: null
  timeout: 10

scan:
  timeout: 300
  nmap_args: "-sV"
  grab_configs: true
  retry_count: 1

analysis:
  enable_cve_check: true
  enable_llm_summary: true
  cve_cache_ttl: 86400

output:
  format: text
  verbose: false
  color: true
```

## Database Setup

### SQLite (Default - Development)
```bash
# Automatically created on first run
pynetworkintel scan 192.168.1.0/24
# Creates: ./pynetworkintel.db
```

### PostgreSQL (Production)
```bash
# Create database
createdb pynetworkintel

# Configure connection
export DATABASE_URL="postgresql://user:password@localhost/pynetworkintel"
```

## Examples

### Example 1: Scan Your Home Network
```bash
$ pynetworkintel scan 192.168.1.0/24

Discovered Devices:
- 192.168.1.1 (router): SSH, HTTP, HTTPS
- 192.168.1.100 (laptop): SSH
- 192.168.1.50 (printer): HTTP
```

### Example 2: Full Analysis with AI Summary
```bash
$ pynetworkintel analyze 10.0.0.0/24 --summarize

✅ GOOD NEWS:
   - 24 devices discovered
   - Connectivity stable
   - No critical vulnerabilities

⚠️  PROBLEMS TO FIX:
   1. SSH password auth enabled on 3 devices
   2. Telnet service exposed on 1 device
   3. Default credentials detected on 2 devices

Next Steps: Fix critical issues first
```

### Example 3: Continuous Monitoring (Python API)
```python
from pynetworkintel.scheduler import MonitoringScheduler
from pynetworkintel.alerts import AlertManager, SlackAlertChannel

# Setup database
from pynetworkintel.db import init_db
db = init_db("sqlite:///pynetworkintel.db")

# Create scheduler
scheduler = MonitoringScheduler(database_url="sqlite:///pynetworkintel.db")

# Add recurring scan
scheduler.add_scan_job(
    job_id="production",
    target="10.0.0.0/24",
    schedule_type="interval",
    hours=1  # Scan hourly
)

# Add alerts
alert_manager = AlertManager(db)
alert_manager.add_channel(
    "slack",
    SlackAlertChannel(webhook_url="https://hooks.slack.com/...")
)

# Start monitoring
scheduler.start()
```

## Roadmap

**Phase 1-4** ✅ Complete
- Network discovery, vulnerability detection, continuous monitoring

**Phase 5** 📅 Planned (4-6 weeks)
- Cloud integration (AWS, Azure, GCP)
- Kubernetes discovery
- ML-powered analytics

**Phase 6** 📅 Planned (6-8 weeks)
- Enterprise HA (99.9% SLA)
- Multi-tenancy
- Advanced compliance

**Phase 7** 📅 Planned (8-12 weeks)
- AI-native architecture advisor

See [Phase 5-7 Planning](https://github.com/Mullassery/PyNetworkIntel) for details.

## Troubleshooting

### "nmap: command not found"
```bash
# Install nmap for your system (see Install Dependencies)
# macOS: brew install nmap
# Ubuntu: sudo apt-get install nmap
```

### SSH Connection Timeout
```bash
# Test SSH connection manually first
ssh -i ~/.ssh/id_rsa admin@192.168.1.1

# Then try scan with verbose logging
pynetworkintel scan 192.168.1.0/24 --verbose --ssh-user admin --ssh-key ~/.ssh/id_rsa
```

### CVE API Rate Limit
```
# NVD API allows ~1 request per 6 seconds (free tier)
# PyNetworkIntel automatically handles rate limiting
# Results are cached to minimize API calls
```

### Database Errors
```bash
# Reset SQLite database
rm pynetworkintel.db
pynetworkintel scan 192.168.1.0/24
```

## Performance

Typical scan times (single /24 subnet):
- Discovery: 1-5 minutes (depends on device response times)
- Analysis: 30-60 seconds
- CVE checking: 1-3 minutes
- LLM summarization: 10-20 seconds

Database queries: <100ms for typical operations

## Security & Privacy

- ✅ No data sent to external services (except NVD CVE API and Anthropic Claude)
- ✅ SSH credentials stored locally
- ✅ Configuration kept in ~/.pynetworkintel/
- ✅ Scan results stored in local database
- ⚠️ Requires API key for Claude summaries (optional)

## License & Distribution

**License**: Proprietary. All rights reserved.

**Distribution**: Wheels only. Source code is proprietary and not published to PyPI.

For licensing inquiries, contact: mullassery@gmail.com

## Support & Contact

**Issues & Questions**: mullassery@gmail.com  
**GitHub**: https://github.com/Mullassery/PyNetworkIntel  
**License**: See LICENSE file

---

**PyNetworkIntel v0.2.0** - AI-Powered Network Intelligence Platform  
*From network scanner to infrastructure advisor*

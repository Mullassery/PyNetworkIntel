# PyNetworkIntel

**Know Your Network. Secure Your Infrastructure.**

Stop wondering what devices are connected to your network. Stop manually checking if they're secure. PyNetworkIntel automatically discovers everything on your network, finds security issues, and explains what matters—in plain English you can actually act on.

**Works with**: Any network size • Any industry • On-premises or cloud • Single scan or continuous monitoring

**Status**: v1.0.1 - Enterprise-Ready with AI Architecture Advisor and Live Dashboard  
**Latest Release**: 2026-07-30  
**Used by**: System Administrators • DevOps Teams • Security Teams • IT Managers • Cloud Architects • Startups to Enterprises

**What's New in v1.0.1**:
- Live stats dashboard (separate terminal window with real-time metrics)
- Multi-cloud discovery (AWS, Azure, GCP)
- Kubernetes security analysis (RBAC, pod security, network policies)
- ML-powered anomaly detection & vulnerability forecasting
- Enterprise features (HA, multi-tenancy, SSO, compliance auditing)
- AI Architecture Advisor (pattern recognition, cost optimization, roadmap generation)

## Why PyNetworkIntel?

**Before PyNetworkIntel**:
- Manual checking: "Is device X online?"
- Blind spots: Not knowing what's actually connected
- Manual config review: SSH into each device individually
- Guessing: "Is this port supposed to be open?"
- Reactive: Finding security issues after something breaks

**After PyNetworkIntel**:
- Automatic discovery: Know everything connected to your network
- Security analysis: Find issues before they become problems
- Plain English: Explanations anyone can understand
- Continuous monitoring: Track changes automatically
- Actionable insights: Know exactly what to fix, in what order

---

## What's New: Enterprise & Cloud Features

### Cloud Discovery (Phase 5)
**Discover all your cloud resources automatically** - AWS, Azure, GCP
```bash
# Find all resources across multiple clouds
pynetworkintel cloud-scan --aws --azure --gcp

# Get cross-cloud asset correlation
pynetworkintel cloud-analyze --correlate
```
- Multi-cloud inventory (EC2, VMs, compute instances, databases)
- Security group analysis, firewall rule review
- Cross-cloud network path analysis
- Credential management (secure storage with 600-bit encryption)

### Kubernetes & Container Security (Phase 5)
**Secure your Kubernetes clusters and containerized workloads**
```bash
# Analyze K8s cluster security
pynetworkintel k8s-analyze --cluster my-cluster

# Check pod security, RBAC, network policies
pynetworkintel k8s-review --rbac --pods --network-policies
```
- Full cluster discovery (nodes, pods, deployments)
- RBAC analysis with risk scoring
- Pod security context review
- Network policy coverage analysis

### ML-Powered Intelligence (Phase 5)
**Predict vulnerabilities and detect anomalies before they're exploited**
```bash
# Learn baseline behavior and detect anomalies
pynetworkintel ml-baseline --device-id server-01
pynetworkintel ml-detect-anomalies --device-id server-01
```
- Behavioral baseline learning
- Anomaly detection (port scans, bandwidth spikes, unusual connections)
- Vulnerability discovery forecasting
- Attack surface growth prediction

### Enterprise Features (Phase 6)
**Deploy at scale with HA, multi-tenancy, and enterprise authentication**
```bash
# Start HA cluster
pynetworkintel cluster-start --nodes 3 --region us-east-1

# Create tenant for customer
pynetworkintel tenant-create --name "Acme Corp" --api-key mykey123
```
- High availability (99.9% SLA, multi-node deployment)
- Multi-tenant isolation with per-tenant encryption
- Enterprise auth (LDAP, OAuth 2.0, SAML 2.0, MFA)
- REST API with rate limiting
- Compliance auditing (SOC 2, ISO 27001, PCI-DSS, HIPAA)

### AI Architecture Advisor (Phase 7)
**Get Principal Architect-level guidance on your infrastructure**
```bash
# Analyze architecture and get recommendations
pynetworkintel architect-review --architecture myarch.json

# Generate implementation roadmap
pynetworkintel architect-roadmap --current state.json --target goals.json --months 12
```
- Architecture graph modeling and SPOF detection
- Pattern recognition (serverless, microservices, multi-cloud)
- Reliability, security, scalability, cost reviews
- ROI-aware recommendations
- Phased implementation roadmaps
- Natural language Q&A about architecture

---

## Getting Started

### Step 1: Install (2 minutes)

**What You Need**:
- Python 3.10+ (check with `python --version`)
- nmap (network scanning tool)

**What's Optional**:
- **AI Summaries** (pick any one):
  - Anthropic Claude (cloud-based, no setup needed)
  - Ollama (runs locally on your machine, completely private)
  - Other LLM endpoints (any REST API)
  - Or use without any AI (built-in analysis is powerful enough)

**Note**: PyNetworkIntel works perfectly fine without any AI! The AI just adds natural language explanations. All core security scanning works offline.

**Install nmap** (if not already installed):
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Fedora/RHEL
sudo dnf install nmap

# Windows (Chocolatey)
choco install nmap

# Windows (Manual)
# Download from https://nmap.org/download.html and add to PATH
```

**Install PyNetworkIntel**:
```bash
pip install pynetworkintel
```

**Verify installation**:
```bash
pynetworkintel --version
# Should show: cli.py 0.2.0
```

### Step 2: Run Your First Scan (5 minutes)

**Scan your local network**:
```bash
pynetworkintel scan 192.168.1.0/24
```

**What you'll see**:
```
[+] Discovering devices...
[+] Found 12 devices
- 192.168.1.1 (router): SSH, HTTP, HTTPS
- 192.168.1.10 (laptop): SSH, RDP
- 192.168.1.50 (printer): HTTP
- 192.168.1.100 (server): SSH, MySQL, PostgreSQL
... and 8 more
```

### Step 3: Analyze for Security Issues (10 minutes)

**Get security analysis**:
```bash
pynetworkintel analyze 192.168.1.0/24 --summarize
```

**What you'll see**:
```
[+] GOOD NEWS:
   - All 12 devices are responding
   - Network connectivity is stable

[!] PROBLEMS TO FIX (in order of importance):
   1. MySQL database exposed to entire network
      Reason: Anyone on network can attempt database access
      Fix: Restrict port 3306 to server IPs only

   2. SSH password authentication enabled on 5 devices
      Reason: Allows brute-force attacks
      Fix: Disable password auth, use SSH keys only

   3. Server running Windows 7 (unsupported OS)
      Reason: No security updates since 2020
      Fix: Upgrade to Windows Server 2022
```

---

## Common Use Cases

### Use Case 1: You Just Got a Server and Don't Know What's Running

**Situation**: New server arrives, you need to know what's on it before putting it into production.

```bash
# Scan the new server
pynetworkintel scan 192.168.1.100 --ssh-user admin --ssh-key ~/.ssh/id_rsa

# Output tells you:
# - What services are running (SSH, HTTP, database, etc.)
# - Which versions (vulnerable or current?)
# - What configuration issues exist
# - What needs to be fixed before production
```

### Use Case 2: You're Managing 100+ Devices and Need an Overview

**Situation**: Managing multiple servers, workstations, and IoT devices. Need to know which ones have security issues.

```bash
# Scan your entire network
pynetworkintel analyze 10.0.0.0/16 --summarize

# Get a dashboard view of:
# - Total devices connected
# - Critical security issues (stop using these right now)
# - High-priority issues (fix within 30 days)
# - Medium-priority issues (track and plan fixes)
# - Compliant devices (no action needed)
```

### Use Case 3: You Need Continuous Monitoring (Not Just One-Time Scans)

**Situation**: You want to know immediately if a security issue appears or a device goes offline.

```bash
# Set up automatic hourly scans with alerts
pynetworkintel init-config

# Edit ~/.pynetworkintel/config.yaml to enable Slack alerts

# Then start monitoring in the background
# Device goes offline? -> Slack alert
# New vulnerability detected? -> Slack alert
# New device appears? -> Slack alert
```

### Use Case 4: You're Responsible for Compliance

**Situation**: Need to prove to auditors that you know what's on your network and it's secure.

```bash
# Generate compliance reports
pynetworkintel analyze 10.0.0.0/8 > scan_results.json
pynetworkintel report > compliance_report.md

# Reports include:
# - Complete device inventory
# - Security findings with evidence
# - Timeline of changes
# - Remediation status
# ➜ Perfect for audits and compliance checks
```

### Use Case 5: You're Incident Response: "What Just Happened?"

**Situation**: Security alert fired, need to understand the attack surface right now.

```bash
# Get immediate vulnerability snapshot
pynetworkintel analyze 192.168.1.0/24

# See:
# - Every device's security posture
# - Known vulnerabilities in each service
# - Configuration issues that might have been exploited
# - Which devices are most at risk
```

---

## Real-World Examples

## Example: Real-World Scan Output

```bash
$ pynetworkintel analyze 192.168.1.0/24 --summarize
```

**Output**:
```
═══════════════════════════════════════════════════════════════

Network Analysis Results

Total Devices: 12
Critical Issues: 1
High Priority Issues: 4
Medium Priority Issues: 3
All Devices Online: [OK]

═══════════════════════════════════════════════════════════════

TOP ISSUES TO FIX

1. [CRITICAL] MySQL Database Exposed to Network
   Device: 192.168.1.50
   Why it matters: Any computer on the network can access your database
   How to fix it: Add firewall rule to restrict port 3306 to only the 
                  web server (192.168.1.100)
   Timeline: Fix TODAY (this is a critical security risk)

2. [HIGH] SSH Password Authentication Enabled
   Device: 192.168.1.100 (web-server)
   Why it matters: Hackers can attempt to guess SSH passwords
   How to fix it: Disable password auth in /etc/ssh/sshd_config
                  Restart SSH service
   Timeline: Fix within 1 week

3. [HIGH] Telnet Service Running (Unencrypted)
   Device: 192.168.1.25
   Why it matters: All Telnet traffic is sent in plain text (no encryption)
   How to fix it: Disable Telnet, use SSH instead
   Timeline: Disable immediately

4. [HIGH] Old Apache Version (2.2.15 - EOL 2018)
   Device: 192.168.1.100 (web-server)
   Why it matters: Running an outdated web server with known vulnerabilities
   How to fix it: Upgrade Apache to version 2.4.54 or later
   Timeline: Fix within 2 weeks

5. [MEDIUM] Default Credentials Detected
   Device: 192.168.1.75 (printer)
   Why it matters: Anyone can change printer settings or print sensitive data
   How to fix it: Log in and change the default admin password
   Timeline: Fix within 1 month

═══════════════════════════════════════════════════════════════

DEVICES THAT ARE FINE
[OK] 7 devices with no critical issues

═══════════════════════════════════════════════════════════════
```

---

## What PyNetworkIntel Does (Under the Hood)

### 1. Automatic Device Discovery
- Scans your network and finds every device
- Identifies what operating system each device runs
- Detects every service running (SSH, HTTP, databases, etc.)
- Gets version numbers for each service

### 2. Configuration Security Check
- Reviews device configurations (SSH settings, firewall rules, etc.)
- Checks against 10+ built-in security best practices
- Explains why each setting matters
- Tells you exactly how to fix issues

### 3. Vulnerability Database Check
- Compares service versions against known vulnerabilities
- Shows CVSS risk scores (how bad is it?)
- Explains if the vulnerability can actually be exploited
- Recommends which versions to upgrade to

### 4. Smart Prioritization
- Tells you which issues to fix first
- Explains why in business terms (not technical jargon)
- Saves you time by eliminating guesswork

### 5. Continuous Monitoring (Optional)
- Can automatically scan hourly/daily
- Detects when something changes
- Sends alerts (Slack, email) when issues appear
- Tracks your progress over time

## Feature Overview

### Discovery & Scanning
- Automatic network device discovery (any network size)
- Service and version detection for every device
- SSH configuration analysis and review
- Support for Windows, macOS, Linux, BSD, IoT devices
- Firewall rule detection and analysis

### Security Intelligence
- 10+ built-in security rules (SSH, protocols, credentials, etc.)
- CVE database integration (knows about known vulnerabilities)
- CVSS risk scoring (prioritize by severity)
- Explains vulnerabilities in plain English
- Configuration compliance checking

### AI-Powered Analysis (Optional)
- **Claude AI** (via Anthropic) - For advanced AI summarization
- **Ollama** - Run LLMs locally (no cloud, completely private)
- **Other endpoints** - Works with any REST API LLM
- **Fallback mode** - Works great without any AI (built-in analysis sufficient)

### Monitoring & Alerting
- Continuous monitoring (hourly, daily, weekly scans)
- Change detection (new devices, vulnerabilities, config changes)
- Multi-channel alerts: Slack, Email, Webhooks
- Device status tracking (online/offline detection)
- Automatic report generation

### Data & Reporting
- SQLite (local) or PostgreSQL (team deployments)
- Export to JSON, Markdown, or text
- Detailed compliance reports
- Historical tracking of changes
- Audit trail of all findings

### Deployment Flexibility
- **Local installation**: `pip install pynetworkintel`
- **Docker container**: For scanning remote networks
- **Python API**: For custom integration
- **CLI tool**: For standalone scans
- **Daemon mode**: For background continuous monitoring

## Compared to Other Open-Source Tools

| Feature | PyNetworkIntel | Nmap | OpenSCAP | Lynis | Prometheus |
|---------|---|---|---|---|---|
| **Network Discovery** | Yes (Full) | Yes (Advanced) | Limited | No | No |
| **Service Detection** | Yes | Yes | No | No | No |
| **Configuration Analysis** | Yes | No | Yes (Compliance) | Yes (Host-based) | No |
| **CVE Checking** | Yes | No | Yes | Yes | No |
| **Continuous Monitoring** | Yes | One-time only | No | One-time only | Yes |
| **AI Summaries** | Yes (Optional) | No | No | No | No |
| **Multi-Channel Alerts** | Yes (Slack, Email, Webhooks) | No | No | No | Yes (basic) |
| **Easy to Use** | Yes (Plain English) | Technical | Technical | Technical | Technical |
| **No Training Needed** | Yes | Steep learning curve | Requires setup | Complex | Complex |
| **All-in-One Solution** | Yes | Scanning only | Compliance only | Audit only | Metrics only |

**Why PyNetworkIntel is Different**:
- Combines discovery, analysis, CVE checking, and monitoring in one tool
- Explains findings in plain English (no technical jargon)
- Works out-of-the-box (no complex setup)
- Suitable for non-experts (DevOps, IT managers, system admins)
- All open-source dependencies (or use your own LLM)

---

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

# Scan with real-time stats dashboard (launches in separate terminal)
pynetworkintel scan 192.168.1.0/24 --dashboard

# Full analysis with dashboard showing live findings
pynetworkintel analyze 192.168.1.0/24 --dashboard --summarize

# Scan with output to file
pynetworkintel scan 192.168.1.0/24 --output-file results.json

# Help and version
pynetworkintel --help
pynetworkintel --version
```

## Real-Time Stats Dashboard

PyNetworkIntel includes a **live stats dashboard** that displays scan progress in a separate terminal window:

```bash
pynetworkintel scan 192.168.1.0/24 --dashboard
```

The dashboard shows:
- **Devices discovered** and online status in real-time
- **Configs grabbed** via SSH
- **Security findings** broken down by severity (critical, high, medium, low, info)
- **Scan progress** and current phase
- **Elapsed time** and performance metrics

### Dashboard Features

- **Cross-platform**: Works on macOS, Linux, and Windows
- **Auto-launching**: Automatically opens in the appropriate terminal emulator
- **Live updates**: Refreshes every second with latest stats
- **Color-coded**: Severity levels color-coded for quick identification
- **Low overhead**: <5% CPU impact

### Supported Terminal Emulators

- **macOS**: Terminal.app
- **Linux**: GNOME Terminal, KDE Konsole, Xterm, XFCE Terminal, Terminator, or Rxvt
- **Windows**: Command Prompt

See [Dashboard Documentation](docs/DASHBOARD.md) for more details.

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
         |                         |                   |
Nmap Scanner    -->  Rule Checker   -->  LLM  -->  CLI/JSON
SSH Config      -->  CVE Checker    -->  Reports
Grabber         -->  Scoring        -->  Alerts
                         |
                 Database (SQLite/PostgreSQL)
                         |
                 Scheduler (APScheduler)
                         |
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

**For SSH Access to Devices** (required for config grabbing):

**Linux/macOS**:
```bash
export PYNETWORKINTEL_SSH_USER="admin"
export PYNETWORKINTEL_SSH_KEY="~/.ssh/id_rsa"
```

**Windows (PowerShell)**:
```powershell
$env:PYNETWORKINTEL_SSH_USER="admin"
$env:PYNETWORKINTEL_SSH_KEY="$env:USERPROFILE\.ssh\id_rsa"
```

**For AI-Powered Summaries** (completely optional):

**Option 1: Use Anthropic Claude** (easiest):
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Option 2: Use Ollama Locally** (private, no cloud):
```bash
# First, install Ollama from https://ollama.ai
# Then start it: ollama run llama2

# Configure PyNetworkIntel:
export PYNETWORKINTEL_LLM_ENDPOINT="http://localhost:11434"
export PYNETWORKINTEL_LLM_MODEL="llama2"
```

**Option 3: Use Any Other LLM** (OpenAI compatible):
```bash
export PYNETWORKINTEL_LLM_ENDPOINT="http://your-api.example.com"
export PYNETWORKINTEL_LLM_MODEL="gpt-4"
export PYNETWORKINTEL_LLM_API_KEY="your-api-key"
```

**No AI** (works great, just simpler output):
```bash
# Don't set any LLM variables
# PyNetworkIntel will use built-in analysis
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

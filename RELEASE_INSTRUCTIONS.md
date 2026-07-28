# PyNetworkIntel Release Instructions

## Version 0.2.0 Release Guide

### Prerequisites

1. **PyPI Account**: Create account at https://pypi.org
2. **API Token**: Generate at https://pypi.org/manage/account/
3. **twine installed**: `pip install twine`

### Step 1: Verify Wheel Build

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info

# Build wheel only (no source distribution)
python -m build --wheel

# Verify wheel exists
ls -lh dist/pynetworkintel-0.2.0-py3-none-any.whl
```

### Step 2: Test Wheel Installation (Optional but Recommended)

```bash
# Create test environment
python -m venv test_env
source test_env/bin/activate

# Install from wheel
pip install dist/pynetworkintel-0.2.0-py3-none-any.whl

# Test CLI
pynetworkintel --version
pynetworkintel --help

# Deactivate
deactivate
rm -rf test_env
```

### Step 3: Upload to PyPI

#### Option A: Interactive (Recommended for first upload)

```bash
# This will prompt for username and password (or API token)
twine upload dist/pynetworkintel-0.2.0-py3-none-any.whl
```

#### Option B: Using Environment Variables

```bash
# Set credentials (use API token as password)
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="pypi-AgEIcHlwaS5vcmc..."  # Your API token

# Upload
twine upload dist/pynetworkintel-0.2.0-py3-none-any.whl
```

#### Option C: Using .pypirc File

Create `~/.pypirc`:
```ini
[distutils]
index-servers = pypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmc...
```

Then:
```bash
twine upload dist/pynetworkintel-0.2.0-py3-none-any.whl
```

### Step 4: Verify Upload

```bash
# Wait a few minutes for PyPI to process the upload
# Then test installation from PyPI

pip install pynetworkintel
pynetworkintel --version  # Should show 0.2.0
```

### Step 5: Tag Release on GitHub

```bash
# Tag the release
git tag -a v0.2.0 -m "PyNetworkIntel v0.2.0: Phase 1-4 Complete"

# Push tag to GitHub
git push origin v0.2.0
```

### Step 6: Create GitHub Release

1. Go to: https://github.com/Mullassery/PyNetworkIntel/releases
2. Click "Draft a new release"
3. Tag: `v0.2.0`
4. Release title: `PyNetworkIntel v0.2.0 - Phase 1-4 Complete`
5. Description:
```markdown
## What's New in v0.2.0

### Phase 1: Device Discovery ✅
- Network scanning via Nmap
- SSH configuration grabbing
- Service enumeration with versions

### Phase 2: Security Analysis ✅
- Configuration rule engine (10+ rules)
- CVE integration (NVD API)
- LLM-powered summarization (Claude)

### Phase 3: CLI & Distribution ✅
- Enhanced CLI with config management
- Docker containerization
- Wheel-only distribution

### Phase 4: Continuous Monitoring ✅
- SQLite/PostgreSQL persistence
- Change detection
- Multi-channel alerting
- Background scheduling
- Automated reporting

## Installation

```bash
pip install pynetworkintel==0.2.0
```

## Quick Start

```bash
pynetworkintel scan 192.168.1.0/24
pynetworkintel analyze 192.168.1.0/24 --summarize
```

## Next Phase

Phase 5 (Cloud Integration, Kubernetes) planned for Q4 2026.

See README.md for complete documentation.
```

6. Click "Publish release"

---

## Important: Wheels-Only Distribution Policy

**PyNetworkIntel uses wheels-only distribution for security and IP protection.**

### What This Means

- ✅ Users install pre-compiled Python code from wheels
- ✅ Source code is protected (not on PyPI)
- ✅ Faster installation (no compilation needed)
- ✅ Consistent behavior across Python installations
- ❌ Source code is NOT available on PyPI
- ❌ Source code is NOT published in source distributions

### GitHub vs PyPI

**GitHub** (`https://github.com/Mullassery/PyNetworkIntel`):
- Contains full source code
- Public repository
- For development and transparency
- **Do NOT use `pip install` from GitHub (would install source)**

**PyPI** (`https://pypi.org/project/pynetworkintel/`):
- Contains wheels only
- Official package index
- **Use `pip install pynetworkintel` from here**

### Build Command Reference

```bash
# Build ONLY wheel (recommended)
python -m build --wheel

# This creates:
# dist/pynetworkintel-0.2.0-py3-none-any.whl

# DO NOT use this (creates source distribution):
# python -m build  # Don't do this - creates sdist
```

---

## Version Numbering

- **v0.1.0**: Phase 1-2 (Device Discovery + Security Analysis)
- **v0.2.0**: Phase 3-4 (CLI Polish + Continuous Monitoring) ← Current
- **v0.3.0**: Phase 5 (Cloud Integration)
- **v0.4.0**: Phase 6 (Enterprise Features)
- **v1.0.0**: Phase 7 (System Design Intelligence)

---

## PyPI Maintenance

### Check PyPI Package Page

After upload, verify at: https://pypi.org/project/pynetworkintel/

### Update Project Description

If needed, update on PyPI dashboard:
https://pypi.org/manage/project/pynetworkintel/

### View Upload History

https://pypi.org/project/pynetworkintel/#history

---

## Troubleshooting

### Upload Fails: "Invalid Distribution"

```
Error: Invalid distribution on line 0.

Solution: Ensure only wheel file is in dist/
rm dist/*.tar.gz  # Remove any source distributions
```

### 403 Forbidden Error

```
Error: HTTPError: 403 Client Error

Solution: 
- Verify API token is correct
- Check username is exactly "__token__"
- Ensure token has upload permissions
```

### Package Already Exists

```
Error: File already exists

Solution:
- Increase version number (e.g., 0.2.0 → 0.2.1)
- Or delete old version on PyPI dashboard
```

### Installation Still Gets Old Version

```
pip install --upgrade --force-reinstall pynetworkintel==0.2.0
```

---

## Security Checklist

Before each release:

- [ ] Run tests: `pytest tests/ -q`
- [ ] Check for secrets in code
- [ ] Review dependencies for vulnerabilities
- [ ] Verify wheel size is reasonable (~38 KB)
- [ ] Test installation from wheel
- [ ] Verify CLI works: `pynetworkintel --version`
- [ ] Update CHANGELOG
- [ ] Tag release in git
- [ ] Create GitHub release

---

## Release Checklist for v0.2.0

- [x] Code changes committed
- [x] README updated
- [x] setup.py updated with v0.2.0
- [x] pyproject.toml created
- [x] Tests passing (21/21)
- [x] Wheel built successfully
- [ ] Wheel tested (manual installation recommended)
- [ ] Uploaded to PyPI
- [ ] GitHub tagged with v0.2.0
- [ ] GitHub release created
- [ ] Installation verified from PyPI

---

## Questions?

Contact: mullassery@gmail.com

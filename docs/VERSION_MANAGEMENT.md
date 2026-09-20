# Version Management

This document describes how to keep versions synchronized across source
files. It has been corrected below to match the real, current tooling -
previously it referenced a `setup.py` that has been removed and a
"README.md Status line" that no longer exists, and claimed a stale current
version.

## Version Sync Status

`scripts/check-version-sync.sh` verifies that these two files agree:
- `pyproject.toml` (`[project].version` - the single source of truth)
- `pynetworkintel/__init__.py` (`__version__`)

Git tags and the PyPI registry are reported by the script for information
but are **not** part of the pass/fail check - this repo has at least one
out-of-order git tag (`v2.0.0`, pointing at a commit older and less
complete than `v1.4.0`; see `ROADMAP_HONEST.md`), so tag names cannot be
trusted as a version source.

Current version: see `pyproject.toml` (`1.4.0` as of this writing - do not
trust this file's own memory of the number, check the source).

## Checking Version Sync

Run the verification script to check if all version numbers match:

```bash
bash scripts/check-version-sync.sh
```

Expected output:
```
✅ pyproject.toml and __init__.py are in sync!
Current version: 1.4.0
```

## Updating Version

To update the version across all sources:

```bash
bash scripts/update-version.sh 1.5.0
```

This script will:
1. Update pyproject.toml
2. Update pynetworkintel/__init__.py
3. Display summary and next steps

## Release Workflow

Follow this workflow when releasing a new version:

### 1. Update Version
```bash
bash scripts/update-version.sh X.Y.Z
```

### 2. Review Changes
```bash
git diff
```

### 3. Commit Changes
```bash
git add pyproject.toml pynetworkintel/__init__.py
git commit -m "Bump version to X.Y.Z"
```

### 4. Create Git Tag
```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

### 5. Build Distribution
```bash
rm -rf dist build
python -m build --wheel
```

### 6. Upload to PyPI
```bash
python -m twine upload dist/pynetworkintel-X.Y.Z-py3-none-any.whl
```

### 7. Verify Sync
```bash
bash scripts/check-version-sync.sh
```

## Version File Locations

| File | Field | Example |
|------|-------|---------|
| `pyproject.toml` | `version = "..."` (source of truth) | `version = "1.4.0"` |
| `pynetworkintel/__init__.py` | `__version__` | `__version__ = "1.4.0"` |
| Git tags (informational only, not verified) | Tag name | `v1.4.0` |
| PyPI (informational only, not verified) | Package info | Published as 1.4.0 |

## CI/CD Integration

The version sync check can be integrated into CI/CD pipelines:

```bash
# In CI/CD pipeline
bash scripts/check-version-sync.sh || exit 1
```

This ensures that all pull requests maintain version consistency before merge.

## Troubleshooting

### Version mismatch detected

If the check fails, verify each file:

```bash
grep "version =" pyproject.toml
grep "__version__" pynetworkintel/__init__.py
git tag -l
```

Fix any mismatches manually, then re-run the check.

### Manual Version Update

If automated scripts fail, update versions manually:

1. Edit pyproject.toml: change `version = "X.Y.Z"`
2. Edit pynetworkintel/__init__.py: change `__version__ = "X.Y.Z"`
3. Create git tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
4. Verify: `bash scripts/check-version-sync.sh`

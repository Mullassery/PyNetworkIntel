# Version Management

This document describes how to keep versions synchronized across PyPI, GitHub, and source files.

## Version Sync Status

All version numbers are automatically verified to stay in sync across:
- `setup.py` (version parameter)
- `pyproject.toml` (version field)
- `README.md` (Status line)
- Git tags (v.X.Y.Z format)
- PyPI registry

Current version: **1.0.0**

## Checking Version Sync

Run the verification script to check if all version numbers match:

```bash
bash scripts/check-version-sync.sh
```

Expected output:
```
✅ All versions are in sync!
Current version: 1.0.0
```

## Updating Version

To update the version across all sources:

```bash
bash scripts/update-version.sh 1.1.0
```

This script will:
1. Update setup.py
2. Update pyproject.toml
3. Update README.md
4. Display summary and next steps

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
git add -A
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
| `setup.py` | `version="..."` | `version="1.0.0"` |
| `pyproject.toml` | `version = "..."` | `version = "1.0.0"` |
| `README.md` | Status line | `Status: v1.0.0 -` |
| Git tags | Tag name | `v1.0.0` |
| PyPI | Package info | Published as 1.0.0 |

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
grep version= setup.py
grep "version =" pyproject.toml
grep "Status.*:" README.md
git tag -l
```

Fix any mismatches manually, then re-run the check.

### Manual Version Update

If automated scripts fail, update versions manually:

1. Edit setup.py: change `version="X.Y.Z"`
2. Edit pyproject.toml: change `version = "X.Y.Z"`
3. Edit README.md: change `Status: vX.Y.Z`
4. Create git tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
5. Verify: `bash scripts/check-version-sync.sh`

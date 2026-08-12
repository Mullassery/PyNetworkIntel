#!/bin/bash

# Version Sync Verification Script
# This script verifies that version numbers are consistent across all sources:
# - pyproject.toml (single source of truth for the package version)
# - GitHub releases (via git tags)
# - README.md (status line)
#
# NOTE: setup.py was removed - pyproject.toml's [project] table is the only
# build metadata source now (avoids two files disagreeing about version/
# license/dependencies, which happened in the past).

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "======================================"
echo "Version Sync Verification"
echo "======================================"
echo ""

# Extract versions from each source
echo "Checking version sources..."
echo ""

PYPROJECT_VERSION=$(grep 'version = ' pyproject.toml | head -1 | sed 's/.*version = "\([^"]*\)".*/\1/')
echo "✓ pyproject.toml version:  $PYPROJECT_VERSION"

README_VERSION=$(grep 'Status.*:' README.md | head -1 | sed 's/.*v\([0-9][0-9.]*\).*/\1/')
echo "✓ README.md version:       $README_VERSION"

# Get latest git tag
GIT_TAG=$(git describe --tags 2>/dev/null | cut -d'-' -f1 | sed 's/v//' || echo "none")
echo "✓ Latest git tag:          $GIT_TAG"

# Get latest PyPI version (requires curl and python)
if command -v curl &> /dev/null; then
    PYPI_VERSION=$(curl -s https://pypi.org/pypi/pynetworkintel/json 2>/dev/null | python -c "import sys, json; print(json.load(sys.stdin)['info']['version'])" 2>/dev/null || echo "unknown")
    echo "✓ PyPI version:            $PYPI_VERSION"
else
    echo "⚠ curl not found, skipping PyPI check"
fi

echo ""
echo "======================================"
echo "Sync Status"
echo "======================================"
echo ""

# Check if all versions match
if [ "$PYPROJECT_VERSION" == "$README_VERSION" ] && [ "$PYPROJECT_VERSION" == "$GIT_TAG" ]; then
    echo "✅ All versions are in sync!"
    echo ""
    echo "Current version: $PYPROJECT_VERSION"
    exit 0
else
    echo "❌ Version mismatch detected!"
    echo ""
    echo "Pyproject.toml: $PYPROJECT_VERSION"
    echo "README.md:      v$README_VERSION"
    echo "Git tag:        v$GIT_TAG"
    [ ! -z "$PYPI_VERSION" ] && echo "PyPI:           $PYPI_VERSION"
    echo ""
    exit 1
fi

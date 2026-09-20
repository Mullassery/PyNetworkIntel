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

INIT_VERSION=$(grep '__version__' pynetworkintel/__init__.py | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
echo "✓ __init__.py version:     $INIT_VERSION"

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

# Check if all versions match. Note: GIT_TAG intentionally is NOT part of
# this check - `git describe` follows commit ancestry, not version-number
# order, and this repo has at least one out-of-order tag (v2.0.0 points at
# an old commit that predates v1.4.0 and has far less functionality; see
# ROADMAP_HONEST.md). Treat GIT_TAG as informational only.
if [ "$PYPROJECT_VERSION" == "$INIT_VERSION" ]; then
    echo "✅ pyproject.toml and __init__.py are in sync!"
    echo ""
    echo "Current version: $PYPROJECT_VERSION"
    exit 0
else
    echo "❌ Version mismatch detected!"
    echo ""
    echo "Pyproject.toml:   $PYPROJECT_VERSION"
    echo "__init__.py:      $INIT_VERSION"
    echo "Git tag (info):   $GIT_TAG"
    [ ! -z "$PYPI_VERSION" ] && echo "PyPI:             $PYPI_VERSION"
    echo ""
    exit 1
fi

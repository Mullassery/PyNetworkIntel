#!/bin/bash

# Version Update Script
# Updates version numbers across all source files and creates git tag

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <new-version>"
    echo "Example: $0 1.1.0"
    exit 1
fi

NEW_VERSION="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "======================================"
echo "Updating Version to $NEW_VERSION"
echo "======================================"
echo ""

# Validate version format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ Invalid version format: $NEW_VERSION"
    echo "Please use format: X.Y.Z (e.g., 1.1.0)"
    exit 1
fi

echo "Updating files..."
echo ""

# Update pyproject.toml
echo "Updating pyproject.toml..."
sed -i "" "s/version = \"[^\"]*\"/version = \"$NEW_VERSION\"/" pyproject.toml
echo "✓ pyproject.toml updated"

# Update pynetworkintel/__init__.py (this was previously missing from this
# script entirely, which is exactly how __init__.py drifted to 1.3.1 while
# pyproject.toml moved on to 1.4.0 - caught and fixed in the 2026-09
# standardization pass; scripts/check-version-sync.sh now checks this file
# too, so a repeat of this drift will fail CI/local verification loudly).
echo "Updating pynetworkintel/__init__.py..."
sed -i "" "s/__version__ = \"[^\"]*\"/__version__ = \"$NEW_VERSION\"/" pynetworkintel/__init__.py
echo "✓ pynetworkintel/__init__.py updated"

# NOTE: README.md no longer carries a "Status: vX.Y.Z" line (it was removed
# in a prior docs rewrite), so there is nothing version-specific to update
# there. The previous version of this script had a sed command targeting
# that line; it was a silent no-op against the current README and has been
# removed rather than left as dead code.

echo ""
echo "======================================"
echo "Version Updated Successfully"
echo "======================================"
echo ""
echo "Summary:"
echo "- pyproject.toml:              v$NEW_VERSION"
echo "- pynetworkintel/__init__.py:  v$NEW_VERSION"
echo ""
echo "Next steps:"
echo "1. Review changes: git diff"
echo "2. Verify sync: bash scripts/check-version-sync.sh"
echo "3. Commit changes: git add pyproject.toml pynetworkintel/__init__.py && git commit -m 'Bump version to $NEW_VERSION'"
echo "4. Create tag: git tag v$NEW_VERSION"
echo "5. Push tag: git push origin v$NEW_VERSION"
echo "6. Build wheel: python -m build --wheel"
echo "7. Upload to PyPI: python -m twine upload dist/pynetworkintel-$NEW_VERSION-py3-none-any.whl"
echo ""

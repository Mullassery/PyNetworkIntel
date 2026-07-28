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

# Update setup.py
echo "Updating setup.py..."
sed -i "" "s/version=\"[^\"]*\"/version=\"$NEW_VERSION\"/" setup.py
echo "✓ setup.py updated"

# Update pyproject.toml
echo "Updating pyproject.toml..."
sed -i "" "s/version = \"[^\"]*\"/version = \"$NEW_VERSION\"/" pyproject.toml
echo "✓ pyproject.toml updated"

# Update README.md version in status line
echo "Updating README.md..."
sed -i "" "s/Status.*: v[0-9.]*\(.*\)/Status: v$NEW_VERSION\1/" README.md
echo "✓ README.md updated"

echo ""
echo "======================================"
echo "Version Updated Successfully"
echo "======================================"
echo ""
echo "Summary:"
echo "- setup.py: v$NEW_VERSION"
echo "- pyproject.toml: v$NEW_VERSION"
echo "- README.md: v$NEW_VERSION"
echo ""
echo "Next steps:"
echo "1. Review changes: git diff"
echo "2. Commit changes: git add -A && git commit -m 'Bump version to $NEW_VERSION'"
echo "3. Create tag: git tag v$NEW_VERSION"
echo "4. Push tag: git push origin v$NEW_VERSION"
echo "5. Build wheel: python -m build --wheel"
echo "6. Upload to PyPI: python -m twine upload dist/pynetworkintel-$NEW_VERSION-py3-none-any.whl"
echo ""

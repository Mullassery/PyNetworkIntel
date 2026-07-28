#!/bin/bash
# Build script for PyNetworkIntel wheels

set -e

echo "Building PyNetworkIntel wheels..."

# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Install build tools if needed
pip install -q build twine

# Build wheel
echo "Building wheel distribution..."
python -m build --wheel

# Display built artifacts
echo ""
echo "Built artifacts:"
ls -lh dist/

echo ""
echo "✅ Build complete!"
echo ""
echo "To install locally:"
echo "  pip install dist/pynetworkintel-*.whl"
echo ""
echo "To test installation:"
echo "  pip install dist/pynetworkintel-*.whl --force-reinstall"
echo "  pynetworkintel --version"

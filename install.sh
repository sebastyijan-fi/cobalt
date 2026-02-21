#!/bin/bash
set -e

echo "=== Cobalt Installer ==="

# Check if we are in the root of the repo
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Run this script from the root of the repository."
    exit 1
fi

echo "Installing cbc via cargo install..."
cargo install --path cbc-cli --force

# Clean up any old binary at ~/.local/bin to avoid shadowing
if [ -f "$HOME/.local/bin/cbc" ]; then
    echo "Removing old binary at ~/.local/bin/cbc to avoid PATH shadowing..."
    rm "$HOME/.local/bin/cbc"
fi

echo ""
echo "✓ Installed: $(which cbc)"
echo "Usage: cbc --help"

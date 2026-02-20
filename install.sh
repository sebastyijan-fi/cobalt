#!/bin/bash
set -e

echo "=== Cobalt Installer ==="

# Check if we are in the root of the repo
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Run this script from the root of the repository."
    exit 1
fi

DEST_DIR="$HOME/.local/bin"
mkdir -p "$DEST_DIR"

echo "Installing cbc to $DEST_DIR..."
# We assume the build has already run or will be run.
# For robustness, we check if target/release/cbc differs or is missing.

if [ ! -f "target/release/cbc" ]; then
    echo "Building Cobalt..."
    cargo build --release
fi

cp target/release/cbc "$DEST_DIR/cbc"
chmod +x "$DEST_DIR/cbc"

echo "✓ Installation complete: $DEST_DIR/cbc"
echo ""

# Check PATH
if [[ ":$PATH:" != *":$DEST_DIR:"* ]]; then
    echo "WARNING: $DEST_DIR is not in your PATH."
    echo "Add the following to your shell config (~/.bashrc, ~/.zshrc):"
    echo "    export PATH=\"$DEST_DIR:\$PATH\""
else
    echo "Usage: cbc --help"
fi

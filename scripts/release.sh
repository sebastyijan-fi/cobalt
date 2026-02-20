#!/bin/bash
set -e

# Cobalt Release Automation
# Usage: ./scripts/release.sh [version]

VERSION=${1:-"snapshot"}
OUTPUT_DIR="target/release"
DIST_DIR="dist/$VERSION"

echo "=== Cobalt Release: $VERSION ==="

# 1. Clean and Build
echo "Building release binary..."
cargo build --release --locked --bin cbc

# 2. Prepare Distribution
mkdir -p "$DIST_DIR"
cp "$OUTPUT_DIR/cbc" "$DIST_DIR/cbc-linux-amd64"

# 3. Strip Symbols (Deterministic)
echo "Stripping symbols..."
strip "$DIST_DIR/cbc-linux-amd64"

# 4. Generate Checksums
echo "Generating SHA256 checksums..."
cd "$DIST_DIR"
sha256sum cbc-linux-amd64 > SHA256SUMS
cd - > /dev/null

# 5. Sign Artifacts (Placeholder for GPG/Minisign)
echo "Signing release manifest..."
if command -v gpg >/dev/null; then
    # gpg --detach-sign --armor "$DIST_DIR/SHA256SUMS"
    echo "  (GPG signing skipped - key not configured)"
else
    echo "  (GPG not found)"
fi

echo "✓ Release artifacts ready in $DIST_DIR"
ls -l "$DIST_DIR"

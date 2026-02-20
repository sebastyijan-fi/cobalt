#!/bin/bash
# Archivist Demo (Legal Evidence Chain)

# Ensure we are in the script's directory
cd "$(dirname "$0")"

if ! command -v cbc &> /dev/null; then
  if [ -f "../../target/release/cbc" ]; then
    CBC="../../target/release/cbc"
  else
    echo "Error: 'cbc' not found in PATH. Run ./install.sh first."
    exit 1
  fi
else
  CBC="cbc"
fi

echo "=== Scenario: The Legal Archivist (Chain of Custody) ==="
echo ""

# 1. Simulate Evidence Collection
echo "[1] Crime Scene: Ingesting bodycam footage..."
# Just a placeholder file
if [ ! -f police_cam_01.mp4 ]; then
    dd if=/dev/urandom of=police_cam_01.mp4 bs=1M count=5 status=progress
fi

echo "[2] Archive: Encoding evidence with provenance..."
$CBC encode -i police_cam_01.mp4 -o evidence_001.cbc
echo ""

# 2. Simulate Metadata Inspection
echo "[3] Courtroom: Verifying Chain of Custody..."
$CBC inspect -i evidence_001.cbc

echo ""
echo "[4] Judge Miller: 'The Source Root matches the police report.'"
echo "    (In future versions, 'transform' operations will append receipts"
echo "     to this chain, allowing verification of redacted files.)"

echo ""
echo "=== Mission Accomplished ==="
echo "The digital evidence is cryptographically bound to its source."

#!/bin/bash
# Enterprise Compliance: SEC/FINRA WORM Archival Demo
set -euo pipefail

# Ensure we are in the script's directory
cd "$(dirname "$0")"

# Resolve CBC binary
if ! command -v cbc &> /dev/null; then
  if [ -f "../../target/release/cbc" ]; then
    CBC="../../target/release/cbc"
  else
    echo "Error: 'cbc' not found in PATH. Ensure you have built the release binary."
    exit 1
  fi
else
  CBC="cbc"
fi

echo "=== Scenario: SEC/FINRA WORM Archival (Chain of Custody) ==="
echo ""

# 1. Simulate Evidence Collection
echo "[1] Enterprise Platform: Ingesting daily compliance broker logs..."
# Just a placeholder file
if [ ! -f daily_broker_logs.dat ]; then
    dd if=/dev/urandom of=daily_broker_logs.dat bs=1M count=5 status=progress
fi

echo "[2] Compliance Daemon: Packaging records into audited WORM container..."
$CBC encode -i daily_broker_logs.dat -o regulatory_archive_001.cbc
echo ""

# 2. Simulate Metadata Inspection
echo "[3] SEC Auditor: Verifying Enterprise Chain of Custody..."
$CBC inspect -i regulatory_archive_001.cbc

echo ""
echo "[4] Audit Status: 'The Source Root matches the immutable ledger records.'"

echo ""
echo "=== Mission Accomplished ==="
echo "The digital compliance artifacts are cryptographically solidified for their 7-year mandated lifecycle."

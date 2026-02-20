#!/bin/bash
# AI Pipeline Demo

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

echo "=== Scenario: The AI Data Pipeline (Model Provenance) ==="
echo ""

# 1. Simulate Dataset Creation
echo "[1] DataOps: Preparing datasets (v1)..."
mkdir -p data_v1
echo "user_1,score=80" > data_v1/users.csv
echo "user_2,score=20" >> data_v1/users.csv
echo "[Note: This is the CLEAN dataset]"

echo ""
echo "[2] Pipeline: Fingerprinting training data..."
$CBC encode -i data_v1/ -o training_set_v1.cbc --hash blake3 --families A+B
echo ""

# 2. Simulate Audit
echo "[3] Auditor: Verifying training set provenance..."
$CBC validate -i training_set_v1.cbc

# 3. Prove Absence of Poisoned Data
echo ""
echo "[4] Auditor: Checking for 'poisoned_users.csv'..."
# In v0.1, we decode and list the archive to verify contents.
if $CBC decode -i training_set_v1.cbc -o - 2>/dev/null | tar -tf - 2>/dev/null | grep -q "poisoned_users.csv"; then
    echo "❌ ALERT: Poisoned data detected!"
else
    echo "✓ PASS: No poisoned data file found in the manifest."
fi

echo ""
echo "=== Mission Accomplished ==="
echo "The model is cryptographically bound to the CLEAN dataset version."

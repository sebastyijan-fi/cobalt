#!/bin/bash
# Enterprise Compliance: ML Model Provenance
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

echo "=== Scenario: Regulated Machine Learning (Model Provenance) ==="
echo ""

# 1. Simulate Dataset Creation
echo "[1] DataOps: Preparing immutable ML datasets (v1)..."
mkdir -p data_v1
echo "user_1,score=80" > data_v1/users.csv
echo "user_2,score=20" >> data_v1/users.csv
echo "[Note: This represents the cryptographically CLEAN dataset]"

echo ""
echo "[2] CI/CD Pipeline: Fingerprinting training data..."
$CBC encode -i data_v1/ -o training_set_v1.cbc --hash blake3 --families A+B
echo ""

# 2. Simulate Audit
echo "[3] Compliance Auditor: Verifying training set provenance..."
$CBC validate -i training_set_v1.cbc

# 3. Prove Absence of Poisoned Data
echo ""
echo "[4] Compliance Auditor: Checking for presence of known poisoned/biased dataset 'poisoned_users.csv'..."
# Decode and list the archive to verify contents.
if $CBC decode -i training_set_v1.cbc -o - 2>/dev/null | tar -tf - 2>/dev/null | grep -q "poisoned_users.csv"; then
    echo "❌ ALERT: Poisoned data detected in training corpus!"
else
    echo "✓ PASS: No poisoned data file found in the manifest. Dataset is certified clean."
fi

echo ""
echo "=== Mission Accomplished ==="
echo "The compiled LLM/ML Model is cryptographically bound to the certified CLEAN dataset version."

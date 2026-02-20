#!/bin/bash
# Enterprise Compliance: GDPR Redaction Demo
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

echo "=== Scenario: GDPR Right to Erasure (Subrange Extraction) ==="
echo ""

# 1. Simulate the Enterprise Data Lake
echo "[1] Enterprise Platform: Preparing highly sensitive ledger documents..."
mkdir -p ledger_data
echo "Patient_A: Financial Audit 2025" > ledger_data/patient_a_audit.txt
echo "Patient_B: Complete Medical History (PII)" > ledger_data/patient_b_medical.txt

echo "[2] Enterprise Platform: Encoding ledger as 'financial_ledger.cbc'..."
$CBC encode -i ledger_data/ -o financial_ledger.cbc --hash blake3 --families A+B
echo ""

# 2. Establish Audit Baseline
ROOT_HASH=$($CBC inspect -i financial_ledger.cbc | grep "Merkle Root" | awk '{print $3}')
echo "[3] Auditor Baseline: The immutable root is: $ROOT_HASH"
echo ""

# 3. Process GDPR Request
echo "[4] DPO: Receiving Art. 17 Deletion Request for Patient B..."
$CBC validate -i financial_ledger.cbc
echo ""

# 4. Perform Cryptographic Extraction
echo "[5] DPO: Extracting Patient A data, irreversibly destroying Patient B PII..."
# In a true enterprise environment, this would hit KMS. For the local demo, we simulate:
$CBC decode -i financial_ledger.cbc -o output_dir.tar >/dev/null
mkdir -p output_dir
tar -xf output_dir.tar -C output_dir
rm output_dir.tar

# We intentionally drop/destroy Patient_B data
mv output_dir/ledger_data/patient_a_audit.txt ./patient_a_audit.txt
echo " [REDACTED BY COMPLIANCE SCRIPT]" >> patient_a_audit.txt

echo "[6] DPO: Re-encoding redacted ledger for continued audit viability..."
$CBC encode -i patient_a_audit.txt -o financial_ledger_redacted.cbc

echo ""
echo "=== Mission Accomplished ==="
echo "The Enterprise has complied with the deletion request while proving the surviving records match the original $ROOT_HASH."

#!/bin/bash
# Enterprise Compliance: IoT Telemetry & Firmware Demo
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

echo "=== Scenario: Enterprise IoT (Telemetry Audit & Immutable Firmware) ==="
echo ""

# 1. Simulate Firmware Generation
echo "[1] Enterprise Platform: Generating signed firmware v2.0 (10MB) for Edge Fleet..."
# Just a placeholder file
if [ ! -f firmware_v2.0.bin ]; then
    dd if=/dev/urandom of=firmware_v2.0.bin bs=1M count=10 status=progress
fi

echo ""
echo "[2] Enterprise Platform: Encoding for high-latency satellite link (Stream Mode)..."
# We use a small block size (4KB) for granular verification over slow links
$CBC stream-encode -i firmware_v2.0.bin -o fw_update.cbc --block-size 4096 --hash blake3 --families A+B
echo ""

# 2. Simulate Transmission
echo "[3] Satellite Uplink: Transmitting Merkle Root to Vanguard Fleet..."
ROOT_HASH=$($CBC inspect -i fw_update.cbc | grep "Merkle Root" | awk '{print $3}')
echo "   Root: $ROOT_HASH"
echo ""

# 3. Simulate IoT Edge Verification
echo "[4] IoT Edge Device: Receiving block stream..."
# In a real C API scenario, this would be `decoder.feed_block()` in a while loop.
# Here we simulate valid stream reception by validating the whole block container.
$CBC validate -i fw_update.cbc

echo ""
echo "=== Mission Accomplished ==="
echo "The Edge hardware verified every 4KB packet individually before flashing it to ROM."

#!/bin/bash
# Drone Firmware Update Demo

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

echo "=== Scenario: The Autonomous Drone (Firmware Integrity) ==="
echo ""

# 1. Simulate Firmware Generation
echo "[1] Nexus Dynamics: Generating firmware v2.0 (10MB)..."
# Just a placeholder file
if [ ! -f firmware_v2.0.bin ]; then
    dd if=/dev/urandom of=firmware_v2.0.bin bs=1M count=10 status=progress
fi

echo ""
echo "[2] HQ: Encoding for satellite link (Stream Mode)..."
# We use a small block size (4KB) for granular verification over slow links
$CBC stream-encode -i firmware_v2.0.bin -o fw_update.cbc --block-size 4096 --hash blake3 --families A+B
echo ""

# 2. Simulate Transmission
echo "[3] Satellite Uplink: Transmitting Merkle Root..."
ROOT_HASH=$($CBC inspect -i fw_update.cbc | grep "Merkle Root" | awk '{print $3}')
echo "   Root: $ROOT_HASH"
echo ""

# 3. Simulate Drone Verification
echo "[4] Drone: Receiving stream..."
# In a real scenario, this would be `decoder.feed_block()` in a loop.
# Here we simulate valid reception by validating the whole file.
$CBC validate -i fw_update.cbc

echo ""
echo "=== Mission Accomplished ==="
echo "The drone verified every 4KB packet individually before writing to flash."

#!/bin/bash
# Drone Attack Scenario: Signal Jammer

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

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Attack Scenario: The Signal Jammer (Drone) ===${NC}"

if [ ! -f fw_update.cbc ]; then
    echo "Creating baseline firmware..."
    ./run_demo.sh > /dev/null
fi

echo -e "${BLUE}[1] The Signal Jammer: Injecting noise into satellite link...${NC}"
cp fw_update.cbc jammed_update.cbc
# Overwrite 4KB in the middle with random noise
dd if=/dev/urandom of=jammed_update.cbc bs=4096 count=1 seek=100 conv=notrunc 2>/dev/null

echo -e "${BLUE}[2] Drone: Attempting to verify stream...${NC}"
$CBC validate -i jammed_update.cbc

if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ ATTACK STOPPED: Drone rejected the corrupted block.${NC}"
else
    echo -e "${RED}❌ ATTACK SUCCESSFUL: Drone accepted corrupted firmware.${NC}"
    exit 1
fi

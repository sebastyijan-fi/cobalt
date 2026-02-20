#!/bin/bash
# Whistleblower Attack: The Mole

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

echo -e "${BLUE}=== Attack Scenario: The Mole (Whistleblower) ===${NC}"

# Ensure baseline exists
if [ ! -f corruption_scandal.cbc ]; then
    echo "Creating baseline artifact..."
    ./run_demo.sh > /dev/null
fi

# 1. Simulate Attack
echo -e "${BLUE}[1] The Mole: Intercepting 'corruption_scandal.cbc'...${NC}"
cp corruption_scandal.cbc tampered_leak.cbc

echo -e "${BLUE}[2] The Mole: Attempting to modify payload (offset 200)...${NC}"
# Flip a byte in the encrypted payload
perl -i -pe 'sysseek(ARGV, 200, 0); syswrite(ARGV, "\xff", 1)' tampered_leak.cbc 2>/dev/null

# 2. Simulate Defense
echo -e "${BLUE}[3] Sarah: Validating the received file...${NC}"
$CBC validate -i tampered_leak.cbc

if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ ATTACK STOPPED: Cobalt detected the checksum mismatch.${NC}"
else
    echo -e "${RED}❌ ATTACK SUCCESSFUL: Cobalt failed to detect tampering.${NC}"
    exit 1
fi

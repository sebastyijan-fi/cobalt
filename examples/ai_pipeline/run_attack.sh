#!/bin/bash
# AI Pipeline Attack Demo

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

echo -e "${BLUE}=== Attack Scenario: The Insider (AI Pipeline) ===${NC}"

# Ensure baselines
if [ ! -f training_set_v1.cbc ]; then
    echo "Creating baseline dataset..."
    ./run_demo.sh > /dev/null
fi

# Get expected root
EXPECTED_ROOT=$($CBC inspect -i training_set_v1.cbc | grep "Merkle Root" | awk '{print $3}')
echo -e "${GREEN}Expected Root (Model Card): $EXPECTED_ROOT${NC}"

# 1. Simulate Attack
echo -e "${BLUE}[1] The Insider: Swapping Clean Dataset with Poisoned Dataset...${NC}"
mkdir -p data_poisoned
echo "user_1,score=80" > data_poisoned/users.csv
echo "user_999,score=999999" >> data_poisoned/users.csv # Poisoned outlier

# Insider encodes the poisoned set
$CBC encode -i data_poisoned/ -o training_set_fake.cbc --hash blake3 --families A+B 2>/dev/null

# Swap files
cp training_set_fake.cbc training_set_v1.cbc
echo -e "${BLUE}[2] The Insider: File swapped. Structure is technically valid.${NC}"

# 2. Simulate Defense (Regulator Audit)
echo -e "${BLUE}[3] Regulator: Auditing Model Provenance...${NC}"

ACTUAL_ROOT=$($CBC inspect -i training_set_v1.cbc | grep "Merkle Root" | awk '{print $3}')
echo "Artifact Root: $ACTUAL_ROOT"

if [ "$ACTUAL_ROOT" != "$EXPECTED_ROOT" ]; then
    echo -e "${GREEN}✓ ATTACK STOPPED: Root Hash Mismatch! Provenance Broken.${NC}"
else
    echo -e "${RED}❌ ATTACK SUCCESSFUL: Regulator fooled.${NC}"
    exit 1
fi

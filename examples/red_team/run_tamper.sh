#!/bin/bash
# set -e  <-- We expect failures, so don't exit on error

# Setup
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
NC='\033[0m' # No Color

echo -e "${BLUE}=== Scenario: Red Team Verification (Adversarial Demo) ===${NC}"
echo ""

# 1. Baseline: Valid Artifact
echo -e "${BLUE}[1] Baseline: Creating valid artifact...${NC}"
if [ ! -f confidential.txt ]; then
    echo "This is confidential data that must not be tampered with." > confidential.txt
fi
$CBC encode -i confidential.txt -o valid.cbc --hash blake3 --families A+B
echo -e "${GREEN}✓ Created valid.cbc${NC}"
$CBC validate -i valid.cbc
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Baseline validation PASSED${NC}"
else
    echo -e "${RED}❌ Baseline validation FAILED${NC}"
    exit 1
fi
echo ""

# 2. Attack: Bit-Flip Payload
echo -e "${BLUE}[2] Attack: Bit-Flipping Payload (1 byte)...${NC}"
cp valid.cbc tampered_payload.cbc
# Use perl to flip a byte in the middle (offset 100)
# Note: Header is ~64 bytes, so 100 is likely in payload
perl -i -pe 'sysseek(ARGV, 100, 0); syswrite(ARGV, "\xff", 1)' tampered_payload.cbc 2>/dev/null

echo "Attempting validation on tampered payload..."
$CBC validate -i tampered_payload.cbc
if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ SUCCESS: Tampering DETECTED (Validation Failed as expected)${NC}"
else
    echo -e "${RED}❌ FAILURE: Tampering NOT DETECTED${NC}"
fi
echo ""

# 3. Attack: Corrupt Header
echo -e "${BLUE}[3] Attack: Header Corruption (Magic Bytes)...${NC}"
cp valid.cbc tampered_header.cbc
# Overwrite first 4 bytes
printf "HACK" | dd of=tampered_header.cbc bs=1 count=4 conv=notrunc 2>/dev/null

echo "Attempting validation on corrupted header..."
$CBC validate -i tampered_header.cbc
if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ SUCCESS: Corruption DETECTED (Validation Failed as expected)${NC}"
else
    echo -e "${RED}❌ FAILURE: Corruption NOT DETECTED${NC}"
fi
echo ""

# 4. Attack: Truncation
echo -e "${BLUE}[4] Attack: Truncation (Missing Footer)...${NC}"
cp valid.cbc truncated.cbc
# Keep only first 100 bytes (stripping footer)
head -c 100 valid.cbc > truncated.cbc

echo "Attempting validation on truncated file..."
$CBC validate -i truncated.cbc
if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ SUCCESS: Truncation DETECTED (Validation Failed as expected)${NC}"
else
    echo -e "${RED}❌ FAILURE: Truncation NOT DETECTED${NC}"
fi

echo ""
echo -e "${BLUE}=== Red Team Assessment Complete ===${NC}"

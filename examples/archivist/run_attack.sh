DIR="$(cd "$(dirname "$0")" && pwd)"
CBC="$DIR/../../target/release/cbc"
# Ensure we run from the script's directory so relative paths work
cd "$DIR"

if [ ! -f "$CBC" ]; then
    echo "Error: Build Cobalt first (cargo build --release)"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Attack Scenario: The Corrupt Clerk (Archivist) ===${NC}"

if [ ! -f evidence_001.cbc ]; then
    echo "Creating baseline evidence..."
    ./run_demo.sh > /dev/null
fi

echo -e "${BLUE}[1] The Clerk: Deleting last 5 seconds of footage...${NC}"
cp evidence_001.cbc interrupted_evidence.cbc
# Keep only first 1MB (simulating deletion/truncation)
head -c 1048576 evidence_001.cbc > interrupted_evidence.cbc

echo -e "${BLUE}[2] Judge Miller: Verifying Chain of Custody...${NC}"
$CBC validate -i interrupted_evidence.cbc

if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ ATTACK STOPPED: Missing Merkle Root detected.${NC}"
else
    echo -e "${RED}❌ ATTACK SUCCESSFUL: Judge accepted broken evidence.${NC}"
    exit 1
fi

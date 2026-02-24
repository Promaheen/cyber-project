#!/bin/bash

# Definition of colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}   CYBER SECURITY DASHBOARD - SYSTEM LAUNCHER    ${NC}"
echo -e "${CYAN}=================================================${NC}"

# Check for sudo upfront
echo -e "${GREEN}[*] Requesting Sudo permissions for Agent (auth.log access)...${NC}"
sudo -v
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Sudo verification failed. Agent requires root privileges.${NC}"
    exit 1
fi

# Clear stale iptables rules from previous sessions
echo -e "${GREEN}[*] Clearing stale iptables block rules...${NC}"
sudo iptables -F INPUT 2>/dev/null
sudo ip6tables -F INPUT 2>/dev/null

# Function to kill all processes on exit
cleanup() {
    echo -e "\n${RED}[!] Shutting down system...${NC}"
    kill $SERVER_PID $FRONTEND_PID 2>/dev/null
    sudo kill $AGENT_PID $NETWORK_AGENT_PID 2>/dev/null
    exit
}
trap cleanup SIGINT

# 1. Start Backend Server
echo -e "${GREEN}[+] Starting Backend Server...${NC}"
./venv/bin/python backend/server/app.py > /dev/null 2>&1 &
SERVER_PID=$!
echo "    Server PID: $SERVER_PID"

# 2. Start Frontend
echo -e "${GREEN}[+] Starting Frontend Dashboard...${NC}"
cd frontend
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ..
echo "    Frontend PID: $FRONTEND_PID"

# 3. Start Agent
echo -e "${GREEN}[+] Starting Security Agent (Log Monitor)...${NC}"
sudo ./venv/bin/python backend/agents/log_agent.py &
AGENT_PID=$!
echo "    Agent PID: $AGENT_PID"

# 4. Start Network Agent
echo -e "${GREEN}[+] Starting Network Agent...${NC}"
sudo ./venv/bin/python backend/agents/network_agent.py &
NETWORK_AGENT_PID=$!
echo "    Network Agent PID: $NETWORK_AGENT_PID"

echo -e "${CYAN}=================================================${NC}"
echo -e "${GREEN}   SYSTEM IS LIVE! ${NC}"
echo -e "   Dashboard: ${CYAN}http://localhost:5173${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "Press Ctrl+C to stop all services."

# Wait for processes
wait

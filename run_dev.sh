#!/bin/bash

# Definition of colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}   CYBER SECURITY DASHBOARD - SYSTEM LAUNCHER (DEV MODE)    ${NC}"
echo -e "${CYAN}=================================================${NC}"

# Start Backend Server
echo -e "${GREEN}[+] Starting Backend Server...${NC}"
./venv/bin/python backend/server/app.py > /dev/null 2>&1 &
SERVER_PID=$!
echo "    Server PID: $SERVER_PID"

# Start Frontend
echo -e "${GREEN}[+] Starting Frontend Dashboard...${NC}"
cd frontend
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ..
echo "    Frontend PID: $FRONTEND_PID"

# Start Agent (Without Sudo - Limited Functionality)
echo -e "${GREEN}[+] Starting Security Agent (Log Monitor)...${NC}"
./venv/bin/python backend/agents/log_agent.py &
AGENT_PID=$!
echo "    Agent PID: $AGENT_PID"

echo -e "${CYAN}=================================================${NC}"
echo -e "${GREEN}   SYSTEM IS LIVE! ${NC}"
echo -e "   Dashboard: ${CYAN}http://localhost:5173${NC}"
echo -e "${CYAN}=================================================${NC}"
echo -e "Press Ctrl+C to stop all services."

# Function to kill all processes on exit
cleanup() {
    echo -e "\n${RED}[!] Shutting down system...${NC}"
    kill $SERVER_PID $FRONTEND_PID $AGENT_PID 2>/dev/null
    exit
}
trap cleanup SIGINT

# Wait for processes
wait

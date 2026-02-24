# 🛡️ Agent-Based Intelligent Threat Detection & Response System

A real-time cybersecurity monitoring platform that uses autonomous agents to detect network attacks (DDoS, brute-force, port scanning), automatically block malicious IPs via `iptables`, and visualize everything on a live dashboard.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-API-green?logo=flask)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?logo=react)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Security Agents](#security-agents)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Attack Simulators](#attack-simulators)

---

## Overview

This project implements a **SOC-style (Security Operations Center)** platform where independent security agents monitor different attack surfaces, detect threats in real-time, and take automated actions — all coordinated through a central backend and visualized on a cyberpunk-themed dashboard.

### How It Works

```
Attack Occurs → Agent Detects → Server Logs Event → Dashboard Shows Alert
                    ↓
            Threshold Exceeded?
                    ↓
        iptables blocks attacker IP → Dashboard updates blocked list
                                           ↓
                                   User clicks "Unblock"
                                           ↓
                              Agent removes iptables rule
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                 FRONTEND (React + Vite)                   │
│                 http://localhost:5173                      │
│      Live Dashboard · Event Feed · Blocked IPs · Charts   │
├──────────────────────────────────────────────────────────┤
│                 BACKEND SERVER (Flask)                     │
│                 http://localhost:5000                      │
│       REST API · Event Processing · Agent Coordination    │
│                Database: SQLite                           │
├──────────────────────────────────────────────────────────┤
│                   SECURITY AGENTS                         │
│  ┌─────────────────────┐  ┌────────────────────────────┐ │
│  │     Log Agent        │  │     Network Agent          │ │
│  │  Monitors auth.log   │  │  Sniffs live packets       │ │
│  │  SSH brute-force     │  │  DDoS / SYN / ICMP / UDP   │ │
│  │  Nmap detection      │  │  Port scan detection       │ │
│  └─────────────────────┘  └────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## Features

- **Real-Time Threat Detection** — agents detect attacks as they happen
- **Automated Response** — malicious IPs are blocked via `iptables` automatically
- **Live Dashboard** — cyberpunk-themed React UI with real-time event feed
- **Progressive Alerts** — events escalate from `low → warning → critical` as attacks intensify
- **Agent Heartbeats** — dashboard shows which agents are online
- **One-Click Unblock** — unblock IPs directly from the dashboard
- **Auto-Unblock** — Network Agent auto-unblocks IPs after a 120-second cooldown
- **Attack Simulators** — included scripts to test DDoS and brute-force detection

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React, Vite, CSS |
| **Backend** | Python, Flask, Flask-CORS |
| **Database** | SQLite |
| **Agents** | Python, Scapy (packet sniffing), psutil |
| **Firewall** | iptables / ip6tables |
| **Attack Tools** | hping3 (DDoS), Hydra (brute-force) |

---

## Project Structure

```
project1/
├── backend/
│   ├── agents/
│   │   ├── log_agent.py          # SSH brute-force & Nmap detection
│   │   └── network_agent.py      # DDoS, flood & port scan detection
│   ├── server/
│   │   └── app.py                # Flask REST API server
│   ├── database/
│   │   ├── setup_db.py           # Database schema initialization
│   │   ├── clear_db.py           # Database reset utility
│   │   └── security_events.db   # SQLite database file
│   └── shared/
│       └── config.py             # Centralized configuration & thresholds
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # Main application component
│   │   ├── main.jsx              # React entry point
│   │   ├── index.css             # Global styles (cyberpunk theme)
│   │   └── components/
│   │       ├── Layout.jsx        # Page layout wrapper
│   │       ├── Sidebar.jsx       # Agent navigation sidebar
│   │       ├── StatGrid.jsx      # Status cards (events, threats)
│   │       ├── EventLog.jsx      # Live scrolling event feed
│   │       ├── ActivityChart.jsx # Metrics visualization
│   │       └── BlockedList.jsx   # Blocked IPs with unblock button
│   ├── package.json
│   └── vite.config.js
├── attack_ddos.sh                # DDoS attack simulator (hping3)
├── attack_hydra.sh               # SSH brute-force simulator (Hydra)
├── run_system.sh                 # One-command system launcher
├── run_dev.sh                    # Development launcher
├── requirements.txt              # Python dependencies
└── venv/                         # Python virtual environment
```

---

## Installation

### Prerequisites

- **Python 3.8+**
- **Node.js 18+** and npm
- **Linux** (requires `iptables` and `/var/log/auth.log`)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd project1
```

### 2. Set Up Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install scapy
```

### 3. Install Frontend Dependencies

```bash
cd frontend
npm install
cd ..
```

### 4. Initialize the Database

```bash
python backend/database/setup_db.py
```

### 5. Install Attack Simulation Tools (Optional)

```bash
sudo apt install hping3 hydra
```

---

## Usage

### Start the Entire System

```bash
./run_system.sh
```

This single command starts all 4 services:

| # | Service | Details |
|---|---------|---------|
| 1 | **Backend Server** | Flask API at `http://localhost:5000` |
| 2 | **Frontend Dashboard** | React app at `http://localhost:5173` |
| 3 | **Log Agent** | Monitors `/var/log/auth.log` (sudo) |
| 4 | **Network Agent** | Sniffs live network packets (sudo) |

> **Note:** The script requests `sudo` at startup (agents need root privileges for `iptables` and packet sniffing).

Press `Ctrl+C` to gracefully shut down all services.

### Start Services Individually

```bash
# Backend server
./venv/bin/python backend/server/app.py

# Frontend
cd frontend && npm run dev

# Log Agent (requires sudo)
sudo ./venv/bin/python backend/agents/log_agent.py

# Network Agent (requires sudo)
sudo ./venv/bin/python backend/agents/network_agent.py
```

---

## Security Agents

### Log Agent — SSH Brute-Force Detection

| What It Monitors | `/var/log/auth.log` |
|---|---|
| **Failed Logins** | Tracks per-IP failures in a 60s sliding window; blocks at 5 attempts |
| **High-Velocity Attacks** | Detects Hydra-style attacks (>1.5 attempts/sec); blocks at just 3 attempts |
| **Nmap Scanners** | Detects scanner signatures in auth.log; immediate block |
| **Suspicious Logins** | Alerts on successful login from IPs with prior failures |
| **Blocking** | Permanent via `iptables` (until manually unblocked from dashboard) |

### Network Agent — DDoS & Flood Detection

| What It Monitors | Live network packets via Scapy |
|---|---|
| **SYN Flood** | ≥100 SYN/sec from one IP → block |
| **ICMP Flood** | ≥100 ICMP/sec from one IP → block |
| **UDP Flood** | ≥200 UDP/sec from one IP → block |
| **Port Scan** | ≥20 unique ports from one IP in 10s → block |
| **Distributed DDoS** | ≥10 different IPs hitting same port → block all |
| **Packet Volume** | ≥500 SYN packets in 10s window → block |
| **Blocking** | Timed cooldown — auto-unblocks after 120 seconds |

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | `GET` | Server health check |
| `/api/events` | `GET` | Fetch latest 100 security events |
| `/api/events` | `POST` | Agents submit events (attacks, heartbeats, blocks) |
| `/api/events` | `DELETE` | Clear event log (optionally filter by agent) |
| `/api/blocked-ips` | `GET` | List all currently blocked IPs |
| `/api/unblock` | `POST` | Queue an IP unblock command for agents |
| `/api/agents` | `GET` | List active agents (alive within 2 minutes) |
| `/api/agent/commands` | `GET` | Agents poll for pending commands |

---

## Configuration

All thresholds are centralized in `backend/shared/config.py`:

### Log Agent Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed attempts before blocking |
| `TIME_WINDOW_SECONDS` | 60 | Sliding window for tracking failures |
| `CRITICAL_RATE` | 1.5 | Attempts/sec to flag as high-velocity |
| `HEARTBEAT_INTERVAL` | 30 | Seconds between heartbeat pings |
| `PROTECTED_IPS` | `127.0.0.1, ::1` | IPs that are never blocked |

### Network Agent Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `NET_SYN_FLOOD_RATE` | 100 | SYN packets/sec to trigger block |
| `NET_ICMP_FLOOD_RATE` | 100 | ICMP packets/sec to trigger block |
| `NET_UDP_FLOOD_RATE` | 200 | UDP packets/sec to trigger block |
| `NET_PORT_SCAN_THRESHOLD` | 20 | Unique ports to flag as port scan |
| `NET_DDOS_SOURCE_THRESHOLD` | 10 | Distinct IPs hitting same port |
| `NET_WINDOW_SECONDS` | 10 | Detection sliding window |
| `NET_BLOCK_DURATION` | 120 | Seconds before auto-unblock |
| `NET_PACKET_FLOOD_THRESHOLD` | 500 | Total SYN packets from one IP in window |

---

## Attack Simulators

### DDoS Simulator

```bash
# SYN flood + ICMP flood (default: both)
./attack_ddos.sh <TARGET_IP>

# SYN flood only
./attack_ddos.sh <TARGET_IP> syn

# ICMP flood only
./attack_ddos.sh <TARGET_IP> icmp
```

Requires: `hping3` (`sudo apt install hping3`)

### Brute-Force Simulator

```bash
# SSH brute-force with 10 common passwords
./attack_hydra.sh <TARGET_IP> [USERNAME]
```

Requires: `hydra` (`sudo apt install hydra`)

---

## Database Schema

| Table | Columns | Purpose |
|-------|---------|---------|
| `events` | id, agent, severity, message, timestamp | All security events |
| `blocked_ips` | id, ip_address, reason, agent, timestamp | Currently blocked IPs |
| `agent_commands` | id, agent_id, command, params, status, timestamp | Server → Agent commands |

---

## License

This project is for educational and demonstration purposes.

---

> **⚠️ Disclaimer:** The attack simulator scripts are for testing this system only. Do not use them against systems you do not own or have explicit permission to test.

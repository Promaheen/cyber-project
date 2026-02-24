from scapy.all import sniff, IP, TCP
import time
import requests
import subprocess
import ipaddress
import sys
import os
import threading
from collections import defaultdict, deque

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.shared import config

SERVER_URL = config.SERVER_URL
AGENT_ID = "Network Agent"

# -------------------------------
# DETECTION SETTINGS
# -------------------------------
PORT_SCAN_THRESHOLD = 20       # Trigger if an IP hits this many UNIQUE ports...
PACKET_FLOOD_THRESHOLD = 500   # OR if an IP sends this many SYN packets to any ports...
WINDOW_SECONDS = 10            # ...within this many seconds.
BLOCK_DURATION_SECONDS = 60    # Temporarily block IP for this duration (cooldown)

# -------------------------------
# SAFE WHITELIST (CIDR-BASED)
# -------------------------------
WHITELIST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),        # IPv4 loopback
    # ipaddress.ip_network("192.168.1.0/24"),   # Commented out for local testing
    # ipaddress.ip_network("10.0.0.0/8"),       # Commented out for local testing
    ipaddress.ip_network("172.16.0.0/12"),      # Private networks
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("fd00::/8")            # IPv6 private (ULA)
]

# STATE TRACKERS
# Map IP -> Unblock Timestamp (when to remove the block)
blocked_ips = {} 
# Track unique ports per IP. We store a queue of (timestamp, dst_port) tuples
# defaultdict(lambda: deque()) provides O(1) appends and pops
port_access_history = defaultdict(lambda: deque())

# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
def is_whitelisted(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in WHITELIST_NETWORKS)
    except ValueError:
        return False

def send_event(msg, severity="MEDIUM", ip=None, blocked=False, event_type="network_alert"):
    print(f"[ALERT] {msg}")
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": event_type,
            "details": {
                "severity": severity,
                "message": msg,
                "source_ip": ip,
                "is_blocked": blocked
            }
        }
        
        if event_type == "ip_unblocked":
            payload["details"]["ip"] = ip
            payload["details"]["reason"] = msg

        requests.post(SERVER_URL, json=payload)
        
        if blocked:
            block_payload = {
                 "agent_id": AGENT_ID,
                 "event_type": "ip_blocked",
                 "details": {
                     "ip": ip,
                     "reason": msg
                 }
            }
            requests.post(SERVER_URL, json=block_payload)
            
    except Exception as e:
        print(f"Error sending event: {e}")

def block_ip(ip):
    if is_whitelisted(ip):
        print(f"[SAFE] Skipping internal/whitelisted IP {ip}")
        return

    if ip in blocked_ips:
        return # Already blocked

    try:
        print(f"[ACTION] Blocking IP {ip} for {BLOCK_DURATION_SECONDS} seconds")
        if ":" in ip:
            subprocess.run(
                ["ip6tables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
        else:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

        # Record when this IP should be unblocked
        blocked_ips[ip] = time.time() + BLOCK_DURATION_SECONDS
        
        # Clear the sliding window queue for this IP so it doesn't instantly re-trigger upon unblock
        if ip in port_access_history:
            port_access_history[ip].clear()
            
        send_event(f"IP {ip} blocked due to port scanning ({BLOCK_DURATION_SECONDS}s cooldown)", "HIGH", ip=ip, blocked=True)

    except Exception as e:
        print("[ERROR] Failed to block IP:", e)

# -------------------------------
# COOLDOWN/UNBLOCK DAEMON
# -------------------------------
def unblock_expired_ips():
    """Background thread that removes IPs from iptables once their cooldown expires."""
    while True:
        now = time.time()
        # Find IPs whose unblock time has passed
        expired_ips = [ip for ip, unblock_time in blocked_ips.items() if now >= unblock_time]
        
        for ip in expired_ips:
            print(f"[ACTION] Cooldown expired. Unblocking IP {ip}")
            try:
                if ":" in ip:
                    subprocess.run(["ip6tables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                else:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            except Exception as e:
                print(f"[ERROR] Failed to unblock IP {ip}: {e}")
                
            # Remove from our tracked dictionary and send a resolution event
            del blocked_ips[ip]
            # Send explicit ip_unblocked event so backend removes it from DB
            send_event(f"Cooldown expired for {ip}", "INFO", ip=ip, blocked=False, event_type="ip_unblocked")
            
        time.sleep(5) # Check every 5 seconds

# -------------------------------
# DETECTION LOGIC
# -------------------------------
def detect(packet):
    # Only process TCP packets with an IP layer
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src = packet[IP].src
        
        # Ignore whitelisted IPs early to prevent alert spam
        if is_whitelisted(src):
            return
            
        # We only care about connection attempts (SYN flag).
        # This prevents large downloads (mostly ACK packets) from triggering false positives.
        flags = packet[TCP].flags
        if 'S' in str(flags): 
            src = packet[IP].src
            dport = packet[TCP].dport
            now = time.time()

            queue = port_access_history[src]
            
            # 1. Clean up old entries outside the time window for this specific IP
            # (deque is O(1) for popleft, making this extremely CPU efficient)
            while queue and (now - queue[0][0]) > WINDOW_SECONDS:
                queue.popleft()
                
            # 2. Add current connection attempt
            queue.append((now, dport))
            
            # 3. If currently blocked, don't trigger alerts, but KEEP clearing the queue so
            #    the queue doesn't build up during the block phase
            if src in blocked_ips:
                return
                
            # 4. Check for unique ports. A real port scan hits many different ports.
            # Convert list of tuples to a set of the destination ports to get a unique count
            unique_ports = len(set(item[1] for item in queue))
            
            if unique_ports >= PORT_SCAN_THRESHOLD:
                send_event(f"Port scan detected ({unique_ports} unique ports hit) from IP {src}", ip=src)
                block_ip(src)
            elif len(queue) >= PACKET_FLOOD_THRESHOLD:
                send_event(f"SYN Flood/High Traffic detected ({len(queue)} connection attempts) from IP {src}", ip=src)
                block_ip(src)

def send_heartbeat():
    while True:
        try:
            requests.post(SERVER_URL, json={
                "agent_id": AGENT_ID,
                "event_type": "heartbeat",
                "details": {
                    "severity": "INFO",
                    "message": "Network Agent Active (Port Scan Detection Mode)"
                }
            })
        except Exception as e:
            pass
        time.sleep(30)

# -------------------------------
# START AGENT
# -------------------------------
if __name__ == "__main__":
    print(f"[*] {AGENT_ID} started (Smart Auto-Blocking Enabled)")
    
    # Start Heartbeat Thread
    threading.Thread(target=send_heartbeat, daemon=True).start()
    
    # Start Cooldown/Unblock Thread
    threading.Thread(target=unblock_expired_ips, daemon=True).start()
    
    # Using eth0 as default, but trying to be robust
    while True:
        try:
            print("Attempting to sniff on eth0... (Tracking SYN packets only)")
            sniff(iface="eth0", filter="tcp", prn=detect, store=False)
        except Exception as e:
            print(f"Error sniffing on eth0: {e}")
            try:
                print("Fallback: Sniffing on all interfaces...")
                sniff(filter="tcp", prn=detect, store=False)
            except Exception as e2:
                print(f"Critical Sniff Error: {e2}")
                time.sleep(5)

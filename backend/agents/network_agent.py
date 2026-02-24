from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import requests
import subprocess
import ipaddress
import sys
import os
import threading
import logging
from collections import defaultdict, deque

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.shared import config

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("NetworkAgent")

# --- Configuration ---
SERVER_URL = config.SERVER_URL
AGENT_ID = "Network Agent"

PORT_SCAN_THRESHOLD = config.NET_PORT_SCAN_THRESHOLD
SYN_FLOOD_RATE = config.NET_SYN_FLOOD_RATE
ICMP_FLOOD_RATE = config.NET_ICMP_FLOOD_RATE
UDP_FLOOD_RATE = config.NET_UDP_FLOOD_RATE
DDOS_SOURCE_THRESHOLD = config.NET_DDOS_SOURCE_THRESHOLD
WINDOW_SECONDS = config.NET_WINDOW_SECONDS
BLOCK_DURATION = config.NET_BLOCK_DURATION
PACKET_FLOOD_THRESHOLD = config.NET_PACKET_FLOOD_THRESHOLD
REQUEST_TIMEOUT = config.REQUEST_TIMEOUT

# --- Whitelist ---
WHITELIST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00::/8")
]

# Auto-detect this machine's own IPs and whitelist them
import psutil
try:
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            try:
                ip = addr.address.split('%')[0]  # Strip interface suffix from IPv6
                net = ipaddress.ip_network(ip + "/32") if ":" not in ip else ipaddress.ip_network(ip + "/128")
                WHITELIST_NETWORKS.append(net)
                logger.info(f"Whitelisted own IP: {ip} ({iface})")
            except ValueError:
                pass
except Exception as e:
    logger.warning(f"Could not auto-detect own IPs: {e}")

logger.info(f"Whitelisted networks: {[str(n) for n in WHITELIST_NETWORKS]}")

# --- State Trackers ---
blocked_ips = {}                                    # IP -> unblock_timestamp
port_access_history = defaultdict(lambda: deque())  # IP -> deque of (timestamp, dst_port)
syn_rate_tracker = defaultdict(lambda: deque())     # IP -> deque of timestamps (SYN packets)
icmp_rate_tracker = defaultdict(lambda: deque())    # IP -> deque of timestamps (ICMP packets)
udp_rate_tracker = defaultdict(lambda: deque())     # IP -> deque of timestamps (UDP packets)
ddos_port_tracker = defaultdict(lambda: {})         # port -> {ip: last_seen_timestamp}
alerted_ips = set()                                 # IPs that have been alerted (avoid spam)


# =======================================
# HELPER FUNCTIONS
# =======================================

def is_whitelisted(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in WHITELIST_NETWORKS)
    except ValueError:
        return False


def _request_post(url, **kwargs):
    """HTTP POST with timeout."""
    kwargs.setdefault('timeout', REQUEST_TIMEOUT)
    try:
        requests.post(url, **kwargs)
    except Exception as e:
        logger.error(f"HTTP request failed: {e}")


def send_alert(msg, severity="warning", ip=None, attack_type="network_alert"):
    """Send a network detection event to the server."""
    logger.warning(f"[{severity.upper()}] {msg}")
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": attack_type,
            "details": {
                "severity": severity,
                "message": msg,
                "source_ip": ip
            }
        }
        _request_post(SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending alert: {e}")


def send_block_event(ip, reason):
    """Send block event so dashboard shows it in the blocked list."""
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": "ip_blocked",
            "details": {
                "ip": ip,
                "reason": reason
            }
        }
        _request_post(SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending block event: {e}")


def send_ddos_progress(ip, current, threshold, attack_type_label, is_critical=False):
    """Send a progressive DDoS detection event (like log agent's N/threshold)."""
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": "ddos_alert",
            "details": {
                "ip": ip,
                "count": current,
                "threshold": threshold,
                "attack_type": attack_type_label,
                "is_critical": is_critical
            }
        }
        _request_post(SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending DDoS progress: {e}")


def block_ip(ip, reason):
    """Block an IP via iptables with a cooldown timer."""
    if is_whitelisted(ip):
        logger.info(f"[SAFE] Skipping whitelisted IP {ip}")
        return False

    if ip in blocked_ips:
        return False  # Already blocked

    try:
        logger.info(f"[ACTION] Blocking IP {ip} for {BLOCK_DURATION}s — {reason}")
        cmd = "ip6tables" if ":" in ip else "iptables"
        subprocess.run([cmd, "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips[ip] = time.time() + BLOCK_DURATION

        # Clear all trackers for this IP
        for tracker in [port_access_history, syn_rate_tracker, icmp_rate_tracker, udp_rate_tracker]:
            if ip in tracker:
                tracker[ip].clear()

        send_block_event(ip, reason)
        return True

    except Exception as e:
        logger.error(f"Failed to block IP {ip}: {e}")
    return False


# =======================================
# COOLDOWN / UNBLOCK DAEMON
# =======================================

def unblock_expired_ips():
    """Background thread: removes iptables rules when cooldown expires."""
    while True:
        now = time.time()
        expired = [ip for ip, t in blocked_ips.items() if now >= t]

        for ip in expired:
            logger.info(f"[ACTION] Cooldown expired — unblocking {ip}")
            try:
                cmd = "ip6tables" if ":" in ip else "iptables"
                # check=False: suppress error if rule was already removed (manual unblock)
                subprocess.run([cmd, "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Failed to unblock {ip}: {e}")

            del blocked_ips[ip]
            alerted_ips.discard(ip)

            # Notify server to remove from blocked list
            try:
                payload = {
                    "agent_id": AGENT_ID,
                    "event_type": "ip_unblocked",
                    "details": {
                        "ip": ip,
                        "reason": f"Cooldown expired for {ip}"
                    }
                }
                _request_post(SERVER_URL, json=payload)
            except Exception as e:
                logger.error(f"Error sending unblock event: {e}")

        time.sleep(5)


def check_commands():
    """Poll server for pending UNBLOCK_IP commands from the dashboard."""
    try:
        res = requests.get(
            f"{SERVER_URL.replace('/events', '/agent/commands')}?agent_id={AGENT_ID}",
            timeout=REQUEST_TIMEOUT
        )
        if res and res.ok:
            commands = res.json()
            for cmd in commands:
                if cmd['command'] == 'UNBLOCK_IP':
                    ip = cmd['params']
                    logger.info(f"[COMMAND] Dashboard requested unblock of {ip}")

                    # Remove from iptables
                    try:
                        iptcmd = "ip6tables" if ":" in ip else "iptables"
                        subprocess.run([iptcmd, "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except Exception:
                        pass

                    # Remove from internal trackers so cooldown timer won't re-fire
                    if ip in blocked_ips:
                        del blocked_ips[ip]
                    alerted_ips.discard(ip)
    except Exception as e:
        logger.error(f"Error checking commands: {e}")


def command_poller():
    """Background thread: polls for dashboard commands every 5 seconds."""
    while True:
        check_commands()
        time.sleep(5)


# =======================================
# RATE HELPER
# =======================================

def _get_rate(tracker, ip, now):
    """Calculate packets/sec for an IP from its timestamp deque."""
    queue = tracker[ip]

    # Purge entries outside window
    while queue and (now - queue[0]) > WINDOW_SECONDS:
        queue.popleft()

    if len(queue) < 2:
        return 0.0, len(queue)

    duration = now - queue[0]
    if duration < 0.1:
        duration = 0.1
    return len(queue) / duration, len(queue)


# =======================================
# DETECTION LOGIC
# =======================================

def detect(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src

    if is_whitelisted(src):
        return

    if src in blocked_ips:
        return

    now = time.time()

    # ------- TCP / SYN Detection -------
    if packet.haslayer(TCP):
        flags = str(packet[TCP].flags)
        if 'S' in flags:
            dport = packet[TCP].dport

            # Track for port scanning
            queue = port_access_history[src]
            while queue and (now - queue[0][0]) > WINDOW_SECONDS:
                queue.popleft()
            queue.append((now, dport))

            # Track for SYN flood rate
            syn_rate_tracker[src].append(now)
            rate, count = _get_rate(syn_rate_tracker, src, now)

            # Track for DDoS (multi-source on same port)
            if dport not in ddos_port_tracker:
                ddos_port_tracker[dport] = {}
            ddos_port_tracker[dport][src] = now

            # --- Detection 1: Port Scan ---
            unique_ports = len(set(item[1] for item in queue))
            if unique_ports >= PORT_SCAN_THRESHOLD:
                if src not in alerted_ips:
                    reason = f"Port Scan Detected — {unique_ports} unique ports from {src}"
                    send_alert(reason, severity="critical", ip=src)
                    block_ip(src, reason)
                    alerted_ips.add(src)
                return

            # --- Detection 2: SYN Flood (rate-based) ---
            if rate >= SYN_FLOOD_RATE:
                if src not in alerted_ips:
                    reason = f"SYN Flood Detected — {int(rate)} SYN/sec from {src}"
                    send_ddos_progress(src, int(rate), SYN_FLOOD_RATE, "SYN Flood", is_critical=True)
                    block_ip(src, reason)
                    alerted_ips.add(src)
                return

            # --- Detection 3: Packet Flood (volume-based) ---
            if count >= PACKET_FLOOD_THRESHOLD:
                if src not in alerted_ips:
                    reason = f"SYN Packet Flood — {count} packets in {WINDOW_SECONDS}s from {src}"
                    send_ddos_progress(src, count, PACKET_FLOOD_THRESHOLD, "SYN Packet Flood", is_critical=True)
                    block_ip(src, reason)
                    alerted_ips.add(src)
                return

            # --- Progressive alerts for SYN at milestones ---
            milestones = [10, 25, 40]
            for m in milestones:
                if int(rate) == m and f"{src}_syn_{m}" not in alerted_ips:
                    send_ddos_progress(src, int(rate), SYN_FLOOD_RATE, "SYN Traffic", is_critical=(rate >= SYN_FLOOD_RATE * 0.6))
                    alerted_ips.add(f"{src}_syn_{m}")

    # ------- ICMP / Ping Flood Detection -------
    elif packet.haslayer(ICMP):
        icmp_rate_tracker[src].append(now)
        rate, count = _get_rate(icmp_rate_tracker, src, now)

        if rate >= ICMP_FLOOD_RATE:
            if src not in alerted_ips:
                reason = f"ICMP Flood (Ping Flood) — {int(rate)} pkt/sec from {src}"
                send_ddos_progress(src, int(rate), ICMP_FLOOD_RATE, "ICMP Flood", is_critical=True)
                block_ip(src, reason)
                alerted_ips.add(src)
            return

        # Progressive alerts for ICMP
        milestones = [20, 50, 80]
        for m in milestones:
            if int(rate) >= m and f"{src}_icmp_{m}" not in alerted_ips:
                send_ddos_progress(src, int(rate), ICMP_FLOOD_RATE, "ICMP Traffic", is_critical=(rate >= ICMP_FLOOD_RATE * 0.6))
                alerted_ips.add(f"{src}_icmp_{m}")

    # ------- UDP Flood Detection -------
    elif packet.haslayer(UDP):
        udp_rate_tracker[src].append(now)
        rate, count = _get_rate(udp_rate_tracker, src, now)

        if rate >= UDP_FLOOD_RATE:
            if src not in alerted_ips:
                reason = f"UDP Flood — {int(rate)} pkt/sec from {src}"
                send_ddos_progress(src, int(rate), UDP_FLOOD_RATE, "UDP Flood", is_critical=True)
                block_ip(src, reason)
                alerted_ips.add(src)
            return

        # Progressive alerts for UDP
        milestones = [50, 100, 150]
        for m in milestones:
            if int(rate) >= m and f"{src}_udp_{m}" not in alerted_ips:
                send_ddos_progress(src, int(rate), UDP_FLOOD_RATE, "UDP Traffic", is_critical=(rate >= UDP_FLOOD_RATE * 0.6))
                alerted_ips.add(f"{src}_udp_{m}")


def check_ddos_multi_source():
    """Background thread: detect distributed DDoS (many IPs hitting same port)."""
    while True:
        now = time.time()
        for port, sources in list(ddos_port_tracker.items()):
            # Clean stale entries
            active = {ip: ts for ip, ts in sources.items() if now - ts < WINDOW_SECONDS}
            ddos_port_tracker[port] = active

            if len(active) >= DDOS_SOURCE_THRESHOLD:
                alert_key = f"ddos_port_{port}"
                if alert_key not in alerted_ips:
                    ips_list = list(active.keys())[:5]  # Show first 5 IPs
                    reason = f"DDoS Detected — {len(active)} sources hitting port {port} [{', '.join(ips_list)}...]"
                    send_alert(reason, severity="critical", ip=ips_list[0], attack_type="ddos_alert")
                    alerted_ips.add(alert_key)

                    # Block all attackers
                    for attacker_ip in active:
                        block_ip(attacker_ip, f"DDoS participant on port {port}")

        time.sleep(3)


# =======================================
# HEARTBEAT
# =======================================

def send_heartbeat():
    while True:
        try:
            _request_post(SERVER_URL, json={
                "agent_id": AGENT_ID,
                "event_type": "heartbeat",
                "details": {
                    "severity": "INFO",
                    "message": "Network Agent Active (DDoS + Port Scan Detection)"
                }
            })
        except Exception:
            pass
        time.sleep(30)


# =======================================
# MAIN
# =======================================

if __name__ == "__main__":
    logger.info(f"[*] {AGENT_ID} started — DDoS + Port Scan + Flood Detection")

    # Start background threads
    threading.Thread(target=send_heartbeat, daemon=True).start()
    threading.Thread(target=unblock_expired_ips, daemon=True).start()
    threading.Thread(target=check_ddos_multi_source, daemon=True).start()
    threading.Thread(target=command_poller, daemon=True).start()

    # Sniff all protocols (TCP + UDP + ICMP)
    while True:
        try:
            logger.info("Sniffing on eth0... (TCP/UDP/ICMP)")
            sniff(iface="eth0", filter="tcp or udp or icmp", prn=detect, store=False)
        except Exception as e:
            logger.warning(f"eth0 failed: {e}")
            try:
                logger.info("Fallback: sniffing on all interfaces...")
                sniff(filter="tcp or udp or icmp", prn=detect, store=False)
            except Exception as e2:
                logger.error(f"Critical sniff error: {e2}")
                time.sleep(5)

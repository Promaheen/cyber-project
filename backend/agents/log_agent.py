import time
import requests
import sys
import psutil
import os
import subprocess
import re
import logging
import ipaddress
import socket

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.shared import config

# --- Configuration ---
SERVER_URL = config.SERVER_URL
AGENT_ID = config.AGENT_ID
LOG_FILE = config.LOG_FILE

BRUTE_FORCE_THRESHOLD = config.BRUTE_FORCE_THRESHOLD
TIME_WINDOW_SECONDS = config.TIME_WINDOW_SECONDS
CRITICAL_RATE = config.CRITICAL_RATE
HEARTBEAT_INTERVAL = config.HEARTBEAT_INTERVAL
FAILURE_SEND_INTERVAL = config.FAILURE_SEND_INTERVAL
REQUEST_TIMEOUT = config.REQUEST_TIMEOUT
MAX_RETRIES = config.MAX_RETRIES
RETRY_DELAY = config.RETRY_DELAY

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("LogAgent")

# --- Protected IPs ---
# Start with configured list, then auto-detect machine's own IPs
PROTECTED_IPS = set(config.PROTECTED_IPS)

def _detect_own_ips():
    """Auto-detect this machine's IP addresses and add them to protected set."""
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            PROTECTED_IPS.add(info[4][0])
    except Exception:
        pass
    # Also grab the server IP from SERVER_URL
    try:
        from urllib.parse import urlparse
        host = urlparse(SERVER_URL).hostname
        if host:
            PROTECTED_IPS.add(host)
    except Exception:
        pass
    logger.info(f"Protected IPs (will never be blocked): {PROTECTED_IPS}")

# --- Blocked IPs (skip further processing until unblocked) ---
blocked_ips = set()

_detect_own_ips()


def is_valid_ip(ip_string):
    """Validate that a string is a real IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def follow(thefile):
    """Generator that yields new lines from a file, handling log rotation."""
    thefile.seek(0, os.SEEK_END)
    current_inode = os.fstat(thefile.fileno()).st_ino

    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.5)

            # --- Log Rotation Detection ---
            try:
                stat = os.stat(thefile.name)
                # Inode changed (file was replaced) or file was truncated
                if stat.st_ino != current_inode or stat.st_size < thefile.tell():
                    logger.warning("Log rotation detected — reopening file.")
                    thefile.close()
                    new_file = open(thefile.name, 'r')
                    current_inode = os.fstat(new_file.fileno()).st_ino
                    # Return the new file handle via a special yield
                    # We re-assign and continue from the top
                    thefile = new_file
                    continue
            except FileNotFoundError:
                # File temporarily missing during rotation, wait and retry
                logger.warning("Log file missing (rotation in progress?), waiting...")
                time.sleep(1)
                continue

            yield None  # Yield None to allow checking timer
            continue
        yield line


def _request_with_retry(method, url, **kwargs):
    """HTTP request wrapper with timeout and retry logic."""
    kwargs.setdefault('timeout', REQUEST_TIMEOUT)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if method == 'post':
                return requests.post(url, **kwargs)
            else:
                return requests.get(url, **kwargs)
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES:
                logger.warning(f"Request failed (attempt {attempt}/{MAX_RETRIES}): {e}. Retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                logger.error(f"Request failed after {MAX_RETRIES} attempts: {e}")
    return None


def block_ip(ip_address):
    """Executes iptables command to block IP, with safeguards."""
    # Validate IP format
    if not is_valid_ip(ip_address):
        logger.warning(f"Invalid IP address, skipping block: {ip_address}")
        return False

    # SAFEGUARD: Never block protected IPs
    if ip_address in PROTECTED_IPS:
        logger.info(f"[SAFEGUARD] Skipping block for protected IP: {ip_address}")
        return True  # Return true to log the event, but don't actually block

    try:
        logger.info(f"[ACTIVE RESPONSE] Blocking IP: {ip_address}")
        # Check if already blocked to avoid duplicates
        check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if check.returncode != 0:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        else:
            logger.info(f"IP {ip_address} is already blocked in iptables.")
        return True  # IP is blocked (either newly or already)
    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
    return False


def send_block_event(ip, reason):
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": "ip_blocked",
            "details": {
                "ip": ip,
                "reason": reason
            }
        }
        logger.info(f"Reporting BLOCK event for {ip}...")
        _request_with_retry('post', SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending block event: {e}")


def send_heartbeat():
    """Send a heartbeat so the server knows this agent is alive."""
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": "heartbeat",
            "details": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent
            }
        }
        _request_with_retry('post', SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending heartbeat: {e}")


def send_failed_login_event(ip, count, is_critical=False):
    """Send an immediate event for a single failed login attempt with per-IP progress."""
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": "login_attempt",
            "details": {
                "ip": ip,
                "count": count,
                "threshold": BRUTE_FORCE_THRESHOLD,
                "is_critical": is_critical
            }
        }
        logger.warning(f"Failed login {count}/{BRUTE_FORCE_THRESHOLD} from {ip}" + (" [HIGH VELOCITY]" if is_critical else ""))
        _request_with_retry('post', SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending login event: {e}")


def unblock_ip(ip_address):
    """Executes iptables command to UNBLOCK IP."""
    try:
        logger.info(f"[ACTIVE RESPONSE] Unblocking IP: {ip_address}")

        check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if check.returncode == 0:
            res = subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
                                 check=False, capture_output=True, text=True)
            if res.returncode != 0:
                logger.error(f"iptables unblock failed: {res.stderr.strip()}")
            else:
                logger.info(f"[SUCCESS] Unblocked {ip_address}")
        else:
            logger.info(f"IP {ip_address} was not blocked in iptables (or already unblocked).")

        return True
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
    return False


def check_commands():
    """Polls server for pending commands."""
    try:
        res = _request_with_retry('get', f"{SERVER_URL.replace('/events', '/agent/commands')}?agent_id={AGENT_ID}")
        if res and res.ok:
            commands = res.json()
            for cmd in commands:
                if cmd['command'] == 'UNBLOCK_IP':
                    ip = cmd['params']
                    unblock_ip(ip)
                    blocked_ips.discard(ip)  # Allow re-detection
    except Exception as e:
        logger.error(f"Error checking commands: {e}")


def send_suspicious_login_event(ip):
    """Report a successful login from an IP that previously had failures."""
    try:
        payload = {
            "agent_id": AGENT_ID,
            "event_type": "suspicious_login",
            "details": {
                "ip": ip,
                "reason": "Successful login after multiple failed attempts"
            }
        }
        logger.warning(f"[ALERT] Suspicious successful login from {ip} (had prior failures)")
        _request_with_retry('post', SERVER_URL, json=payload)
    except Exception as e:
        logger.error(f"Error sending suspicious login event: {e}")


def _cleanup_ip_tracker(ip_tracker, current_time):
    """Remove stale entries from ip_tracker to prevent memory leak."""
    stale_ips = [
        ip for ip, data in ip_tracker.items()
        if isinstance(data, list) and len(data) == 2 and current_time - data[1] > TIME_WINDOW_SECONDS
    ]
    for ip in stale_ips:
        del ip_tracker[ip]


def monitor_ssh_logs():
    logger.info(f"Monitoring Real SSH Logs: {LOG_FILE}")

    if not os.access(LOG_FILE, os.R_OK):
        logger.critical(f"Cannot read {LOG_FILE}. Please run with sudo.")
        return

    ip_tracker = {}            # Track failures per IP: {ip: [count, first_seen_time]}
    failed_ips = set()          # IPs that have had failed attempts (for suspicious login detection)
    last_heartbeat = time.time()
    last_cmd_check = time.time()

    try:
        with open(LOG_FILE, 'r') as f:
            loglines = follow(f)
            last_line_content = ""

            for line in loglines:
                current_time = time.time()

                # --- Periodic IP tracker cleanup (runs every iteration) ---
                _cleanup_ip_tracker(ip_tracker, current_time)

                # --- Check for server commands periodically ---
                if current_time - last_cmd_check >= 5:
                    check_commands()
                    last_cmd_check = current_time

                if line is None:
                    # Heartbeat when idle
                    if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:
                        send_heartbeat()
                        last_heartbeat = current_time
                    continue

                line = line.strip()

                # --- Heartbeat during active log flow ---
                if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:
                    send_heartbeat()
                    last_heartbeat = current_time

                # --- NMAP / SCANNER DETECTION ---
                if "Did not receive identification string" in line or "Bad protocol version identification" in line:
                    logger.warning(f"[DETECTED] Potential Nmap/Scanner Activity: {line}")
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+|[\w:]+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if is_valid_ip(ip) and block_ip(ip):
                            send_block_event(ip, "Port Scanning Detected (Nmap Signature)")
                    continue

                # --- SUCCESSFUL LOGIN AFTER FAILURES (Suspicious Login) ---
                if "Accepted password" in line or "Accepted publickey" in line:
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+|[\w:]+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip in failed_ips:
                            send_suspicious_login_event(ip)
                            failed_ips.discard(ip)
                    continue

                # --- HYDRA / BRUTE FORCE DETECTION ---
                if "Failed password" in line:
                    if line == last_line_content:
                        continue

                    logger.info(f"[DETECTED] {line}")

                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+|[\w:]+)", line)
                    if ip_match:
                        ip = ip_match.group(1)

                        if not is_valid_ip(ip):
                            logger.warning(f"Extracted invalid IP, skipping: {ip}")
                            continue

                        # Skip if this IP is already blocked
                        if ip in blocked_ips:
                            continue

                        # Track this IP for suspicious-login detection
                        failed_ips.add(ip)

                        # Update per-IP tracker
                        if ip not in ip_tracker or not isinstance(ip_tracker[ip], list):
                            ip_tracker[ip] = [0, current_time]

                        count_data = ip_tracker[ip]
                        if current_time - count_data[1] > TIME_WINDOW_SECONDS:
                            count_data = [0, current_time]

                        count_data[0] += 1
                        ip_tracker[ip] = count_data

                        # Velocity check for high-speed attacks
                        is_critical = False
                        if count_data[0] >= 2:
                            duration = current_time - count_data[1]
                            if duration < 0.1:
                                duration = 0.1
                            rate = count_data[0] / duration
                            if rate > CRITICAL_RATE:
                                is_critical = True

                        # --- SEND IMMEDIATELY for each failed attempt ---
                        send_failed_login_event(ip, count_data[0], is_critical)

                        # TRIGGER BLOCK if threshold met
                        # Use lower threshold for high-velocity brute force
                        effective_threshold = 3 if is_critical else BRUTE_FORCE_THRESHOLD
                        if count_data[0] >= effective_threshold:
                            if is_critical:
                                reason = "High-Velocity Brute Force (Likely Hydra)"
                            else:
                                reason = f"Exceeded {BRUTE_FORCE_THRESHOLD} failed login attempts"

                            if block_ip(ip):
                                send_block_event(ip, reason)
                                ip_tracker[ip] = [0, current_time]
                                blocked_ips.add(ip)  # Stop processing further failures

                    last_line_content = line

    except PermissionError:
        logger.critical(f"Permission denied for {LOG_FILE}. Run as root/sudo.")
    except Exception as e:
        logger.error(f"Error reading logs: {e}")


if __name__ == "__main__":
    logger.info(f"Starting Agent {AGENT_ID}...")
    monitor_ssh_logs()

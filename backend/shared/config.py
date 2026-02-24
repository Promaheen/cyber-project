import os

# Base Directory (backend/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database
DB_PATH = os.path.join(BASE_DIR, 'database', 'security_events.db')


# Server
SERVER_URL = "http://localhost:5000/api/events"
COMMANDS_URL = "http://localhost:5000/api/agent/commands"

# Agent
AGENT_ID = "Log Agent"
LOG_FILE = "/var/log/auth.log"

# Log Agent Thresholds
BRUTE_FORCE_THRESHOLD = 5       # Failed attempts before blocking
TIME_WINDOW_SECONDS = 60        # Sliding window for tracking failures per IP
CRITICAL_RATE = 1.5             # Attempts/sec to flag as critical threat
HEARTBEAT_INTERVAL = 30         # Seconds between heartbeat pings
FAILURE_SEND_INTERVAL = 2       # Seconds between failure reports
REQUEST_TIMEOUT = 5             # HTTP request timeout in seconds
MAX_RETRIES = 3                 # Retry count for failed HTTP requests
RETRY_DELAY = 1                 # Seconds between retries
PROTECTED_IPS = ["127.0.0.1", "::1"]  # IPs that must never be blocked

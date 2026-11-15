"""
config.py - All the settings for the scanner live in one place.

Beginners: if you want to change how fast / how aggressive the tool is,
this is the ONLY file you need to edit.
"""
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent          # the project folder
REPORTS_DIR = BASE_DIR / "reports"                  # where JSON/HTML reports go
WORDLIST_DIR = BASE_DIR / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"
LOG_FILE = REPORTS_DIR / "scanner.log"

# ---------------------------------------------------------------------------
# SAFETY: which targets are allowed without extra friction
# ---------------------------------------------------------------------------
# localhost / 127.0.0.1 and private LAN ranges (10.x, 172.16-31.x, 192.168.x)
# are always allowed (after you confirm you own them).
# Add the hostnames/IPs of YOUR practice labs here (e.g. a TryHackMe/HTB VPN IP),
# or set the environment variable RECON_ALLOW_LIST="10.10.11.5,mylab.local".
ALLOW_LIST: list[str] = [
    # "10.10.11.5",
]
ALLOW_LIST += [h.strip() for h in os.getenv("RECON_ALLOW_LIST", "").split(",") if h.strip()]

# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------
# The most common TCP ports. "--ports full" scans 1-65535 instead.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 6379,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017,
]
PORT_TIMEOUT = 1.0          # seconds to wait for a TCP connection
BANNER_TIMEOUT = 2.0        # seconds to wait for a service to "say hello"
MAX_CONCURRENT_PORTS = 300  # how many ports we try at the same time

# Ports where we expect a web server.
WEB_PORTS = {80: "http", 443: "https", 3000: "http", 5000: "http", 8000: "http",
             8008: "http", 8080: "http", 8081: "http", 8443: "https", 8888: "http", 9000: "http"}

# ---------------------------------------------------------------------------
# Web scanning (rate limiting keeps us polite and safe)
# ---------------------------------------------------------------------------
HTTP_TIMEOUT = 10           # seconds per HTTP request
MAX_CONCURRENT_HTTP = 5     # parallel HTTP requests
HTTP_RATE_LIMIT = 15        # max HTTP requests per second
MAX_CRAWL_PAGES = 40        # stop crawling after this many pages
MAX_RESPONSE_BYTES = 2_000_000
USER_AGENT = "Ishtar-Edu/1.0 (educational scanner; authorized testing only)"

# URLs containing these words are NEVER visited or tested, because touching
# them can log you out, reset a lab database or change a password.
CRAWL_EXCLUDE_KEYWORDS = [
    "logout", "logoff", "signout", "setup", "reset", "delete", "remove",
    "csrf", "password", "security.php", "captcha", "drop",
]

# ---------------------------------------------------------------------------
# AI / LLM
# ---------------------------------------------------------------------------
# If ANTHROPIC_API_KEY is set, the summary is written by Claude.
# Otherwise everything runs 100% offline with the local ML model.
LLM_MODEL = "claude-opus-5-5"
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HOST = "127.0.0.1"   # only reachable from your own machine
DASHBOARD_PORT = 5050

TOOL_NAME = "Ishtar"
TOOL_VERSION = "1.0.0"

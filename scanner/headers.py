"""
headers.py - Security header checks, cookie flags, and exposed sensitive files.

Security headers are instructions the server sends to the browser, like
"don't let other sites put me in an iframe" (X-Frame-Options). Missing
headers are not bugs by themselves, but they remove layers of protection.

Sensitive files are things that should never be public: a .git folder
(full source code), a .env file (passwords/API keys), phpinfo() pages...
We confirm each one by checking its CONTENT, not just the status code,
to avoid false alarms.
"""
import logging
import re
from urllib.parse import urljoin, urlparse

from scanner.http_client import HttpClient, Response

log = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": "Limits where scripts can load from - a strong defense against XSS.",
    "X-Frame-Options": "Stops other sites from embedding this page in an iframe (clickjacking).",
    "X-Content-Type-Options": "Stops the browser from guessing file types (MIME sniffing).",
    "Referrer-Policy": "Controls how much of the URL is leaked to other sites.",
    "Permissions-Policy": "Restricts powerful browser features (camera, mic, geolocation).",
    "Strict-Transport-Security": "Forces browsers to always use HTTPS.",
}

# (path, regex that must match the content, how serious, description)
SENSITIVE_FILES = [
    (".git/HEAD", r"^ref: refs/", 0.95, "Git repository exposed - full source code can be downloaded."),
    (".env", r"^[A-Z_]+=.+", 0.95, "Environment file exposed - often contains passwords and API keys."),
    ("config.php.bak", r"<\?php|password", 0.9, "Backup of a config file - may contain DB credentials."),
    ("wp-config.php.bak", r"DB_PASSWORD", 0.95, "WordPress config backup - contains DB credentials."),
    (".htpasswd", r"^\w+:\$?[\w./$]+", 0.9, "Password hash file exposed."),
    ("phpinfo.php", r"phpinfo\(\)|PHP Version", 0.5, "phpinfo() page reveals server configuration."),
    ("info.php", r"phpinfo\(\)|PHP Version", 0.5, "phpinfo() page reveals server configuration."),
    ("server-status", r"Apache Server Status", 0.5, "Apache status page shows live requests and IPs."),
    (".DS_Store", r"Bud1", 0.4, "macOS folder metadata leaks file names."),
    ("backup.zip", r"^PK", 0.85, "Backup archive is downloadable."),
    ("backup.sql", r"(CREATE TABLE|INSERT INTO)", 0.95, "Database dump is downloadable."),
    ("robots.txt", r"(?i)disallow", 0.1, "robots.txt lists paths the owner wants hidden (informational)."),
]


def check_headers(resp: Response) -> list[dict]:
    """Look at one HTTP response and report missing/weak headers and cookie flags."""
    findings = []
    is_https = urlparse(resp.url).scheme == "https"
    headers = {k.lower(): v for k, v in resp.headers.items()}

    for name, why in SECURITY_HEADERS.items():
        if name == "Strict-Transport-Security" and not is_https:
            continue  # HSTS only makes sense over HTTPS
        if name.lower() not in headers:
            findings.append({
                "category": "missing_header",
                "title": f"Missing security header: {name}",
                "location": resp.url, "parameter": name,
                "evidence": why, "confidence": 1.0,
            })

    # Version numbers in headers help attackers find known exploits.
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = headers.get(name, "")
        if re.search(r"\d", value):
            findings.append({
                "category": "info_disclosure",
                "title": f"Software version disclosed in '{name}' header",
                "location": resp.url, "parameter": name,
                "evidence": f"{name}: {value}", "confidence": 0.95,
            })

    for cookie in resp.set_cookies:
        cname = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = [flag for flag, ok in (("HttpOnly", "httponly" in low),
                                         ("Secure", "secure" in low or not is_https),
                                         ("SameSite", "samesite" in low)) if not ok]
        if missing:
            findings.append({
                "category": "insecure_cookie",
                "title": f"Cookie '{cname}' missing flags: {', '.join(missing)}",
                "location": resp.url, "parameter": cname,
                "evidence": cookie[:150], "confidence": 0.9,
            })
    return findings


async def check_sensitive_files(client: HttpClient, base_url: str) -> list[dict]:
    """Request a list of commonly-leaked files and verify their content."""
    findings = []
    root = urljoin(base_url, "/")
    bases = {root, base_url if base_url.endswith("/") else base_url + "/"}
    for base in bases:
        for path, signature, impact, description in SENSITIVE_FILES:
            url = urljoin(base, path)
            resp = await client.get(url, allow_redirects=False)
            if resp and resp.status == 200 and re.search(signature, resp.text[:5000], re.M):
                log.warning("Sensitive file exposed: %s", url)
                findings.append({
                    "category": "sensitive_file",
                    "title": f"Exposed sensitive file: /{path}" if base == root
                             else f"Exposed sensitive file: {urlparse(url).path}",
                    "location": url, "parameter": "",
                    "evidence": description, "confidence": 0.9,
                    # tells the AI how damaging this particular file is
                    "overrides": {"impact": impact, "data_exposure": impact},
                })
    return findings

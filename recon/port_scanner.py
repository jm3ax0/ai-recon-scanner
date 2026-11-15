"""
port_scanner.py - Fast asynchronous TCP port scanner + banner grabber.

How it works (simple version):
  * A "TCP connect scan" tries to open a normal connection to each port.
    If the connection succeeds, the port is OPEN.
  * asyncio lets us try hundreds of ports at the same time instead of one
    by one, so a scan takes seconds instead of minutes.
  * A Semaphore is like a bouncer: it only lets N connections in at once,
    so we don't overload the target or our own computer.
  * After connecting we listen for a "banner" - many services introduce
    themselves (e.g. "SSH-2.0-OpenSSH_8.9"). That tells us WHAT is running.
"""
import asyncio
import logging
import re

import config

log = logging.getLogger(__name__)

# Well-known port -> service name (used when the banner tells us nothing).
KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker-api", 3000: "http-dev",
    3306: "mysql", 3389: "rdp", 5000: "http-dev", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

# Patterns we look for inside banners to identify a service.
BANNER_SIGNATURES = [
    (re.compile(r"^SSH-", re.I), "ssh"),
    (re.compile(r"^HTTP/", re.I), "http"),
    (re.compile(r"^220.*ftp", re.I), "ftp"),
    (re.compile(r"^220.*(smtp|mail)", re.I), "smtp"),
    (re.compile(r"mysql|mariadb", re.I), "mysql"),
    (re.compile(r"^\+OK", re.I), "pop3"),
    (re.compile(r"^\* OK", re.I), "imap"),
    (re.compile(r"^-ERR|redis", re.I), "redis"),
    (re.compile(r"^RFB \d", re.I), "vnc"),
]


def _clean_banner(raw: bytes) -> str:
    """Make raw bytes printable and short."""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() or ch in "\r\n" else "." for ch in text)
    return text.strip()[:300]


def _identify(port: int, banner: str) -> tuple[str, str]:
    """Return (service, version) guessed from the banner or the port number."""
    service = KNOWN_SERVICES.get(port, "unknown")
    version = ""
    for pattern, name in BANNER_SIGNATURES:
        if pattern.search(banner):
            service = name if not (name == "http" and port in (443, 8443)) else "https"
            break
    # Try to pull out a version string, e.g. "Server: Apache/2.4.25 (Debian)"
    m = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
    if m:
        version = m.group(1).strip()
    elif banner.startswith("SSH-"):
        version = banner.splitlines()[0]
    elif banner.startswith("220"):
        version = banner.splitlines()[0][4:]
    return service, version


async def _probe(ip: str, port: int, sem: asyncio.Semaphore) -> dict | None:
    """Try one port. Returns a dict if the port is open, otherwise None."""
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=config.PORT_TIMEOUT)
        except (OSError, TimeoutError):
            return None  # closed, filtered or timed out

        raw = b""
        http_probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
        try:
            if port in config.WEB_PORTS:
                # Web servers wait for US to speak first, so send a tiny request.
                writer.write(http_probe)
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(1024), timeout=config.BANNER_TIMEOUT)
            else:
                # Other services (SSH, FTP...) usually greet us first. Listen...
                try:
                    raw = await asyncio.wait_for(reader.read(1024), timeout=config.BANNER_TIMEOUT)
                except TimeoutError:
                    # ...and if it stays silent, maybe it's a web server on an odd port.
                    writer.write(http_probe)
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(1024), timeout=config.BANNER_TIMEOUT)
        except (OSError, TimeoutError):
            pass  # open but silent - that's fine
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    banner = _clean_banner(raw)
    service, version = _identify(port, banner)
    log.info("Port %d open (%s) %s", port, service, version)
    return {"port": port, "state": "open", "service": service,
            "version": version, "banner": banner}


async def scan_ports(ip: str, ports: list[int],
                     concurrency: int = config.MAX_CONCURRENT_PORTS) -> list[dict]:
    """Scan all ports concurrently and return the open ones, sorted."""
    sem = asyncio.Semaphore(concurrency)
    log.info("Scanning %d ports on %s (concurrency=%d)", len(ports), ip, concurrency)
    results = await asyncio.gather(*(_probe(ip, p, sem) for p in ports))
    open_ports = sorted((r for r in results if r), key=lambda r: r["port"])
    log.info("Found %d open ports", len(open_ports))
    return open_ports


def parse_port_spec(spec: str) -> list[int]:
    """
    'common' -> config.COMMON_PORTS
    'full'   -> 1..65535
    '1-1024' or '22,80,443' or '20-25,80' -> custom list
    """
    spec = spec.strip().lower()
    if spec == "common":
        return list(config.COMMON_PORTS)
    if spec == "full":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Invalid port numbers: {bad[:5]}")
    return sorted(ports)


# Services that are risky to expose on a network -> become findings for the AI.
RISKY_SERVICES = {
    "telnet": "Telnet sends everything (including passwords) in plain text.",
    "ftp": "FTP often sends credentials in plain text and may allow anonymous login.",
    "smb": "SMB file sharing has a long history of critical remote vulnerabilities.",
    "rdp": "Remote Desktop exposed to the network is a top target for brute-force attacks.",
    "vnc": "VNC remote desktop is often weakly protected.",
    "redis": "Redis often runs without a password and can be abused for code execution.",
    "mongodb": "MongoDB is frequently exposed without authentication.",
    "memcached": "Memcached has no authentication and can leak cached data.",
    "elasticsearch": "Elasticsearch is frequently exposed without authentication.",
    "docker-api": "An exposed Docker API gives full control of the host.",
    "mysql": "The database port is reachable directly from the network.",
    "postgresql": "The database port is reachable directly from the network.",
    "mssql": "The database port is reachable directly from the network.",
    "winrm": "Windows remote management is exposed.",
}


def port_findings(open_ports: list[dict]) -> list[dict]:
    """Convert risky open services into 'findings' that the AI layer will rank."""
    findings = []
    for p in open_ports:
        reason = RISKY_SERVICES.get(p["service"])
        if reason:
            findings.append({
                "category": "risky_service",
                "title": f"Risky service exposed: {p['service']} on port {p['port']}",
                "location": f"tcp/{p['port']}",
                "parameter": "",
                "evidence": (p["banner"] or reason)[:200],
                "confidence": 0.9 if p["banner"] else 0.6,
                "details": reason,
            })
    return findings

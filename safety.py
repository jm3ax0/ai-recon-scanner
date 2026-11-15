"""
safety.py - The "are you allowed to scan this?" gate.

Rules:
  1. Every scan asks you to confirm you own / are authorized to test the target.
  2. localhost, private LAN IPs and the allow-list in config.py are accepted
     after that confirmation.
  3. ANY public internet target requires you to type an exact sentence.
     This cannot be skipped with --yes.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import config

log = logging.getLogger(__name__)


class TargetNotAllowed(Exception):
    """Raised when the user does not authorize the scan."""


def extract_host(target: str) -> str:
    """Turn 'http://127.0.0.1:8080/dvwa' or '127.0.0.1' into just the host part."""
    if "://" in target:
        host = urlparse(target).hostname or ""
    else:
        host = target.split("/")[0]
        # strip a ":port" suffix, but keep IPv6 like [::1]
        if host.startswith("["):
            host = host[1:].split("]")[0]
        elif host.count(":") == 1:
            host = host.split(":")[0]
    if not host:
        raise ValueError(f"Could not find a host name in '{target}'")
    return host


def resolve(host: str) -> str:
    """DNS lookup: host name -> IP address (string)."""
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{host}': {exc}") from exc


def classify_target(target: str) -> tuple[str, str, str]:
    """
    Returns (host, ip, kind). kind is one of:
      'local'       -> this computer (127.0.0.1, ::1)
      'private'     -> your home/lab network (10.x, 172.16-31.x, 192.168.x)
      'allowlisted' -> listed in config.ALLOW_LIST
      'public'      -> anything on the internet
    """
    host = extract_host(target)
    ip = resolve(host)
    addr = ipaddress.ip_address(ip)

    if addr.is_loopback:
        kind = "local"
    elif host in config.ALLOW_LIST or ip in config.ALLOW_LIST:
        kind = "allowlisted"
    elif addr.is_private or addr.is_link_local:
        kind = "private"
    else:
        kind = "public"
    return host, ip, kind


def confirm_authorization(target: str, assume_yes: bool = False) -> tuple[str, str, str]:
    """
    Ask the human for permission. Returns (host, ip, kind) if allowed,
    raises TargetNotAllowed otherwise.
    """
    host, ip, kind = classify_target(target)

    print("\n" + "=" * 70)
    print(" AUTHORIZATION CHECK")
    print("=" * 70)
    print(f" Target : {target}")
    print(f" Host   : {host}  ->  IP {ip}")
    print(f" Type   : {kind.upper()}")
    print(" Scanning systems you do not own or have written permission to test")
    print(" is ILLEGAL in most countries. Use this tool on your own lab only.")
    print("=" * 70)

    if kind == "public":
        # Public targets: a strict, typed acknowledgment. --yes does NOT skip this.
        phrase = f"I am authorized to test {host}"
        print("\n !!! This is a PUBLIC internet address. !!!")
        print(" Only continue if you have WRITTEN permission from the owner")
        print(" (e.g. a bug bounty scope or a signed pentest contract).")
        print(f'\n Type exactly:  {phrase}')
        answer = input(" > ").strip()
        if answer != phrase:
            raise TargetNotAllowed("Public target not acknowledged - scan cancelled.")
        log.warning("User acknowledged authorization for PUBLIC target %s (%s)", host, ip)
        return host, ip, kind

    if assume_yes:
        log.info("Authorization pre-confirmed with --yes for %s target %s", kind, host)
        return host, ip, kind

    answer = input("\n Do you own this system or have permission to test it? [yes/no] > ")
    if answer.strip().lower() not in ("yes", "y"):
        raise TargetNotAllowed("Authorization not confirmed - scan cancelled.")
    log.info("User confirmed authorization for %s target %s", kind, host)
    return host, ip, kind

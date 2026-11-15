"""
dir_enum.py - Directory / path enumeration ("dirbusting").

Idea: web servers often contain pages that are not linked anywhere
(/admin, /backup, /phpmyadmin ...). We take a list of common names
(a "wordlist") and ask the server for each one. The HTTP status code
tells us whether it exists:
    200 OK            -> exists
    301/302 redirect  -> usually exists (often a folder)
    401/403           -> exists but protected (still interesting!)
    404               -> does not exist

Trick - "soft 404": some servers answer 200 for EVERY URL. To avoid false
positives we first request a random path that surely doesn't exist and
remember what a "not found" answer looks like.
"""
import asyncio
import logging
import secrets
from pathlib import Path
from urllib.parse import urljoin

from scanner.http_client import HttpClient

log = logging.getLogger(__name__)

INTERESTING_STATUS = {200, 204, 301, 302, 307, 308, 401, 403}

# Paths that deserve a finding of their own (admin panels, DB tools...).
SENSITIVE_WORDS = ("admin", "phpmyadmin", "backup", "config", "console", "debug",
                   "dashboard", "manager", "private", "secret", "upload", "db", "sql")


def load_wordlist(path: Path, limit: int | None = None) -> list[str]:
    words = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line.lstrip("/"))
    return words[:limit] if limit else words


async def enumerate_paths(client: HttpClient, base_url: str, wordlist: Path,
                          limit: int | None = None) -> tuple[list[dict], list[dict]]:
    """Returns (found_paths, findings)."""
    if not base_url.endswith("/"):
        base_url += "/"
    words = load_wordlist(wordlist, limit)
    log.info("Directory enumeration on %s with %d words", base_url, len(words))

    # 1) Learn what "not found" looks like on this server.
    fake = await client.get(urljoin(base_url, f"nope-{secrets.token_hex(6)}"),
                            allow_redirects=False)
    soft404 = (fake.status, len(fake.text)) if fake else (404, 0)

    async def check(word: str):
        url = urljoin(base_url, word)
        resp = await client.get(url, allow_redirects=False)
        if not resp or resp.status not in INTERESTING_STATUS:
            return None
        # Same status and roughly same size as the fake page => soft 404, ignore.
        if resp.status == soft404[0] and abs(len(resp.text) - soft404[1]) < 50:
            return None
        return {"path": "/" + word, "url": url, "status": resp.status,
                "length": len(resp.text), "redirect": resp.headers.get("Location", ""),
                "_text": resp.text}

    results = [r for r in await asyncio.gather(*(check(w) for w in words)) if r]

    findings = []
    for r in results:
        text = r.pop("_text")
        if r["status"] == 200 and "<title>Index of /" in text:
            findings.append({
                "category": "dir_listing",
                "title": f"Directory listing enabled at {r['path']}",
                "location": r["url"], "parameter": "",
                "evidence": "Page title starts with 'Index of /'", "confidence": 0.95,
            })
        elif any(w in r["path"].lower() for w in SENSITIVE_WORDS):
            findings.append({
                "category": "interesting_path",
                "title": f"Sensitive-looking path found: {r['path']} (HTTP {r['status']})",
                "location": r["url"], "parameter": "",
                "evidence": f"HTTP {r['status']}, {r['length']} bytes",
                "confidence": 0.6 if r["status"] in (401, 403) else 0.8,
            })
    log.info("Directory enumeration found %d paths", len(results))
    return sorted(results, key=lambda r: r["path"]), findings

"""
xss.py - Reflected Cross-Site Scripting (XSS) DETECTION.

What is reflected XSS?
  The website takes something from the URL/form and puts it back into the
  page WITHOUT escaping it. Then an attacker could make a link that runs
  their JavaScript in a victim's browser.

How we detect it safely (no real attack code):
  1. Generate a random, harmless marker, e.g.  zx3f9a1c
  2. Send the value  "><zx3f9a1c>  in one parameter.
  3. If the page contains  <zx3f9a1c>  exactly (raw angle brackets), the
     browser would treat our text as a real HTML tag -> the parameter is
     vulnerable. If we see  &lt;zx3f9a1c&gt;  the site escaped it -> safe.
  We never send <script> or anything that actually executes.
"""
import logging
import secrets

from scanner.http_client import HttpClient

log = logging.getLogger(__name__)


async def _send(client: HttpClient, point: dict, params: dict):
    if point["method"] == "POST":
        return await client.request("POST", point["url"], data=params)
    return await client.get(point["url"], params=params)


async def test_xss(client: HttpClient, points: list[dict]) -> list[dict]:
    findings = []
    for point in points:
        for param in point["params"]:
            token = "zx" + secrets.token_hex(4)
            probe = f'"><{token}>'          # harmless made-up HTML tag
            params = dict(point["params"])
            params[param] = probe
            resp = await _send(client, point, params)
            if not resp:
                continue
            if f"<{token}>" in resp.text:
                log.warning("Reflected XSS: %s param=%s", point["url"], param)
                findings.append({
                    "category": "xss",
                    "title": f"Reflected XSS in parameter '{param}'",
                    "location": point["url"],
                    "parameter": param,
                    "method": point["method"],
                    "evidence": f"Probe {probe!r} was reflected unescaped in the response",
                    "confidence": 0.9,
                })
            elif token in resp.text:
                log.info("Input reflected but escaped (good) at %s param=%s", point["url"], param)
    return findings

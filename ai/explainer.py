"""
explainer.py - Plain-language explanations + suggested next steps (offline).

For each category we store a short "knowledge card" written for beginners.
The text is filled in with details of the specific finding.
"""

KNOWLEDGE = {
    "sqli_error": {
        "what": "The parameter '{parameter}' is put directly into a database query. Adding a single "
                "quote broke the query and the database error was shown on the page.",
        "risk": "An attacker could read, change or delete data in the database (user accounts, passwords).",
        "next_step": "Confirm manually in your lab. Fix: use parameterized queries / prepared statements "
                     "and never show raw database errors to users.",
        "learn": "https://owasp.org/www-community/attacks/SQL_Injection",
    },
    "sqli_boolean": {
        "what": "The page for '{parameter}' changes depending on whether a TRUE or FALSE SQL condition is "
                "added - the database is executing logic we control.",
        "risk": "Even without error messages, an attacker can extract data one yes/no question at a time.",
        "next_step": "Verify by hand (compare the TRUE/FALSE pages). Fix with prepared statements and "
                     "input validation.",
        "learn": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
    },
    "xss": {
        "what": "Text sent in '{parameter}' is copied back into the page without escaping, so the browser "
                "would treat it as real HTML.",
        "risk": "An attacker could send a victim a link that runs JavaScript in their browser - stealing "
                "their session or acting as them.",
        "next_step": "Fix by HTML-encoding output (e.g. htmlspecialchars in PHP) and adding a "
                     "Content-Security-Policy header.",
        "learn": "https://owasp.org/www-community/attacks/xss/",
    },
    "sensitive_file": {
        "what": "A file that should be private is publicly downloadable: {evidence}",
        "risk": "Leaked files often contain source code, passwords or keys that lead to full compromise.",
        "next_step": "Remove the file from the web root or block it in the web server config, then rotate "
                     "any secrets it contained.",
        "learn": "https://owasp.org/www-project-web-security-testing-guide/",
    },
    "dir_listing": {
        "what": "The web server shows a list of every file in this folder.",
        "risk": "Attackers can browse and download files that were never meant to be linked.",
        "next_step": "Disable directory listing (Apache: 'Options -Indexes').",
        "learn": "https://cwe.mitre.org/data/definitions/548.html",
    },
    "risky_service": {
        "what": "{details}",
        "risk": "Network services like this are common entry points for attackers.",
        "next_step": "If it isn't needed, stop it. Otherwise firewall it to trusted IPs, require strong "
                     "authentication, and keep it updated.",
        "learn": "https://www.cisa.gov/topics/cybersecurity-best-practices",
    },
    "interesting_path": {
        "what": "A path that looks sensitive exists on the server ({location}).",
        "risk": "Admin panels and tools are attractive targets for password guessing.",
        "next_step": "Check what it is. Restrict access (VPN / IP allow-list) and use strong passwords + MFA.",
        "learn": "https://owasp.org/www-project-web-security-testing-guide/",
    },
    "insecure_cookie": {
        "what": "A cookie is set without important security flags: {title}.",
        "risk": "Without HttpOnly, JavaScript (e.g. via XSS) can steal the cookie; without Secure it can "
                "travel over plain HTTP; without SameSite it helps CSRF attacks.",
        "next_step": "Set cookies with HttpOnly; Secure; SameSite=Lax (or Strict).",
        "learn": "https://owasp.org/www-community/HttpOnly",
    },
    "missing_header": {
        "what": "The response does not include the '{parameter}' header. {evidence}",
        "risk": "Not a vulnerability alone, but it removes a layer of defense.",
        "next_step": "Add the header in your web server or application configuration.",
        "learn": "https://owasp.org/www-project-secure-headers/",
    },
    "info_disclosure": {
        "what": "The server reveals exact software versions ({evidence}).",
        "risk": "Attackers can look up known vulnerabilities (CVEs) for that exact version.",
        "next_step": "Hide version banners (Apache: 'ServerTokens Prod', PHP: 'expose_php = Off') and keep "
                     "software updated.",
        "learn": "https://owasp.org/www-project-web-security-testing-guide/",
    },
}


class _SafeDict(dict):
    def __missing__(self, key):
        return ""


def explain(finding: dict) -> dict:
    """Return {"explanation", "risk", "next_step", "learn_more"} for one finding."""
    card = KNOWLEDGE.get(finding.get("category"))
    if not card:
        return {"explanation": finding.get("title", ""), "risk": "", "next_step":
                "Review this finding manually.", "learn_more": ""}
    data = _SafeDict(finding)
    return {
        "explanation": card["what"].format_map(data),
        "risk": card["risk"],
        "next_step": card["next_step"],
        "learn_more": card["learn"],
    }


def add_explanations(findings: list[dict]) -> list[dict]:
    for f in findings:
        f.update(explain(f))
    return findings


def local_summary(target: str, ports: list[dict], findings: list[dict]) -> str:
    """Offline executive summary built from the ranked findings."""
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("Critical", "High", "Medium", "Low")}
    lines = [f"Scan of {target}: {len(ports)} open port(s) and {len(findings)} finding(s) "
             f"({counts['Critical']} Critical, {counts['High']} High, "
             f"{counts['Medium']} Medium, {counts['Low']} Low)."]
    top = [f for f in findings if f["severity"] in ("Critical", "High")][:3] or findings[:3]
    if top:
        lines.append("Fix these first:")
        for f in top:
            lines.append(f"  {f['priority']}. [{f['severity']}] {f['title']} -> {f['next_step']}")
    else:
        lines.append("No significant issues were detected with the current checks.")
    lines.append("Remember: an automated scan is a starting point - verify every finding manually.")
    return "\n".join(lines)

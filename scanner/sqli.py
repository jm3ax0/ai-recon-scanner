"""
sqli.py - Basic SQL Injection DETECTION (error-based + boolean-based).

What is SQL injection?
  The app builds a database query by gluing user input into SQL text, e.g.
      SELECT * FROM users WHERE id = '<your input>'
  If the input is not handled safely, special characters change the query.

Test 1 - Error-based:
  Send a single quote  '  . A vulnerable app often crashes the SQL query and
  prints a database error like "You have an error in your SQL syntax".

Test 2 - Boolean-based:
  Send two inputs that ask the database a TRUE and a FALSE question:
      1' AND '1'='1     (always true  -> page should look normal)
      1' AND '1'='2     (always false -> page should be different/empty)
  If TRUE looks like the normal page but FALSE looks different, the database
  is evaluating our logic -> injectable.

We only detect. We never extract data, dump tables or run destructive SQL.
"""
import difflib
import logging
import re

from scanner.http_client import HttpClient

log = logging.getLogger(__name__)

DB_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysqli?_(fetch|query|num_rows)",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|postgresql.*error|syntax error at or near",
    r"sqlite3?\.operationalerror|sqlite_error|near \".*\": syntax error",
    r"sqlstate\[",
    r"ora-\d{5}",
    r"microsoft ole db provider for (sql server|odbc)",
    r"odbc sql server driver",
]
DB_ERROR_RE = re.compile("|".join(DB_ERROR_PATTERNS), re.I)


def _similarity(a: str, b: str) -> float:
    """0.0 = totally different pages, 1.0 = identical pages."""
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


async def _send(client: HttpClient, point: dict, params: dict):
    if point["method"] == "POST":
        return await client.request("POST", point["url"], data=params)
    return await client.get(point["url"], params=params)


async def test_sqli(client: HttpClient, points: list[dict]) -> list[dict]:
    findings = []
    for point in points:
        for param in point["params"]:
            original = point["params"][param] or "1"

            async def send_value(value: str):
                params = dict(point["params"])
                params[param] = value
                resp = await _send(client, point, params)
                # remove our own input from the page so it doesn't skew comparisons
                return resp, (resp.text.replace(value, "") if resp else "")

            base_resp, base_text = await send_value(original)
            if not base_resp:
                continue

            # ---- Test 1: error-based ------------------------------------
            err_resp, err_text = await send_value(original + "'")
            match = DB_ERROR_RE.search(err_text) if err_resp else None
            if match and not DB_ERROR_RE.search(base_text):
                log.warning("Error-based SQLi: %s param=%s", point["url"], param)
                findings.append({
                    "category": "sqli_error",
                    "title": f"SQL Injection (error-based) in parameter '{param}'",
                    "location": point["url"], "parameter": param, "method": point["method"],
                    "evidence": f"Adding a quote produced a database error: '{match.group(0)}'",
                    "confidence": 0.9,
                })
                continue  # one finding per parameter is enough

            # ---- Test 2: boolean-based ----------------------------------
            for true_v, false_v in ((f"{original}' AND '1'='1", f"{original}' AND '1'='2"),
                                    (f"{original} AND 1=1", f"{original} AND 1=2")):
                t_resp, t_text = await send_value(true_v)
                f_resp, f_text = await send_value(false_v)
                if not (t_resp and f_resp):
                    continue
                true_vs_base = _similarity(base_text, t_text)
                true_vs_false = _similarity(t_text, f_text)
                if true_vs_base > 0.95 and true_vs_false < 0.90:
                    log.warning("Boolean SQLi: %s param=%s", point["url"], param)
                    findings.append({
                        "category": "sqli_boolean",
                        "title": f"SQL Injection (boolean-based) in parameter '{param}'",
                        "location": point["url"], "parameter": param, "method": point["method"],
                        "evidence": (f"TRUE condition matched normal page ({true_vs_base:.0%} similar) "
                                     f"but FALSE condition differed ({true_vs_false:.0%} similar)"),
                        "confidence": 0.7,
                    })
                    break
    return findings

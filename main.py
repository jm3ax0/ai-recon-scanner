"""
main.py - Command-line entry point.

Usage examples:
    python main.py scan 127.0.0.1
    python main.py scan http://127.0.0.1:8080/ --cookie "PHPSESSID=abc; security=low"
    python main.py scan 192.168.1.20 --ports full --no-web
    python main.py dashboard

Pipeline:  SAFETY CHECK -> RECON (ports, banners, paths) -> WEB CHECKS
           -> AI (rank + explain + summary) -> REPORTS (JSON/HTML) -> dashboard
"""
import argparse
import asyncio
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import config
from safety import TargetNotAllowed, confirm_authorization

log = logging.getLogger("main")


def setup_logging(verbose: bool):
    config.REPORTS_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(config.LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
    )
    # Libraries are noisy at DEBUG level; keep them quiet.
    for noisy in ("asyncio", "urllib3", "werkzeug", "httpx", "anthropic"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def pick_base_url(target: str, host: str, open_ports: list[dict]) -> str | None:
    """Decide which web address to test."""
    if "://" in target:
        return target if target.endswith("/") else target + "/"
    for p in open_ports:
        scheme = config.WEB_PORTS.get(p["port"])
        if scheme or p["service"].startswith("http"):
            scheme = scheme or ("https" if "https" in p["service"] else "http")
            default = (scheme == "http" and p["port"] == 80) or (scheme == "https" and p["port"] == 443)
            return f"{scheme}://{host}/" if default else f"{scheme}://{host}:{p['port']}/"
    return None


async def web_scan(base_url: str, args) -> dict:
    """All web checks. Imported here so port-only scans don't need aiohttp-heavy setup."""
    from recon.dir_enum import enumerate_paths
    from scanner.crawler import crawl
    from scanner.headers import check_headers, check_sensitive_files
    from scanner.http_client import HttpClient
    from scanner.sqli import test_sqli
    from scanner.xss import test_xss

    findings: list[dict] = []
    async with HttpClient(cookie=args.cookie, rate=args.rate) as client:
        first = await client.get(base_url)
        if not first:
            log.error("Web server at %s did not respond - skipping web checks.", base_url)
            return {"paths": [], "findings": [], "requests": client.request_count, "points": 0}
        if "login" in first.url.lower() and not args.cookie:
            log.warning("Redirected to a login page (%s). For DVWA pass --cookie, see README.", first.url)

        print("[*] Checking security headers and cookies...")
        findings += check_headers(first)

        print("[*] Looking for exposed sensitive files...")
        findings += await check_sensitive_files(client, base_url)

        print("[*] Enumerating directories with the wordlist...")
        paths, path_findings = await enumerate_paths(client, base_url, Path(args.wordlist))
        findings += path_findings

        print("[*] Crawling the site to find forms and parameters...")
        seeds = [d["url"] for d in paths if d["status"] == 200]
        _, points = await crawl(client, first.url, seeds, include_post=args.test_post)
        print(f"    -> {len(points)} injection point(s) found")

        print("[*] Testing for reflected XSS (harmless probes)...")
        findings += await test_xss(client, points)

        print("[*] Testing for SQL injection (error + boolean, detection only)...")
        findings += await test_sqli(client, points)

        return {"paths": paths, "findings": findings,
                "requests": client.request_count, "points": len(points)}


async def run_scan(args):
    from ai.explainer import add_explanations, local_summary
    from ai.llm import llm_summary
    from ai.prioritizer import Prioritizer
    from app.report_export import save_report
    from recon.port_scanner import parse_port_spec, port_findings, scan_ports

    # ---- 1. Safety gate ----------------------------------------------------
    host, ip, kind = confirm_authorization(args.target, assume_yes=args.yes)
    started = datetime.now()
    t0 = time.monotonic()

    # ---- 2. Port scan + banners --------------------------------------------
    ports = parse_port_spec(args.ports)
    print(f"\n[*] Scanning {len(ports)} TCP port(s) on {ip} ...")
    open_ports = await scan_ports(ip, ports)
    for p in open_ports:
        print(f"    {p['port']:>5}/tcp  {p['service']:<14} {p['version'][:60]}")
    findings = port_findings(open_ports)

    # ---- 3. Web checks -----------------------------------------------------
    web = {"paths": [], "findings": [], "requests": 0, "points": 0}
    base_url = None if args.no_web else pick_base_url(args.target, host, open_ports)
    if base_url:
        print(f"\n[*] Web target: {base_url}")
        web = await web_scan(base_url, args)
        findings += web["findings"]
    elif not args.no_web:
        print("[!] No web server found - skipping web checks.")

    # ---- 4. AI layer -------------------------------------------------------
    print("\n[*] AI: ranking findings by severity...")
    prioritizer = Prioritizer()
    findings = add_explanations(prioritizer.score(findings))

    summary, llm_used = None, False
    if not args.no_llm:
        summary = llm_summary(args.target, open_ports, findings, language=args.lang)
        llm_used = summary is not None
    if not summary:
        summary = local_summary(args.target, open_ports, findings)

    # ---- 5. Report ---------------------------------------------------------
    name = f"{started:%Y%m%d-%H%M%S}_{host.replace(':', '_')}"
    report = {
        "meta": {"tool": config.TOOL_NAME, "version": config.TOOL_VERSION,
                 "target": args.target, "host": host, "ip": ip, "target_kind": kind,
                 "base_url": base_url, "started": started.strftime("%Y-%m-%d %H:%M:%S"),
                 "duration_s": round(time.monotonic() - t0, 1),
                 "ports_scanned": len(ports), "injection_points": web["points"],
                 "requests_sent": web["requests"], "llm_used": llm_used, "report_name": name},
        "ports": open_ports,
        "paths": web["paths"],
        "findings": findings,
        "severity_counts": {s: sum(1 for f in findings if f["severity"] == s)
                            for s in ("Critical", "High", "Medium", "Low")},
        "summary": summary,
        "model_info": {"type": "RandomForest + rule hybrid",
                       "feature_importances": prioritizer.feature_importances()},
    }
    json_path, html_path = save_report(report, name)

    print("\n" + "=" * 70)
    print(summary)
    print("=" * 70)
    print(f"Reports saved:\n  {json_path}\n  {html_path}")
    print("View them in the dashboard:  python main.py dashboard")


def main():
    parser = argparse.ArgumentParser(description="AI-assisted recon & vulnerability scanner "
                                                 "(educational - authorized targets only)")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a target you are authorized to test")
    s.add_argument("target", help="IP, hostname or URL, e.g. 127.0.0.1 or http://127.0.0.1:8080/")
    s.add_argument("--ports", default="common", help="'common' (default), 'full', or e.g. '1-1024,8080'")
    s.add_argument("--wordlist", default=str(config.DEFAULT_WORDLIST), help="path wordlist file")
    s.add_argument("--cookie", help='session cookie, e.g. "PHPSESSID=xyz; security=low"')
    s.add_argument("--rate", type=float, default=config.HTTP_RATE_LIMIT, help="max HTTP requests/second")
    s.add_argument("--test-post", action="store_true", help="also test POST forms (off by default: safer)")
    s.add_argument("--no-web", action="store_true", help="only do the port scan")
    s.add_argument("--no-llm", action="store_true", help="never call the LLM API, stay offline")
    s.add_argument("--lang", choices=["en", "ar"], default="en", help="language of the LLM summary")
    s.add_argument("--yes", action="store_true",
                   help="pre-confirm authorization for local/private targets (public ones still ask)")
    s.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("dashboard", help="open the Flask dashboard at http://127.0.0.1:5050")

    args = parser.parse_args()
    setup_logging(getattr(args, "verbose", False))

    if args.command == "dashboard":
        from app.server import run
        run()
        return

    if args.rate <= 0 or args.rate > 100:
        parser.error("--rate must be between 0 and 100 requests/second")
    if urlparse(args.target).scheme not in ("", "http", "https") and "://" in args.target:
        parser.error("Only http:// and https:// URLs are supported")

    try:
        asyncio.run(run_scan(args))
    except TargetNotAllowed as exc:
        print(f"\n[x] {exc}")
        sys.exit(1)
    except ValueError as exc:
        print(f"\n[x] {exc}")
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[x] Scan stopped by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()

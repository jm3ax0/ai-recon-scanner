"""
report_export.py - Save a scan report as JSON (for machines) and HTML (for humans).

The HTML file uses the SAME template as the Flask dashboard, so the exported
report looks exactly like the dashboard page and can be opened offline
(the charts need internet once to load Chart.js).
"""
import json
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config

log = logging.getLogger(__name__)
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

# autoescape=True is IMPORTANT: findings contain our XSS probes like "><zx..>.
# Escaping makes sure the report itself can never become vulnerable.
_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR),
                   autoescape=select_autoescape(["html"]))


def render_report_html(report: dict, standalone: bool = True) -> str:
    return _env.get_template("report.html").render(report=report, standalone=standalone)


def save_report(report: dict, name: str) -> tuple[Path, Path]:
    config.REPORTS_DIR.mkdir(exist_ok=True)
    json_path = config.REPORTS_DIR / f"{name}.json"
    html_path = config.REPORTS_DIR / f"{name}.html"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    html_path.write_text(render_report_html(report), encoding="utf-8")
    log.info("Report saved: %s and %s", json_path, html_path)
    return json_path, html_path

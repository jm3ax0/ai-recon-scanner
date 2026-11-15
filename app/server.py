"""
server.py - Flask web dashboard to browse your scan reports.

Run:  python main.py dashboard   ->  open http://127.0.0.1:5050

It only listens on 127.0.0.1 (your own computer), so nobody else on the
network can see your reports.
"""
import json
import re

from flask import Flask, Response, abort, render_template, send_file

import config
from app.report_export import render_report_html

app = Flask(__name__)
SAFE_NAME = re.compile(r"^[\w\-.]+$")   # blocks "../" path tricks


def _load(name: str) -> dict:
    if not SAFE_NAME.match(name):
        abort(400)
    path = config.REPORTS_DIR / f"{name}.json"
    if not path.is_file():
        abort(404)
    return json.loads(path.read_text(encoding="utf-8"))


@app.route("/")
def index():
    reports = []
    for path in sorted(config.REPORTS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            reports.append({"name": path.stem, "meta": data.get("meta", {}),
                            "counts": data.get("severity_counts", {}),
                            "ports": len(data.get("ports", []))})
        except (json.JSONDecodeError, OSError):
            continue
    return render_template("index.html", reports=reports)


@app.route("/report/<name>")
def report(name):
    return render_template("report.html", report=_load(name), standalone=False)


@app.route("/report/<name>.json")
def report_json(name):
    _load(name)
    return send_file(config.REPORTS_DIR / f"{name}.json", as_attachment=True)


@app.route("/report/<name>.html")
def report_html(name):
    html = render_report_html(_load(name), standalone=True)
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename={name}.html"})


@app.after_request
def security_headers(resp):
    # Practice what we preach: our own dashboard sends good security headers.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def run():
    config.REPORTS_DIR.mkdir(exist_ok=True)
    print(f"\n Dashboard running at http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}  (Ctrl+C to stop)\n")
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=False)

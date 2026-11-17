"""
demo_lab.py - A TINY, INTENTIONALLY VULNERABLE web app for trying Ishtar
without Docker. It only listens on 127.0.0.1 (your own computer).

    python examples/demo_lab.py
    python main.py scan http://127.0.0.1:8099/

Contains on purpose:
  * /search?q=   reflected XSS
  * /user?id=    SQL injection (SQLite, in-memory)
  * /.git/HEAD   exposed sensitive file
  * /admin       protected path (403)
NEVER expose this app to a network. Stop it with Ctrl+C.
"""
import sqlite3

from flask import Flask, make_response, request

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("create table users(id int, name text)")
db.executemany("insert into users values(?,?)", [(1, "alice"), (2, "bob")])


@app.route("/")
def home():
    resp = make_response(
        '<html><body><h1>Ishtar demo lab</h1>'
        '<a href="/search?q=hi">search</a>'
        '<form action="/user" method="get"><input name="id" value="1">'
        '<input type="submit" name="Submit" value="Go"></form>'
        '<a href="/logout">logout</a></body></html>')
    resp.headers["Server"] = "Apache/2.4.25 (Debian)"   # fake version banner
    resp.set_cookie("PHPSESSID", "demo")                  # cookie without flags
    return resp


@app.route("/search")
def search():
    # VULNERABLE: user input is put into HTML without escaping
    return f"<p>You searched: {request.args.get('q', '')}</p>"


@app.route("/user")
def user():
    # VULNERABLE: user input is glued into the SQL query
    try:
        rows = db.execute(f"select name from users where id = '{request.args.get('id', '')}'").fetchall()
    except sqlite3.Error as exc:
        return f"sqlite3.OperationalError: {exc}", 500
    return "<ul>" + "".join(f"<li>{r[0]}</li>" for r in rows) + "</ul>"


@app.route("/.git/HEAD")
def git_head():
    return "ref: refs/heads/main\n"


@app.route("/admin")
def admin():
    return "admin panel", 403


if __name__ == "__main__":
    print("Demo lab on http://127.0.0.1:8099/  (local only, Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=8099)

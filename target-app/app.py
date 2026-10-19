"""
AI Cyber Defense & Evolution System — Stage 1: Vulnerable Target App

This app contains THREE deliberate vulnerabilities for the defense system to detect and patch:
  1. SQL Injection  — POST /login  (string-concatenated query)
  2. Reflected XSS  — GET  /search (unescaped user input in HTML)
  3. Path Traversal — GET  /file   (unsanitized filename joined to base path)

DO NOT deploy this anywhere public. It exists solely as a training target.
"""

import os
import sqlite3
from flask import Flask, request, g, redirect, url_for

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def get_db():
    """Return a per-request database connection stored on Flask's `g` object."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the users table and seed it with fake accounts."""
    conn = sqlite3.connect(DATABASE)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password TEXT NOT NULL,"
        "  role TEXT NOT NULL DEFAULT 'user'"
        ")"
    )
    # Seed data — passwords are plaintext on purpose (another weak point).
    seed = [
        ("admin", "supersecret", "admin"),
        ("alice", "password123", "user"),
        ("bob", "hunter2", "user"),
    ]
    for uname, pwd, role in seed:
        try:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (uname, pwd, role),
            )
        except sqlite3.IntegrityError:
            pass  # already seeded
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return (
        "<h1>Target App</h1>"
        "<p>Endpoints: /login, /search, /file</p>"
    )


# ---- VULNERABILITY 1: SQL Injection ------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return (
            '<form method="POST">'
            '<input name="username" placeholder="username">'
            '<input name="password" type="password" placeholder="password">'
            '<button type="submit">Login</button>'
            '</form>'
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ⚠️  VULNERABLE: raw string concatenation — no parameterised query
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    db = get_db()
    user = db.execute(query).fetchone()

    if user:
        return f"<p>Welcome, {user['username']}! Role: {user['role']}</p>"
    return "<p>Invalid credentials.</p>", 401


# ---- VULNERABILITY 2: Reflected XSS ------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        "SELECT username, role FROM users WHERE username LIKE ?",
        (f"%{q}%",),
    ).fetchall()

    # ⚠️  VULNERABLE: `q` is injected straight into HTML without escaping
    rows = "".join(
        f"<li>{r['username']} ({r['role']})</li>" for r in results
    )
    return (
        f"<h2>Search results for: {q}</h2>"
        f"<ul>{rows}</ul>"
    )


# ---- VULNERABILITY 3: Path Traversal -----------------------------------
SAFE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")


@app.route("/file")
def fetch_file():
    filename = request.args.get("name", "")
    if not filename:
        return "<p>Provide ?name=filename</p>", 400

    # ⚠️  VULNERABLE: no sanitisation — "../" sequences escape SAFE_DIR
    filepath = os.path.join(SAFE_DIR, filename)
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except FileNotFoundError:
        return "<p>File not found.</p>", 404
    except Exception as e:
        return f"<p>Error: {e}</p>", 500


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    os.makedirs(SAFE_DIR, exist_ok=True)
    # Drop a harmless sample file so the /file endpoint has something legit
    sample = os.path.join(SAFE_DIR, "hello.txt")
    if not os.path.exists(sample):
        with open(sample, "w") as f:
            f.write("Hello from the public directory!\n")
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)

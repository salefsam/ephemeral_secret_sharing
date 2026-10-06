import os
import secrets
import sqlite3
import time

from flask import Flask, jsonify, request, send_from_directory, abort

DB_PATH = os.environ.get("DB_PATH", "secrets.db")
MAX_CIPHERTEXT_B64 = 40_000  # ~30KB of plaintext after base64 + GCM overhead
TTL_OPTIONS = {"1h": 3600, "24h": 86400, "7d": 604800}
MAX_VIEWS_ALLOWED = 5

app = Flask(__name__, static_folder="static", static_url_path="/static")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            ciphertext TEXT NOT NULL,
            iv TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            views_left INTEGER NOT NULL DEFAULT 1
        )"""
    )
    # Migrate databases created before view limits existed.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(secrets)")]
    if "views_left" not in cols:
        conn.execute("ALTER TABLE secrets ADD COLUMN views_left INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    return conn


def purge_expired(conn):
    conn.execute("DELETE FROM secrets WHERE expires_at <= ?", (int(time.time()),))


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'"
    )
    return resp


@app.get("/")
@app.get("/s/<secret_id>")
def index(secret_id=None):
    return send_from_directory("static", "index.html")


@app.post("/api/secrets")
def create():
    body = request.get_json(silent=True) or {}
    ct, iv, ttl = body.get("ciphertext"), body.get("iv"), body.get("ttl", "24h")
    views = body.get("views", 1)
    if not isinstance(ct, str) or not isinstance(iv, str) or ttl not in TTL_OPTIONS:
        abort(400)
    if (
        isinstance(views, bool)
        or not isinstance(views, int)
        or not 1 <= views <= MAX_VIEWS_ALLOWED
    ):
        abort(400)
    if not ct or len(ct) > MAX_CIPHERTEXT_B64 or len(iv) > 64:
        abort(413 if len(ct) > MAX_CIPHERTEXT_B64 else 400)
    sid = secrets.token_urlsafe(16)
    conn = db()
    with conn:
        purge_expired(conn)
        conn.execute(
            "INSERT INTO secrets (id, ciphertext, iv, expires_at, views_left) VALUES (?,?,?,?,?)",
            (sid, ct, iv, int(time.time()) + TTL_OPTIONS[ttl], views),
        )
    conn.close()
    return jsonify(id=sid), 201


@app.post("/api/secrets/<secret_id>/reveal")
def reveal(secret_id):
    """Return the ciphertext and use up one view; delete it when none are left."""
    conn = db()
    try:
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        purge_expired(conn)
        row = conn.execute(
            "SELECT ciphertext, iv, views_left FROM secrets WHERE id = ?", (secret_id,)
        ).fetchone()
        remaining = 0
        if row:
            remaining = row[2] - 1
            if remaining <= 0:
                conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
                remaining = 0
            else:
                conn.execute(
                    "UPDATE secrets SET views_left = ? WHERE id = ?", (remaining, secret_id)
                )
        conn.execute("COMMIT")
    finally:
        conn.close()
    if not row:
        abort(404)
    return jsonify(ciphertext=row[0], iv=row[1], remaining=remaining)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))

import html
import os
import sqlite3
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="Vulnerable Training Target", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DB_PATH = os.getenv("TARGET_DB_PATH", "/data/target.db")


def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notes(
      id INTEGER PRIMARY KEY,
      owner TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL
    );
    """)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany("INSERT INTO users(id, username, password, role) VALUES(?,?,?,?)", [
            (1, "alice", "wonderland", "user"),
            (2, "bob", "builder", "user"),
            (3, "admin", "training-admin", "admin"),
        ])
        conn.executemany("INSERT INTO notes(id, owner, title, body) VALUES(?,?,?,?)", [
            (1, "alice", "Alice private note", "Demo secret: ALICE-ONLY-123"),
            (2, "bob", "Bob private note", "Demo secret: BOB-ONLY-456"),
            (3, "admin", "Admin note", "Demo secret: ADMIN-ONLY-789"),
        ])
    conn.commit()
    conn.close()


init_db()


class Login(BaseModel):
    username: str
    password: str


class UploadMeta(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    size: int = 0


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "ok", "service": "vulnerable-training-target"}


# -------------------------
# 1) IDOR / Broken access control
# -------------------------
@app.get("/vuln/notes/{note_id}")
def vuln_note(note_id: int, user: str = "alice"):
    # Intentionally vulnerable: trusts object ID and never checks ownership.
    conn = connect()
    row = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Note not found")
    return {"viewer": user, "note": dict(row), "vulnerable": True}


@app.get("/protected/notes/{note_id}")
def protected_note(note_id: int, user: str = "alice"):
    conn = connect()
    row = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Note not found")
    if row["owner"] != user:
        raise HTTPException(403, "Ownership check blocked access")
    return {"viewer": user, "note": dict(row), "vulnerable": False}


# -------------------------
# 2) Reflected XSS
# -------------------------
@app.get("/vuln/search", response_class=HTMLResponse)
def vuln_search(q: str = ""):
    # Intentionally vulnerable: raw, unescaped user input in HTML.
    return HTMLResponse(f"<h2>Search results</h2><div id='result'>{q}</div>")


@app.get("/protected/search", response_class=HTMLResponse)
def protected_search(q: str = ""):
    return HTMLResponse(f"<h2>Search results</h2><div id='result'>{html.escape(q)}</div>")


# -------------------------
# 3) SQL injection in login
# -------------------------
@app.post("/vuln/login")
def vuln_login(body: Login):
    # Intentionally vulnerable: string-built SQL for local training only.
    query = f"SELECT id, username, role FROM users WHERE username = '{body.username}' AND password = '{body.password}'"
    conn = connect()
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        conn.close()
        return {"authenticated": False, "error": str(exc), "vulnerable": True}
    conn.close()
    return {"authenticated": bool(row), "user": dict(row) if row else None, "vulnerable": True}


@app.post("/protected/login")
def protected_login(body: Login):
    conn = connect()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password=?",
        (body.username, body.password),
    ).fetchone()
    conn.close()
    return {"authenticated": bool(row), "user": dict(row) if row else None, "vulnerable": False}


# -------------------------
# 4) Brute-force / missing rate limiting
# -------------------------
FAILED = {}
WINDOW_SECONDS = 60
MAX_ATTEMPTS = 5

@app.post("/vuln/auth-check")
def vuln_auth_check(body: Login):
    # No rate limiting by design.
    return {"authenticated": body.username == "alice" and body.password == "wonderland", "rate_limited": False}


@app.post("/protected/auth-check")
def protected_auth_check(body: Login):
    now = time.time()
    attempts = [t for t in FAILED.get(body.username, []) if now - t < WINDOW_SECONDS]
    if len(attempts) >= MAX_ATTEMPTS:
        FAILED[body.username] = attempts
        raise HTTPException(429, "Rate limit active")
    ok = body.username == "alice" and body.password == "wonderland"
    if not ok:
        attempts.append(now)
    else:
        attempts.clear()
    FAILED[body.username] = attempts
    return {"authenticated": ok, "rate_limited": False, "attempts_in_window": len(attempts)}


# -------------------------
# 5) Unsafe upload validation (metadata-only: files are never executed)
# -------------------------
@app.post("/vuln/upload")
def vuln_upload(body: UploadMeta):
    return {
        "accepted": True,
        "stored_as": body.filename,
        "content_type": body.content_type,
        "size": body.size,
        "note": "Training target accepts metadata without type/extension validation; no content is executed.",
    }


@app.post("/protected/upload")
def protected_upload(body: UploadMeta):
    allowed_ext = {".txt", ".csv", ".png", ".jpg", ".jpeg"}
    allowed_types = {"text/plain", "text/csv", "image/png", "image/jpeg"}
    ext = Path(body.filename).suffix.lower()
    if ext not in allowed_ext or body.content_type.lower() not in allowed_types:
        raise HTTPException(415, "File type rejected")
    if body.size > 2_000_000:
        raise HTTPException(413, "File too large")
    safe_name = Path(body.filename).name
    return {"accepted": True, "stored_as": safe_name, "vulnerable": False}

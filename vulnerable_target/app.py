import html
import os
import secrets
import sqlite3
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

TAGS = [
    {"name": "A01 Broken Access Control", "description": "Authorization failures, IDOR, path traversal and SSRF-style trust-boundary mistakes."},
    {"name": "A02 Security Misconfiguration", "description": "Debug information, unsafe defaults and excessive environment disclosure."},
    {"name": "A03 Software Supply Chain Failures", "description": "Unpinned or unverified dependencies and weak software provenance controls."},
    {"name": "A04 Cryptographic Failures", "description": "Sensitive data stored or exposed without appropriate cryptographic protection."},
    {"name": "A05 Injection", "description": "Untrusted input interpreted as SQL or browser markup instead of data."},
    {"name": "A06 Insecure Design", "description": "Security weaknesses caused by an unsafe workflow or missing abuse-case design."},
    {"name": "A07 Authentication Failures", "description": "Weak authentication controls such as missing throttling and predictable reset flows."},
    {"name": "A08 Software or Data Integrity Failures", "description": "Trusting client-controlled integrity-sensitive fields or unsafe upload metadata."},
    {"name": "A09 Security Logging & Alerting Failures", "description": "Security-relevant events occur without an auditable record or alert signal."},
    {"name": "A10 Mishandling of Exceptional Conditions", "description": "Errors leak internals, fail open, or are handled inconsistently."},
]

app = FastAPI(
    title="Web Security Lab - Vulnerable Target",
    version="2.0.0",
    description=(
        "A deliberately vulnerable **local training target**. Every exercise has a `/vuln/...` endpoint and a "
        "paired `/protected/...` endpoint so Red Team behavior can be compared before and after mitigation. "
        "The lab uses bounded/simulated sinks for risky classes such as SSRF and path traversal; it does not "
        "perform arbitrary outbound requests or execute uploaded files. Do not expose this service to the public Internet."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    openapi_tags=TAGS,
)
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
    username: str = Field(examples=["alice"])
    password: str = Field(examples=["wonderland"])


class UploadMeta(BaseModel):
    filename: str = Field(examples=["training.php"])
    content_type: str = Field(default="application/octet-stream", examples=["application/x-httpd-php"])
    size: int = Field(default=0, ge=0, examples=[128])


class UrlProbe(BaseModel):
    url: str = Field(examples=["http://169.254.169.254/latest/meta-data/iam/security-credentials/"])


class ProfileUpdate(BaseModel):
    username: str = Field(default="alice", examples=["alice"])
    display_name: str = Field(default="Alice", examples=["Alice Example"])
    role: str = Field(default="user", examples=["admin"])


class ResetVerify(BaseModel):
    username: str = Field(default="alice", examples=["alice"])
    token: str = Field(examples=["reset-alice"])


class AuditEvent(BaseModel):
    username: str = Field(default="alice")
    action: str = Field(default="login_failure")


FAILED = {}
WINDOW_SECONDS = 60
MAX_ATTEMPTS = 5
SECURE_RESET_TOKENS = {"alice": secrets.token_urlsafe(24)}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", tags=["A02 Security Misconfiguration"])
def health():
    return {"status": "ok", "service": "vulnerable-training-target", "swagger": "/docs"}


# A01 - Broken Access Control -------------------------------------------------
@app.get(
    "/vuln/notes/{note_id}",
    tags=["A01 Broken Access Control"],
    summary="VULN - IDOR reads another user's object",
    description="The server trusts the object ID and a user name supplied by the client, but never checks object ownership.",
)
def vuln_note(note_id: int, user: str = "alice"):
    conn = connect()
    row = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Note not found")
    return {"viewer": user, "note": dict(row), "vulnerable": True, "weakness": "IDOR / missing object-level authorization"}


@app.get(
    "/protected/notes/{note_id}",
    tags=["A01 Broken Access Control"],
    summary="PROTECTED - IDOR blocked by ownership check",
    description="The server verifies that the authenticated user owns the requested object before returning it.",
)
def protected_note(note_id: int, user: str = "alice"):
    conn = connect()
    row = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Note not found")
    if row["owner"] != user:
        raise HTTPException(403, "Ownership check blocked access")
    return {"viewer": user, "note": dict(row), "vulnerable": False}


@app.get(
    "/vuln/files",
    tags=["A01 Broken Access Control"],
    summary="VULN - Path traversal style file lookup",
    description="A simulated file service accepts `../` traversal and exposes a fake internal config file. No host filesystem file is read.",
)
def vuln_files(name: str = Query("../config.env")):
    normalized = str(PurePosixPath("/public") / name)
    if ".." in name or name.endswith("config.env"):
        return {"requested": name, "resolved": normalized, "content": "DEMO_API_KEY=LAB-ONLY-KEY", "vulnerable": True}
    return {"requested": name, "content": "public demo file", "vulnerable": True}


@app.get(
    "/protected/files",
    tags=["A01 Broken Access Control"],
    summary="PROTECTED - Path traversal rejected",
    description="Rejects traversal tokens and only permits a safe basename from the public file namespace.",
)
def protected_files(name: str = Query("readme.txt")):
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(400, "Unsafe path rejected")
    return {"requested": name, "content": "public demo file", "vulnerable": False}


@app.post(
    "/vuln/fetch-url",
    tags=["A01 Broken Access Control"],
    summary="VULN - Simulated SSRF to internal metadata",
    description="Training-safe SSRF simulation: internal/link-local URLs return fake metadata. The service never performs a real outbound request.",
)
def vuln_fetch_url(body: UrlProbe):
    host = (urlparse(body.url).hostname or "").lower()
    internal = host in {"169.254.169.254", "localhost", "127.0.0.1", "internal.service"}
    if internal:
        return {"fetched": True, "url": body.url, "data": "FAKE-INSTANCE-METADATA: role=lab-demo", "vulnerable": True, "simulated": True}
    return {"fetched": True, "url": body.url, "data": "simulated public response", "vulnerable": True, "simulated": True}


@app.post(
    "/protected/fetch-url",
    tags=["A01 Broken Access Control"],
    summary="PROTECTED - SSRF allow-list / internal host block",
    description="Rejects internal, loopback and link-local destinations before any fetch would occur.",
)
def protected_fetch_url(body: UrlProbe):
    parsed = urlparse(body.url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or host in {"169.254.169.254", "localhost", "127.0.0.1", "internal.service"}:
        raise HTTPException(403, "Internal or unsupported destination blocked")
    return {"fetched": True, "url": body.url, "data": "simulated public response", "vulnerable": False, "simulated": True}


# A02 - Security Misconfiguration -------------------------------------------
@app.get(
    "/vuln/debug-config",
    tags=["A02 Security Misconfiguration"],
    summary="VULN - Debug/config information disclosure",
    description="Returns unnecessary environment, filesystem and demo-secret details that would help an attacker understand the application.",
)
def vuln_debug_config():
    return {
        "debug": True,
        "environment": "training",
        "database_path": DB_PATH,
        "stack_hint": "app.py -> connect() -> sqlite3",
        "demo_secret": "DEBUG-DEMO-KEY",
        "vulnerable": True,
    }


@app.get(
    "/protected/debug-config",
    tags=["A02 Security Misconfiguration"],
    summary="PROTECTED - Minimal operational status",
    description="Exposes only the information required for health monitoring and keeps implementation details private.",
)
def protected_debug_config():
    return {"debug": False, "status": "ok", "vulnerable": False}


# A03 - Software Supply Chain Failures ---------------------------------------
@app.get(
    "/vuln/dependencies",
    tags=["A03 Software Supply Chain Failures"],
    summary="VULN - Unpinned/unverified dependency policy",
    description="A training manifest demonstrates wildcard versions and missing integrity/provenance metadata.",
)
def vuln_dependencies():
    return {
        "dependencies": [
            {"name": "example-web-lib", "version": "*", "integrity": None},
            {"name": "example-parser", "version": ">=1", "integrity": None},
        ],
        "policy": "floating versions; no integrity verification",
        "vulnerable": True,
    }


@app.get(
    "/protected/dependencies",
    tags=["A03 Software Supply Chain Failures"],
    summary="PROTECTED - Pinned dependencies with integrity metadata",
    description="Demonstrates exact version pinning plus integrity/provenance metadata as a supply-chain control.",
)
def protected_dependencies():
    return {
        "dependencies": [
            {"name": "example-web-lib", "version": "2.4.1", "integrity": "sha256:demo-verified-hash"},
            {"name": "example-parser", "version": "1.8.3", "integrity": "sha256:demo-verified-hash"},
        ],
        "policy": "exact versions + integrity verification",
        "vulnerable": False,
    }


# A04 - Cryptographic Failures ----------------------------------------------
@app.get(
    "/vuln/credentials/{username}",
    tags=["A04 Cryptographic Failures"],
    summary="VULN - Cleartext credential exposure",
    description="Reads the lab's intentionally cleartext demo password, illustrating why sensitive credentials must not be stored or exposed in plaintext.",
)
def vuln_credentials(username: str):
    conn = connect()
    row = conn.execute("SELECT username, password, role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    return {"credential_record": dict(row), "storage": "cleartext", "vulnerable": True}


@app.get(
    "/protected/credentials/{username}",
    tags=["A04 Cryptographic Failures"],
    summary="PROTECTED - Sensitive credential value never returned",
    description="Returns only non-secret account metadata and describes password hashing without exposing a password or hash value.",
)
def protected_credentials(username: str):
    conn = connect()
    row = conn.execute("SELECT username, role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    return {"account": dict(row), "password_storage": "Argon2id/bcrypt-style one-way hash (demo description)", "vulnerable": False}


# A05 - Injection ------------------------------------------------------------
@app.get(
    "/vuln/search",
    response_class=HTMLResponse,
    tags=["A05 Injection"],
    summary="VULN - Reflected XSS",
    description="Reflects untrusted query text directly into HTML, so browser markup is interpreted instead of encoded as text.",
)
def vuln_search(q: str = ""):
    return HTMLResponse(f"<h2>Search results</h2><div id='result'>{q}</div>")


@app.get(
    "/protected/search",
    response_class=HTMLResponse,
    tags=["A05 Injection"],
    summary="PROTECTED - XSS output encoding",
    description="HTML-encodes attacker-controlled output before rendering it in the response.",
)
def protected_search(q: str = ""):
    return HTMLResponse(f"<h2>Search results</h2><div id='result'>{html.escape(q)}</div>")


@app.post(
    "/vuln/login",
    tags=["A05 Injection"],
    summary="VULN - SQL Injection in login",
    description="Builds SQL by string interpolation. In this isolated lab, a crafted username can alter the query logic.",
)
def vuln_login(body: Login):
    query = f"SELECT id, username, role FROM users WHERE username = '{body.username}' AND password = '{body.password}'"
    conn = connect()
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        conn.close()
        return {"authenticated": False, "error": str(exc), "vulnerable": True}
    conn.close()
    return {"authenticated": bool(row), "user": dict(row) if row else None, "vulnerable": True}


@app.post(
    "/protected/login",
    tags=["A05 Injection"],
    summary="PROTECTED - Parameterized SQL login",
    description="Uses SQL query parameters so user input remains data rather than executable SQL syntax.",
)
def protected_login(body: Login):
    conn = connect()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password=?",
        (body.username, body.password),
    ).fetchone()
    conn.close()
    return {"authenticated": bool(row), "user": dict(row) if row else None, "vulnerable": False}


# A06 - Insecure Design ------------------------------------------------------
@app.post(
    "/vuln/password-reset/verify",
    tags=["A06 Insecure Design"],
    summary="VULN - Predictable password reset token",
    description="The reset token is derived from the username (`reset-{username}`), so the security of the workflow depends on a guessable value.",
)
def vuln_password_reset(body: ResetVerify):
    expected = f"reset-{body.username}"
    return {"valid": body.token == expected, "token_scheme": "predictable username-derived token", "vulnerable": True}


@app.post(
    "/protected/password-reset/verify",
    tags=["A06 Insecure Design"],
    summary="PROTECTED - High-entropy one-time reset token",
    description="Uses a server-generated high-entropy token. The common predictable guess used by Red Team will fail.",
)
def protected_password_reset(body: ResetVerify):
    expected = SECURE_RESET_TOKENS.get(body.username)
    return {"valid": bool(expected and secrets.compare_digest(body.token, expected)), "token_scheme": "high-entropy one-time token", "vulnerable": False}


# A07 - Authentication Failures --------------------------------------------
@app.post(
    "/vuln/auth-check",
    tags=["A07 Authentication Failures"],
    summary="VULN - Missing brute-force protection",
    description="Accepts unlimited authentication attempts with no throttling or lockout.",
)
def vuln_auth_check(body: Login):
    return {"authenticated": body.username == "alice" and body.password == "wonderland", "rate_limited": False, "vulnerable": True}


@app.post(
    "/protected/auth-check",
    tags=["A07 Authentication Failures"],
    summary="PROTECTED - Rate limiting / temporary lockout",
    description="Allows at most five failed attempts per user in a 60-second training window.",
)
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
    return {"authenticated": ok, "rate_limited": False, "attempts_in_window": len(attempts), "vulnerable": False}


# A08 - Software or Data Integrity Failures ---------------------------------
@app.post(
    "/vuln/profile",
    tags=["A08 Software or Data Integrity Failures"],
    summary="VULN - Mass assignment / client-controlled role",
    description="Copies an integrity-sensitive `role` field directly from the request, letting a client promote its own account.",
)
def vuln_profile(body: ProfileUpdate):
    return {"profile": body.model_dump(), "is_admin": body.role == "admin", "vulnerable": True}


@app.post(
    "/protected/profile",
    tags=["A08 Software or Data Integrity Failures"],
    summary="PROTECTED - Server controls integrity-sensitive fields",
    description="Ignores the client-supplied role and uses the authoritative role stored by the server.",
)
def protected_profile(body: ProfileUpdate):
    conn = connect()
    row = conn.execute("SELECT role FROM users WHERE username=?", (body.username,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    profile = {"username": body.username, "display_name": body.display_name, "role": row["role"]}
    return {"profile": profile, "is_admin": row["role"] == "admin", "vulnerable": False}


@app.post(
    "/vuln/upload",
    tags=["A08 Software or Data Integrity Failures"],
    summary="VULN - Unsafe file upload validation",
    description="Accepts arbitrary filename/type metadata. The lab never stores executable content or runs uploaded files.",
)
def vuln_upload(body: UploadMeta):
    return {
        "accepted": True,
        "stored_as": body.filename,
        "content_type": body.content_type,
        "size": body.size,
        "note": "Metadata-only training sink; no uploaded content is executed.",
        "vulnerable": True,
    }


@app.post(
    "/protected/upload",
    tags=["A08 Software or Data Integrity Failures"],
    summary="PROTECTED - Upload allow-list and size limit",
    description="Checks extension, MIME type, size and strips any path portion from the supplied filename.",
)
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


# A09 - Security Logging & Alerting Failures --------------------------------
@app.post(
    "/vuln/audit-event",
    tags=["A09 Security Logging & Alerting Failures"],
    summary="VULN - Security event is not recorded",
    description="Simulates a security-relevant event that produces no audit record or alerting signal.",
)
def vuln_audit_event(body: AuditEvent):
    return {"accepted": True, "audit_logged": False, "alert_emitted": False, "event": body.model_dump(), "vulnerable": True}


@app.post(
    "/protected/audit-event",
    tags=["A09 Security Logging & Alerting Failures"],
    summary="PROTECTED - Structured security audit event",
    description="Simulates a structured audit record and an alertable signal for a security-relevant event.",
)
def protected_audit_event(body: AuditEvent):
    return {"accepted": True, "audit_logged": True, "alert_emitted": True, "event": body.model_dump(), "vulnerable": False}


# A10 - Mishandling of Exceptional Conditions -------------------------------
@app.get(
    "/vuln/calculate",
    tags=["A10 Mishandling of Exceptional Conditions"],
    summary="VULN - Internal exception details leaked",
    description="A zero input causes an error response that reveals internal exception type and implementation details.",
)
def vuln_calculate(value: int = 0):
    try:
        result = 100 / value
        return {"result": result, "vulnerable": True}
    except Exception as exc:
        return {
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "internal_operation": "100 / value in app.py",
            "vulnerable": True,
        }


@app.get(
    "/protected/calculate",
    tags=["A10 Mishandling of Exceptional Conditions"],
    summary="PROTECTED - Safe validation and generic error",
    description="Validates the exceptional condition before computation and returns a controlled client error without internal details.",
)
def protected_calculate(value: int = 0):
    if value == 0:
        raise HTTPException(400, "value must be non-zero")
    return {"result": 100 / value, "vulnerable": False}

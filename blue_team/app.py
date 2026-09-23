import os
import sqlite3
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(
    title="Web Security Lab - Blue Team",
    version="2.0.0",
    description="Defensive telemetry, detection rules and before/after mitigation assessment for the local web-security lab.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DB_PATH = os.getenv("DB_PATH", "/data/blue_team.db")
RED_TEAM_URL = os.getenv("RED_TEAM_URL", "http://localhost:8201")

RULES = {
    "idor": {"rule": "AUTHZ-001", "owasp": "A01:2025", "control": "Object ownership validation", "detect": "Cross-user object access", "remediation": "Enforce object-level authorization on every object read/write."},
    "path_traversal": {"rule": "PATH-001", "owasp": "A01:2025", "control": "Canonical path / basename validation", "detect": "Traversal tokens such as ../", "remediation": "Reject traversal, canonicalize and allow-list served files."},
    "ssrf": {"rule": "SSRF-001", "owasp": "A01:2025", "control": "Outbound destination policy", "detect": "Loopback/private/link-local destination", "remediation": "Allow-list destinations and restrict network egress."},
    "misconfig": {"rule": "CFG-001", "owasp": "A02:2025", "control": "Production-safe diagnostics", "detect": "Debug secrets, paths or stack hints in responses", "remediation": "Disable debug disclosure and expose minimal health data."},
    "supply_chain": {"rule": "SCA-001", "owasp": "A03:2025", "control": "Dependency integrity policy", "detect": "Floating/unverified dependency metadata", "remediation": "Pin versions, verify provenance/hashes and scan dependencies."},
    "crypto": {"rule": "CRYPTO-001", "owasp": "A04:2025", "control": "Password hashing / secret minimization", "detect": "Cleartext credential material in API response", "remediation": "Hash passwords with Argon2id/bcrypt/scrypt and never return password material."},
    "xss": {"rule": "XSS-001", "owasp": "A05:2025", "control": "Output encoding / sanitization", "detect": "Active markup reflected unescaped", "remediation": "Use context-aware output encoding and safe templates."},
    "sqli": {"rule": "SQLI-001", "owasp": "A05:2025", "control": "Parameterized queries", "detect": "SQL metacharacters altering authentication logic", "remediation": "Use prepared statements and least-privilege DB access."},
    "insecure_design": {"rule": "DESIGN-001", "owasp": "A06:2025", "control": "High-entropy reset workflow", "detect": "Predictable username-derived reset token", "remediation": "Use random, one-time, expiring reset tokens plus rate limiting."},
    "bruteforce": {"rule": "AUTH-002", "owasp": "A07:2025", "control": "Rate limiting / lockout", "detect": "Repeated failed authentication attempts", "remediation": "Throttle attempts and alert on anomalous login activity."},
    "mass_assignment": {"rule": "INTEGRITY-001", "owasp": "A08:2025", "control": "Server-owned privileged fields", "detect": "Client attempts to modify role/privilege fields", "remediation": "Allow-list writable fields and derive privileges from server state."},
    "upload": {"rule": "UPLOAD-001", "owasp": "A08:2025", "control": "Upload type / size / path validation", "detect": "Disallowed executable-like upload metadata", "remediation": "Allow-list, inspect, rename, size-limit and isolate uploads."},
    "logging": {"rule": "LOG-001", "owasp": "A09:2025", "control": "Structured security logging + alerts", "detect": "Security event with no audit/alert signal", "remediation": "Centralize structured logs and define actionable alerts."},
    "exceptions": {"rule": "ERR-001", "owasp": "A10:2025", "control": "Safe exception handling", "detect": "Internal exception type/details returned to client", "remediation": "Validate preconditions, fail closed and keep diagnostics server-side."},
}


def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        scenario TEXT NOT NULL,
        scenario_name TEXT NOT NULL,
        owasp TEXT NOT NULL DEFAULT '',
        mode TEXT NOT NULL,
        severity TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        probe TEXT NOT NULL,
        attack_success INTEGER NOT NULL,
        detected INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        rule_id TEXT NOT NULL,
        control TEXT NOT NULL,
        detection_latency_ms REAL NOT NULL,
        target_status INTEGER NOT NULL,
        target_decision TEXT NOT NULL
      )
    """)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
    if "owasp" not in columns:
        conn.execute("ALTER TABLE events ADD COLUMN owasp TEXT NOT NULL DEFAULT ''")
    conn.commit()
    conn.close()


init_db()


class Event(BaseModel):
    scenario: str
    scenario_name: str
    owasp: str
    endpoint: str
    method: str
    probe: str
    severity: str
    expected_control: str
    mode: str
    attack_success: bool
    target_status: int
    target_decision: str
    execution_ms: float
    source: str


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "rules": RULES})


@app.get("/health", tags=["Operations"])
def health():
    return {"status": "ok", "service": "blue-team", "rule_count": len(RULES)}


@app.get("/api/rules", tags=["Detection & Response"])
def rules():
    """Explain every detection rule, OWASP mapping, control and remediation used by the lab."""
    return RULES


@app.post("/events", tags=["Detection & Response"])
def ingest(event: Event):
    """Ingest Red Team telemetry, correlate it to an explainable rule and store the result."""
    t0 = time.perf_counter()
    mapping = RULES.get(event.scenario, {"rule": "GEN-001", "control": "Generic review"})
    detected = event.scenario in RULES
    blocked = detected and event.mode == "protected"
    detection_latency_ms = round((time.perf_counter() - t0) * 1000, 3)

    conn = db()
    conn.execute("""
      INSERT INTO events(
        ts, scenario, scenario_name, owasp, mode, severity, endpoint, method, probe,
        attack_success, detected, blocked, rule_id, control,
        detection_latency_ms, target_status, target_decision
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        event.scenario, event.scenario_name, event.owasp, event.mode, event.severity,
        event.endpoint, event.method, event.probe,
        int(event.attack_success), int(detected), int(blocked),
        mapping["rule"], mapping["control"], detection_latency_ms,
        event.target_status, event.target_decision,
    ))
    conn.commit()
    event_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    return {
        "event_id": event_id,
        "detected": detected,
        "blocked": blocked,
        "rule_id": mapping["rule"],
        "control": mapping["control"],
        "detection_latency_ms": detection_latency_ms,
    }


@app.get("/api/events", tags=["Detection & Response"])
def events():
    """Return the latest 200 correlated security events."""
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()]
    conn.close()
    return rows


@app.get("/api/summary", tags=["Detection & Response"])
def summary():
    """Return assessment KPIs, including attack success before and after mitigation."""
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM events").fetchall()]
    conn.close()

    n = len(rows)
    if n == 0:
        return {
            "total": 0, "attack_success_rate": 0, "detection_rate": 0, "block_rate": 0,
            "mean_detection_latency_ms": 0, "vulnerable_success_rate": 0, "protected_success_rate": 0,
        }

    def rate(vals):
        return round(100 * sum(vals) / len(vals), 1) if vals else 0

    vulnerable = [r for r in rows if r["mode"] == "vulnerable"]
    protected = [r for r in rows if r["mode"] == "protected"]
    return {
        "total": n,
        "attack_success_rate": rate([r["attack_success"] for r in rows]),
        "detection_rate": rate([r["detected"] for r in rows]),
        "block_rate": rate([r["blocked"] for r in rows]),
        "mean_detection_latency_ms": round(sum(r["detection_latency_ms"] for r in rows) / n, 3),
        "vulnerable_success_rate": rate([r["attack_success"] for r in vulnerable]),
        "protected_success_rate": rate([r["attack_success"] for r in protected]),
    }


@app.post("/api/run-assessment", tags=["Assessment"])
async def run_assessment():
    """Run the complete Red Team catalog against vulnerable twins and then protected twins."""
    async with httpx.AsyncClient(timeout=90.0) as client:
        before = await client.post(f"{RED_TEAM_URL}/run-all", params={"mode": "vulnerable"})
        before.raise_for_status()
        after = await client.post(f"{RED_TEAM_URL}/run-all", params={"mode": "protected"})
        after.raise_for_status()
    return {"before": before.json(), "after": after.json()}


@app.post("/api/reset", tags=["Assessment"])
def reset():
    """Clear Blue Team event history. Does not change the scenario catalog."""
    conn = db()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    return {"status": "reset"}

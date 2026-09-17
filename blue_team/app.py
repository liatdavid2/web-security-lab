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

app = FastAPI(title="Blue Team Service", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DB_PATH = os.getenv("DB_PATH", "/data/blue_team.db")
RED_TEAM_URL = os.getenv("RED_TEAM_URL", "http://localhost:8201")

RULES = {
    "idor": {"rule": "AUTHZ-001", "control": "Object ownership validation"},
    "xss": {"rule": "XSS-001", "control": "Output encoding / sanitization"},
    "sqli": {"rule": "SQLI-001", "control": "Parameterized queries"},
    "bruteforce": {"rule": "AUTH-002", "control": "Rate limiting / lockout"},
    "upload": {"rule": "UPLOAD-001", "control": "Type / size / content validation"},
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
    conn.commit()
    conn.close()

init_db()

class Event(BaseModel):
    scenario: str
    scenario_name: str
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

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
def health():
    return {"status": "ok", "service": "blue-team"}

@app.post("/events")
def ingest(event: Event):
    t0 = time.perf_counter()

    # Simple explainable detection engine.
    # In a larger system this is where SIEM / IDS / WAF / ML logic would sit.
    mapping = RULES.get(event.scenario, {"rule": "GEN-001", "control": "Generic review"})
    detected = event.scenario in RULES

    # "Would block" decision: protected mode models the mitigation being enabled.
    blocked = detected and event.mode == "protected"

    detection_latency_ms = round((time.perf_counter() - t0) * 1000, 3)

    conn = db()
    conn.execute("""
      INSERT INTO events(
        ts, scenario, scenario_name, mode, severity, endpoint, method, probe,
        attack_success, detected, blocked, rule_id, control,
        detection_latency_ms, target_status, target_decision
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        event.scenario, event.scenario_name, event.mode, event.severity,
        event.endpoint, event.method, event.probe,
        int(event.attack_success), int(detected), int(blocked),
        mapping["rule"], mapping["control"], detection_latency_ms,
        event.target_status, event.target_decision
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

@app.get("/api/events")
def events():
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()]
    conn.close()
    return rows

@app.get("/api/summary")
def summary():
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM events").fetchall()]
    conn.close()

    n = len(rows)
    if n == 0:
        return {
            "total": 0,
            "attack_success_rate": 0,
            "detection_rate": 0,
            "block_rate": 0,
            "mean_detection_latency_ms": 0,
            "vulnerable_success_rate": 0,
            "protected_success_rate": 0,
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

@app.post("/api/run-assessment")
async def run_assessment():
    async with httpx.AsyncClient(timeout=30.0) as client:
        before = await client.post(f"{RED_TEAM_URL}/run-all", params={"mode": "vulnerable"})
        before.raise_for_status()
        after = await client.post(f"{RED_TEAM_URL}/run-all", params={"mode": "protected"})
        after.raise_for_status()
    return {"before": before.json(), "after": after.json()}

@app.post("/api/reset")
def reset():
    conn = db()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    return {"status": "reset"}

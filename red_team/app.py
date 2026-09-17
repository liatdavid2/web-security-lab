import os
import time
from typing import Literal
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(
    title="Red Team Service",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

BLUE_TEAM_URL = os.getenv("BLUE_TEAM_URL", "http://localhost:8202")

SCENARIOS = {
    "idor": {
        "name": "IDOR / Broken Access Control",
        "endpoint": "/lab/idor",
        "method": "GET",
        "probe": "LAB_IDOR_PROBE",
        "severity": "High",
        "expected_control": "Ownership / authorization check",
        "description": "Access-control test: can one user reach another user's object?"
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "endpoint": "/lab/xss",
        "method": "POST",
        "probe": "LAB_XSS_MARKER",
        "severity": "Medium",
        "expected_control": "Output encoding / sanitization",
        "description": "Safe marker representing untrusted browser input."
    },
    "sqli": {
        "name": "SQL Injection",
        "endpoint": "/lab/sqli",
        "method": "POST",
        "probe": "LAB_SQLI_PROBE",
        "severity": "High",
        "expected_control": "Parameterized query",
        "description": "Safe marker representing SQL-injection style input."
    },
    "bruteforce": {
        "name": "Brute-force Login",
        "endpoint": "/lab/bruteforce",
        "method": "POST",
        "probe": "LAB_BRUTE_FORCE_SEQUENCE",
        "severity": "Medium",
        "expected_control": "Rate limiting / lockout",
        "description": "Simulates repeated authentication failures."
    },
    "upload": {
        "name": "Unsafe File Upload",
        "endpoint": "/lab/upload",
        "method": "POST",
        "probe": "LAB_UNSAFE_UPLOAD",
        "severity": "High",
        "expected_control": "Type / size / content validation",
        "description": "Safe metadata-only upload validation test."
    },
}

class RunRequest(BaseModel):
    scenario: str
    mode: Literal["vulnerable", "protected"] = "vulnerable"

def simulate_target(scenario: str, mode: str):
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    if mode == "vulnerable":
        return {"status_code": 200, "attack_success": True, "target_decision": "allowed"}
    return {"status_code": 403, "attack_success": False, "target_decision": "blocked"}

async def send_event(event: dict):
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{BLUE_TEAM_URL}/events", json=event)
        r.raise_for_status()
        return r.json()

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "scenarios": SCENARIOS})

@app.get("/health")
def health():
    return {"status": "ok", "service": "red-team"}

@app.get("/scenarios")
def scenarios():
    return SCENARIOS

@app.post("/run")
async def run(req: RunRequest):
    if req.scenario not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")

    s = SCENARIOS[req.scenario]
    t0 = time.perf_counter()
    target = simulate_target(req.scenario, req.mode)
    execution_ms = round((time.perf_counter() - t0) * 1000, 3)

    event = {
        "scenario": req.scenario,
        "scenario_name": s["name"],
        "endpoint": s["endpoint"],
        "method": s["method"],
        "probe": s["probe"],
        "severity": s["severity"],
        "expected_control": s["expected_control"],
        "mode": req.mode,
        "attack_success": target["attack_success"],
        "target_status": target["status_code"],
        "target_decision": target["target_decision"],
        "execution_ms": execution_ms,
        "source": "red-team-service"
    }

    blue_result = await send_event(event)
    return {"red_team": event, "blue_team": blue_result}

@app.post("/run-all")
async def run_all(mode: Literal["vulnerable", "protected"] = "vulnerable"):
    results = []
    for name in SCENARIOS:
        results.append(await run(RunRequest(scenario=name, mode=mode)))
    return {"mode": mode, "results": results}

@app.get("/lab/{scenario}")
def lab_info(scenario: str):
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    return {"scenario": scenario, "target": "local-simulator", **SCENARIOS[scenario]}

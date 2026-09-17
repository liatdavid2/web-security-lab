import os
import time
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="Red Team Service", version="1.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

BLUE_TEAM_URL = os.getenv("BLUE_TEAM_URL", "http://localhost:8202")
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:8203")

SCENARIOS = {
    "idor": {"name":"IDOR / Broken Access Control","endpoint":"/vuln/notes/2","method":"GET","probe":"alice -> note 2","severity":"High","expected_control":"Ownership / authorization check","description":"Attempts to read Bob's note while acting as Alice."},
    "xss": {"name":"Cross-Site Scripting","endpoint":"/vuln/search","method":"GET","probe":"<script>window.__lab_xss=1</script>","severity":"Medium","expected_control":"Output encoding / sanitization","description":"Checks whether attacker-controlled markup is reflected unescaped."},
    "sqli": {"name":"SQL Injection","endpoint":"/vuln/login","method":"POST","probe":"' OR '1'='1' --","severity":"High","expected_control":"Parameterized query","description":"Uses a local training login to test SQL string concatenation."},
    "bruteforce": {"name":"Brute-force Login","endpoint":"/vuln/auth-check","method":"POST","probe":"7 failed logins","severity":"Medium","expected_control":"Rate limiting / lockout","description":"Sends a short bounded sequence of failed logins to the local target."},
    "upload": {"name":"Unsafe File Upload","endpoint":"/vuln/upload","method":"POST","probe":"training.php / application/x-httpd-php","severity":"High","expected_control":"Type / size / content validation","description":"Metadata-only test: target never executes uploaded content."},
}

class RunRequest(BaseModel):
    scenario: str
    mode: Literal["vulnerable", "protected"] = "vulnerable"


def path(mode: str, suffix: str) -> str:
    return f"/{'vuln' if mode == 'vulnerable' else 'protected'}/{suffix}"


async def execute_target(scenario: str, mode: str):
    prefix = "vuln" if mode == "vulnerable" else "protected"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        if scenario == "idor":
            r = await client.get(f"{TARGET_URL}/{prefix}/notes/2", params={"user":"alice"})
            success = r.status_code == 200 and "BOB-ONLY-456" in r.text
        elif scenario == "xss":
            marker = "<script>window.__lab_xss=1</script>"
            r = await client.get(f"{TARGET_URL}/{prefix}/search", params={"q": marker})
            success = r.status_code == 200 and marker in r.text
        elif scenario == "sqli":
            payload = {"username":"' OR '1'='1' --", "password":"x"}
            r = await client.post(f"{TARGET_URL}/{prefix}/login", json=payload)
            success = r.status_code == 200 and bool(r.json().get("authenticated"))
        elif scenario == "bruteforce":
            statuses = []
            for i in range(7):
                r = await client.post(f"{TARGET_URL}/{prefix}/auth-check", json={"username":"alice","password":f"wrong-{i}"})
                statuses.append(r.status_code)
            success = 429 not in statuses
            r._content = str(statuses).encode()
        elif scenario == "upload":
            r = await client.post(f"{TARGET_URL}/{prefix}/upload", json={"filename":"training.php","content_type":"application/x-httpd-php","size":128})
            success = r.status_code == 200 and bool(r.json().get("accepted"))
        else:
            raise HTTPException(404, "Unknown scenario")

        evidence = r.text[:800]
        return {"status_code": r.status_code, "attack_success": success, "target_decision": "allowed" if success else "blocked", "evidence": evidence}


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
    return {"status":"ok","service":"red-team","target":TARGET_URL}

@app.get("/scenarios")
def scenarios():
    return SCENARIOS

@app.post("/run")
async def run(req: RunRequest):
    if req.scenario not in SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    s = SCENARIOS[req.scenario]
    t0 = time.perf_counter()
    try:
        target = await execute_target(req.scenario, req.mode)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Training target unavailable: {exc}")
    execution_ms = round((time.perf_counter()-t0)*1000,3)
    event = {
      "scenario":req.scenario,"scenario_name":s["name"],"endpoint":s["endpoint"],"method":s["method"],
      "probe":s["probe"],"severity":s["severity"],"expected_control":s["expected_control"],"mode":req.mode,
      "attack_success":target["attack_success"],"target_status":target["status_code"],"target_decision":target["target_decision"],
      "execution_ms":execution_ms,"source":"red-team-service"
    }
    blue = await send_event(event)
    return {"red_team":event,"target_evidence":target["evidence"],"blue_team":blue}

@app.post("/run-all")
async def run_all(mode: Literal["vulnerable","protected"]="vulnerable"):
    return {"mode":mode,"results":[await run(RunRequest(scenario=n,mode=mode)) for n in SCENARIOS]}

@app.get("/lab/{scenario}")
def lab_info(scenario: str):
    if scenario not in SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    return {"scenario":scenario,"target":TARGET_URL,**SCENARIOS[scenario]}

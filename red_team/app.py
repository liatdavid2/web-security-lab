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
    title="Web Security Lab - Red Team",
    version="2.0.0",
    description="Runs bounded security checks only against the lab-owned vulnerable target configured by TARGET_URL.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

BLUE_TEAM_URL = os.getenv("BLUE_TEAM_URL", "http://localhost:8202")
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:8203")

SCENARIOS = {
    "idor": {
        "name": "IDOR / Broken Access Control", "owasp": "A01:2025", "endpoint": "/vuln/notes/2", "method": "GET",
        "probe": "alice -> Bob's note #2", "severity": "High", "expected_control": "Object ownership / authorization check",
        "description": "Attempts to read another user's object by changing only its ID.",
        "why": "The server retrieves the object but never verifies that the current user is allowed to access it.",
        "remediation": "Enforce object-level authorization on every request; do not trust a client-supplied owner/user identifier."
    },
    "path_traversal": {
        "name": "Path Traversal", "owasp": "A01:2025", "endpoint": "/vuln/files?name=../config.env", "method": "GET",
        "probe": "../config.env", "severity": "High", "expected_control": "Canonical path validation / safe basename",
        "description": "Checks whether path traversal can escape a public-file namespace.",
        "why": "Untrusted path fragments can point outside the intended directory.",
        "remediation": "Reject traversal tokens, canonicalize paths, use allow-listed filenames and keep sensitive files outside served roots."
    },
    "ssrf": {
        "name": "SSRF (training-safe simulation)", "owasp": "A01:2025", "endpoint": "/vuln/fetch-url", "method": "POST",
        "probe": "169.254.169.254 metadata URL", "severity": "High", "expected_control": "Destination allow-list + private/link-local block",
        "description": "Tests whether a server-side URL fetcher accepts an internal/link-local destination.",
        "why": "A server that fetches arbitrary client URLs can become a bridge into internal services or metadata endpoints.",
        "remediation": "Allow-list destinations, resolve/validate hosts and IPs, block loopback/private/link-local ranges and restrict egress."
    },
    "misconfig": {
        "name": "Security Misconfiguration / Debug Disclosure", "owasp": "A02:2025", "endpoint": "/vuln/debug-config", "method": "GET",
        "probe": "read debug/config response", "severity": "Medium", "expected_control": "Production-safe config + minimal disclosure",
        "description": "Looks for internal paths, stack hints and demo secrets in a debug endpoint.",
        "why": "Verbose debug information reduces attacker uncertainty and can expose secrets or internal architecture.",
        "remediation": "Disable debug output in production, separate health endpoints from diagnostics and keep secrets out of responses."
    },
    "supply_chain": {
        "name": "Software Supply Chain Failure", "owasp": "A03:2025", "endpoint": "/vuln/dependencies", "method": "GET",
        "probe": "floating versions + no integrity metadata", "severity": "Medium", "expected_control": "Pinned versions + integrity/provenance checks",
        "description": "Audits a demo dependency manifest for wildcard versions and missing integrity metadata.",
        "why": "Unpinned or unverified dependencies make builds less reproducible and weaken trust in what code is actually shipped.",
        "remediation": "Pin dependencies, verify hashes/signatures/provenance, scan dependencies and protect the build pipeline."
    },
    "crypto": {
        "name": "Cryptographic Failure / Cleartext Credential", "owasp": "A04:2025", "endpoint": "/vuln/credentials/alice", "method": "GET",
        "probe": "retrieve Alice's cleartext demo password", "severity": "High", "expected_control": "One-way password hashing + secret minimization",
        "description": "Checks whether a credential record exposes a cleartext password.",
        "why": "If passwords are stored or returned in plaintext, a database or API disclosure immediately reveals reusable secrets.",
        "remediation": "Use a modern password hash (Argon2id/bcrypt/scrypt), never return password material and encrypt other sensitive data appropriately."
    },
    "xss": {
        "name": "Reflected Cross-Site Scripting", "owasp": "A05:2025", "endpoint": "/vuln/search", "method": "GET",
        "probe": "<script>window.__lab_xss=1</script>", "severity": "Medium", "expected_control": "Context-aware output encoding / sanitization",
        "description": "Checks whether attacker-controlled markup is reflected into HTML without encoding.",
        "why": "The browser interprets untrusted markup as active content instead of plain text.",
        "remediation": "Encode output for its HTML/attribute/URL/JS context, use safe templating defaults and add CSP as defense in depth."
    },
    "sqli": {
        "name": "SQL Injection", "owasp": "A05:2025", "endpoint": "/vuln/login", "method": "POST",
        "probe": "' OR '1'='1' --", "severity": "Critical", "expected_control": "Parameterized query / prepared statement",
        "description": "Uses a bounded local login payload to test SQL string concatenation.",
        "why": "User input becomes SQL syntax because the query is constructed as a string.",
        "remediation": "Use parameterized queries/prepared statements, least-privilege DB accounts and server-side input validation."
    },
    "insecure_design": {
        "name": "Insecure Design / Predictable Reset Token", "owasp": "A06:2025", "endpoint": "/vuln/password-reset/verify", "method": "POST",
        "probe": "reset-alice", "severity": "High", "expected_control": "High-entropy one-time token + expiry",
        "description": "Guesses a reset token derived from the username.",
        "why": "The reset workflow is insecure by design because account recovery depends on a predictable secret.",
        "remediation": "Generate cryptographically random single-use tokens, expire them quickly, rate-limit verification and send them out-of-band."
    },
    "bruteforce": {
        "name": "Brute-force Authentication", "owasp": "A07:2025", "endpoint": "/vuln/auth-check", "method": "POST",
        "probe": "7 bounded failed logins", "severity": "Medium", "expected_control": "Rate limiting / temporary lockout",
        "description": "Sends a short bounded sequence of failed logins to the local target.",
        "why": "Without throttling, an attacker can make large numbers of password guesses.",
        "remediation": "Rate-limit by account and source signals, use MFA where appropriate and alert on anomalous authentication behavior."
    },
    "mass_assignment": {
        "name": "Mass Assignment / Role Tampering", "owasp": "A08:2025", "endpoint": "/vuln/profile", "method": "POST",
        "probe": "role=admin", "severity": "High", "expected_control": "Server-controlled integrity-sensitive fields",
        "description": "Sends an admin role in a profile update and checks whether the server trusts it.",
        "why": "Binding request objects directly to privileged model fields lets clients modify data they should not control.",
        "remediation": "Use explicit request DTOs/allow-lists, ignore privileged fields from clients and re-read authority from trusted server state."
    },
    "upload": {
        "name": "Unsafe File Upload", "owasp": "A08:2025", "endpoint": "/vuln/upload", "method": "POST",
        "probe": "training.php / application/x-httpd-php", "severity": "High", "expected_control": "Type / extension / size validation",
        "description": "Metadata-only check for an unsafe upload policy; the target never executes uploaded content.",
        "why": "Accepting arbitrary upload types or paths can lead to malicious content storage, execution or overwriting files.",
        "remediation": "Allow-list types/extensions, verify content, rename files, set size limits, store outside web roots and never execute uploads."
    },
    "logging": {
        "name": "Security Logging & Alerting Failure", "owasp": "A09:2025", "endpoint": "/vuln/audit-event", "method": "POST",
        "probe": "login_failure event", "severity": "Medium", "expected_control": "Structured audit log + alertable signal",
        "description": "Checks whether a security-relevant event is recorded and can trigger an alert.",
        "why": "Attacks can continue unnoticed when important events are neither logged nor surfaced to defenders.",
        "remediation": "Log security-relevant events with useful context, protect log integrity, centralize telemetry and define actionable alerts."
    },
    "exceptions": {
        "name": "Exceptional Condition / Error Leakage", "owasp": "A10:2025", "endpoint": "/vuln/calculate?value=0", "method": "GET",
        "probe": "value=0", "severity": "Medium", "expected_control": "Pre-validation + generic client error",
        "description": "Triggers a benign exceptional condition and checks for leaked internal error details.",
        "why": "Poor exception handling can leak implementation details or cause systems to fail open under abnormal inputs.",
        "remediation": "Validate preconditions, fail closed, return generic client errors and keep detailed diagnostics in protected server logs."
    },
}


class RunRequest(BaseModel):
    scenario: str
    mode: Literal["vulnerable", "protected"] = "vulnerable"


async def execute_target(scenario: str, mode: str):
    prefix = "vuln" if mode == "vulnerable" else "protected"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        if scenario == "idor":
            r = await client.get(f"{TARGET_URL}/{prefix}/notes/2", params={"user": "alice"})
            success = r.status_code == 200 and "BOB-ONLY-456" in r.text
        elif scenario == "path_traversal":
            r = await client.get(f"{TARGET_URL}/{prefix}/files", params={"name": "../config.env"})
            success = r.status_code == 200 and "LAB-ONLY-KEY" in r.text
        elif scenario == "ssrf":
            r = await client.post(f"{TARGET_URL}/{prefix}/fetch-url", json={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
            success = r.status_code == 200 and "FAKE-INSTANCE-METADATA" in r.text
        elif scenario == "misconfig":
            r = await client.get(f"{TARGET_URL}/{prefix}/debug-config")
            success = r.status_code == 200 and "DEBUG-DEMO-KEY" in r.text
        elif scenario == "supply_chain":
            r = await client.get(f"{TARGET_URL}/{prefix}/dependencies")
            data = r.json() if r.status_code == 200 else {}
            deps = data.get("dependencies", [])
            success = r.status_code == 200 and any(d.get("version") in {"*", ">=1"} or not d.get("integrity") for d in deps)
        elif scenario == "crypto":
            r = await client.get(f"{TARGET_URL}/{prefix}/credentials/alice")
            success = r.status_code == 200 and "wonderland" in r.text
        elif scenario == "xss":
            marker = "<script>window.__lab_xss=1</script>"
            r = await client.get(f"{TARGET_URL}/{prefix}/search", params={"q": marker})
            success = r.status_code == 200 and marker in r.text
        elif scenario == "sqli":
            payload = {"username": "' OR '1'='1' --", "password": "x"}
            r = await client.post(f"{TARGET_URL}/{prefix}/login", json=payload)
            success = r.status_code == 200 and bool(r.json().get("authenticated"))
        elif scenario == "insecure_design":
            r = await client.post(f"{TARGET_URL}/{prefix}/password-reset/verify", json={"username": "alice", "token": "reset-alice"})
            success = r.status_code == 200 and bool(r.json().get("valid"))
        elif scenario == "bruteforce":
            statuses = []
            for i in range(7):
                r = await client.post(f"{TARGET_URL}/{prefix}/auth-check", json={"username": "alice", "password": f"wrong-{i}"})
                statuses.append(r.status_code)
            success = 429 not in statuses
            evidence = str(statuses)
            return {"status_code": statuses[-1], "attack_success": success, "target_decision": "allowed" if success else "blocked", "evidence": evidence}
        elif scenario == "mass_assignment":
            r = await client.post(f"{TARGET_URL}/{prefix}/profile", json={"username": "alice", "display_name": "Alice", "role": "admin"})
            success = r.status_code == 200 and bool(r.json().get("is_admin"))
        elif scenario == "upload":
            r = await client.post(f"{TARGET_URL}/{prefix}/upload", json={"filename": "training.php", "content_type": "application/x-httpd-php", "size": 128})
            success = r.status_code == 200 and bool(r.json().get("accepted"))
        elif scenario == "logging":
            r = await client.post(f"{TARGET_URL}/{prefix}/audit-event", json={"username": "alice", "action": "login_failure"})
            success = r.status_code == 200 and not bool(r.json().get("audit_logged"))
        elif scenario == "exceptions":
            r = await client.get(f"{TARGET_URL}/{prefix}/calculate", params={"value": 0})
            success = r.status_code == 200 and "ZeroDivisionError" in r.text
        else:
            raise HTTPException(404, "Unknown scenario")

        evidence = r.text[:1000]
        return {
            "status_code": r.status_code,
            "attack_success": success,
            "target_decision": "allowed" if success else "blocked",
            "evidence": evidence,
        }


async def send_event(event: dict):
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{BLUE_TEAM_URL}/events", json=event)
        r.raise_for_status()
        return r.json()


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "scenarios": SCENARIOS})


@app.get("/health", tags=["Operations"])
def health():
    return {"status": "ok", "service": "red-team", "target": TARGET_URL, "scenario_count": len(SCENARIOS)}


@app.get("/scenarios", tags=["Red Team"])
def scenarios():
    """Return the complete bounded scenario catalog used by the Red Team UI."""
    return SCENARIOS


@app.post("/run", tags=["Red Team"])
async def run(req: RunRequest):
    """Run one lab scenario against either the vulnerable or protected twin and forward telemetry to Blue Team."""
    if req.scenario not in SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    s = SCENARIOS[req.scenario]
    t0 = time.perf_counter()
    try:
        target = await execute_target(req.scenario, req.mode)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Training target unavailable: {exc}")
    execution_ms = round((time.perf_counter() - t0) * 1000, 3)
    event = {
        "scenario": req.scenario,
        "scenario_name": s["name"],
        "owasp": s["owasp"],
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
        "source": "red-team-service",
    }
    blue = await send_event(event)
    return {"red_team": event, "target_evidence": target["evidence"], "blue_team": blue}


@app.post("/run-all", tags=["Red Team"])
async def run_all(mode: Literal["vulnerable", "protected"] = "vulnerable"):
    """Run all scenarios sequentially in one mode. Bounded to the fixed lab scenario catalog."""
    return {"mode": mode, "results": [await run(RunRequest(scenario=n, mode=mode)) for n in SCENARIOS]}


@app.get("/lab/{scenario}", tags=["Red Team"])
def lab_info(scenario: str):
    """Return explanation, OWASP mapping, probe and expected defense for one scenario."""
    if scenario not in SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    return {"scenario": scenario, "target": TARGET_URL, **SCENARIOS[scenario]}

# web-security-lab

A local **Swagger + Red Team + Blue Team** web-security training lab.

The project contains three Docker services:

- **Vulnerable Target** (`8203`) — intentionally insecure endpoints with a protected twin for every exercise, plus Swagger documentation.
- **Red Team** (`8201`) — runs a fixed, bounded catalog of training probes against the lab-owned target.
- **Blue Team** (`8202`) — receives telemetry, correlates it with explainable detection rules, stores events, and compares vulnerable vs protected behavior.

> **Safety:** this lab is intentionally vulnerable. The Compose ports are bound to `127.0.0.1` and should remain local. Do not expose the target to the public Internet.

## Start

```bash
docker compose up --build
```

Open:

- Target home: http://localhost:8203
- **Target Swagger:** http://localhost:8203/docs
- Red Team UI: http://localhost:8201
- Red Team Swagger: http://localhost:8201/docs
- Blue Team UI: http://localhost:8202
- Blue Team Swagger: http://localhost:8202/docs

## Learning flow

1. Open **Target Swagger** and select an exercise.
2. Read what the weakness is and why the endpoint is vulnerable.
3. Execute the `/vuln/...` endpoint.
4. Execute the matching `/protected/...` endpoint and compare the response.
5. Open **Red Team** to run the same check automatically.
6. Open **Blue Team** to see detection, mitigation status, rule ID, control, and before/after metrics.
7. Use **Run full assessment** in Blue Team to run all 14 scenarios first against vulnerable twins and then against protected twins.

## Included exercises

The catalog is organized around **OWASP Top 10:2025** categories and practical web weaknesses.

| OWASP area | Exercise | Vulnerable behavior | Protected twin |
|---|---|---|---|
| A01 Broken Access Control | IDOR | Reads another user's note by object ID | Checks object ownership |
| A01 Broken Access Control | Path Traversal | Simulated `../config.env` escape | Rejects traversal / unsafe path |
| A01 Broken Access Control | SSRF | Training-safe simulated internal metadata fetch | Blocks internal/link-local destination |
| A02 Security Misconfiguration | Debug disclosure | Returns paths, stack hints and demo secret | Minimal health/config response |
| A03 Software Supply Chain Failures | Dependency policy | Floating versions / no integrity metadata | Exact versions + integrity metadata |
| A04 Cryptographic Failures | Cleartext credential | Returns lab password in plaintext | Never returns password material |
| A05 Injection | Reflected XSS | Renders unescaped user input | HTML output encoding |
| A05 Injection | SQL Injection | Builds SQLite query by string interpolation | Parameterized SQL query |
| A06 Insecure Design | Password reset | Predictable `reset-{username}` token | High-entropy one-time token |
| A07 Authentication Failures | Brute force | No authentication throttling | 5 failures / 60s rate limit |
| A08 Software/Data Integrity | Mass assignment | Client can submit `role=admin` | Server controls privileged role |
| A08 Software/Data Integrity | Unsafe upload | Accepts arbitrary upload metadata | Type/extension/size allow-list |
| A09 Logging & Alerting | Logging gap | Security event not audited | Structured audit + alert signal |
| A10 Exceptional Conditions | Error leakage | Returns internal exception details | Validates input + generic client error |

### Safe simulations

Some vulnerability classes can be dangerous even in a training project. This lab therefore keeps the educational behavior while constraining the sink:

- SSRF **does not make arbitrary outbound network requests**; internal metadata is simulated.
- Path traversal **does not read arbitrary host/container files**; it returns a fake internal config value.
- Unsafe upload is **metadata-only**; uploaded executable content is never stored or executed.
- Red Team probes are fixed in the scenario catalog and target only the configured lab service.

## Architecture

```text
Browser
  |-- Red Team UI / Swagger -------- :8201
  |-- Blue Team UI / Swagger ------- :8202
  `-- Vulnerable Target / Swagger -- :8203
                    ^
                    |
                Red Team
                    |
                    v
                Blue Team -> SQLite event history
```

## Main APIs

### Red Team

- `GET /scenarios` — scenario catalog with OWASP mapping, explanation and remediation.
- `POST /run` — run one fixed scenario in `vulnerable` or `protected` mode.
- `POST /run-all` — run all scenarios in one mode.
- `GET /lab/{scenario}` — scenario details.

### Blue Team

- `GET /api/rules` — rule/control/remediation catalog.
- `POST /events` — ingest Red Team telemetry.
- `GET /api/summary` — before/after KPIs.
- `GET /api/events` — latest correlated events.
- `POST /api/run-assessment` — run the full vulnerable + protected assessment.
- `POST /api/reset` — clear event history.

### Vulnerable Target

Every exercise uses a `/vuln/...` endpoint and a matching `/protected/...` endpoint. Swagger at `/docs` is the easiest way to explore all paths and explanations.

## Expected full-assessment result

With the built-in fixed probes:

- Vulnerable mode: **14 / 14 weaknesses reproduced**.
- Protected mode: **0 / 14 weaknesses reproduced**.
- Blue Team detection: **14 explainable rules** mapped to the scenario catalog.

These are deterministic lab checks, not a claim that the protected examples are complete production-grade security controls.

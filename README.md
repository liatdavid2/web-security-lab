# web-security-lab

A small, safe, local-only portfolio project that clearly separates:

- **Red Team** — generates controlled web-security test scenarios and produces evidence.
- **Blue Team** — receives telemetry, detects suspicious activity, decides whether it would block it, persists the results, and provides a dashboard.

The project intentionally uses **simulation markers** rather than real destructive exploitation. It is designed for local labs, demos, interviews and experimentation.

## Architecture

```text
Browser
   |
   v
Blue Team UI :8202
   |
   |  "Run assessment"
   v
Red Team API :8201
   |
   |  attack telemetry
   v
Blue Team API / Detection Engine
   |
   +--> SQLite
   |
   +--> Metrics / Dashboard
```

## Industry-style flow

The lab follows the same separation of concerns commonly used in security programs:

1. **Scenario definition** — Red Team describes the technique, target endpoint and expected security control.
2. **Execution** — Red Team sends controlled requests to a deliberately vulnerable local target simulator.
3. **Telemetry** — request metadata and evidence are forwarded to Blue Team.
4. **Detection** — Blue Team maps events to detection rules.
5. **Response** — Blue Team records whether the event would be blocked.
6. **Retest** — the same scenario is run in `protected` mode.
7. **Measurement** — dashboard compares before/after results.

## Included scenarios

- IDOR / Broken Access Control
- XSS
- SQL Injection
- Brute-force login
- Unsafe file upload

These are intentionally simulated and use lab markers such as `LAB_SQLI_PROBE`, not production attack payloads.

## Metrics

The dashboard shows:

- Attack Success Rate
- Detection Rate
- Block Rate
- Retest Success Rate
- Mean Detection Latency
- Scenario-by-scenario evidence

## Run

```bash
docker compose up --build
```

Then open:

- Red Team UI: http://localhost:8201
- Blue Team UI: http://localhost:8202

Swagger/ReDoc are intentionally disabled; the project is operated through the two dedicated UIs.

## Main API endpoints

### Red Team

- `GET /scenarios`
- `POST /run`
- `POST /run-all`
- `GET /lab/{scenario}`

### Blue Team

- `POST /events`
- `GET /api/summary`
- `GET /api/events`
- `POST /api/run-assessment`
- `POST /api/reset`

## Why this structure is useful

A real security platform normally separates offensive testing from defensive detection and monitoring. This project keeps that separation visible:

- Red Team owns **test generation and evidence**.
- Blue Team owns **detection, blocking decision, persistence and reporting**.
- The UI shows **before defense vs after defense** instead of only saying "vulnerability found".

For a larger version, the HTTP event handoff can be replaced by Kafka, OpenTelemetry, SIEM ingestion, or a cloud event bus.

# web-security-lab

A local Red Team / Blue Team training lab with **three Docker services**:

- **Red Team** — executes bounded training attacks and sends evidence/telemetry.
- **Blue Team** — detects, records and compares attack behavior before/after mitigation.
- **Vulnerable Target** — an intentionally insecure web app owned by this lab, plus protected twin endpoints for retesting.

> **Safety:** the vulnerable target is for localhost / isolated lab use only. Do not expose port `8203` to the public Internet.

## Architecture

```text
Browser
  |-- Red Team UI -------- :8201
  |-- Blue Team UI ------- :8202
  `-- Vulnerable Target -- :8203
              ^
              |
          Red Team
              |
              v
          Blue Team -> SQLite
```

The Red Team now sends **real HTTP requests to the lab-owned target** instead of simulating the target response.

## Included exercises

| Exercise | Vulnerable behavior | Protected twin |
|---|---|---|
| IDOR | Reads another user's note by object ID | Checks object ownership |
| Reflected XSS | Renders search input without escaping | HTML-escapes output |
| SQL injection | Builds a SQLite login query by string concatenation | Uses query parameters |
| Brute force | No authentication rate limit | 5 failures / 60s limit |
| Unsafe upload | Accepts arbitrary filename/type metadata | Extension/type/size allow-list |

The upload exercise is deliberately **metadata-only**: uploaded content is not executed.

## Run

```bash
docker compose up --build
```

Open:

- Red Team UI: http://localhost:8201
- Blue Team UI: http://localhost:8202
- Vulnerable Target UI: http://localhost:8203

From the Blue Team UI, **Run assessment** executes every scenario first against `/vuln/...` and then against `/protected/...` so the dashboard can compare the results.

## Services

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

### Vulnerable Target
- `GET /vuln/notes/{id}` / `GET /protected/notes/{id}`
- `GET /vuln/search` / `GET /protected/search`
- `POST /vuln/login` / `POST /protected/login`
- `POST /vuln/auth-check` / `POST /protected/auth-check`
- `POST /vuln/upload` / `POST /protected/upload`

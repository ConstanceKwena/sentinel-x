# Sentinel-X


Student Project Code: WTC-P5C374AU

Cybersecurity threat detection and incident response platform.

Sentinel-X is a local-first security event detection and incident-response demo. It uses FastAPI, SQLite, deterministic Python detection rules, and a dependency-free browser dashboard. Events and incidents remain in a local SQLite database; no external AI or network service is required.

## Requirements and installation

- Python 3.10 or later
- pip

From the repository root, install the runtime and development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
python -m pip install -r requirements-dev.txt
```

## Start the application

Run the API and dashboard from the repository root:

```powershell
python -m uvicorn backend.main:app --reload
```

Open <http://127.0.0.1:8000/dashboard> for the dashboard. The API root is <http://127.0.0.1:8000/> and the health check is <http://127.0.0.1:8000/health>. FastAPI's interactive API documentation is at <http://127.0.0.1:8000/docs>.

The dashboard is served by FastAPI from `frontend/`; it has no separate build step or external runtime dependencies. The SQLite database is created at `backend/sentinel_x.db` on startup.

The dashboard polls the API for persisted events and findings. It defaults to **Connected application** activity. Use the activity selector to view **Simulation**, **Unknown origin**, or **All activity**; these selections affect event, detection, incident, and response summaries. Live statistics are computed from SQLite records. Loading the dashboard or requesting incidents/detections does not create incidents or events.

Events store a server-generated UTC `received_at` timestamp and an explicit `source_origin` plus optional `source_application`. Events from an application identified with `X-Sentinel-Application` are marked `connected_application` only when ingestion authentication is configured and the matching `X-Sentinel-Key` is valid. Safe attack simulation events are marked `simulation`. Historical event and incident records from before provenance was added remain `unknown` and are never relabeled based on inference. An API request without a verified application identifier remains `unknown`. Existing rows are preserved during startup migrations.

To serve the frontend separately at `http://127.0.0.1:5500` during development, start a second terminal and run `python -m http.server 5500 --directory frontend` from the repository root. The frontend loads CSS and JavaScript from relative paths and connects to the API on port 8000; the backend allows this local development origin through CORS.

## External application and safe response demo

The separate demo login app sends `login_success` and `login_failed` events to the existing `POST /events` API. Sentinel-X assigns the authoritative UTC `received_at` timestamp, stores the event using the existing schema, and runs its normal detection and incident pipeline. The connected app identifies itself with `X-Sentinel-Application: demo-login-app`; its connection status is based on the time of its most recent event.

For connected-app authentication, configure an ingestion key in the Sentinel-X process before starting the API:

```powershell
$env:SENTINEL_INGEST_API_KEY = "set-a-long-random-value-here"
$env:SENTINEL_ADMIN_API_KEY = "set-a-separate-long-random-value-here"
$env:SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD = "5"
$env:SENTINEL_RESPONSE_WINDOW_MINUTES = "10"
$env:SENTINEL_RESPONSE_BLOCK_MINUTES = "15"
$env:SENTINEL_RESPONSE_MINIMUM_ACCOUNTS = "2"
$env:SENTINEL_AUTO_BLOCK_ENABLED = "true"
python -m uvicorn backend.main:app --reload
```

Keep both keys in environment variables; never put them in the dashboard or browser JavaScript. Without a configured `SENTINEL_INGEST_API_KEY`, unmarked API events may still be accepted for compatibility but remain `unknown`; connected-application events are rejected until ingestion authentication is configured. Authenticated clients must send the key as `X-Sentinel-Key`. The demo login app reads the same ingestion key server-side.

In another terminal, pass the same ingestion key to the demo app and start it separately:

```powershell
$env:SENTINEL_INGEST_API_KEY = "the-same-ingestion-key"
$env:SENTINEL_API_URL = "http://127.0.0.1:8000"
python -m uvicorn backend.demo_login:app --host 127.0.0.1 --port 8001 --reload
```

Open <http://127.0.0.1:8001/> and sign in with the published demo-only account `demo-user` / `demo-password`; try an incorrect password to submit a failed-login event. The stored event contains the actual account and client IP and records `Invalid credentials` only for an unsuccessful login; passwords and API keys are not included. Review the event stream, rule findings, incidents, connected-app status, active source blocks, expirations, and response history in the main dashboard at <http://127.0.0.1:8000/dashboard>. Click **Investigate** on an event for its timestamp, source, related authentication timeline, detections, associated incidents, and response actions. The demo app is intentionally separate and has only this sample account.

Automatic response is local to the demo application's login endpoint. By default it requires at least five failures across at least two account identifiers within ten minutes, then blocks that source from logging into the demo app for 15 minutes. A single account with repeated mistyped passwords is not enough to cause a block. All policy values above are configurable; `SENTINEL_RESPONSE_MINIMUM_ACCOUNTS` cannot be lower than two. Set `SENTINEL_RESPONSE_TRUSTED_IPS` to a comma-separated list of addresses that must never be blocked, or set `SENTINEL_AUTO_BLOCK_ENABLED=false` to turn off automatic blocks. Blocks and their expiry are stored in SQLite; block, manual removal, and expiry actions are retained in the response audit history. No network traffic is blocked and no operating-system firewall is changed.

Response evaluation is restricted to failed-login events with connected-application provenance. Simulated events and events with unknown origin do not create automatic blocks. Events are scoped by application during rule evaluation, and a response block is enforced only by the demo application's `/login` endpoint.

### Clean demonstration database (without deleting data)

To leave the existing database untouched and start with zero verified connected-application activity, stop both app processes with **Ctrl+C**. In the PowerShell terminal for the Sentinel-X backend, choose a new isolated database path and start the API:

```powershell
$env:SENTINEL_DATABASE_PATH = "$env:TEMP\sentinel_x_clean_demo.db"
$env:SENTINEL_INGEST_API_KEY = "use-the-same-long-random-key-in-both-terminals"
$env:SENTINEL_ADMIN_API_KEY = "set-a-separate-administrator-key"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In the second PowerShell terminal, use the same path-independent ingestion key and start the login application:

```powershell
$env:SENTINEL_DATABASE_PATH = "$env:TEMP\sentinel_x_clean_demo.db"
$env:SENTINEL_INGEST_API_KEY = "use-the-same-long-random-key-in-both-terminals"
$env:SENTINEL_API_URL = "http://127.0.0.1:8000"
python -m uvicorn backend.demo_login:app --host 127.0.0.1 --port 8001
```

The dashboard's **Connected application** view initially reports zero events and incidents in that new database. A new SQLite file is created if the selected path does not exist; the original `backend/sentinel_x.db` is not cleared or modified by this procedure. Continue using the same new path on both launches to retain this demo's activity. To inspect old records, select **Unknown origin** or **All activity**; they remain stored but are not represented as verified login-app events.

Administrator block removal requires `SENTINEL_ADMIN_API_KEY` and the `X-Sentinel-Admin-Key` header. For example, in the administrator's PowerShell session:

```powershell
$headers = @{ "X-Sentinel-Admin-Key" = $env:SENTINEL_ADMIN_API_KEY }
Invoke-RestMethod -Method Delete `
  -Uri "http://127.0.0.1:8000/response/blocks/192.0.2.77" `
  -Headers $headers
```

## Detection and risk scoring

The detector evaluates event type, account, source IP, event timestamps, and (for transfer-size context) event details. Its default time window is 10 minutes and the failed-login threshold is 3 attempts.

| Rule | Detection | Risk points |
|---|---|---:|
| `AUTH-001` | A successful login follows at least 3 failed logins for the same account and IP within the window | 50 |
| `AUTH-002` | At least 3 failed logins from one IP target at least 2 accounts within the window | 20 |
| `AUTH-004` | At least 3 failed logins target one account from one IP within the window | 25 |
| `PRIV-001` | A privilege-change event is recorded | 30 |
| `DATA-001` | An outbound-transfer event is recorded; transfer sizes at or above the configured size are called out in the explanation | 35 |
| `CORR-001` | Multiple distinct rules match the same account or IP within the window; adds 10 points to the contributing rules | 10 plus contributing rule points |
| `CHAIN-001` | Ordered failed login → successful login → privilege change and/or outbound transfer, for the same account and IP within the window | 20 plus the chain's rule points |

Scores are capped at 100. Severity is Low (0–24), Medium (25–49), High (50–74), or Critical (75–100). The incident stores its score, rule explanation, event IDs, recommended analyst actions, and any correlated chain. This is a transparent triage heuristic, not a calibrated probability of compromise.

Override the defaults before starting the backend:

```powershell
$env:SENTINEL_FAILED_LOGIN_THRESHOLD = "3"
$env:SENTINEL_DETECTION_WINDOW_MINUTES = "10"
$env:SENTINEL_SUSPICIOUS_TRANSFER_MB = "100"
$env:SENTINEL_SIMULATION_ENABLED = "true"
# Optional: store SQLite data outside the repository
$env:SENTINEL_DATABASE_PATH = "$env:TEMP\sentinel_x.db"
```

The simulation endpoint is enabled by default for local development and can be disabled with `SENTINEL_SIMULATION_ENABLED=false`.

## Safe attack demonstration

With the backend running, select a scenario from the dashboard and click **Run safe simulation**, or use the command line from the repository root:

```powershell
python -m backend.simulate_attack
python -m backend.simulate_attack --scenario brute_force
python -m backend.simulate_attack --scenario account_compromise
python -m backend.simulate_attack --scenario privilege_escalation
python -m backend.simulate_attack --scenario data_transfer
python -m backend.simulate_attack --scenario full_attack_chain
```

The full simulation sends six synthetic events using the documentation-only address `192.0.2.50`: three failed logins, a successful login, a privilege change, and a 250 MB outbound-transfer event. The other selectable scenarios demonstrate brute force, account compromise, privilege escalation, or data transfer independently. The simulation does not connect to or send traffic to the simulated address. The backend persists the events, detects the behavior, correlates the ordered chain, and creates incidents. Review the resulting incident in the dashboard and change its status from the incident investigation view.

## API overview

- `POST /events` — validate and persist one security event; updates incident detections.
- `GET /events` — retrieve recent events; supports `event_type`, `username`, `source_ip`, and `limit` filters.
- `GET /events/{event_id}` — inspect the persisted event with its source provenance, findings, incidents, related authentication attempts, and response history.
- `GET /events?source_origin=connected_application` — retrieve verified connected-app activity (`simulation`, `unknown`, and `all` are also supported).
- `GET /detections` — list rule detections with evidence, explanations, criteria, and response recommendations.
- `GET /attack-chains` — return event sequences correlated by exact account and IP.
- `GET /incidents` — retrieve persistent incidents; supports `status`, `severity`, and `limit`.
- `GET /incidents/{incident_id}` — retrieve details and status history.
- `PATCH /incidents/{incident_id}` — update status to `Open`, `Investigating`, or `Resolved`, optionally with a history note.
- `GET /dashboard/summary?source_origin=connected_application` — return database-derived metrics and recent events for a selected origin (`simulation`, `unknown`, and `all` are also supported). The unfiltered API request continues to return all origins.
- `GET /connected-applications` — list external applications and their last-event status.
- `GET /response/blocks` — list active, unexpired demo-app blocks.
- `GET /response/blocks/check?source_ip=...` — check whether the demo app must refuse a source.
- `GET /response/history` — review recent automatic block, expiry, and manual removal actions.
- `DELETE /response/blocks/{source_ip}` — manually remove an active block; requires `X-Sentinel-Admin-Key`.
- `POST /simulation/run` — create the selected safe synthetic event sequence (`brute_force`, `account_compromise`, `privilege_escalation`, `data_transfer`, or `full_attack_chain`); omit `scenario` for the full chain. Disabled by configuration when `SENTINEL_SIMULATION_ENABLED=false`.

## Tests

Run the full test suite from the repository root:

```powershell
python -m pytest -q
```

The tests use temporary SQLite databases and cover event validation and persistence, authenticated external-app ingestion, detection rules and thresholds, correlation boundaries, incident creation and status history, safe demo-app blocks and expiration, administrator removal, error responses, dashboard data, and simulation behavior.

## Project layout

```text
backend/
  database.py          SQLite setup and schema
  detection.py         Detection rules, risk criteria, and attack-chain correlation
  main.py              FastAPI routes and incident orchestration
  response.py          Configurable demo-app block policy and response auditing
  demo_login.py        Separate monitored demo login application
  simulate_attack.py   Client for the local synthetic simulation endpoint
frontend/
  index.html           Dashboard markup
  styles.css           Responsive dark theme
  app.js               Live API integration and incident interactions
  demo_login.html      Separate demo login page
  demo.css             Demo login styling
  demo.js              Demo login form integration
tests/
  test_api.py
  test_detection.py
```

## Limitations

- This competition/demo application is not production-hardened and has no general user authentication, multi-tenant isolation, or production identity management. Event ingestion can be protected with a configured shared API key, and block administration requires a separately configured key; keep both apps bound to localhost and do not expose them to untrusted networks.
- Rules are deterministic and deliberately conservative. Outbound-transfer events are treated as suspicious signals for analyst review; the event source should provide trustworthy context and measured volume.
- SQLite is suitable for the local demo, not a high-volume distributed event pipeline. The database is local state and is excluded from version control.
- Status changes are recorded in an incident history, but there is no analyst identity or external ticketing integration.

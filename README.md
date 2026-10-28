# AI vs AI — Autonomous Cyber Defense Challenge

A local SOC and website-defense management prototype for synthetic security exercises and authorized Linux server telemetry. An agent overview brings together background patrols, event-volume analytics, source coverage, campaign investigation, and individually approved sandbox responses. Registered Linux collectors can now report actual local resource metrics and explicitly authorized log feeds over verified HTTPS. They do not crawl websites, execute remote commands, or report website availability.

## Quick start

Requires Python 3.12+ and Node.js 20.19+ (or 22.12+). From this repository:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend install
npm --prefix frontend run build
backend/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Open **http://127.0.0.1:8000**. The first launch loads a synthetic attack replay so there is immediately something to investigate. SQLite persists local state between launches. API documentation is at `/docs`.

For editing with hot reload, run `./scripts/dev.sh` and open **http://127.0.0.1:5173**. Vite forwards `/api` calls to the backend on port 8000. Stop with Ctrl+C. If your Python installation uses mise, activate a supported Python version or use its absolute executable path when creating the virtual environment.

## Connect data sources

**Add Server** now opens **Connect Data Source**. Choose a **Website / Web Application** using an authenticated HTTPS security-events API, a **Linux Server** with one-use agent enrollment, or a separate **Simulated Demo Source**. Cloud and identity-provider connectors are clearly unavailable until their authorization flows are implemented. Multiple sources retain separate credentials, events, and incidents.

Website connections are validated by the backend before saving, with actual granted categories and encrypted API-key storage. A URL alone does not establish connectivity. The outbound-only Linux collector sends real `/proc` metrics and explicitly authorized logs; a simulated collector sends only synthetic fixtures. Every containment action remains simulated and requires individual human approval.

See [Connect Data Source setup and API contract](docs/data-sources.md) for the working local HTTPS website fixture, exact test steps, credential handling, source management, and current limits.

Stop the HTTP development backend first, then run `./scripts/dev_https.sh` and open **https://localhost:8443**. This standalone HTTPS mode replaces the HTTP backend; never run both app processes against one database. Local CA/key files stay under ignored `.local-tls/` and are not installed globally. See [server enrollment and Linux agent setup](docs/server-enrollment.md) for CA trust, hidden-token enrollment, real collection, revocation, retries, and an optional least-privilege systemd user service.

## Demo walkthrough

1. Open the agent overview and run a patrol. It analyzes the currently loaded synthetic events, investigates correlated incidents, and creates pending recommendations without executing them.
2. Review patrol history, source coverage, event-volume charts, authentication failures, outbound bytes, and host status. Charts are derived from actual loaded fixtures.
3. Optionally enable recurring patrols and choose an interval. The default schedule is paused.
4. Choose **Review incidents** and inspect a campaign's severity, probability, shared entities, and timestamped evidence. Investigate it again when needed.
5. Review each response individually. Approve only after entering analyst details and explicitly confirming, or reject it.
6. Inspect response verification and audit history. Reset and replay events to explore progression, or re-run evaluation for measured local holdout results.

## How it works

- **Detection:** a Bernoulli naive Bayes classifier is trained locally on `data/train.json`. Its observable features cover credential lures, sender mismatch, abnormal authentication, MFA fatigue, beaconing, unusual outbound volume, prompt overrides, and obfuscation. Test labels, entity names, and event IDs do not enter prediction features.
- **Correlation:** shared identities, hosts, or addresses within a bounded time window connect telemetry into campaigns. Linked benign context remains available as evidence. Severity reflects suspicious activity and attack progression.
- **Investigation:** deterministic evidence explanations summarize the local model's findings and associated event IDs. This is explainable statistical AI, **not a hosted LLM**. No API key is required.
- **Patrols:** a backend scheduler reclassifies existing simulated telemetry, updates event predictions, correlates campaigns, and investigates incidents. It may create pending recommendations, but never approves or executes containment. Manual runs, scheduled runs, durations, failures, and coverage are recorded in SQLite.
- **Analytics:** source, category, and host totals reconcile to loaded telemetry. Time windows (15 minutes, 1 hour, 24 hours) anchor to the latest event timestamp, not the current clock. Authentication failures include denied MFA prompts and failed/denied logins.
- **Response:** only approved actions change isolated SQLite host/session state. Approval, execution, verification, and audit recording are coordinated by the backend. There is no shell execution, scanning, real identity-provider access, or network containment.
- **Telemetry explorer:** filter by source, campaign severity, and text; pause the displayed event snapshot; download the filtered records as JSON or CSV. CSV cells escape delimiters and leading spreadsheet formula characters. Pausing the display does not stop backend patrols.
- **Interface:** React, TypeScript, Tailwind CSS, Vite, and Lucide icons; FastAPI serves the API and built frontend. Polling keeps the event feed current.

## Background patrol scheduling

The schedule is **paused by default**. Enabling it persists the interval and next due time in SQLite. The FastAPI lifespan starts one scheduler thread, so due patrols continue while the backend is running even when the browser is closed. Use **one Uvicorn worker**; this prototype has no distributed scheduler or cross-process job ownership.

Intervals range from 30 seconds to 24 hours. Manual and scheduled runs cannot overlap. A completed or failed run schedules the next interval from its completion; missed intervals are not replayed as a backlog. A persisted overdue schedule can run once after backend restart. Pausing prevents future scheduled scans; an already running scan may finish. Closing the backend stops scheduling. Reset clears telemetry and sandbox response state but retains audit history, patrol history, and schedule settings; pause first if you want an entirely quiet demo.

A patrol analyzes stored telemetry from synthetic fixtures and registered collectors; it is not a website crawler, attack, health check, or real containment agent. "Coverage" counts represented synthetic sources, and process uptime describes this backend process only.

## Safety and limitations

This is a **single-user localhost demo**, not a production SOC service. Keep it bound to `127.0.0.1`; it does not provide production authentication, roles, tamper-proof audit storage, or hardened multi-tenant isolation. A per-process token gates administrator API reads and writes, and collector ingestion uses separately scoped server credentials. The local session bootstrap is not a substitute for production authentication; keep administrative access local.

Synthetic addresses use documentation ranges and synthetic domains. Email content is untrusted data; prompt-injection strings never become executable instructions. Each response needs its own explicit human approval. The API is intended for a human-operated UI, not an autonomous approver.

The local classifier recognizes selected behavioral indicators. It cannot establish that a phishing message was AI-generated, identify arbitrary polymorphic malware, or guarantee detection of unseen attacks. Scores are uncalibrated model probabilities, not empirical certainty. Correlation can over-link shared infrastructure or miss activity outside its time window.

The supplied challenge image references an official sandbox API, baseline detector, development telemetry, hidden evaluation set, and published campaign scoring rules. Those resources were **not supplied**. This prototype therefore uses a local sandbox and locally generated fixtures; it does not claim official integration, hidden-test scores, or competition-grade campaign metrics. The sandbox implementation is the replacement point once the official API contract is available.

## Evaluation and tests

```bash
./scripts/check.sh
```

Tests cover label-independent detection, prompt-injection handling, evasion normalization, metric calculations, traceable cross-source incidents, replay, persistence, approval rejection, explicit confirmation, and concurrent decisions. The dashboard's precision, recall, F1, and false-positive rate are calculated from actual predictions on `data/evaluation.json` (66 events), not hardcoded percentages.

The training and holdout fixtures share a deliberately simple synthetic generator. Hard negatives (legitimate periodic traffic) and blind spots (stolen-session activity without known indicators) expose errors. This benchmark tests prototype behavior; it does not measure generalization to real attacks. Per-event latency measures classifier wall-clock execution on the current machine, excluding transport and human review. The separate 66-event batch latency includes classification, in-memory SQLite commit/read, and correlation. It excludes HTTP transport, disk I/O, and browser rendering; it is not production throughput.

Regenerate reproducible safe fixtures with:

```bash
backend/.venv/bin/python scripts/generate_data.py
```

Restart the backend after changing training data. Existing persisted replay state may need resetting before replaying changed fixtures.

For browser checks (these reset local demo state), use an installed Chromium or install Playwright's browser:

```bash
cd frontend
npx playwright install chromium  # only needed if Chromium is not installed
npm run test:e2e
```

Override browser location with `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chromium` when needed. The suite includes approval, scheduler, analytics, and browser workflow regression tests. Desktop/mobile captures are written to ignored `artifacts/`.

For the complete source and dashboard browser suite with an isolated test database and real local HTTPS fixture, run `cd frontend && npx playwright test -c playwright.integration.config.ts` after building and running `./scripts/setup_tls.sh`. It includes website connection management and actual Linux collector enrollment. Ports 8445 and 9445 must be free.

For modal interaction checks, first build the frontend and run `./scripts/dev_https.sh`, then run `npm --prefix frontend run test:modals`. This separate suite uses `https://localhost:8443` and checks viewport centering, focus restoration and trapping, backdrop dismissal, scroll locking, mobile resizing, reduced motion, and enrollment dialog handoffs. Enrollment mutations are mocked; it does not reset demo state.

Refresh the saved measured report with `backend/.venv/bin/python scripts/evaluate.py`; results are in `docs/evaluation-results.json`. See `docs/architecture.md` for extension points and the official sandbox integration boundary.

## Edit points

| Path | Purpose |
| --- | --- |
| `agent/soc_agent.py` | Outbound-only verified-HTTPS Linux metrics/log collector |
| `scripts/dev_https.sh` | Standalone local TLS backend (replaces HTTP development server) |
| `frontend/src/` | Dashboard, approval UX, styles, API client |
| `backend/app/main.py` | API routes, request validation, orchestration |
| `backend/app/sources.py`, `backend/app/connectors.py` | Source registry, encrypted credentials, validated website connector |
| `scripts/demo_website.py` | Authenticated local HTTPS fixture, explicitly simulated |
| `backend/app/store.py` | SQLite state, correlation, sandbox responses |
| `backend/app/patrol.py` | Single-process background patrol scheduling |
| `backend/app/detection.py` | Model features, training, explanations, metrics |
| `scripts/generate_data.py` | Synthetic scenario and benchmark generation |
| `data/*.json` | Committed training, evaluation, and replay fixtures |
| `backend/tests/` | Safety and integration regression tests |

The optional collector may read authorized local metrics/logs, but response execution must remain isolated simulation. Integrating the official challenge sandbox should retain the backend approval gate, immutable action targets, idempotency, verification, and audit traceability.

### Browser regression tests

With Chromium installed at `/usr/bin/chromium`:

```bash
npm --prefix frontend run test:e2e
```

Set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to another Chromium executable when needed. Tests start the backend and Vite when those local ports are free, or reuse running instances. Browser tests reset the local demo simulation; do not point them at valuable state.

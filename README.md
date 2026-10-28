# AI vs AI — Autonomous Cyber Defense Challenge

A local, working SOC prototype for investigating **synthetic** email, authentication, and network telemetry. It combines an explainable trained classifier with cross-source campaign correlation, evidence-backed investigation, and individually approved sandbox responses.

## Quick start

Requires Python 3.12+ and Node.js 20.19+ (or 22.12+). From this repository:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend install
npm --prefix frontend run build
backend/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. The first launch loads a synthetic attack replay so there is immediately something to investigate. SQLite persists local state between launches. API documentation is at `/docs`.

For editing with hot reload, run `./scripts/dev.sh` and open **http://127.0.0.1:5173**. Vite forwards `/api` calls to the backend on port 8000. Stop with Ctrl+C. If your Python installation uses mise, activate a supported Python version or use its absolute executable path when creating the virtual environment.

## Demo walkthrough

1. Select a campaign in the incident queue. Review its severity, model probability, shared entities, and timestamped evidence.
2. Investigate the incident. The local investigator explains the detected features and proposes defensive actions.
3. Review each proposal individually. Approve only after entering analyst details and explicitly confirming, or reject it.
4. Inspect response verification, simulated host/session state, and the audit trail. Rejected and pending actions never execute.
5. Reset the simulation, then step through or replay all events to watch incidents form.
6. Re-run evaluation to see metrics calculated from the labeled local holdout fixtures.

## How it works

- **Detection:** a Bernoulli naive Bayes classifier is trained locally on `data/train.json`. Its observable features cover credential lures, sender mismatch, abnormal authentication, MFA fatigue, beaconing, unusual outbound volume, prompt overrides, and obfuscation. Test labels, entity names, and event IDs do not enter prediction features.
- **Correlation:** shared identities, hosts, or addresses within a bounded time window connect telemetry into campaigns. Linked benign context remains available as evidence. Severity reflects suspicious activity and attack progression.
- **Investigation:** deterministic evidence explanations summarize the local model's findings and associated event IDs. This is explainable statistical AI, **not a hosted LLM**. No API key is required.
- **Response:** only approved actions change isolated SQLite host/session state. Approval, execution, verification, and audit recording are coordinated by the backend. There is no shell execution, scanning, real identity-provider access, or network containment.
- **Interface:** React, TypeScript, Tailwind CSS, Vite, and Lucide icons; FastAPI serves the API and built frontend. Polling keeps the event feed current.

## Safety and limitations

This is a **single-user localhost demo**, not a production SOC service. Keep it bound to `127.0.0.1`; it does not provide production authentication, roles, tamper-proof audit storage, or hardened multi-tenant isolation. A per-process token gates mutating API requests; that token is not a substitute for production authentication.

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

## Edit points

| Path | Purpose |
| --- | --- |
| `frontend/src/` | Dashboard, approval UX, styles, API client |
| `backend/app/main.py` | API routes, request validation, orchestration |
| `backend/app/store.py` | SQLite state, correlation, sandbox responses |
| `backend/app/detection.py` | Model features, training, explanations, metrics |
| `scripts/generate_data.py` | Synthetic scenario and benchmark generation |
| `data/*.json` | Committed training, evaluation, and replay fixtures |
| `backend/tests/` | Safety and integration regression tests |

Do not connect the local simulation to real systems. Integrating the official challenge sandbox should retain the backend approval gate, immutable action targets, idempotency, verification, and audit traceability.

### Browser regression tests

With Chromium installed at `/usr/bin/chromium`:

```bash
npm --prefix frontend run test:e2e
```

Set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to another Chromium executable when needed. Tests start the backend and Vite when those local ports are free, or reuse running instances. Browser tests reset the local demo simulation; do not point them at valuable state.

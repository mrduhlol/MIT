# Server enrollment and outbound Linux agent

The dashboard supports individually registered collectors. Each server has a fixed **simulated** or **real** mode, a one-use enrollment token, and its own revocable ingest credential. No SSH username, SSH password, private SSH key, or remote command channel is required. A website URL is descriptive metadata, not a target to crawl or attack.

The agent requires Linux and Python 3.10+ standard library only. It has no incoming listener, does not execute shell commands, and cannot receive containment instructions. It runs as an ordinary user and reads only `/proc` plus optional files explicitly authorized on its command line. All incident responses remain SQLite simulations even for telemetry from real servers.

## 1. Start one verified HTTPS backend

Install the application dependencies and build the frontend as described in the README. **Stop the HTTP backend on port 8000 first**, including `scripts/dev.sh`. Do not run HTTP and HTTPS app processes against the same SQLite database: each process would own a scheduler thread.

```bash
./scripts/dev_https.sh
```

This generates a development CA and a 30-day server certificate under `.local-tls/`, then runs the same application at **https://localhost:8443**. It binds to loopback and disables proxy-header trust. It does not install certificates in your operating system or browser. Existing complete TLS material is verified and reused; incomplete, expired, insecure, mismatched, or symlinked files are not silently replaced.

The directory is mode `0700`; files are mode `0600` and ignored by Git. Keep `ca.key` and `server.key` on the backend machine. Distribute **only `ca.crt`** to collectors through a trusted channel. The certificate SANs cover `localhost`, `127.0.0.1`, and `::1`; they do not cover another machine's hostname or public IP.

For browser access, trust this specific development CA in a dedicated development browser profile if desired, or use a certificate already trusted by the browser. The collector always verifies CA trust and hostname. It has no insecure/skip-verification option.

## 2. Register a server in the local dashboard

Select **Add Server**, enter a name and hostname, optionally add a website URL, and choose:

- **Simulated:** fixed synthetic metrics and safe example email/auth/network events. No `/proc` or log-file collection occurs.
- **Real:** actual local `/proc` CPU/memory/load/uptime readings, plus optional authorized telemetry files. No logs are collected unless paths are supplied explicitly.

Use **Create server**. Copy the displayed one-use enrollment token; it expires after 10 minutes. The hostname and mode in the agent command must match the registered values. Tokens are shown once; rotation invalidates the previous enrollment token and any existing ingest credential.

## 3. Enroll without exposing the token in shell history

On a remote authorized Linux host, copy only `agent/soc_agent.py` from this checkout and, if using a private CA, its public `ca.crt` through your trusted deployment mechanism. No React, Node.js, FastAPI, SSH credentials, or backend database is needed on the collector host. Run the script with Python 3.10+ as an ordinary user. Adjust the script and CA paths below to where you installed those two files.

For a same-machine simulated demo:

```bash
python3 agent/soc_agent.py enroll \
  --url https://localhost:8443 \
  --ca-cert .local-tls/ca.crt \
  --state-dir ~/.local/state/ai-defense-demo \
  --hostname demo-host \
  --mode simulated
```

Paste the token at the hidden `One-use enrollment token:` prompt. There is deliberately **no `--token` argument**. An automation may instead supply `--token-file /private/enrollment-token.txt`; that regular file must be owned by the current user and mode `0600`. Delete that file after successful enrollment. Never put tokens into process arguments, service-unit environment variables, screenshots, commits, or support logs.

The state directory must be mode `0700`, owned by the collector user, and contain no symlink path components. `credentials.json` is written atomically with mode `0600`. Existing enrollment is not overwritten. The stored CA path must remain readable to the service. Agent requests reject all redirects and ignore environment HTTP proxy settings so credentials cannot be forwarded by an unexpected redirect or proxy configuration.

## 4. Send a heartbeat and telemetry

```bash
python3 agent/soc_agent.py run \
  --state-dir ~/.local/state/ai-defense-demo \
  --once
```

Omit `--once` for continuous collection (default every 30 seconds). `--interval 60` changes the collection cadence. Collection cadence is separate from the dashboard's scheduled analysis patrol cadence.

For real mode, enroll a separate registered real collector and state directory, then optionally add authorized readable files:

```bash
python3 agent/soc_agent.py run \
  --state-dir ~/.local/state/ai-defense-real \
  --interval 30 \
  --events-file /path/to/authorized-events.jsonl \
  --auth-log /path/to/authorized-auth.log
```

Do not grant root just to make a log readable. Provide a dedicated, sanitized log feed or narrowly scoped read permission. The agent opens regular files read-only, rejects symlinks/devices/FIFOs, and reads at most 64 KiB and 100 complete lines from one configured source per cycle. If both sources are configured, it alternates between them. It tracks file identity and byte offset, handles rotation/truncation, waits for partial final lines, and drops overlong/malformed records. Standard copy-truncation races can still lose records; this is not a production log shipper.

JSONL rows use only `timestamp`, `source` (`email`, `auth`, `network`), `identity`, `ip`, and allowlisted `details` fields. IDs are generated by the collector. Server identity and host are assigned by the ingest credential, never trusted from a log row. Known password/token/API-key assignments and bearer tokens in text are redacted; unknown detail keys are dropped. This limited sanitizer is **not a complete secret detector**: supply purpose-built telemetry rather than arbitrary application request bodies. Out-of-window timestamps are dropped.

The auth-log parser recognizes failed-password and accepted-password/public-key records, retains identity/IP/result and aggregate failed-attempt counts, and never forwards raw log lines. ISO timestamp prefixes are preserved. Traditional syslog timestamps infer the current or previous year using the collector machine's local time zone; configure that zone correctly. Records older than 24 hours or more than five minutes in the future are skipped. Counts are grouped by identity, address, outcome, and five-minute window. Timestamped records carry `details.timestamp_basis="log"`; only lines without a recognized timestamp use the observation time and explicitly carry `timestamp_basis="collection"`. Avoid archived/untimestamped logs when evaluating event chronology. CPU readings use a short `/proc/stat` sampling interval; memory uses `MemAvailable`, with `MemFree` fallback. The agent does not collect processes, environment variables, credentials, filesystem contents, or network packets.

## Delivery, revocation, and recovery

Before upload, the agent durably writes a private `pending.json` containing its UUID batch ID, exact payload, and proposed source cursors. On a transient failure, the same batch is retried. Cursors advance only after a matching server acknowledgment; backend deduplication handles acknowledgment-loss retries. Fresh samples get new event IDs. A private advisory lock prevents two collectors using the same state directory.

Authentication rejection, revocation, or permanent payload rejection stops the agent and retains pending data. Tokens and response bodies are not logged. A pending batch older than the server's 24-hour acceptance window needs operator review; the agent does not silently discard it. An interrupted process can resume from its private state. Malformed/private-file permission errors also fail safely.

Use **Revoke agent** to stop future enrollment/ingest for a server. To replace credentials, choose **Rotate enrollment**, then enroll with its new token into a new private state directory. Stop the old collector first. Inspect and archive the old directory securely; do not copy an old pending batch into a different server identity. Deleting state forfeits the corresponding delivery/cursor recovery information.

## Optional systemd user service

`agent/ai-defense-agent.service` is an example, not an automatically installed service. Edit its absolute script path, state directory, and optional authorized log paths after enrollment. A non-root user service can be installed with:

```bash
mkdir -p ~/.config/systemd/user
cp agent/ai-defense-agent.service ~/.config/systemd/user/ai-defense-agent.service
# Edit the copied ExecStart and ReadWritePaths before enabling it.
systemctl --user daemon-reload
systemctl --user enable --now ai-defense-agent.service
```

The example sets `NoNewPrivileges`, a read-only filesystem/home view, private temporary files, and write access only to its enrolled state directory. User-namespace restrictions on some Linux distributions may prevent these hardening directives from starting; inspect the unit logs and adapt under your administrator's policy rather than running the collector as root. A user service normally follows the user's login lifecycle. Enabling lingering is an explicit administrator policy choice, not performed by this project.

## Beyond a same-machine demo

The shipped HTTPS helper is intentionally loopback-only. For an authorized remote collector, use a deployment certificate matching the reachable backend DNS name and a trusted CA; set the explicit allowed hostname configuration and firewall policy. Keep the single-operator admin/session bootstrap reachable only locally or through separately authenticated administrative access. Expose only the authenticated enrollment and ingest paths needed by agents. Do not broadly proxy arbitrary caller-supplied forwarded headers or expose the local bootstrap API as a public login substitute.

The application is still a single-operator prototype, **not a multi-tenant SaaS platform**. It has no production account/login system, RBAC, distributed scheduler, fleet update mechanism, or remote command execution. Use one application process/worker per SQLite database. All containment remains approval-gated simulation.

## Agent verification

```bash
backend/.venv/bin/python -m pytest backend/tests/test_linux_agent.py -q
```

Tests include real loopback TLS enrollment/upload, untrusted CA and wrong-host rejection, redirect refusal, owner-only credential handling, retry/acknowledgment semantics, source bounds/rotation, redaction, and isolated simulated collection. No external system is contacted.

## Complete UI-to-agent test

With the HTTPS backend running and development dependencies installed:

```bash
cd frontend
npx playwright test -c playwright.https.config.ts
```

This test registers a simulated host through the UI, enrolls the actual Python collector using a private token file, verifies CA-checked upload, reviews telemetry and approval enforcement, then revokes the credential. The browser test alone accepts the development browser certificate; the collector still performs full CA and hostname verification. Test collectors are explicitly labeled simulated and revoked afterward.

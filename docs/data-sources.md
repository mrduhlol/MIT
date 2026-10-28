# Connect data sources

Use **Add Server → Connect Data Source** to choose a connector. Website API integration and Linux agent enrollment are implemented. Cloud Infrastructure and Identity Provider cards describe unavailable integrations; they cannot connect accounts, request OAuth scopes, or ingest provider events. The application remains one local administrator workspace, not a multi-tenant service.

## Website / Web Application

The website must expose the read-only API contract below. Entering an ordinary website URL does not connect it. The SOC backend makes a verified HTTPS request to the configured security-events endpoint using `Authorization: Bearer <API key>`, checks the response schema and granted categories, and only saves a source if validation succeeds. **Test Connection** checks connectivity without saving; saving checks again. Keys are password inputs, never included in installation commands, URL parameters, source listings, or audit records.

Provide the website name, HTTPS base URL, HTTPS security-events API endpoint, API key, and desired categories. **Test Connection** shows the actual categories available and granted by that credential. Select only granted categories, then **Save integration**. The source detail provides **Test Connection**, event collection, permission editing, disconnection, and credential revocation. Testing a connection does not imply that every event category is available.

A website source is marked offline when its last successful connection check is older than five minutes. With manual polling, this means the check is stale; it does not prove the website is currently unreachable. An error state records an actual failed authentication, transport, permissions, or response check.

This version uses explicit polling. A SOC patrol analyzes events already stored; it does not automatically fetch website events. Fetch events through the source's collection action. The UI refreshes stored state independently. Event IDs must remain stable across retries to avoid duplicates. Each fetch is limited to 100 events; the connector does not implement pagination or guarantee delivery of events that disappear between fetches.

### Website API contract

The endpoint receives a read-only `GET` with a bearer key. Validate that key in your application and derive permissions from it. Return HTTP 401/403 for invalid/revoked/insufficient credentials, not a login page or redirect. The response is JSON:

```json
{
  "schema_version": 1,
  "telemetry_mode": "real",
  "permissions": {
    "available": ["authentication", "suspicious_sessions", "account_changes", "application_security"],
    "granted": ["authentication"]
  },
  "events": [
    {
      "id": "login-attempt-342",
      "timestamp": "2026-10-28T12:00:00+00:00",
      "category": "authentication",
      "identity": "account-42",
      "ip": "192.0.2.42",
      "details": {"result": "failed", "failed_attempts": 8}
    }
  ]
}
```

Replace the example timestamp with the actual event time. The backend accepts timezone-qualified events up to 24 hours old and five minutes in the future. `telemetry_mode` must truthfully be `real` or `simulated`; it is preserved in SOC evidence. The example IP is a documentation address. Do not forward passwords, access tokens, session cookies, raw request bodies, or arbitrary logs. Use the strict allowlisted detail fields exposed by the backend OpenAPI schema.

Events with categories outside the credential's grant are rejected. Events outside the operator's selected categories are not ingested. Source IDs, host identity, and namespaced internal event IDs are assigned by the backend, not trusted from the upstream API. Different sources cannot overwrite one another's event IDs or correlate into one campaign merely because their user names or addresses match. Normalized events enter the existing classifier, correlation, investigation, and explicit human-approval workflow. Every containment response remains a local database simulation.

Evidence preserves the upstream event `timestamp` separately from the backend-assigned `received_at`. Source details show the last receipt time. Historical events ingested before receipt tracking was added show that their receipt time is unavailable rather than inventing one.

### Try the safe local website fixture

1. Install dependencies, build the frontend, and generate development TLS material:

   ```bash
   backend/.venv/bin/python -m pip install -r backend/requirements.txt
   npm --prefix frontend run build
   ./scripts/setup_tls.sh
   ```

2. Start the fixture in one terminal:

   ```bash
   backend/.venv/bin/python scripts/demo_website.py
   ```

   It serves **https://localhost:9443/security-events** and creates an owner-only API-key file at `.agent-state/demo-website.key`. This is a working authenticated HTTPS endpoint returning explicitly **simulated** events, not a real monitored website.

3. Start the SOC in another terminal with an explicit allowlist for that local fixture:

   ```bash
   export SOC_CONNECTOR_ALLOWED_ORIGINS=https://localhost:9443
   export SOC_CONNECTOR_CA_FILE="$PWD/.local-tls/ca.crt"
   ./scripts/dev_https.sh
   ```

   Stop any previous SOC backend first. Run only one application process against a SQLite database. This does not require stopping unrelated applications on port 8000.

4. Open **https://localhost:8443**, select **Add Server → Website / Web Application**, and enter:

   | Field | Value |
   | --- | --- |
   | Website name | Local website fixture |
   | Base URL | `https://localhost:9443` |
   | Security-events API endpoint | `https://localhost:9443/security-events` |
   | API key | Contents of `.agent-state/demo-website.key` |
   | Categories | Select the categories to collect |

   Open the private key file locally and paste its contents into the password field. Do not put the key in a command, URL, screenshot, commit, or support message.

5. Test, save, and fetch events. Confirm the source and its events are marked simulated. Repeat the fetch: fixed event IDs are deduplicated. Try an incorrect key in a new connection and confirm it cannot save. Disconnect the saved source and confirm collection stops. Revoke credentials to remove the SOC's stored key; also revoke that key in the upstream application when retiring a real integration.

The local fixture is allowlisted solely for the demo. The default connector rejects private, loopback, link-local, multicast, and other non-public destination addresses. It resolves and pins approved public addresses, verifies TLS hostname/CA, disables redirects and environment proxies, and bounds response size and time. Do not broadly allowlist networks or untrusted origins. A custom CA extends trust only for installations you administer; it does not disable verification.

### Credential storage and recovery

Website keys are encrypted on the backend with Fernet authenticated encryption. `SOC_CREDENTIAL_KEY` can provide an operator-managed encryption key; otherwise the application creates a private key under `.agent-state/connector.key` in the database directory. Keep that file owner-only and back it up separately from exported databases. Losing the encryption key makes existing website credentials unusable; reconnect with newly issued upstream credentials. Never commit either the credential key or database. Encryption at rest does not protect against an attacker who controls the running application account.

Disconnecting retains source history. Revocation removes the locally stored credential; it cannot revoke a key at an arbitrary upstream website, so perform upstream revocation in that website's admin console too. Editing event categories changes what this SOC collects and does not grant new upstream permissions.

## Linux Server

Choose **Linux Server**, enter the display name and exact hostname, and generate an enrollment token. The token is single-use and expires after ten minutes. Follow the generated Python collector command; it prompts for the token rather than embedding it in shell history. The collector has no SSH credentials, incoming listener, command executor, or remote containment channel.

Enrollment establishes a credential, not proof of monitoring. The source stays pending until an authenticated heartbeat with telemetry arrives. Run the collector once to verify, or continuously at the desired interval. The dashboard displays last heartbeat, received telemetry, resource metrics, and incidents. A heartbeat older than 120 seconds is offline. Rotation invalidates old credentials, and revocation prevents further enrollment/ingestion while preserving evidence.

The real collector reads Linux `/proc` metrics and only log paths explicitly authorized when it is launched. Dashboard category labels describe protocol capabilities, not proof that the agent has filesystem permission to read every log. See [server enrollment and agent installation](server-enrollment.md) for exact commands, private state handling, optional log feeds, and a least-privilege user service.

## Simulated Demo Source

Choose **Simulated Demo Source**, enter a display name and hostname, and enroll the collector using the generated command with `--mode simulated`. It sends fixed synthetic metrics and safe example events; it never reads `/proc` or real log files. Each demo source has its own identity and credentials. Do not enroll a real collector under a simulated source or change the provenance of collected events. Existing fixture replay/evaluation remain synthetic and separate from connected-source evidence.

## Cloud Infrastructure and Identity Provider

No cloud or identity-provider connector is implemented in this version. The selector explains this limitation instead of presenting fake OAuth or permissions. A future connector needs provider registration, a supported OAuth/service-identity flow, explicit least-privilege scopes, revocation, normalized event mapping, and connector-specific tests before it can be enabled. The generic website API connector is not an AWS, Azure, Google Cloud, Okta, or Entra integration.

## Verification

```bash
backend/.venv/bin/python -m pytest backend/tests -q
npm --prefix frontend run build
```

`backend/tests/test_sources.py` uses a real loopback HTTPS server with an ephemeral certificate to test bearer authentication, invalid/revoked keys, TLS verification, grants, deduplication, source isolation, encrypted storage, SSRF rejection, simulated provenance, and approval enforcement. No external website is contacted. Existing Linux tests cover single-use enrollment, expiry, heartbeat/offline status, revocation, and actual CA-verified agent upload.

The complete browser regression suite starts its own HTTPS SOC backend on port 8445 with a fresh temporary database and a synthetic website fixture on port 9445. It leaves the user's dashboard database untouched:

```bash
./scripts/setup_tls.sh
npm --prefix frontend run build
cd frontend
npx playwright test -c playwright.integration.config.ts
```

This checks source selection, unavailable-provider messaging, website validation and actual HTTPS collection, permission editing/disconnection/revocation, enrollment with the real Python collector, modal behavior, and existing SOC approval/scheduling/export workflows. Screenshots contain only blank setup forms or non-secret dashboard content. The browser alone accepts the development certificate; both backend connector and Linux collector verify TLS trust.

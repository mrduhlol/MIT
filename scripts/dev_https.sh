#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Running HTTP and HTTPS app processes on the same database duplicates schedulers.
backend/.venv/bin/python - <<'PY_CHECK'
import json
import sys
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import URLError
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
try:
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open('http://127.0.0.1:8000/api/health', timeout=1) as response:
        health = json.loads(response.read(4096))
    if health.get('mode') in ('isolated-local-simulation', 'local-control-plane', 'telemetry-monitoring-with-simulated-containment'):
        sys.exit('Stop this project HTTP development backend on port 8000 before starting standalone HTTPS.')
except (URLError, OSError, ValueError, AttributeError):
    pass  # Another service on port 8000 does not share this application database.

PY_CHECK
./scripts/setup_tls.sh
if [[ ! -d frontend/dist ]]; then npm --prefix frontend run build; fi
exec backend/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8443 --no-proxy-headers --ssl-keyfile .local-tls/server.key --ssl-certfile .local-tls/server.crt

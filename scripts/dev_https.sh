#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Running HTTP and HTTPS app processes on the same database duplicates schedulers.
backend/.venv/bin/python - <<'PY_CHECK'
import socket
import sys
with socket.socket() as sock:
    sock.settimeout(0.3)
    if sock.connect_ex(('127.0.0.1', 8000)) == 0:
        sys.exit('Stop the HTTP development backend on port 8000 before starting standalone HTTPS.')
PY_CHECK
./scripts/setup_tls.sh
if [[ ! -d frontend/dist ]]; then npm --prefix frontend run build; fi
exec backend/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8443 --no-proxy-headers --ssl-keyfile .local-tls/server.key --ssl-certfile .local-tls/server.crt

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
backend/.venv/bin/python -m pytest backend/tests -q
npm --prefix frontend run build

#!/usr/bin/env bash
set -euo pipefail

uv run uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000 &
backend_pid=$!

cleanup() {
  kill "$backend_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

npm --prefix frontend run dev -- --host 127.0.0.1


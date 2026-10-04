#!/bin/sh
# Demo: API + frontend together.
# Starts the real API (:8000) and the Vite dev server (:5173), prints
# URLs, cleans up on exit/interrupt. Stops ONLY the processes it
# started (recorded PIDs, no broad pkill). Logs go to a mktemp directory
# printed at startup (never a hardcoded path).
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

test -x .venv/bin/python || { echo "need the project venv: python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e ."; exit 2; }
test -f engine/models/vectorizer.joblib || { echo "train first: ipsec-analyze train"; exit 2; }
test -d frontend/node_modules || { echo "install first: cd frontend && npm ci"; exit 2; }
command -v npm >/dev/null 2>&1 || { echo "need npm (Node $(cat frontend/.nvmrc 2>/dev/null || echo '>=20'))"; exit 2; }

port_busy() {
  # Try IPv4 and IPv6 loopback: dev servers may bind either.
  .venv/bin/python -c "
import socket, sys
for fam, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
    try:
        s = socket.socket(fam); s.settimeout(1)
        if s.connect_ex((host, $1)) == 0:
            sys.exit(0)
    except Exception:
        pass
sys.exit(1)" 2>/dev/null
}
if port_busy 8000; then echo "port 8000 is busy (API already running?) — free it or set PORT_API"; exit 2; fi
if port_busy 5173; then echo "port 5173 is busy (Vite already running?) — free it first"; exit 2; fi

LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/ipsec-demo.XXXXXX")"
API_PID=""; UI_PID=""; DONE=""
alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
cleanup() {
  [ -n "$DONE" ] && return 0
  DONE=1
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  [ -n "$UI_PID" ] && kill "$UI_PID" 2>/dev/null || true
  # Shutdown is graceful (TERM); escalate only our own PIDs, never a scan.
  for _ in $(seq 1 25); do
    alive "$API_PID" || alive "$UI_PID" || break
    sleep 0.2
  done
  if alive "$API_PID"; then kill -9 "$API_PID" 2>/dev/null || true; fi
  if alive "$UI_PID"; then kill -9 "$UI_PID" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  echo "stopped (logs kept at $LOGDIR)"
}
trap 'cleanup' EXIT INT TERM

.venv/bin/python -m uvicorn engine.api.app:app --port 8000 > "$LOGDIR/api.log" 2>&1 &
API_PID=$!
# vite directly (not via npm) so $! is the server itself and kill stops it.
(cd frontend && VITE_API_URL=http://127.0.0.1:8000 VITE_USE_MOCK=false ./node_modules/.bin/vite --port 5173 > "$LOGDIR/vite.log" 2>&1 &
echo $! > "$LOGDIR/vite.pid")
# Wait for the pid file (background subshell writes it asynchronously).
for _ in $(seq 1 50); do
  [ -s "$LOGDIR/vite.pid" ] && break
  sleep 0.2
done
UI_PID="$(cat "$LOGDIR/vite.pid" 2>/dev/null || true)"
for _ in $(seq 1 30); do
  if port_busy 5173; then break; fi
  sleep 1
done
if ! port_busy 5173; then echo "vite did not come up; see $LOGDIR/vite.log"; exit 1; fi
echo "API:      http://127.0.0.1:8000/health  (log $LOGDIR/api.log)"
echo "UI (dev): http://localhost:5173  (set Live in Settings > Data source; log $LOGDIR/vite.log)"
echo "Mock UI:  VITE_USE_MOCK=true npm run dev (fixtures, no backend)"
echo "Ctrl-C to stop."
wait "$API_PID"

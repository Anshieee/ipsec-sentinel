#!/bin/sh
# Demo: API + frontend together (integration task step 5).
# Starts the real API (:8000) and the Vite dev server (:5173), prints
# URLs, cleans up on exit/interrupt.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

command -v uv >/dev/null 2>&1 || { echo "need uv on PATH"; exit 2; }
test -f engine/models/vectorizer.joblib || { echo "train first: ipsec-analyze train"; exit 2; }
test -d frontend/node_modules || { echo "install first: cd frontend && npm ci"; exit 2; }

.venv/bin/python -m uvicorn engine.api.app:app --port 8000 &
API=$!
(cd frontend && VITE_API_URL=http://127.0.0.1:8000 VITE_USE_MOCK=false npm run dev -- --port 5173 > /tmp/opencode/demo-vite.log 2>&1 &)
sleep 8
echo "API:      http://127.0.0.1:8000/health"
echo "UI (dev): http://localhost:5173  (set Live in Settings > Data source)"
echo "Mock UI:  VITE_USE_MOCK=true npm run dev (fixtures, no backend)"
echo "Ctrl-C to stop."
trap 'kill $API 2>/dev/null; pkill -f "vite.*5173" 2>/dev/null; echo stopped' EXIT INT TERM
wait $API

#!/bin/sh
# Record the terminal demo (M4 req 6): typescript + timing, replayable via
# scriptreplay. Run on a verified tree (models + data present).
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
test -x .venv/bin/python || { echo "need .venv with the project env"; exit 2; }
test -f engine/models/vectorizer.joblib || { echo "train first"; exit 2; }
export PATH="$REPO/.venv/bin:$PATH"
export PYTHONWARNINGS="ignore"
# script(1) uses $SHELL for -c; force bash (fish breaks on $!/wait).
SHELL=/bin/bash script --timing=demo/demo.timing demo/demo.typescript -c '
set -x
ipsec-analyze analyze demo/samples/v1-voip.pcap
ipsec-analyze analyze demo/samples/v12-voip.pcap --json | head -25
ipsec-analyze serve & SRV=$!; sleep 4
curl -s localhost:8000/health; echo
curl -s -F file=@demo/samples/real-v18-voip.pcap localhost:8000/analyze | head -c 600; echo
kill $SRV; wait 2>/dev/null || true
ipsec-analyze serve --mock & SRV=$!; sleep 4
curl -s localhost:8000/analyze -F file=@demo/samples/v1-voip.pcap | head -c 400; echo
kill $SRV; wait 2>/dev/null || true
'
echo "replay: scriptreplay --timing demo/demo.timing --typescript demo/demo.typescript"

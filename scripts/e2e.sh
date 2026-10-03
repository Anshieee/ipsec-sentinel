#!/bin/sh
# M4/M5 end-to-end: clean checkout + fresh venv, full pipeline.
# Full mode: generate -> validate-gate -> train -> API -> CLI -> reports
#   -> tests -> git-archive quickstart. Exit 0 only if every stage passes.
# --quick: uses committed demo/samples (+ a tiny synthetic smoke set),
#   skips regeneration and retraining. Worktree/venvs live in mktemp dirs
#   removed by trap on exit or interrupt (no stale state).
set -eu

QUICK=0
for a in "$@"; do [ "$a" = "--quick" ] && QUICK=1; done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/e2e-clean.XXXXXX)"
VENV="$WORK/.venv-e2e"
N=0
if [ "$QUICK" = 1 ]; then TOTAL=2; else TOTAL=10; fi
step() { N=$((N + 1)); echo "== STEP $N/$TOTAL: $1"; }
cleanup() { git -C "$REPO" worktree remove --force "$WORK" 2>/dev/null || true;
  rm -rf "${WORK}-ab" 2>/dev/null || true; }
trap 'cleanup' EXIT INT TERM

git -C "$REPO" diff --quiet && git -C "$REPO" diff --cached --quiet \
  || { echo "e2e refuses a dirty tree (commit first)"; exit 2; }
[ -z "$(git -C "$REPO" status --porcelain)" ] \
  || { echo "e2e refuses untracked files (commit first)"; exit 2; }
git -C "$REPO" worktree add "$WORK" HEAD >/dev/null
cd "$WORK"

uv venv "$VENV" >/dev/null
uv pip install --python "$VENV/bin/python" -r requirements.txt >/dev/null
uv pip install --python "$VENV/bin/python" -e . >/dev/null
PY="$VENV/bin/python"
"$PY" -c "import scapy, sklearn, fastapi, typer; print('deps ok')"

if [ "$QUICK" = 1 ]; then
  step "quick smoke on committed samples (no regen/retrain)"
  "$PY" -c "
import sys; sys.path.insert(0, 'engine/features')
from extract import extract
f = extract('demo/samples/v7-voip.pcap')
assert f['has_ah'] == 1 and f['n_ike'] > 0
print('samples ok')"
  step "quick mock-API + CLI smoke (model-free)"
  $PY -m uvicorn engine.api.mock:app --port 8125 &
  SRV=$!
  sleep 5
  curl -sf http://127.0.0.1:8125/health | grep -q '"mock":true'
  curl -sf -F file=@demo/samples/v1-voip.pcap http://127.0.0.1:8125/analyze \
    | grep -q '"decided_by"'
  kill $SRV 2>/dev/null || true
  wait $SRV 2>/dev/null || true
  for c in analyze batch train evaluate generate-data serve; do
    $VENV/bin/ipsec-analyze $c --help >/dev/null
  done
  echo "cli help ok"
else
  step "generate-data (synthetic, deterministic)"
  $PY capture/synth/synth_pcap.py
  [ "$($PY -c "import csv;print(sum(1 for _ in open('data/manifest.csv'))-1)")" = "396" ] \
    || { echo "synthetic row count != 396"; exit 1; }
  if [ -f "$REPO/dataset/ipsec-dataset-v1.tar.gz" ]; then
    step "restore real captures from dataset tarball"
    tar -xzf "$REPO/dataset/ipsec-dataset-v1.tar.gz" -C "$WORK/data" real labels/real
    $PY capture/synth/synth_pcap.py --ingest-real
    [ "$($PY -c "import csv;print(sum(1 for _ in open('data/manifest.csv'))-1)")" = "462" ] \
      || { echo "full row count != 462"; exit 1; }
  else
    echo "no dataset tarball: synthetic-only e2e (real tests skip)"
  fi

  step "validator self-test gate"
  $PY capture/validate_pcap.py --self-test

  step "train"
  $PY engine/classifier/train.py

  step "API smoke (uvicorn + curl)"
  $PY -m uvicorn engine.api.app:app --port 8123 &
  SRV=$!
  sleep 6
  curl -sf http://127.0.0.1:8123/health | grep -q '"status":"ok"'
  curl -sf -F file=@demo/samples/v1-voip.pcap http://127.0.0.1:8123/analyze \
    | grep -q '"enc_alg"'
  curl -sf http://127.0.0.1:8123/variants | grep -q '"v1"'
  curl -sf "http://127.0.0.1:8123/datasets/samples?limit=2" | grep -q samples
  kill $SRV 2>/dev/null || true
  wait $SRV 2>/dev/null || true

  step "CLI serve smoke (installed entry point path)"
  $VENV/bin/ipsec-analyze serve --port 8124 &
  SRV=$!
  sleep 6
  curl -sf http://127.0.0.1:8124/health | grep -q '"status":"ok"'
  kill $SRV 2>/dev/null || true
  wait $SRV 2>/dev/null || true

  step "CLI"
  $VENV/bin/ipsec-analyze analyze demo/samples/v1-voip.pcap | grep -q "aes-128-cbc"
  $VENV/bin/ipsec-analyze analyze demo/samples/v1-voip.pcap --json | grep -q '"traffic_type"'
  $VENV/bin/ipsec-analyze batch demo/samples --json | grep -q '"file"'
  if $VENV/bin/ipsec-analyze analyze missing.pcap 2>&1 | grep -q "no such file"; then
    echo "error path ok"
  else
    echo "missing-file check failed"; exit 1
  fi

  step "reports"
  $PY reports/make_all.py
  [ -f reports/out/executive.pdf ] && [ -f reports/out/comparative.pdf ]

  step "tests"
  $PY -m pytest engine/tests -q

  step "git archive bundle unpack + full quickstart"
  AB="$WORK-ab"
  rm -rf "$AB"
  mkdir -p "$AB"
  git -C "$REPO" archive HEAD | tar -x -C "$AB"
  cd "$AB"
  uv venv "$AB/.venv-a" >/dev/null
  uv pip install --python "$AB/.venv-a/bin/python" -r requirements.txt >/dev/null
  uv pip install --python "$AB/.venv-a/bin/python" -e . >/dev/null
  APY="$AB/.venv-a/bin/python"
  $APY capture/synth/synth_pcap.py
  $APY engine/classifier/train.py >/dev/null
  "$AB/.venv-a/bin/ipsec-analyze" analyze demo/samples/v1-voip.pcap | grep -q "aes-128-cbc"
  $APY -c "
import sys; sys.path.insert(0, 'engine/features')
from extract import extract
f = extract('demo/samples/v7-voip.pcap')
assert f['has_ah'] == 1 and f['n_ike'] > 0
print('archive quickstart ok')"
  cd "$WORK"
fi

echo "== done"
echo "E2E OK"

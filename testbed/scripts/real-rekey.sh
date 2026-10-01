#!/bin/sh
# Long real capture with a forced CHILD rekey mid-capture.
#   testbed/scripts/real-rekey.sh <variant> <run_id> [traffic] [duration_s] [rekey_at_s]
# Runs inside the tb-real container (docker exec ... sh /tb/...), like real-run.sh.
# Output: data/real/<variant>/<run_id>/<traffic>.pcap
set -eu

VARIANT="${1:?Usage: real-rekey.sh <variant> <run_id> [traffic] [duration_s] [rekey_at_s]}"
RUN_ID="${2:?Usage: real-rekey.sh <variant> <run_id> [traffic] [duration_s] [rekey_at_s]}"
T="${3:-voip}"
DURATION="${4:-60}"
REKEY_AT="${5:-30}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$TESTBED_DIR")"
CONF="$TESTBED_DIR/variants/$VARIANT/gw-a/swanctl.conf"
[ -f "$CONF" ] || { echo "unknown variant '$VARIANT'" >&2; exit 1; }

MODE="$(sed -n 's/^ *mode = //p' "$CONF" | head -1)"
TS="$(sed -n 's/^ *local_ts = //p' "$CONF" | head -1)"
case "$TS" in
  fd00*) FAMILY=6 ;;
  *)     FAMILY=4 ;;
esac

if [ "$MODE" = "transport" ]; then
  SRC_NS=tb-gw-a DST_NS=tb-gw-b
  [ "$FAMILY" = 6 ] && TARGET="fd00:ff::2" || TARGET="10.30.0.20"
else
  SRC_NS=tb-cl-a DST_NS=tb-cl-b
  [ "$FAMILY" = 6 ] && TARGET="fd00:2::10" || TARGET="10.2.0.10"
fi

OUT="$REPO_DIR/data/real/$VARIANT/$RUN_ID"
mkdir -p "$OUT"
echo "== rekey session $VARIANT/$RUN_ID/$T (${DURATION}s, rekey at ${REKEY_AT}s)"
SEED="$(printf '%s' "$VARIANT$RUN_ID$T-rekey" | cksum | cut -d' ' -f1)"
CAPTURE_OUT="$OUT/$T.pcap" sh "$SCRIPT_DIR/netns-up.sh" "$VARIANT"

ip netns exec "$DST_NS" python3 "$TESTBED_DIR/traffic/live_gen.py" \
  serve "$T" --duration $((DURATION + 30)) &
SERVE_PID=$!
sleep 0.5

ip netns exec "$SRC_NS" python3 "$TESTBED_DIR/traffic/live_gen.py" \
  send "$T" --target "$TARGET" --duration "$DURATION" --seed "$SEED" &
SEND_PID=$!

sleep "$REKEY_AT"
echo "-- forcing CHILD rekey: $VARIANT-child"
if ip netns exec tb-gw-a swanctl --rekey -u "unix:///tb-run/gw-a.vici" \
    --child "$VARIANT-child"; then
  echo "-- rekey command accepted"
else
  echo "-- rekey command FAILED (continuing capture)" >&2
fi
sleep 2
ip netns exec tb-gw-a swanctl --list-sas -u "unix:///tb-run/gw-a.vici" \
  | grep -i -m4 "rekey\|spi\|state" || true

wait "$SEND_PID" 2>/dev/null || true
kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
sh "$SCRIPT_DIR/netns-down.sh"
echo "== wrote $OUT/$T.pcap ($(wc -c < "$OUT/$T.pcap") bytes)"

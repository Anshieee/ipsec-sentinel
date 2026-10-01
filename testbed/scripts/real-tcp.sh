#!/bin/sh
# Extra real TCP captures (web/email/whatsapp) into an existing/new run dir.
#   testbed/scripts/real-tcp.sh <variant> <run_id>
# Same bring-up/endpoint rules as real-run.sh; runs inside tb-real.
set -eu

VARIANT="${1:?Usage: real-tcp.sh <variant> <run_id>}"
RUN_ID="${2:?Usage: real-tcp.sh <variant> <run_id>}"

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

for T in web email whatsapp; do
  echo "== $VARIANT/$RUN_ID/$T ($MODE, target $TARGET)"
  SEED="$(printf '%s' "$VARIANT$RUN_ID$T" | cksum | cut -d' ' -f1)"
  CAPTURE_OUT="$OUT/$T.pcap" sh "$SCRIPT_DIR/netns-up.sh" "$VARIANT"

  ip netns exec "$DST_NS" python3 "$TESTBED_DIR/traffic/live_gen.py" \
    serve "$T" --duration 90 &
  SERVE_PID=$!
  sleep 0.5

  ip netns exec "$SRC_NS" python3 "$TESTBED_DIR/traffic/live_gen.py" \
    send "$T" --target "$TARGET" --duration 10 --seed "$SEED"

  kill "$SERVE_PID" 2>/dev/null || true
  wait "$SERVE_PID" 2>/dev/null || true
  sh "$SCRIPT_DIR/netns-down.sh"
  echo "== wrote $OUT/$T.pcap ($(wc -c < "$OUT/$T.pcap") bytes)"
done

echo "real TCP session complete: $OUT"

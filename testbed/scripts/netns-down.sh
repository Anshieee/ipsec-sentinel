#!/bin/sh
# Tear down the netns testbed started by netns-up.sh. Idempotent; never
# touches repo data (captures in data/real/ survive).
set -eu

RUN=/tb-run

for f in tcpdump.pid gw-a.charon.pid gw-b.charon.pid; do
  if [ -f "$RUN/$f" ]; then
    kill "$(cat "$RUN/$f")" 2>/dev/null || true
    rm -f "$RUN/$f"
  fi
done
killall -q python3 2>/dev/null || true   # leftover live_gen serve processes
sleep 0.5

# charons must be dead before the netns is unmounted, otherwise they keep
# running in an unreachable namespace.
for ns in tb-gw-a tb-gw-b tb-cl-a tb-cl-b; do
  ip netns del "$ns" 2>/dev/null || true
done
rm -f "$RUN"/*.vici "$RUN"/initiate.log /var/run/charon.pid
echo "[netns-down] testbed torn down"

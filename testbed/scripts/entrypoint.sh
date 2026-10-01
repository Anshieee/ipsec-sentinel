#!/bin/sh
# Container entrypoint for the fallback compose lab (see testbed/DESIGN.md).
# Order matters: charon must be running (vici socket present) BEFORE swanctl
# can load anything - the previous order loaded configs into a dead daemon.
set -eu

VARIANT="${VARIANT:-v1}"
echo "[entrypoint] VARIANT=${VARIANT} ($(hostname))"

# Routes to the peer's LAN via the peer's transit address (matrix.py TOPOLOGY)
ip route add 10.2.0.0/24 via 10.30.0.20 2>/dev/null || true
ip route add fd00:2::/64 via fd00:ff::2 2>/dev/null || true
ip route add 10.1.0.0/24 via 10.30.0.10 2>/dev/null || true
ip route add fd00:1::/64 via fd00:ff::1 2>/dev/null || true

if command -v swanctl >/dev/null 2>&1; then
  echo "[entrypoint] starting charon"
  /usr/lib/strongswan/charon >/tmp/charon.log 2>&1 &
  i=0
  while [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    if [ "$i" -ge 50 ]; then
      echo "[entrypoint] charon vici socket did not appear" >&2
      exit 1
    fi
    sleep 0.2
  done

  echo "[entrypoint] loading ${VARIANT} config"
  swanctl --load-conns
  swanctl --load-creds

  # retry: the peer gateway may still be starting
  n=0
  while [ "$n" -lt 5 ]; do
    if swanctl --initiate --child "${VARIANT}-child"; then
      echo "[entrypoint] CHILD_SA ${VARIANT}-child initiated"
      break
    fi
    n=$((n + 1))
    echo "[entrypoint] initiate attempt ${n} failed, retrying..."
    sleep 2
  done
  wait
else
  # busybox clients: point the peer LAN at this side's gateway
  ip route add 10.2.0.0/24 via 10.1.0.1 2>/dev/null || true
  ip route add 10.1.0.0/24 via 10.2.0.1 2>/dev/null || true
  echo "[entrypoint] non-strongSwan container, sleeping"
  sleep infinity
fi

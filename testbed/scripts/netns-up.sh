#!/bin/sh
# M2 real-capture testbed bring-up (decision D3, spec M2 "Real captures").
#
# Host root is unavailable (DECISIONS D1: sudo -n fails) and Docker is
# already working, which is the path the spec permits. The whole topology
# therefore runs INSIDE one --privileged container:
#
#   tb-cl-a ── veth ── tb-gw-a ══ gateway link ══ tb-gw-b ── veth ── tb-cl-b
#  10.1.0.10        10.1.0.1   10.30.0.10  10.30.0.20  10.2.0.1  10.2.0.10
#  fd00:1::10        fd00:1::1  fd00:ff::1   fd00:ff::2  fd00:2::1 fd00:2::10
#                            ^ capture here (tcpdump -i v-ga2)
#
# One charon per gateway netns, each with its own vici socket
# (charon.plugins.vici.socket; config file overridden per process via
# STRONGSWAN_CONF, swanctl gets -u <uri>). Same addressing as
# testbed/matrix.py TOPOLOGY. Run inside the container:
#
#   docker run --rm -d --name tb-real --privileged \
#     -v <repo>:/tb --entrypoint sh <image> -c 'sleep infinity'
#   docker exec tb-real sh /tb/testbed/scripts/netns-up.sh v1
#   docker exec tb-real sh /tb/testbed/scripts/netns-down.sh
set -eu

VARIANT="${1:?Usage: netns-up.sh <variant>  (e.g. netns-up.sh v1)}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"   # .../testbed
REPO_DIR="$(dirname "$TESTBED_DIR")"     # repo root
VAR_A="$TESTBED_DIR/variants/$VARIANT/gw-a/swanctl.conf"
VAR_B="$TESTBED_DIR/variants/$VARIANT/gw-b/swanctl.conf"
RUN=/tb-run   # must live outside /run: each charon binds a private dir over
              # /var/run (-> /run in Alpine), which hides anything under /run
CHARON=/usr/lib/strongswan/charon

die() { echo "[netns-up] ERROR: $*" >&2; exit 1; }
log() { echo "[netns-up] $*"; }

[ "$(id -u)" = "0" ] || die "must run as root (inside the testbed container)"
[ -f "$VAR_A" ] && [ -f "$VAR_B" ] || die "unknown variant '$VARIANT' (run testbed/gen_configs.py first)"
# note: `ip netns help` exits non-zero even when supported; use a real op
ip netns list >/dev/null 2>&1 || die "iproute2 'ip netns' unavailable in this image"
command -v tcpdump >/dev/null 2>&1 || {
  log "installing tcpdump (image ships without it)..."
  apk add --no-cache tcpdump >/dev/null 2>&1 || die "cannot install tcpdump"
}
command -v python3 >/dev/null 2>&1 || {
  log "installing python3 (live traffic generators)..."
  apk add --no-cache python3 >/dev/null 2>&1 || die "cannot install python3"
}

CAPTURE_OUT="${CAPTURE_OUT:-$REPO_DIR/data/real/$VARIANT/capture.pcap}"
mkdir -p "$RUN" "$(dirname "$CAPTURE_OUT")"

# --- idempotent cleanup of a previous run -------------------------------
for f in tcpdump.pid gw-a.charon.pid gw-b.charon.pid; do
  [ -f "$RUN/$f" ] && kill "$(cat "$RUN/$f")" 2>/dev/null || true
done
killall -q charon 2>/dev/null || true
killall -q tcpdump 2>/dev/null || true
killall -q python3 2>/dev/null || true   # leftover live_gen serve processes
# charon's shutdown is async: it releases the SHARED /var/run/charon.pid
# only when done, and a new charon that starts too early exits with
# "charon already running" AFTER having bound its vici socket (orphan
# socket file with no listener -> swanctl gets ECONNREFUSED).
n=0
while [ -f /var/run/charon.pid ] && [ "$n" -lt 25 ]; do
  n=$((n + 1))
  sleep 0.2
done
if [ -f /var/run/charon.pid ]; then
  kill -9 "$(cat /var/run/charon.pid)" 2>/dev/null || true
  sleep 0.3
fi
rm -f /var/run/charon.pid
for ns in tb-cl-a tb-gw-a tb-gw-b tb-cl-b; do
  ip netns del "$ns" 2>/dev/null || true
done
rm -f "$RUN"/*.vici "$RUN"/*.pid "$RUN"/initiate.log

# --- per-gateway strongswan.conf: separate vici sockets ------------------
for gw in gw-a gw-b; do
  cat > "$RUN/$gw.conf" <<EOF
charon {
  plugins {
    vici {
      socket = unix://$RUN/$gw.vici
    }
  }
}
EOF
done

# --- namespaces + veth pairs ---------------------------------------------
for ns in tb-cl-a tb-gw-a tb-gw-b tb-cl-b; do
  ip netns add "$ns"
done
ip link add v-ca  type veth peer name v-ga1
ip link add v-cb  type veth peer name v-gb1
ip link add v-ga2 type veth peer name v-gb2
ip link set v-ca  netns tb-cl-a
ip link set v-cb  netns tb-cl-b
ip link set v-ga1 netns tb-gw-a
ip link set v-ga2 netns tb-gw-a
ip link set v-gb1 netns tb-gw-b
ip link set v-gb2 netns tb-gw-b

nin() { ns="$1"; shift; ip netns exec "$ns" "$@"; }

# --- addressing (matrix.py TOPOLOGY) --------------------------------------
nin tb-cl-a ip link set lo up
nin tb-cl-a ip link set v-ca up
nin tb-cl-a ip addr add 10.1.0.10/24 dev v-ca
nin tb-cl-a ip -6 addr add fd00:1::10/64 dev v-ca nodad

nin tb-cl-b ip link set lo up
nin tb-cl-b ip link set v-cb up
nin tb-cl-b ip addr add 10.2.0.10/24 dev v-cb
nin tb-cl-b ip -6 addr add fd00:2::10/64 dev v-cb nodad

nin tb-gw-a ip link set lo up
nin tb-gw-a ip link set v-ga1 up
nin tb-gw-a ip link set v-ga2 up
nin tb-gw-a ip addr add 10.1.0.1/24 dev v-ga1
nin tb-gw-a ip addr add 10.30.0.10/24 dev v-ga2
nin tb-gw-a ip -6 addr add fd00:1::1/64 dev v-ga1 nodad
nin tb-gw-a ip -6 addr add fd00:ff::1/64 dev v-ga2 nodad

nin tb-gw-b ip link set lo up
nin tb-gw-b ip link set v-gb1 up
nin tb-gw-b ip link set v-gb2 up
nin tb-gw-b ip addr add 10.2.0.1/24 dev v-gb1
nin tb-gw-b ip addr add 10.30.0.20/24 dev v-gb2
nin tb-gw-b ip -6 addr add fd00:2::1/64 dev v-gb1 nodad
nin tb-gw-b ip -6 addr add fd00:ff::2/64 dev v-gb2 nodad

# --- gateways forward; strict rp_filter would drop the decap-then-forward
#     return path (inner source arrives over the "wrong" interface) -------
for gw in tb-gw-a tb-gw-b; do
  nin "$gw" sysctl -q -w net.ipv4.ip_forward=1
  nin "$gw" sysctl -q -w net.ipv4.conf.all.rp_filter=0
  nin "$gw" sysctl -q -w net.ipv4.conf.default.rp_filter=0
  nin "$gw" sysctl -q -w net.ipv6.conf.all.forwarding=1
done

# --- routes ---------------------------------------------------------------
nin tb-cl-a ip route add default via 10.1.0.1
nin tb-cl-a ip -6 route add default via fd00:1::1
nin tb-cl-b ip route add default via 10.2.0.1
nin tb-cl-b ip -6 route add default via fd00:2::1
nin tb-gw-a ip route add 10.2.0.0/24 via 10.30.0.20
nin tb-gw-a ip -6 route add fd00:2::/64 via fd00:ff::2
nin tb-gw-b ip route add 10.1.0.0/24 via 10.30.0.10
nin tb-gw-b ip -6 route add fd00:1::/64 via fd00:ff::1

# --- one charon per gateway netns, own vici socket + private /var/run -----
# /var/run is shared filesystem state: charon's compile-time PID_FILE and
# the stroke socket /var/run/charon.ctl would collide for a second instance
# ("charon already running"). Each charon therefore gets a private mount
# namespace with its own dir bound over /var/run; vici sockets stay at
# $RUN (outside /run) so swanctl can reach them from the normal namespace.
mkdir -p "$RUN/var-run-a" "$RUN/var-run-b"
for gw in gw-a gw-b; do
  case "$gw" in
    gw-a) vr="$RUN/var-run-a" ;;
    gw-b) vr="$RUN/var-run-b" ;;
  esac
  ip netns exec "tb-$gw" unshare -m sh -c \
    "mount --bind $vr /var/run && exec env STRONGSWAN_CONF=$RUN/$gw.conf $CHARON" \
    > "$RUN/$gw.charon.log" 2>&1 &
  echo $! > "$RUN/$gw.charon.pid"
done
for gw in gw-a gw-b; do
  n=0
  while [ ! -S "$RUN/$gw.vici" ]; do
    n=$((n + 1))
    if [ "$n" -ge 50 ]; then
      echo "---- $gw charon log:" >&2
      tail -30 "$RUN/$gw.charon.log" >&2 || true
      die "charon $gw did not create its vici socket"
    fi
    sleep 0.2
  done
  # socket file existing is not enough (orphan sockets have no listener):
  # confirm vici actually accepts connections
  n=0
  until ip netns exec "tb-$gw" swanctl --list-sas -u "unix://$RUN/$gw.vici" >/dev/null 2>&1; do
    n=$((n + 1))
    if [ "$n" -ge 25 ]; then
      echo "---- $gw charon log:" >&2
      tail -30 "$RUN/$gw.charon.log" >&2 || true
      die "charon $gw vici socket not accepting connections"
    fi
    sleep 0.2
  done
done
log "charons up (separate vici sockets, vici accepting)"

# --- capture on the gateway link BEFORE initiating (records the IKE too) ---
ip netns exec tb-gw-a tcpdump -i v-ga2 -s 0 -U -w "$CAPTURE_OUT" \
  'udp port 500 or udp port 4500 or proto 50 or proto 51' \
  > "$RUN/tcpdump.log" 2>&1 &
echo $! > "$RUN/tcpdump.pid"
sleep 1
[ -f "$CAPTURE_OUT" ] || { tail -10 "$RUN/tcpdump.log" >&2; die "tcpdump did not start"; }

# --- deploy-time secrets (MAJOR-2: PSKs live only in matrix.psk_for,
# never in git; fill the committed REDACTED placeholders + legacy files)
python3 "$TESTBED_DIR/gen_secrets.py" "$VARIANT" || die "gen_secrets failed"

# --- load this variant into both charons -----------------------------------
ip netns exec tb-gw-a swanctl --load-conns -u "unix://$RUN/gw-a.vici" -f "$VAR_A"
ip netns exec tb-gw-a swanctl --load-creds -u "unix://$RUN/gw-a.vici" -f "$VAR_A"
ip netns exec tb-gw-b swanctl --load-conns -u "unix://$RUN/gw-b.vici" -f "$VAR_B"
ip netns exec tb-gw-b swanctl --load-creds -u "unix://$RUN/gw-b.vici" -f "$VAR_B"

# --- initiate (retry: peer charon may still be loading) ---------------------
ok=0
n=0
while [ "$n" -lt 5 ]; do
  if ip netns exec tb-gw-a swanctl --initiate -u "unix://$RUN/gw-a.vici" \
      --child "$VARIANT-child" >> "$RUN/initiate.log" 2>&1; then
    ok=1
    break
  fi
  n=$((n + 1))
  log "initiate attempt $n failed, retrying..."
  sleep 2
done
if [ "$ok" != 1 ]; then
  tail -40 "$RUN/initiate.log" >&2 || true
  echo "---- gw-a charon log:" >&2
  tail -40 "$RUN/gw-a.charon.log" >&2 || true
  echo "---- gw-b charon log:" >&2
  tail -40 "$RUN/gw-b.charon.log" >&2 || true
  die "CHILD_SA $VARIANT-child not established"
fi

# --- spec gate: SAs must be ESTABLISHED/INSTALLED BEFORE any traffic --------
A_SAS="$(ip netns exec tb-gw-a swanctl --list-sas -u "unix://$RUN/gw-a.vici")"
B_SAS="$(ip netns exec tb-gw-b swanctl --list-sas -u "unix://$RUN/gw-b.vici")"
echo "$A_SAS" | grep -q ESTABLISHED || { echo "$A_SAS"; die "gw-a IKE SA not ESTABLISHED"; }
echo "$A_SAS" | grep -q INSTALLED   || { echo "$A_SAS"; die "gw-a CHILD SA not INSTALLED"; }
echo "$B_SAS" | grep -q ESTABLISHED || { echo "$B_SAS"; die "gw-b IKE SA not ESTABLISHED"; }
echo "$B_SAS" | grep -q INSTALLED   || { echo "$B_SAS"; die "gw-b CHILD SA not INSTALLED"; }

log "SAs confirmed ESTABLISHED/INSTALLED for $VARIANT (pre-traffic gate passed)"
log "capture -> $CAPTURE_OUT"
log "smoke traffic: docker exec <c> ip netns exec tb-cl-a ping -c 3 10.2.0.10"
echo "$A_SAS"

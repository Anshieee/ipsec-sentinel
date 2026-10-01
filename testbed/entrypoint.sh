#!/bin/sh
set -eu

export PATH="/usr/sbin:/usr/libexec/ipsec:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "[entrypoint] Starting container"
echo "[entrypoint] VARIANT=${VARIANT:-v1}"

# Copy config from /config to /etc if provided
if [ -f /config/ipsec.conf ]; then
  echo "[entrypoint] Copying config from /config to /etc"
  cp /config/ipsec.conf /etc/ipsec.conf
fi
if [ -f /config/ipsec.secrets ]; then
  cp /config/ipsec.secrets /etc/ipsec.secrets
fi

echo "[entrypoint] Starting container"
echo "[entrypoint] VARIANT=${VARIANT:-v1}"

# Add inter-network routes for tunnel connectivity
ip route add 10.2.0.0/24 via 192.168.200.2 2>/dev/null || true
ip route add fd00:2::/64 via fd00:ff::2 2>/dev/null || true
ip route add 10.1.0.0/24 via 192.168.200.1 2>/dev/null || true
ip route add fd00:1::/64 via fd00:ff::1 2>/dev/null || true

# For strongSwan gateways
if command -v ipsec >/dev/null 2>&1; then
  echo "[entrypoint] Found ipsec at $(which ipsec)"
  echo "[entrypoint] Loading strongSwan config for variant ${VARIANT:-v1}"
  ipsec reload 2>/dev/null || ipsec start 2>/dev/null || true
  sleep 3
  echo "[entrypoint] IPsec started, SAs: $(ipsec status 2>&1 | head -5)"
  sleep infinity
else
  echo "[entrypoint] ipsec NOT FOUND in PATH"
  echo "[entrypoint] Non-strongSwan container, sleeping"
  sleep infinity
fi
#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
NEW_VARIANT="${1:?Usage: switch-variant.sh <variant>   e.g. switch-variant.sh v7}"

# Variant list is whatever gen_configs.py produced (v<N> directories).
AVAILABLE="$(ls "$TESTBED_DIR/variants" | grep -E '^v[0-9]+$' | tr '\n' ' ')"
if ! printf '%s' "$NEW_VARIANT" | grep -Eq '^v[0-9]+$' ||
   [ ! -d "$TESTBED_DIR/variants/$NEW_VARIANT" ]; then
  echo "Unknown variant '$NEW_VARIANT'. Available: $AVAILABLE"
  exit 1
fi

echo "[switch] Stopping testbed..."
cd "$TESTBED_DIR"
docker compose down -v

echo "[switch] Starting variant $NEW_VARIANT..."
export VARIANT="$NEW_VARIANT"
docker compose up -d gw-a gw-b capture

# charon must be restarted to drop children referenced by the old IKE_SA
# (loading a replacement connection does not update established IKE_SAs),
# the entrypoint starts a fresh daemon per container, so just wait for it.
echo "[switch] Waiting for IKE SA..."
sleep 5
docker compose exec -T gw-a swanctl --list-sas 2>/dev/null && echo "[switch] gw-a SA up" || echo "[switch] gw-a no SA"
docker compose exec -T gw-b swanctl --list-sas 2>/dev/null && echo "[switch] gw-b SA up" || echo "[switch] gw-b no SA"

echo "[switch] Variant $NEW_VARIANT active"

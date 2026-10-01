#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
VARIANT="${VARIANT:-v1}"

echo "[up] Starting testbed variant $VARIANT"

export VARIANT
cd "$TESTBED_DIR"

docker compose up -d gw-a gw-b capture

echo "[up] Waiting for IKE SA establishment..."
sleep 5

docker compose exec -T gw-a swanctl --list-sas 2>/dev/null && echo "[up] IKE SA established on gw-a" || echo "[up] No SA on gw-a (check logs)"
docker compose exec -T gw-b swanctl --list-sas 2>/dev/null && echo "[up] IKE SA established on gw-b" || echo "[up] No SA on gw-b (check logs)"

echo "[up] Testbed up — variant $VARIANT"

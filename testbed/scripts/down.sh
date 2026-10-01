#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"

echo "[down] Tearing down testbed"
cd "$TESTBED_DIR"
docker compose down -v
echo "[down] Testbed down"

#!/bin/sh
# Build dataset/ipsec-dataset-v1.tar.gz (M4 req 5): grouped manifests,
# checksums, README. Tarball itself is a build artifact (gitignored).
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

.venv/bin/python - "$@" <<'EOF'
import csv, sys
from pathlib import Path
rows = list(csv.DictReader(open("data/manifest.csv")))
def sel(pred):
    return [r for r in rows if pred(r)]
def run_of(r):
    p = Path(r["file"]).parts
    if p[1] == "pcaps":
        return p[5] if p[3] == "plain" else p[4]
    return p[3]
syn = [r for r in rows if r["source"] == "synthetic"]
real = [r for r in rows if r["source"] == "real"]
train = [r for r in syn if run_of(r) in ("r1", "r2")]
test = [r for r in syn if run_of(r) == "r3"]
for name, subset in (("train", train), ("test", test), ("real", real)):
    with open(f"dataset/manifest-{name}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(subset)
    print(f"dataset/manifest-{name}.csv: {len(subset)} rows")
EOF

# checksums over every shipped file (paths relative to tarball root)
( cd data && find pcaps real -name "*.pcap" | sort | xargs sha256sum ) > dataset/checksums.sha256
( cd data && find labels -name "*.json" | sort | xargs sha256sum ) >> dataset/checksums.sha256
( cd data && sha256sum manifest.csv ) >> dataset/checksums.sha256
wc -l dataset/checksums.sha256
tar -czf dataset/ipsec-dataset-v1.tar.gz -C data pcaps real labels manifest.csv \
  -C ../dataset README.md manifest-train.csv manifest-test.csv manifest-real.csv checksums.sha256
ls -la dataset/ipsec-dataset-v1.tar.gz

# AI-driven IPsec VPN Protocol Analysis Platform

Classify IPsec captures (variant, crypto, traffic), score their security,
and serve results over a frozen API. No dashboard in this repo — the
frontend is built separately against `docs/api-contract.md`.

## Quickstart (fresh venv)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .   # provides `ipsec-analyze`
ipsec-analyze generate-data --real   # 360 synthetic + 66 real labels
ipsec-analyze train                  # per-field RF models (seed 7)
ipsec-analyze analyze data/pcaps/synth/v1/r1/voip.pcap
python -m pytest engine/tests -q     # full suite green
sh scripts/e2e.sh --quick            # fast smoke (full e2e: sh scripts/e2e.sh)
```

Full pipeline + checks: `scripts/e2e.sh` (exit 0).

## UI

```bash
cd frontend && npm ci
sh scripts/run_demo.sh   # API :8000 + UI :5173, Ctrl-C stops both
```

In the UI, Settings → Data source toggles Mock (fixtures, default) and
Live (real API at `VITE_API_URL`, default `http://127.0.0.1:8000`).
Simulated surfaces (live-capture stream, model registry) carry a
SIMULATED badge in live mode. Contract: `docs/api-contract.md`,
`docs/frontend-integration.md`.

## Real data needs the dataset tarball

`data/` (pcaps, labels, models) is regenerable and NOT in git — except 21
demo samples. The full corpus, including `data/real` (66 captures) needed
for the real-NAT-T report and real evaluations, ships ONLY in
`dataset/ipsec-dataset-v1.tar.gz` (built by `scripts/build-dataset.sh`,
checksummed in `dataset/checksums.sha256`). Get it from the release
artifacts (or rebuild: recapture via `testbed/scripts/`, ~1 h), extract
over `data/` (`tar -xzf dataset/ipsec-dataset-v1.tar.gz -C /tmp/ds && cp
-r /tmp/ds/* data/`), then `ipsec-analyze generate-data --real` folds the
labels. Without it, `generate-data` builds the 360 synthetic pcaps and
anything referencing `data/real` skips gracefully.

## Layout

- `testbed/` — 18-variant matrix (`matrix.py`), configs, netns testbed,
  live traffic generators. All PSKs in the repo are deterministic
  TEST-ONLY lab credentials derived from `matrix.psk_for` (never real
  secrets, never on the wire); secret-bearing files are generated at
  deploy time (`testbed/gen_secrets.py`) and never committed.
- `capture/` — synthetic generator, validator (gate), leakage audit.
- `engine/` — bytes-only features, parsed+model classifier, grouped
  evaluation, security assessment, FastAPI service.
- `cli/` — `ipsec-analyze` Typer CLI. `reports/` — PDF builders.
- `docs/` — datasheet, model evaluation, rubric, API contract, examples.
- `demo/` — CLI+API walkthrough script. `dataset/` — manifests/checksums.

## Honest limits

Synthetic pcaps prove pipeline behavior on the synthetic distribution
only; 66 real captures (v1,v3,v5,v7,v12,v18) are the only
out-of-distribution evidence. Lifetimes/replay/ESN are never observed in
short captures; PFS needs a rekey on the wire. See
`docs/model-evaluation.md` and `docs/dataset-datasheet.md`.

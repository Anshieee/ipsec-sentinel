# AI-driven IPsec VPN Protocol Analysis Platform

Classify IPsec captures (variant, crypto, traffic), score their security,
and serve results over a frozen API, with a React frontend in
`frontend/` (Node 24, see `frontend/.nvmrc`) built against
`docs/api-contract.md`.

## Quickstart (fresh venv)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .   # provides `ipsec-analyze`
ipsec-analyze generate-data --real   # 414 synthetic + 66 real labels
ipsec-analyze train                  # per-field RF models (seed 7)
ipsec-analyze analyze data/pcaps/synth/v1/r1/voip.pcap
python -m pytest engine/tests -q     # full suite green
sh scripts/e2e.sh --quick            # fast smoke (full e2e: sh scripts/e2e.sh)
```

Full pipeline + checks: `scripts/e2e.sh` (exit 0).

Corpus counts above are pinned by `engine/tests/test_corpus_counts.py`
and `engine/tests/test_readme_counts.py`: if they drift from
`data/manifest.csv`, the suite fails — edit the generator and the docs
together.

Without the dataset tarball (synthetic-only checkout),
`test_corpus_counts.py::test_doc_counts_match_manifest` and
`test_parse.py::test_ah_without_rekey_pfs_unknown` skip: both need
`data/real/` (the real-NAT-T report, synth→real eval and the real
holdout need it too).

## UI

Requires Node 24 (`frontend/.nvmrc`; check with `node --version`):

```bash
cd frontend && npm ci && npm run build
sh scripts/run_demo.sh   # API :8000 + UI :5173, Ctrl-C stops both
```

`scripts/run_demo.sh` uses the project `.venv` (no `uv` needed), writes
logs to a fresh mktemp directory it prints, records only the PIDs it
starts (no broad `pkill`), refuses with a clear message when ports
8000/5173 are busy, and cleans up on exit.

In the UI, Settings → Data source toggles Mock (fixtures, default) and
Live (real API at `VITE_API_URL`, default `http://127.0.0.1:8000`).
Simulated surfaces (live-capture stream, model registry) carry a
SIMULATED badge in live mode. Contract: `docs/api-contract.md`,
`docs/frontend-integration.md`. Frontend gates:
`npm ci && npm run lint && npm run typecheck && npm test && npm run build`.

## Real data needs the dataset tarball

`data/` (pcaps, labels, models) is regenerable and NOT in git — except
22 demo samples (21 scored + 1 derived ESP-only fixture). The full
corpus, including `data/real` (66 captures) needed for the real-NAT-T
report and real evaluations, ships ONLY in
`dataset/ipsec-dataset-v1.tar.gz` (built by `scripts/build-dataset.sh`,
checksummed in `dataset/checksums.sha256`). Get it from the release
artifacts (see `docs/RELEASE.md` for the tarball sha256 and the exact
`gh release create` provenance) or rebuild by recapturing via
`testbed/scripts/` (~1 h). Extract over `data/`
(`mkdir -p data && tar -xzf dataset/ipsec-dataset-v1.tar.gz -C /tmp/ds
&& cp -r /tmp/ds/* data/`), then `ipsec-analyze generate-data --real` folds the labels —
and fails with an actionable error naming the tarball if `data/real`
is absent. Without it, `generate-data` builds the 414 synthetic pcaps
and anything referencing `data/real` skips gracefully.

## Layout

- `testbed/` — 21-variant matrix (`matrix.py`), configs, netns testbed,
  live traffic generators. All PSKs in the repo are deterministic
  TEST-ONLY lab credentials derived from `matrix.psk_for` (never real
  secrets, never on the wire); secret-bearing files are generated at
  deploy time (`testbed/gen_secrets.py`) and never committed.
- `capture/` — synthetic generator, validator (gate), leakage audit.
- `engine/` — bytes-only features, parsed+model classifier, grouped
  evaluation, security assessment, FastAPI service.
- `frontend/` — React UI (Vite + vitest); live mapper in
  `src/api/backend.ts`, types in `src/types/analysis.ts`.
- `cli/` — `ipsec-analyze` Typer CLI. `reports/` — PDF builders.
- `docs/` — datasheet, model evaluation, rubric, API contract, examples.
- `demo/` — CLI+API walkthrough script. `dataset/` — manifests/checksums.

## Honest limits

Synthetic pcaps prove pipeline behavior on the synthetic distribution
only; 66 real captures (v1,v3,v5,v7,v12,v18) are the only
out-of-distribution evidence. Lifetimes/replay/ESN are never observed in
short captures; PFS needs a rekey on the wire. See
`docs/model-evaluation.md` and `docs/dataset-datasheet.md`.

## How does it do on someone else's data?

`docs/head-to-head.md`: our frozen pipeline on 180 captures from
[naman9271/ipsec-pcap-lab](https://github.com/naman9271/ipsec-pcap-lab)
(`c0cf256`, real strongSwan, no handshakes in the labeled captures).
Parsed fields transfer at 1.000 (ip_version, nat_t, IKE on the 5
handshake sessions); auth at 0.910; encryption at 0.322 accuracy
(0.690 when it answers — our own synth→real is 0.7121 on the same
metric); mode and traffic classification do not transfer (0.011 and
0.000 — the tunnel-size signal and the six synthetic traffic profiles
do not survive a different generator). Reproduce:
`git clone https://github.com/naman9271/ipsec-pcap-lab ~/.tmp-work/ipsec-pcap-lab`
(check out `c0cf256`), then `.venv/bin/python scripts/eval_external.py`.
Their repo carries no license, so no third-party pcaps or labels ship
in ours — only our script and aggregate results.

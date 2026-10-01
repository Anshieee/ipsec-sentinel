# Submission checklist (M5)

Each deliverable → path → verification (command + result, all executed).

- 18-variant testbed + configs → `testbed/matrix.py`, `testbed/variants/`
  → `testbed/validate_configs.py` → M1 gate 1437/1437, rc=0.
- Real captures (66) → `data/real/` (tarball) via `testbed/scripts/real-{run,rekey,tcp}.sh`
  → SAs ESTABLISHED/INSTALLED logged; forced rekeys verified on wire
  (exch-36 pairs, v12 2nd QM).
- Synthetic generator → `capture/synth/synth_pcap.py`
  → 360 pcaps, byte-verified vs real captures (D13).
- Validator gate → `capture/validate_pcap.py`
  → `--self-test` 15/15 rc=0; full corpus 426/426 valid rc=0.
- Leakage gate → `capture/audit_leakage.py`
  → stratified MI + grouped exact-match all PASS, rc=0.
- Dataset → `dataset/` + `ipsec-dataset-v1.tar.gz` (artifact)
  → `scripts/build-dataset.sh` rc=0; `sha256sum -c` 0 failures (919 entries).
- Classifier → `engine/{features,classifier}/`
  → `pytest engine/tests/test_parse.py engine/tests/test_no_labels.py`
  green; labels-hidden identity proven.
- Evaluation → `docs/model-evaluation.md` + `docs/plots/` (11 PNGs)
  → grouped 5-fold CV, ESP ablation, synth→real (66), holdout (30);
  parsed fields 1.000 incl. real; TCP abstains with 0 wrong.
- Security → `docs/security-rubric.md`, `engine/assess/`
  → `pytest engine/tests/test_assess.py` (v1=88, v7/v11=73, v8=75, plain=5).
- API + contract + mock → `engine/api/`, `docs/api-contract.md`,
  `docs/openapi.json`, `docs/examples/` (10 files)
  → `pytest engine/tests/test_api.py` (incl. 51 MB → 413).
- CLI → `cli/main.py` + `pyproject.toml`
  → `pytest engine/tests/test_cli.py`; entry point cwd-independent.
- Reports → `reports/build.py`, `reports/out/` (8 PDFs)
  → `reports/make_all.py` rc=0; confidence/unknowns/caveat in every PDF.
- Demo → `demo/DEMO_SCRIPT.md` + recorded typescript (replay verified).
- E2E → `scripts/e2e.sh` (full + `--quick`) → exit 0 on clean checkout.
- Docs → `docs/{architecture,testbed-guide,methodology,cli-guide,
  reproduction,limitations,traceability,QA_PREP,frontend-handoff,
  self-review,dataset-datasheet}.md` + `README.md` + `demo/samples/` (12).

Not in scope (D17): Streamlit dashboard. The friend's Vite+React UI is
vendored under `frontend/` and wired to the live API (mapper layer +
badged simulated surfaces); see `docs/frontend-integration.md`,
`frontend/SOURCE.md`, `demo/` via `scripts/run_demo.sh`.
Known partials: real coverage 6/19 variants; PFS unknown without rekey
SK; lifetimes/replay/ESN never observed; see `docs/limitations.md`.

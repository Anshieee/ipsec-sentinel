# PROGRESS

Status key: `[ ]` not started · `[~]` in progress · `[x]` verified by executed command
· `[!]` blocked (reason recorded in DECISIONS.md / NEEDS_HUMAN.md)

**Current step:** M5 complete — all milestones verified, tagged `final`
**Next step:** human double-checks per FINAL_REPORT.md, then handoff

---

## M0 — Bootstrap

- [x] `git init` (branch `master`, default)
- [x] `.gitignore` written (venv, pycache, logs)
- [x] `.venv` created: uv + Python 3.12.13
- [x] Pinned deps installed: `uv pip install -r requirements.txt` → rc=0 (82 locked packages)
- [x] Smoke verification (executed): scapy/sklearn/xgboost/lightgbm/pandas/numpy/fastapi/uvicorn/pydantic/streamlit/plotly/typer/jinja2/weasyprint/reportlab/pytest/httpx all import; WeasyPrint rendered a real PDF
- [x] `requirements.txt` (direct, pinned) + `requirements.lock.txt` (full freeze)
- [x] Reusable prior work copied in per user decision (see DECISIONS.md D2); `__pycache__` excluded
- [x] `PLAN.md` written (architecture, stack, layout, schema, milestones, risks)
- [x] `DECISIONS.md` written (D1 environment inventory with evidence, D2–D6)
- [x] `PROGRESS.md` written (this file)
- [x] Hardcoded `/home/ansh/Projects/sih-2/...` paths in ALL copied scripts replaced with repo-relative (`Path(__file__)`); nonexistent `web.py`/`email.py`/... refs corrected to actual `*_gen.py` files; all 14 scripts compile
- [x] Copy verification: `synth_pcap.py` ran here → 114 pcaps + labels + manifest in `data/pcaps/` (3.3 s); `validate_pcap.py` → 114/114 valid, rc=0
- [x] **BUT validator audited as weak (negative-tested):** a fake synthetic pcap with NO ESP and NO IKE still reports `valid=True` — missing IPsec is only a *warning*, not an error. Not a trustworthy gate yet.
- [x] **Generator audited vs spec:** `generate_ike_handshake()` is random bytes on UDP/500 (no real IKEv2 header/payloads/SA proposal/KE/nonces/rekey); ESP padding/ICV structure not spec-conformant; traffic payloads not actually encodable per type. → M2 rework items.
- [x] Variant config audit (gate: gaps listed → M1 work items):
  - ✅ v1–v6 cover Tunnel/Transport, AES-128/256-CBC+SHA256, AES-128/256-GCM, DH 14/19/20 (modp2048/ecp256/ecp384), PFS on (v3/v6 off), IPv4/IPv6 — matches spec baseline v1–v6
  - ✅ 6 unique PSKs (prior blocker L2 fixed); legacy `ipsec.conf` exists for v1 only
  - ❌ **Missing weak coverage:** DH2/DH5, SHA1, 3DES, IKEv1 main mode, short/long lifetimes, replay protection off, ESN on/off, NAT-T, AH variant (v7 is a stub)
  - ❌ No label schema JSON yet; manifest schema OK (has esp_packets/ike_packets) but no run_id/duration columns
- [x] First commit

## M1 — Testbed design and configuration

- [x] Variant matrix documented in `testbed/DESIGN.md` — **18 variants**
      (spec min 15): v1–v6 spec baselines + v7 AH + v8/v9 DH2/DH5 + v10 SHA1 +
      v11 3DES + v12 IKEv1 main mode + v13/v14 short/long lifetimes + v15 replay off +
      v16/v17 ESN on/off + v18 NAT-T; one-factor diffs vs v1 (matrix.py self-check 117/117)
- [x] strongSwan configs for BOTH gateways of every variant: 36 swanctl + 36
      legacy ipsec.conf + 36 ipsec.secrets, generated from `matrix.py` by
      `gen_configs.py` (unique PSK per variant, child name `<variant>-child`)
- [x] Topology/addressing documented (IPv4 + IPv6): LAN-A/B + transit
      10.30.0.0/24 (fd00:ff::/64) as IKE/ESP endpoints + capture point; transport
      = host TS on transit, tunnel = LAN subnets (D9, empirically proven)
- [x] Ground-truth label schema JSON: `testbed/label_schema.json` (draft-07,
      21 required fields incl. esn/replay/nat_t/rekeys; cross-field rules) +
      `labels/variants.json` + `labels/example-label.json`, all validated
- [x] **Gate A** (swanctl loads into live charon): 72/72 · **Gate B** (legacy
      `starter --conftest`, stdout grepped for `parsing error`): 36/36 ·
      negative controls prove both gates can fail · schema phase 25/25 →
      `validate_configs.py` **1437/1437 passed, rc=0** (log: /tmp/opencode/m1-validate.log)
- [x] Two-charon probe established (D9/D11): tunnel, transport (host TS),
      IKEv1 MM, NAT-T, AH, ESN, replay-0, 3DES/SHA1/modp1024 all proven
      end-to-end with packets on the wire
- [x] `switch-variant.sh` dynamic variant discovery (all 18 listed, invalid
      rejected); compose `${VARIANT:-v1}` + entrypoint-order fix +
      transit-net addressing; `docker compose config -q` OK
- [x] DECISIONS D8–D11 appended; probe containers cleaned up

## M2 — Data generation

- [x] Real captures: 42 pcaps (`data/real`, v1×2 runs + v3/v5/v7/v12/v18 × 6 types), netns-in-container testbed (D3/D12), SAs verified ESTABLISHED/INSTALLED; documented in `docs/testbed-known-issues.md`
- [x] Traffic generators (`testbed/traffic/live_gen.py`): 6 types with spec payloads; synthetic mirrors the same schedules
- [x] Synthetic generator rewritten to spec (`capture/synth/synth_pcap.py`, imports `testbed/matrix`): byte-realistic IKEv2 (true transform IDs, correct KE lens, nonces, SK, rekey KE iff PFS) on UDP 500 / 4500+marker for v18; ESP CBC/GCM/3DES with real crypto; AH; IKEv1 MM+QM; plain negatives; deterministic ESP keys; per-run seeds + jitter + randomized incidental fields
- [x] Anti-leakage audit (`capture/audit_leakage.py` → `docs/anti-leakage-audit.md`, D5 gate)
- [x] 402 pcaps (360 synthetic: 18×3×6 + plain 2×3×6; 42 real); `data/manifest.csv` (file,variant,traffic,ip_version,packets,esp_packets,ike_packets,source,valid)
- [x] `capture/validate_pcap.py` rewritten (D7): independent byte-level IKE parse + scapy + dpkt + tcpdump; `--self-test` 15/15 green; EVERY manifest row valid=true, rc=0
- [x] `docs/dataset-datasheet.md`

## M3 — AI classification engine

- [x] `engine/features/`: IKE/ESP/AH/NAT-T presence+counts, proposal parsing in clear, SPIs, seq behavior, size/IAT/burstiness/direction, ESP len mod 8/16, header layout, rekey/lifetime, ipver (bytes-only; hiding labels => identical output, tested)
- [x] `engine/classifier/`: deterministic parsers (enc/keylen/PRF/auth/DH/ike/esp-ah/nat-t/rekey-PFS/AH-mode) + RF models (traffic always, ESP mode, cipher-if-no-IKE); per-field `source` + confidence; `unknown` below 0.5/AH-absent-DH/IKEv1-PFS; AI Confidence Score
- [x] `engine/eval/`: grouped 5-fold CV (variant/run groups), synth->real (42, v1/v3/v5/v7/v12/v18 only), ESP-only ablation (IKE blinded pre-parse+pre-model) → docs/model-evaluation.md + 9 PNG plots; ~100%/chance cells explained in writing
- [x] `docs/security-rubric.md` (weighted 100, thresholds, NIST/RFC refs)
- [x] `engine/assess/`: Security 0–100, Risk, Threat Matrix, findings+severity, remediation; hand-computed oracle literals (v1=88, v7/v11=73, v8=75, plain=5) green
- [x] Metadata inference (duration/rate/size/direction_ratio measured + traffic_type model) in analyze()
- [x] `engine/api/`: POST /analyze, GET /health, GET /models, POST /report; Pydantic schemas; 50 MB cap, .pcap-only, temp cleanup
- [x] Models persisted to `engine/models/` (7 joblibs + classes/meta) + model_card.md; seed 7; requirements pinned (M0)
- [x] pytest: 17 tests (no-label features/predictions, IKE proposal parsing, assessment oracles, API) — all pass

## M4 — CLI, reports, API contract (no dashboard per D17)

- [x] Typer CLI installable via pyproject.toml: analyze [--json] [--report pdf], batch, train, evaluate, generate-data, serve [--mock] (entry point verified; tests per command green)
- [x] Executive PDF + 6 Technical PDFs (weak/AH/plain/real/IKEv1/GCM); comparative across 18 variants + plain (confidence, unknowns, caveat in every PDF)
- [x] Frozen API contract: `docs/api-contract.md` + `docs/openapi.json` + per-endpoint examples under `docs/examples/` (generated from the live app) + CORS local origins + mock mode with deterministic samples incl. unknown/mode-detail
- [x] Extra demo-data endpoints: `GET /variants`, `GET /datasets/samples` (tested)
- [x] Mode basis (addition 1): header-structure parse + size-overhead signal both reported; `mode.detail.decided_by` = ah-next-header|no-ipsec|size-overhead-model; API renders it, contract documents size-only case
- [x] Real PFS runs (addition 2): forced `swanctl --rekey` captures for v1/v3/v5/v7/v12/v18 (new r2/r3 runs); finding: strongSwan encrypts the whole CREATE_CHILD_SA (source + wire proof, D19), so PFS stays `unknown` on real — stated plainly, validator notes opaque rekeys
- [x] Real TCP eval (addition 3): +18 web/email/whatsapp captures as new runs; holdout eval (train synth + real r1 → test real r2/r3, runs apart) reported separately with sample counts
- [x] `scripts/e2e.sh`: clean worktree + fresh venv → generate → validate-gate → train → API → CLI → reports → tests → git-archive quickstart; exit 0 (e2e found unpinned cryptography + samples short-fill + serve import — all fixed, final run green)
- [x] Repo hygiene: 249 tracked (<2000), .git 11 MB (<100 MB); models+pcaps+tarball out of git; 12 committed demo samples; dataset tarball (92 MB, 919 entries, checksums 0 failures) verified
- [x] Demo: `demo/DEMO_SCRIPT.md` + recorded `demo/demo.typescript` (replay verified, 0 tracebacks)

## M5 — Final polish and packaging

- [x] docs/: architecture (Mermaid), testbed guide, datasheet, classification+security methodology, API ref (contract+openapi), CLI guide, reproduction, limitations, traceability, QA_PREP, frontend-handoff, self-review
- [x] dataset/ package: train/test/real manifests (grouped), checksums (0 failures), README + tarball build script
- [x] Demo = CLI + API terminal walkthrough: `demo/DEMO_SCRIPT.md` + recorded typescript (replay-verified, 0 tracebacks)
- [x] README.md quickstart (incl. tarball notes for data/real)
- [x] SUBMISSION_CHECKLIST.md (each line verified on final tree just now)
- [x] FINAL_REPORT.md (metrics: 426 corpus, CV/ablation/holdout tables, oracles)
- [x] README quickstart tested from fresh `git clone` + fresh venv (rc=0)
- [x] Fresh-clone + final e2e green, then final commit + tag; clean tree; no secrets

## Integration task (friend frontend + live backend)

- [x] Inspection (step 0): remote `github.com/HarshitGbu/sih-frontend-`,
  `d2b0d87`, node 24/npm 12; mock-default confirmed; `/api/*`+WS gaps found
- [x] Hygiene (step 1): snapshot vendored (`.git` removed, SOURCE.md,
  .gitignore); 237 files, .git 15 MB
- [x] Contract diff (step 2): `docs/frontend-integration.md` (24-row table)
- [x] Live wiring (step 3): `backend.ts` mapper, real paths, VITE_API_URL,
  runtime Mock/Live toggle, SIMULATED badges, CORS :5173/:4173 (+test)
- [x] Verify (step 4): npm ci/lint/typecheck/test/build green; 6-file
  live integration test green vs real API; CLI≡API; UI+API served with
  CORS preflight green; backend pytest + e2e --quick green
- [x] Demo+docs (step 5): run_demo.sh verified (trap clean); README UI
  section; dashboard/README, handoff, SUBMISSION/FINAL updated
- [x] Release (step 6): fresh-clone backend+frontend green → tag final-5

## Post-freeze fix (test hermeticity + touch-ups, tag final-3)

- [x] `test_analyze_report_pdf` order-dependence: sole test writing into
  `data/` — hardened with tmp_path isolation everywhere + cwd/env
  restore fixture (`engine/tests/conftest.py`); failing assertion
  captured from a read-only-tree run before fixing
- [x] Full suite 3× green + `-p no:randomly` + reverse file order green
- [x] QA_PREP Q16 (73 vs 88 oracle-vs-live); AGENTS 426/426; reproduction 66 real
- [x] Final e2e green → tag final-3, freeze holds
- Hygiene at final-3: 237 tracked files (<2000), .git 15 MB (<100 MB)

- [x] SK-only synthetic rekeys (real parity) + deterministic IKE keys; validator decrypts AUTH/rekey inners; PFS = rekey-length model gated on rekey presence
- [x] MAJOR-3: counts corrected (360/66/426, 853 checksums) + doc-count guard + byte-for-byte regen test
- [x] MAJOR-4: 21 samples, docs/expected-live-scores.md, pinning test; oracle-vs-live note (rubric untouched)
- [x] MAJOR-5: tarball rebuilt from current output (0 failures); RNG ike|data stream split
- [x] MAJOR-2: legacy ipsec.secrets out of tree (history kept), REDACTED placeholders, gen_secrets.py deploy fill (netns-up hook, container-verified), no-secrets-in-git gate (1474/1474)
- [x] MAJOR-1: dashboard/README.md pointer (no dashboard built)
- [x] MINORs: attempted-accuracy labeled; .PCAP casefold (+test); AH/no-rekey unknown (+test/docs); checksum commands verified; demo-video note
- [x] Reports + contract examples regenerated; e2e restores real data from tarball
- [x] Final e2e green → tag final-2, freeze (bug fixes only)
- Hygiene at freeze: 236 tracked files (<2000), .git 14 MB (<100 MB)

---

## Session log

- **2026-09-30** M1: two-charon probe (m1net lab) resolved the transport-mode
  addressing question empirically (subnet TS → TS_UNACCEPT; host TS → INSTALLED,
  ESP captured; source `child_cfg.c:284` + `check_mode()` explain it → D9) and
  proven tunnel/IKEv1/NAT-T/AH/ESN/replay-0/3DES-SHA1-modp1024 end-to-end (D11).
  Built `matrix.py` (18 variants) + `gen_configs.py` + `validate_configs.py`
  (6 phases incl. negative controls → **1437/1437**, D8/D10), rewrote
  `DESIGN.md`, `label_schema.json`, fixed `switch-variant.sh` (dynamic list),
  compose (`${VARIANT:-v1}`, transit-net 10.30.0.0/24 static addressing,
  entrypoint override) and `entrypoint.sh` (charon-before-load order,
  initiate retry). DECISIONS D8–D11 appended.
- **2026-09-30** M0: env inventory executed (DECISIONS D1), git init, venv (py3.12.13) + 82 pkgs pinned & installed, smoke imports + WeasyPrint render verified, prior work copied per D2, PLAN/DECISIONS/PROGRESS written. Prior attempt located at sih-2/ipsec-analysis (Phase 1 done, Track A degraded, 114 synth pcaps, engine empty) — reused selectively.

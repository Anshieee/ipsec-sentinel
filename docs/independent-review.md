# Independent review — AI-driven IPsec VPN analysis platform

Reviewer stance: no prior context, working tree only. Verified by running
commands, not by reading claims. The only file written by this review is
this one (`git status` was clean before and after; all scratch output went
to `/tmp/opencode/rev/`).

Environment: repo `.venv` (Python 3.12.13), system Python 3.14, `tcpdump`
present, `tshark` absent, `docker` working (`ss-verify` + `testbed-strongswan`
containers up), no passwordless sudo, `uv` present.

## Verdict

The core pipeline is real and end-to-end working: testbed configs validate,
426 pcaps validate, the classifier runs on samples with honest `unknown`s,
the API/CLI behave, gates pass. No BLOCKERs. The gaps are: no dashboard
artifact at all, lab secrets committed to git, stale corpus numbers in
entry-point docs, oracle security scores that the live tool never reproduces,
and a dataset tarball that no longer matches generator output.

## What passed (command + result)

- ` .venv/bin/python -m pytest tests/ engine/tests/ -q` → **27 passed**, rc=0.
- `.venv/bin/python testbed/validate_configs.py` → **1437/1437 checks passed**, rc=0
  (M1 gate, ran against the live `ss-verify` container).
- `.venv/bin/python capture/validate_pcap.py` → **426/426 valid**, rc=0;
  `data/manifest.csv` byte-identical after the run. `--self-test` → 0 failures.
- `engine/tests/test_no_labels.py` + `test_predict_no_labels.py` → 3 passed:
  hiding `data/labels` + manifest leaves features and predictions bit-identical,
  and no endpoint value (IP/MAC/SPI/cookie/epoch) appears in features.
- CLI: `ipsec-analyze analyze data/pcaps/synth/v1/r1/voip.pcap` → correct
  parsed fields (ikev2/esp/aes-128-cbc/dh14), `pfs`/`mode`/`traffic_type` as
  model with confidence, security 73/risk 27. AH (`v7`), IKEv1 (`v12`,
  `pfs: unknown`), transport (`v5`), IPv6 (`v6`), plain negatives all classify
  sensibly. Bad inputs: non-pcap → error, missing → error, empty → error.
  `batch` on a dir with a corrupt pcap records per-file error and continues
  (`== .../bad.pcap: exit 1`, good file still analyzed, rc=0).
  `analyze --report pdf` writes a real multi-page PDF (verified via `pdftotext`).
- API (TestClient + live `uvicorn engine.api.app:app` on :8129): `/health`
  ok, `/models` ok, `/analyze` 200 with `fields/ai_confidence/metadata/
  assessment{security_score,risk_score,threat_matrix,findings[].solution}`.
  `evil.txt` → 400, `a.pcap.exe` → 400, garbage bytes as `.pcap` → 422 with
  reason, `../../evil.pcap` name accepted but safely written via `tempfile`
  (no traversal — filename never joins a path). 50 MB cap enforced by chunked
  pre-read; oversize test (51 MB → 413) exists in `engine/tests/test_api.py`.
  `openapi.json` paths match live routes (`/analyze /health /models /report
  /variants /datasets/samples`).
- `tcpdump -nn -vvv -r` on synth + real pcaps: IKE_SA_INIT transforms in the
  clear on **both** (RFC-legitimate; the real strongSwan capture shows the same),
  ESP payloads opaque — a needle scan for `LOGIN/RETR/RTP/GET /psk-/variant/
  SMTP` across ESP bytes found only 2-byte `v1` coincidences at the rate
  expected for random bytes (~4 hits / ~80 KB), no cleartext leakage.
- `sh scripts/e2e.sh --quick` → `E2E OK`, rc=0 (clean worktree + fresh venv).
- `cd /tmp/opencode/rev && tar -xzf dataset/ipsec-dataset-v1.tar.gz &&
  sha256sum -c checksums.sha256` → **853 OK, 0 FAILED**. Tarball is
  self-consistent (see MAJOR-5 for the caveat).
- `reports/out/` (8 PDFs) are real ReportLab PDFs with classification tables,
  confidence, and caveats (`pdftotext` verified).
- `git log -p` secret scan: no keys/tokens/private-keys; no hardcoded
  `/home|/root|C:\` paths in `engine/ capture/ cli/ testbed/`. Evaluation
  tables all carry sample counts (`n`, train/test splits stated).

## MAJOR

### MAJOR-1 — No dashboard artifact; `dashboard/` is an empty directory
Requirement (e)/deliverables asks for an interactive dashboard; the problem
statement lists it as a deliverable. There is no Streamlit app, no page, no
screenshot in this repo.
```
$ ls -la dashboard/
total 0
```
Mitigation present (`docs/frontend-handoff.md`, frozen `docs/openapi.json`,
`serve --mock`), but that is documentation for a separately-built frontend,
not a working artifact. A fresh-clone reviewer cannot run any dashboard.

### MAJOR-2 — Lab PSKs committed to git history
`testbed/configs/*/gw-*/ipsec.secrets` (36 files) are tracked and contain
working pre-shared keys, violating the build prompt's own "never commit
secrets" rule. Baked into history and tag `final`.
```
$ git ls-files testbed/configs | head -4
testbed/configs/v1/gw-a/ipsec.conf
testbed/configs/v1/gw-a/ipsec.secrets ...
$ cat testbed/configs/v1/gw-a/ipsec.secrets
gw-a gw-b : PSK "psk-422bf0b21f2b5825"
```
Impact is limited (test-only credentials, derivation function `matrix.psk_for`
is equally public), but secret material in git is permanent; test creds
should be generated at deploy time and gitignored.

### MAJOR-3 — Stale corpus counts in entry-point docs (claim vs evidence)
Actual corpus (measured): 360 synthetic + **66** real = **426** rows.
```
$ .venv/bin/python -c "import csv; ..."   # Counter({'synthetic': 360, 'real': 66})
```
Docs still claim the old 42/402 numbers:
- `README.md:12`: `generate-data --real   # 360 synthetic + 42 real labels`
- `README.md:47`: `42+ real captures ... are the only out-of-distribution evidence`
- `docs/dataset-datasheet.md:4`: `Corpus: 402 pcaps — 360 synthetic + 42 real`
- `docs/model-evaluation.md:83`: `The 42 real pcaps are the only ... evidence`
- `AGENTS.md:58`: `fold 42 real pcaps -> labels, rebuild manifest (402 rows)`
- `dataset/README.md:12`: `checksums verified (0 failures, 919 entries)` —
  `dataset/checksums.sha256` has **853** lines.
The evaluation *tables* (n=66 synth→real) are correct; the prose around them
is wrong, including the README quickstart a new user follows first.

### MAJOR-4 — Oracle security scores are not what the live tool outputs
`engine/tests/test_assess.py` asserts v1=88, but the CLI/API report **73**
for a v1 capture:
```
$ .venv/bin/ipsec-analyze analyze data/pcaps/synth/v1/r1/voip.pcap
  security 73/100 risk 27 (medium)
  [medium] SA lifetime unknown: assuming weak.
  [medium] Replay state unknown: assuming weak.
```
Root cause: oracles call `assess(classification, lifetimes)` with **label**
lifetimes/replay windows (`test_assess.py: classify_from_label`), while the
live path calls `assess(out)` with `lifetimes=None` (`engine/api/app.py:
to_response`, same in CLI), so every live analysis eats the unknown-lifetime
and unknown-replay penalties. The rubric documents conservative scoring of
unknowns, but there is **no variant → expected-tool-output table** anywhere,
and `FINAL_REPORT.md` cites `v1=88` without noting the tool itself reports 73.
Related: the M3 requirement "expected-score table for every variant,
unit-tested" is covered only for 5 of 19 variants (v1/v7/v11/v8/plain);
orderings are tested for all, exact scores are not.

### MAJOR-5 — Dataset tarball diverges from current generator output
Manifests agree (both 426 rows, same 360/66 split), but pcap bytes differ:
```
$ sha256sum data/pcaps/synth/v1/r1/voip.pcap
5920f1b1...  data/pcaps/synth/v1/r1/voip.pcap
$ grep "pcaps/synth/v1/r1/voip.pcap" dataset/checksums.sha256
6be0d121...  pcaps/synth/v1/r1/voip.pcap
$ diff <tarball labels/.../voip.json> <local labels/.../voip.json>
<   "packet_count": 407        >   "packet_count": 405
```
The tarball is internally consistent (853/853 OK), but it is a stale snapshot:
regenerating with the current (`deterministic`, per-docs) generator does not
reproduce it. Rebuild the tarball via `scripts/build-dataset.sh` before
handing the dataset anywhere (FINAL_REPORT's own double-check #4).

## MINOR

### MINOR-1 — FINAL_REPORT headline metrics use different denominators than the tables
`FINAL_REPORT.md:13-14`: `traffic 0.994; PFS-length model 1.000 (v12 abstains)`.
`docs/model-evaluation.md` tables: traffic acc **0.9861**, pfs acc **0.95**
(both count `unknown` as errors, as the doc states). 1.000 is accuracy-*given-
attempted* (18 v12 abstentions excluded); 0.994 matches no full-table cell
(closest: ESP-ablation macro-P 0.9946). Reconciliation is possible, but the
report never states the exclusion — headline numbers look better than the
tables under the tables' own scoring rule.

### MINOR-2 — Upload suffix check is case-sensitive
`engine/api/app.py:78`: `if not filename.endswith(".pcap")` → `VOIP.PCAP`
uploads get 400 (`upper-PCAP: 400 {"detail":"only .pcap uploads accepted"}`).
Trivial robustness nit (casefold the suffix).

### MINOR-3 — AH `pfs: False` at 0.55 confidence looks like a guess
`analyze demo/samples/v7-ah-voip.pcap` → `pfs False model 0.55` with
`[high] No PFS` fired. The 0.5 `UNKNOWN_THRESHOLD`
(`engine/classifier/model.py:24`) barely keeps this a prediction; for AH
(where PFS semantics are murky) `unknown` would be more honest. Live score
for v7 is 48 vs oracle 73 (compounds MAJOR-4).

### MINOR-4 — Checksum verify command not documented with the correct cwd
`sha256sum -c dataset/checksums.sha256` from the repo root fails (853
`No such file` — entries are relative to the tarball root, i.e. `data/`
layout). `dataset/README.md` should print the exact command
(`tar -xzf ... -C <dir> && cd <dir> && sha256sum -c checksums.sha256`).

### MINOR-5 — Demo video deliverable is a fallback, not a video
`demo/` holds `DEMO_SCRIPT.md` + replay-verified `demo.typescript` (4.6 KB)
+ 12 samples; no MP4 exists (`find . -name '*.mp4'` → nothing). Acceptable
fallback per the build prompt's own ladder, honestly declared — but the
"demo video" requirement has no video artifact.

## Requirement traceability (problem statement a–e + deliverables)

- (a) testbed variations — YES: 18-variant matrix (`testbed/matrix.py`
  self-check prints all variants incl. weak DH2/DH5, SHA1, 3DES, IKEv1,
  short/long lifetimes, replay-off, ESN on/off, NAT-T, AH); configs +
  1437-check gate green. Real netns scripts present; 66 real captures prove
  the testbed ran.
- (b) captures IKE/ESP/AH/plain — YES: 426 pcaps, tcpdump-verified by hand
  (IKEv2 init/auth, rekeys, ESP/AH, plain negatives); validator triple-parses
  (scapy + dpkt + tcpdump counts).
- (c) AI identification — YES, with honest bounds: parsed where visible
  (proposal/KE/rekey/AH/version/NAT-T, 1.000 incl. real), modeled where hidden
  (traffic/mode/cipher-without-IKE/PFS-by-length), `unknown` otherwise
  (DH-without-IKE, real PFS, lifetimes). Grouped-by-run CV + ablations +
  synth→real + holdout, all with sample counts. TCP traffic abstains (0 wrong).
- (d) security assessment — YES, with MAJOR-4 caveat: rubric implemented,
  scores/threat-matrix/findings/remediation all present in API JSON, CLI, and
  PDFs; oracles pass but describe label-fed, not live, scores.
- (e) outputs — YES: security/risk scores, traffic analysis, metadata
  inference, executive + technical + comparative PDFs (8), threat matrix, AI
  confidence, remediation text — all observed in real outputs.
- Deliverables: prototype YES, AI engine YES, dataset YES (MAJOR-5),
  assessment report YES, demo PARTIAL (MINOR-5), docs YES (MAJOR-3 staleness),
  **dashboard NO (MAJOR-1)**.

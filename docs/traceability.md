# Problem-statement traceability (M5 fix 4)

Original statement items (a–e + deliverables) → file → verification.
Partial coverage is marked honestly.

## a. Testbed variations
21-variant matrix incl. tunnel/transport, AES-128/256-CBC+SHA256,
AES-128/256-GCM, DH 14/19/20 + weak DH2/DH5, SHA1, 3DES, IKEv1, short/long
lifetimes, replay off, ESN on/off, NAT-T, AH, IKE/ESP mismatch.
→ `testbed/matrix.py` + `testbed/DESIGN.md`
→ `.venv/bin/python testbed/matrix.py` (self-check table) and
→ `.venv/bin/python testbed/validate_configs.py` (M1 gate 1717/1717).

## b. Capture
Real (66 pcaps, netns testbed, SAs verified) + synthetic (414 pcaps).
→ `testbed/scripts/real-{run,rekey,tcp}.sh`, `capture/synth/synth_pcap.py`
→ `ls data/real/*/*/ | wc -l` (66) + `capture/validate_pcap.py` (rc=0,
480/480 rows valid).

## c. Identification fields
Parsed where visible (proposal/KE/rekey/AH/IKE version/presence/NAT-T),
modeled where hidden (traffic, ESP mode, cipher-if-no-IKE, PFS-by-length),
unknown otherwise (DH-without-IKE, real PFS, lifetimes).
→ `engine/classifier/{parse,model,predict}.py`
→ `pytest engine/tests/test_parse.py` + `docs/model-evaluation.md`
(PARTIAL: unknown fields documented, not guessed).

## d. Security assessment criteria
Weighted rubric (cipher/DH/integrity/PFS/lifetime/replay/IKE/mode),
threat matrix, findings + remediation.
→ `docs/security-rubric.md`, `engine/assess/assess.py`
→ `pytest engine/tests/test_assess.py` (hand-computed oracles).

## e. Outputs
JSON API + CLI + executive/technical/comparative PDFs.
→ `engine/api/app.py`, `cli/main.py`, `reports/build.py`
→ `scripts/e2e.sh` (exit 0 incl. API/CLI smoke + PDF build).

## Deliverables
- Dataset (+manifest/labels/splits/checksums): `dataset/` +
  `ipsec-dataset-v1.tar.gz` (artifact, checksums 0 failures).
- Trained models: `engine/models/` (rebuilt by `train`, seed 7).
- Evaluation: `docs/model-evaluation.md` + `docs/plots/` (PARTIAL: real
  coverage is 6 variants / 66 pcaps; synthetic-only limits stated).
- API contract + mock: `docs/api-contract.md`, `openapi.json`,
  `docs/examples/`, `serve --mock`.
- Demo: `demo/DEMO_SCRIPT.md` + recorded typescript (no dashboard: D17).

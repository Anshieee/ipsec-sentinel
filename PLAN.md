# PLAN — AI-driven IPsec VPN Protocol Analysis Platform

Authoritative requirements: `OpenCode_Build_Prompt.md` (read in full before working).
This file records *how* this repo implements them. Update when decisions change.

## Architecture and data flow

```
testbed/   Docker-based IPsec testbed (variant matrix, strongSwan configs,
           traffic generators) + netns-in-container topology for real captures
   │
capture/   real (tcpdump) + synthetic (synth/synth_pcap.py) pcap generation
   │       validate_pcap.py gates every manifest row
   ▼
data/pcaps/  pcaps + label JSONs + manifest.csv
   │
engine/
   ├ features/    deterministic IKE/ESP/AH/NAT-T parsers + traffic statistics
   ├ classifier/  parsed-first hybrid; ML for inferred fields; per-field
   │              confidence with source: parsed|model; "unknown" when low
   ├ eval/        grouped-by-run splits, CV, per-field P/R/F1, ablations
   ├ assess/      security rubric → Score 0-100, Risk Score, Threat Matrix,
   │              findings + remediation; oracle unit tests
   └ api/         FastAPI: POST /analyze, GET /health, GET /models, POST /report
      │
      ├ dashboard/  Streamlit + Plotly (6 pages)
      ├ cli/        Typer: analyze / batch / train / evaluate / generate-data
      └ reports/    Jinja2 → WeasyPrint PDFs (reportlab fallback verified)
```

## Tech stack (verified installed in `.venv`, Python 3.12.13)

- Parsing: scapy 2.7.0 + dpkt 1.9.8 (independent double-parse for validation)
- ML: scikit-learn 1.9.1, xgboost 3.4.1, lightgbm 4.7.0
- API: FastAPI 0.142.1 + uvicorn; schemas: pydantic 2.13.5
- Dashboard: streamlit 1.64.0 + plotly 7.1.0
- CLI: typer 0.27.2
- Reports: jinja2 + weasyprint 70.0 (render verified), reportlab 5.0.1 fallback
- Tests: pytest 9.1.1 (+ httpx for API tests)
- Env: `uv venv --python 3.12 .venv`; install via `uv pip install --python .venv/bin/python -r requirements.txt`
  (uv does **not** seed pip into the venv — `.venv/bin/pip` does not exist)

## Directory layout

- `testbed/` — DESIGN.md, variants/v1..v6 (swanctl + legacy ipsec.conf), Docker assets, `traffic/` generators, `scripts/`
- `capture/` — synth generator, validator, matrix runner, labeling, feature scratch
- `data/pcaps/` — working dataset (pcaps, labels, manifest); released package goes in `dataset/`
- `engine/` — features, classifier, eval, assess, api, `models/` (persisted + model_card.md)
- `docs/` — design/, review/, methodology, datasheet, evaluation
- `dashboard/`, `cli/`, `reports/`, `tests/`, `scripts/`

## Data schema

- Label JSON per pcap: variant id, ipsec_proto, ike_version, mode, enc_alg,
  enc_key_len, auth_alg, dh_group, pfs, ip_version, traffic_type,
  source real|synthetic, run_id, duration, packet_count
- `manifest.csv` columns (per spec): file, variant, traffic, ip_version,
  packets, esp_packets, ike_packets, source, valid

## Milestones (acceptance criteria live in PROGRESS.md)

- M0 Bootstrap — done when: git repo, pinned deps verified by execution, memory files written
- M1 Testbed design — variant matrix incl. weak coverage (DH2/DH5, SHA1, 3DES, IKEv1 MM, replay off, ESN, NAT-T, AH), both gateways' configs, label schema
- M2 Data generation — ≥15 variants ×3 runs ×6 traffic types → 300+ validated pcaps; real-capture attempt time-boxed or documented failure; datasheet
- M3 Engine — hybrid classification, grouped-split eval, rubric-based assessment + oracle tests, FastAPI, model_card
- M4 Surfaces — dashboard, CLI, PDFs (≥6 + comparative), e2e.sh from clean, screenshots
- M5 Polish — docs set, dataset package w/ checksums, demo video, README quickstart verified, submission checklist, final report, tag

## Risks and fallbacks

| Risk | Fallback |
|---|---|
| Real testbed (NET_ADMIN container) fails to ESTABLISHED | document in docs/review/testbed-known-issues.md; synthetic-only, labeled honestly |
| WeasyPrint system-lib issue at runtime | reportlab (verified installable) |
| Python 3.12 wheel issue | 3.14.7 available; full dep set dry-run resolves on cp314 |
| Near-perfect eval score | assume label leakage, audit before reporting (spec rule) |
| 2 CPUs / ~4 GiB free RAM | n_jobs=2, modest hyperparameters |

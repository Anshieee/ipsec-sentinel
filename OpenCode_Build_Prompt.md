# TASK: Plan and build the AI-driven IPsec VPN Protocol Analysis Platform (autonomous, single-agent)

You are the sole engineer on this project. Work autonomously from planning through delivery. No one is available to answer questions: make sensible decisions, record them, and keep going until everything below is finished and verified. Time and token cost are irrelevant; **correctness, honesty and quality are the only goals.**

Work only inside the current working directory (the project folder). It contains earlier work copied from a previous attempt. **Inspect it first, reuse what is good, fix or replace what is not.** Ignore any files that are not part of this project (tooling or orchestration leftovers, logs, hidden state folders); do not build on them and do not modify them.

---

## 1. PROBLEM STATEMENT

Build an AI-driven platform that automatically analyses IPsec VPN deployments.

a) **VPN testbed generation**: a lab environment with variations: Tunnel mode, Transport mode; AES-128, AES-256, AES-GCM, AES-CBC + HMAC; different DH groups; PFS enabled/disabled; IPv4 and IPv6; traffic types: VoIP, WhatsApp-like messaging, Email, Web, ICMP, Video streaming.
b) **Traffic capture**: Wireshark/tcpdump-style pcaps of IKE negotiation, ESP packets, AH packets, normal (non-IPsec) communication.
c) **AI-based protocol identification**: automatically identify IPsec protocol (ESP/AH), IKE version, tunnel/transport mode, encryption and authentication algorithms, key exchange method / DH group, SA characteristics, and the type of traffic inside ESP.
d) **Security assessment**: cryptographic strength, configuration compliance, SA parameters, key lifetime, replay protection, forward secrecy, cipher suite strength, metadata exposure.
e) **Outputs**: Security Score, traffic analysis, metadata inference, Executive report, Technical report, Risk Score, Threat Matrix, AI Confidence Score, Expected Solutions (remediation).

**Deliverables:** working prototype, AI classification engine, interactive dashboard, security assessment report, demo video, technical documentation, training/testing dataset.

---

## 2. RULES OF ENGAGEMENT

1. **Plan first, then build.** Your first output is a written plan (section 3). Then execute it step by step.
2. **Persist your memory in files.** Your context will fill up. Keep `PLAN.md` (architecture, milestones), `PROGRESS.md` (checklist with verified status, current step, next step, decisions with reasons) and `DECISIONS.md` up to date after every meaningful step. At the start of every session/turn, re-read them.
3. **Verify, never assume.** After writing code, run it. A milestone is complete only when you have executed the tests/commands and read the real output. Never mark something done because it "should work".
4. **Be honest.** No fabricated metrics, no fake data presented as real, no placeholder outputs. Label synthetic data as synthetic everywhere. If a score is suspiciously perfect (e.g. 100 % accuracy), assume label leakage and investigate before reporting.
5. **Keep going.** Do not stop after a phase to ask for confirmation. If a step fails, diagnose, fix, retry; after three failed attempts with the same approach, change approach and record why. If something truly needs a human (e.g. root access, missing system package you cannot install), write it to `NEEDS_HUMAN.md`, use the best safe fallback, and continue.
6. **Use subagents/parallel tools if available** for independent work (e.g. reviewing your own code, writing tests, drafting docs), but you remain responsible for verifying results.
7. **Git hygiene.** Initialize git if needed, commit at each verified milestone with clear messages, add a `.gitignore` (venvs, caches, logs, large generated artifacts), never commit secrets, never rewrite history.
8. **Shell limits.** Commands may time out; run long jobs in the background with output redirected to a log file and poll the log. Keep individual commands short.
9. **Environment first.** Before designing, check what exists: OS, Python version, `pip`, `scapy`, `tcpdump`, `tshark`, `ffmpeg`, `docker`, `ip netns`, root/sudo availability (`sudo -n true`), `strongswan`/`swanctl`/`ipsec`. Record findings in `DECISIONS.md`. Prefer `pip install --user` / a virtualenv; do not assume you can install system packages.

---

## 3. STEP 0: INVESTIGATE, THEN WRITE THE PLAN

1. Inventory the project folder (tree, git log, existing docs, code, data). Determine what already exists and its quality. Existing material may include: a project skeleton, a testbed design with six IPsec variants (strongSwan configs), traffic generator scripts, capture and validation scripts, a security scoring rubric with expected scores, dashboard wireframes, and a synthetic pcap generator with a generated dataset. **Treat all of it as unverified**: run it, read it, keep what passes, fix or rewrite the rest.
2. Write `PLAN.md` covering: architecture (components and data flow), tech stack, directory layout, data schema, milestones with acceptance criteria, risk list and fallbacks. Suggested stack (change with justification): Python 3.11+, Scapy/dpkt for pcap parsing, scikit-learn (+ XGBoost/LightGBM if installable) for ML, FastAPI for the engine API, Streamlit + Plotly for the dashboard, Typer for the CLI, Jinja2 + WeasyPrint/reportlab for PDF reports, pytest for tests.
3. Write `PROGRESS.md` with every milestone below as a checklist.

---

## 4. MILESTONES (execute in order; verify each before moving on)

### M1: Testbed design and configuration
- Document the variant matrix in `testbed/DESIGN.md`. The minimum set covers: Tunnel and Transport; AES-128-CBC+HMAC-SHA256, AES-256-CBC+HMAC-SHA256, AES-128-GCM, AES-256-GCM; several DH groups (e.g. 14, 19, 20); PFS on/off; IPv4 and IPv6. Example baseline: v1 Tunnel/IPv4/AES-128-CBC+SHA256/DH14/PFS on; v2 Tunnel/IPv4/AES-256-CBC+SHA256/DH20/PFS on; v3 Tunnel/IPv4/AES-128-GCM/DH14/PFS off; v4 Tunnel/IPv6/AES-256-GCM/DH20/PFS on; v5 Transport/IPv4/AES-256-GCM/DH19/PFS on; v6 Transport/IPv6/AES-256-CBC+SHA256/DH14/PFS off; plus an AH variant.
- Provide strongSwan configs (swanctl format, and legacy `ipsec.conf` if the installed strongSwan requires it) for both gateways of each variant, topology and addressing (IPv4 and IPv6), and the ground-truth label schema (JSON: variant id, ipsec protocol, IKE version, mode, encryption algorithm and key length, auth algorithm, DH group, PFS, IP version, traffic type, source real|synthetic, run id, duration, packet count).
- Include weak-to-strong coverage so the security assessment is meaningful: DH2/DH5 (insecure/weak), SHA1 integrity, 3DES, IKEv1 main mode, short and long lifetimes, replay protection off, ESN on/off, NAT-T.

### M2: Data generation
- **Real captures (attempt, time-boxed):** if root is available non-interactively and strongSwan is installed (or installable), build a Linux network-namespace testbed (`ip netns` + veth pairs, one charon instance per gateway namespace with separate config and socket paths, topology client-a — gw-a — gw-b — client-b, tcpdump on the gateway link). Do not use Docker unless it is already working. Scripts: `testbed/scripts/netns-up.sh <variant>` / `netns-down.sh`. Confirm SAs are ESTABLISHED/INSTALLED before generating traffic. If it cannot be made to work in a reasonable time, document exactly why in `docs/testbed-known-issues.md` and continue with synthetic data.
- **Traffic generators** for all six types (VoIP RTP-like UDP at 20 ms with ~160 B payload; video with bursty 1200–1400 B packets in 2 s segments; web request/response bursts; email SMTP/IMAP with occasional large attachments; WhatsApp-like small bidirectional TLS messages plus sparse media blobs; ICMP of 64/512/1400 B).
- **Synthetic pcap generator (`capture/synth/synth_pcap.py`, Scapy)** that needs no VPN software: realistic IKEv2 on UDP 500 (and 4500 with the non-ESP marker for a NAT-T subset): IKE_SA_INIT request/response with SA proposal carrying the variant's true transform IDs (ENCR with key length, PRF, INTEG, DH group), KE payload of the correct length for the DH group, nonces; IKE_AUTH request/response with encrypted payload of realistic length; at least one CREATE_CHILD_SA rekey (KE payload only when PFS is on). Correct IKEv2 header fields (SPIs, version, exchange type, flags, message ID). ESP (IP proto 50) with SPI, incrementing sequence numbers, encrypted random payload with correct structure (CBC: 16-byte IV, pad to 16-byte blocks with pad-length and next-header trailer, 16-byte ICV; GCM: 8-byte IV, 16-byte ICV); tunnel mode has an outer IP header, transport mode does not; IPv4 and IPv6. AH (IP proto 51) packets for an AH subset. IKEv1 main-mode sequences for a subset. Plain (non-IPsec) negatives.
- **Anti-leakage rules (mandatory):** randomize SPIs, addresses within subnets, non-IKE ports, start times and other incidental fields per run; no incidental field may uniquely identify a variant; jitter (±10–30 %) and per-run seeds; do not encode labels in anything the classifier can see.
- **Target size:** at least 15 variants, 3+ runs × variants × 6 traffic types, 300+ pcaps in total, with labels and `manifest.csv` (file, variant, traffic, ip_version, packets, esp_packets, ike_packets, source, valid).
- **Validation script `capture/validate_pcap.py`:** checks IKE_SA_INIT/IKE_AUTH presence, transform IDs match the label, KE lengths, rekey present, ESP SPI matches label, ESP structure, tunnel/transport header layout, AH presence for AH runs, negatives contain no IPsec, packet counts match. Use tshark if available; otherwise `tcpdump -nn -vvv -r` and independent Scapy/dpkt parsing. Every manifest row must be valid.
- Document the dataset in `docs/dataset-datasheet.md` (composition, generation, labels, splits, limitations, real vs synthetic).

### M3: AI classification engine (`engine/`)
- **Feature extraction (`engine/features/`):** counts and presence of IKE/ESP/AH/NAT-T; IKE version, exchange types, flags; parse IKE SA proposals in the clear from IKE_SA_INIT (transform IDs, key lengths, DH group from transform and KE length, responder's selected proposal); SPIs; ESP sequence behavior (replay window hints, ESN hints); packet size distribution, inter-arrival statistics, burstiness, direction ratios; ESP length modulo 8/16 patterns (CBC vs GCM); outer/inner header layout for tunnel vs transport; rekey detection and observed SA lifetime; IPv4/IPv6.
- **Hybrid classification:** deterministic parsers for everything visible on the wire, plus ML models (RandomForest/GradientBoosting, XGBoost/LightGBM if available) for inferred fields (mode, cipher family when IKE is absent, traffic type inside ESP, PFS from rekey behavior, DH group with partial information). Multi-output fields: `ipsec_proto, ike_version, mode, enc_alg, enc_key_len, auth_alg, dh_group, pfs, ip_version, traffic_type`.
- **Confidence:** per-field calibrated confidence with `source: parsed|model`; an overall **AI Confidence Score**; emit `unknown` instead of guessing when confidence is low.
- **Evaluation (`engine/eval/`):** split **grouped by capture run** (never split one pcap's packets or one run across train/test); cross-validation; per-field accuracy/precision/recall/F1; confusion matrices; feature importances; ablations (IKE visible vs ESP-only traffic inference, real vs synthetic if both exist); results and PNG plots in `docs/model-evaluation.md`. Investigate any near-perfect score for leakage and fix before reporting. State plainly what synthetic-only evaluation does and does not prove.
- **Security assessment (`engine/assess/`):** write `docs/security-rubric.md` (weighted criteria: cipher suite strength, DH group/curve strength, integrity algorithm, PFS, SA lifetime/rekey, replay protection, IKE version, mode-specific exposure, metadata exposure; thresholds; aggregation; references such as NIST SP 800-77r1, SP 800-57, RFC 8221, RFC 8247) and implement it: Security Score 0–100, Risk Score, Threat Matrix (likelihood × impact), findings with severity, and Expected Solutions (remediation text). Provide an expected-score table for every variant and unit-test the implementation against it.
- **Metadata inference:** what a passive observer can learn from ESP metadata alone (traffic-type guess, session duration, bitrate, direction), with confidence, feeding the metadata-exposure criterion.
- **API (`engine/api/`, FastAPI):** `POST /analyze` (upload pcap → JSON with classification, per-field confidence, assessment, threat matrix, traffic analysis), `GET /health`, `GET /models`, `POST /report`. Pydantic schemas.
- Persist trained models to `engine/models/` with a `model_card.md`. Deterministic seeds and pinned `requirements.txt`.
- Tests (pytest): feature extraction on known pcaps, IKE proposal parsing, classifier smoke test, assessment oracle tests, API tests. All pass.

### M4: Dashboard, CLI, reports
- **Dashboard (Streamlit + Plotly):** pages for Upload/Select PCAP + Analyze; Classification Result (fields with confidence bars, overall AI Confidence Score); Security Assessment (score gauge, Risk Score, Threat Matrix heatmap, findings table, Expected Solutions); Traffic Analysis (size histogram, timeline, bitrate, inferred traffic type, IKE handshake sequence diagram); Dataset & Model (metrics, confusion matrices); Reports (download Executive and Technical PDF). Sample pcaps and a "load demo" button. Consistent theme, severity colors, friendly error messages for empty/corrupt/non-pcap files.
- **CLI (Typer, installable via `pyproject.toml`):** `analyze <pcap> [--json] [--report pdf]`, `batch <dir>`, `train`, `evaluate`, `generate-data`.
- **Reports:** Executive report (1–2 pages: score, risk, top findings, recommendations) and Technical report (protocol details, SA parameters, cipher analysis, metadata inference, threat matrix, methodology, confidence, limitations); generate samples for at least 6 varied pcaps; plus a comparative security assessment report across all variants.
- `scripts/e2e.sh`: from a clean state → generate data → train → run API → run CLI on samples → produce reports → run tests. It must succeed.
- Take screenshots of the running dashboard (headless browser such as Playwright if installable) and iterate on visual polish.

### M5: Final polish and packaging
- Documentation in `docs/`: architecture (Mermaid/PNG diagrams), testbed guide, dataset datasheet, classification methodology, security methodology, API reference, user guide, reproduction steps, limitations and future work, honest description of every synthetic component.
- Dataset package `dataset/` with train/test manifests (grouped split), checksums, README.
- **Demo video:** try in order: scripted Playwright/Xvfb screen recording + ffmpeg; slideshow MP4 from screenshots with text overlays via ffmpeg; else write `demo/DEMO_SCRIPT.md` (shot list, narration, exact click path, timings) with screenshots and note in `NEEDS_HUMAN.md` that only the recording remains. Target 3–5 minutes.
- Polished top-level `README.md` with a quickstart that you actually test from a clean checkout in a fresh virtualenv.
- `SUBMISSION_CHECKLIST.md` (each deliverable → path → verified status), `FINAL_REPORT.md` (what was built, real metrics, limitations, what a human should double-check). Final commit and tag; clean working tree; no secrets.

---

## 5. SELF-REVIEW LOOP

After each milestone, and before finishing: (1) re-run all tests and validators; (2) review your own code critically as if you were an independent reviewer (correctness, edge cases, error handling, security of file upload handling, dead code); (3) review the dataset and evaluation for leakage and realism as a methodology reviewer would; (4) re-read section 1 and check every sub-requirement (a–e and each deliverable) has a concrete, working, verified artifact; (5) fix every gap found. Record findings and fixes in `PROGRESS.md`.

## 6. DONE CRITERIA (all verified by executing commands)

- [ ] Variant matrix documented; configs for all variants; real-capture attempt done and either delivered or its failure documented
- [ ] 300+ validated pcaps with labels and manifest (real vs synthetic clearly marked), datasheet written
- [ ] Classification engine working with per-field and overall confidence, grouped-split evaluation with real numbers, leakage checked
- [ ] Security assessment implements the rubric; Security Score, Risk Score, Threat Matrix, findings, Expected Solutions; oracle tests pass
- [ ] Metadata/traffic inference implemented and evaluated
- [ ] API, CLI and dashboard work end-to-end on sample pcaps; bad-input handling verified
- [ ] Executive and Technical PDF reports for multiple pcaps plus the comparative assessment report
- [ ] All tests pass; `scripts/e2e.sh` succeeds from clean; README quickstart verified
- [ ] Documentation complete; demo video produced (or script + screenshots + note)
- [ ] `SUBMISSION_CHECKLIST.md` fully checked; `FINAL_REPORT.md` written; clean git tree

When every box is verified, print a final summary. Until then, keep working.

## START NOW

Begin with the environment check and project inventory, write `PLAN.md` and `PROGRESS.md`, then proceed through M1 to M5 without waiting for confirmation.

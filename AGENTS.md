# AGENTS.md

## What this repo is

Greenfield project: an AI-driven IPsec VPN protocol analysis platform
(testbed variants, pcap capture/generation, ML classification, security
scoring, FastAPI + Streamlit + Typer CLI, PDF reports).

The single source of truth is `OpenCode_Build_Prompt.md`. Read it in full
before writing code — it contains the requirements, milestones M1–M5, done
criteria, and rules of engagement. Nothing in this repo implements it yet.

## Rules that matter

- **Before coding:** inventory the folder, then write `PLAN.md`,
  `PROGRESS.md`, `DECISIONS.md`. Re-read them at the start of every session
  and update after every meaningful step. Use `NEEDS_HUMAN.md` for blockers
  instead of stopping.
- **Verify, never assume.** A milestone is done only after running the
  command and reading real output. No fabricated metrics or data; label
  synthetic data as synthetic; investigate near-perfect scores for label
  leakage before reporting them.
- **Environment first** — check before designing: Python/pip/venv, scapy,
  tcpdump, tshark, ffmpeg, docker, `ip netns`, `sudo -n true`,
  strongSwan/swanctl. Prefer `pip install --user` or a venv; system package
  installs may be impossible. Record findings in `DECISIONS.md`.
- **Long commands:** run in the background with output to a log file and poll
  it; keep individual commands short. After 3 failed attempts with the same
  approach, change approach and record why.

## Leave these alone

`.claude/`, `.codex/`, `.agents/`, `.mcp.json` are orchestration leftovers,
not project code — do not build on or modify them. Their hooks reference
`/home/ansh/Projects/sih-2`, a different project; ignore failures from them.

## Once code exists

Record exact commands here as they become real (venv activation, `pytest`,
`scripts/e2e.sh`, dashboard/API launch) — do not write commands that have
not been executed yet.

Executed and verified (M1):

```bash
.venv/bin/python testbed/matrix.py            # variant matrix self-check table
.venv/bin/python testbed/gen_configs.py       # regenerate variants/ configs/ labels/
.venv/bin/python testbed/validate_configs.py  # M1 gate: 1437/1437, rc=0
                                              # (needs `ss-verify` container running
                                              #  + `testbed-strongswan` image)
docker compose config -q                       # compose renders clean (in testbed/)
```

Executed and verified (M2):

```bash
.venv/bin/python capture/synth/synth_pcap.py                # 360 synthetic pcaps + labels + manifest
.venv/bin/python capture/synth/synth_pcap.py --ingest-real  # fold 66 real pcaps -> labels, rebuild manifest (426 rows)
.venv/bin/python capture/validate_pcap.py --self-test       # 15/15 negative controls green, rc=0
.venv/bin/python capture/validate_pcap.py                   # M2 gate: 426/426 rows valid=true, rc=0
.venv/bin/python capture/audit_leakage.py                   # anti-leakage audit -> docs/anti-leakage-audit.md, rc=0
```

Executed and verified (M3):

```bash
.venv/bin/python engine/classifier/train.py                 # per-field RF, seed 7 -> engine/models/
.venv/bin/python engine/eval/evaluate.py                    # grouped CV + ablation + synth->real + holdout -> docs/model-evaluation.md
.venv/bin/python -m pytest engine/tests/ -q                 # 27 green
```

Executed and verified (M4/M5):

```bash
.venv/bin/ipsec-analyze analyze <pcap> [--json] [--report pdf]
.venv/bin/python reports/make_all.py                        # 8 PDFs -> reports/out/
.venv/bin/python engine/api/export_contract.py              # docs/openapi.json + docs/examples/
sh scripts/e2e.sh [--quick]                                 # clean-room gate, exit 0
sh scripts/build-dataset.sh                                 # dataset/*.tar.gz + checksums (verified 0 failures)
sh scripts/record-demo.sh                                   # demo/demo.typescript (scriptreplay-verified)
```

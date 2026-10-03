# Reproduction steps

All commands run from the repo root with `.venv/bin/python` (Python
3.12.13, `requirements.txt` pinned) unless noted.

```bash
uv venv && uv pip install -r requirements.txt && uv pip install -e .
ipsec-analyze generate-data --real   # 414 synthetic pcaps + manifest
                                     # (+ 66 real labels if data/real present;
                                     # full real set: dataset tarball, see below)
.venv/bin/python capture/validate_pcap.py --self-test   # 15/15
.venv/bin/python capture/validate_pcap.py               # gate: rc=0
.venv/bin/python capture/audit_leakage.py               # gate: rc=0
ipsec-analyze train                                     # models, seed 7
ipsec-analyze evaluate                                  # metrics + report
sh scripts/e2e.sh                                       # full clean-room gate
sh scripts/e2e.sh --quick                               # 1-minute smoke
```

Real captures need the dataset tarball (repo ships code only):
`dataset/ipsec-dataset-v1.tar.gz` contains `data/real/` — extract it over
`data/` (see `dataset/README.md`), then `--ingest-real` folds the labels.
The real-NAT-T technical report and the `analyze-real.json` example also
require the tarball. Everything synthetic regenerates deterministically
from seeds (same bytes, verified by re-generation + revalidation).

Real-capture testbed (to re-capture, not just replay): one privileged
Docker container, `testbed/scripts/real-run.sh`, `real-rekey.sh`,
`real-tcp.sh` via `docker exec tb-real` — see `docs/testbed-guide.md`.
Takes ~1 h for the full 66-pcap real set.

#!/usr/bin/env python3
"""Export the frozen frontend contract (M4 req 1).

Writes docs/openapi.json (from the live FastAPI app) and one full
example response per endpoint under docs/examples/, generated through
TestClient against the real app + mock app so examples never drift.
Every field object renders {value, source, confidence, detail};
unknowns are explicit, nothing is dropped.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "api"))
from app import app  # noqa: E402
from mock import app as mock_app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

EXAMPLE_PCAPS = {
    "analyze-v1": "data/pcaps/synth/v1/r1/voip.pcap",
    "analyze-v12": "data/pcaps/synth/v12/r1/voip.pcap",
    "analyze-plain": "data/pcaps/synth/plain/v4/r1/voip.pcap",
    "analyze-real": "data/real/v18/r1/voip.pcap",
}


def main() -> int:
    out = ROOT / "docs" / "examples"
    out.mkdir(parents=True, exist_ok=True)
    (ROOT / "docs" / "openapi.json").write_text(
        json.dumps(app.openapi(), indent=1))
    c = TestClient(app)
    (out / "health.json").write_text(json.dumps(c.get("/health").json(),
                                                indent=1))
    models = c.get("/models").json()
    models["meta"] = {k: v for k, v in models["meta"].items()
                      if k != "feature_keys"}
    (out / "models.json").write_text(json.dumps(models, indent=1))
    for name, rel in EXAMPLE_PCAPS.items():
        with (ROOT / rel).open("rb") as f:
            r = c.post("/analyze", files={"file": (Path(rel).name, f)})
        assert r.status_code == 200, (name, r.text[:200])
        (out / f"{name}.json").write_text(json.dumps(r.json(), indent=1))
    with (ROOT / "data/pcaps/synth/v1/r1/voip.pcap").open("rb") as f:
        r = c.post("/report", files={"file": ("voip.pcap", f)})
    (out / "report-v1.json").write_text(json.dumps(r.json(), indent=1))
    (out / "variants.json").write_text(json.dumps(c.get("/variants").json(),
                                                  indent=1)[:4000])
    (out / "samples.json").write_text(
        json.dumps(c.get("/datasets/samples?limit=4").json(), indent=1))
    mc = TestClient(mock_app)
    with (ROOT / "data/pcaps/synth/v1/r1/voip.pcap").open("rb") as f:
        r = mc.post("/analyze", files={"file": ("voip.pcap", f)})
    (out / "mock-analyze.json").write_text(json.dumps(r.json(), indent=1))
    print(f"contract exported to docs/openapi.json + {out} "
          f"({len(list(out.glob('*.json')))} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

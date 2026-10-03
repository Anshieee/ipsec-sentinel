"""Pin live tool outputs (v1.1): posture + coverage + PFS per sample.

Posture is scored over evaluated controls only (UNKNOWN earns no credit
and no penalty); coverage records the evidence gap. Regenerate
docs/expected-live-scores.md if the pipeline changes, then update these
literals deliberately (never silently).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
from predict import analyze  # noqa: E402
from assess import assess  # noqa: E402

# name: (posture, coverage, score_status, pfs value)
EXPECTED = {
    "plain-web": (None, 0.0, "WITHHELD", False),
    "real-v1-voip": (87, 0.55, "PUBLISHED", "unknown"),
    "real-v18-voip": (87, 0.55, "PUBLISHED", "unknown"),
    "v1-voip": (89, 0.65, "PUBLISHED", True),
    "v10-voip": (77, 0.65, "PUBLISHED", True),
    "v11-voip": (66, 0.65, "PUBLISHED", True),
    "v12-voip": (76, 0.55, "PUBLISHED", "unknown"),
    "v13-voip": (89, 0.65, "PUBLISHED", True),
    "v14-voip": (89, 0.65, "PUBLISHED", True),
    "v15-voip": (89, 0.65, "PUBLISHED", True),
    "v16-voip": (89, 0.65, "PUBLISHED", True),
    "v17-voip": (89, 0.65, "PUBLISHED", True),
    "v18-voip": (89, 0.65, "PUBLISHED", True),
    "v2-voip": (92, 0.65, "PUBLISHED", True),
    "v3-voip": (83, 0.65, "PUBLISHED", False),
    "v4-voip": (100, 0.65, "PUBLISHED", True),
    "v5-voip": (100, 0.6, "PUBLISHED", True),
    "v6-voip": (75, 0.6, "PUBLISHED", False),
    "v7-voip": (66, 0.65, "PUBLISHED", True),
    "v8-voip": (77, 0.65, "PUBLISHED", True),
    "v9-voip": (77, 0.65, "PUBLISHED", True),
}


def test_live_scores_pinned():
    models = ROOT / "engine" / "models"
    assert len(EXPECTED) == 21
    for name, (posture, cov, status, pfs) in EXPECTED.items():
        out = analyze(str(ROOT / "demo" / "samples" / f"{name}.pcap"), models)
        a = assess(out)
        assert a["posture_score"] == posture, (name, a["posture_score"])
        assert a["coverage"] == cov, (name, a["coverage"])
        assert a["score_status"] == status, (name, a["score_status"])
        assert out["pfs"]["value"] == pfs, (name, out["pfs"])
        if status == "PUBLISHED":
            assert a["security_score"] == posture
        else:
            assert a["security_score"] is None
            assert a["risk_level"] is None

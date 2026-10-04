"""Pin live tool outputs (v1.2): posture + coverage + PFS per sample.

Posture/coverage are confidence-weighted (OBSERVED/label 1.0, INFERRED
its model confidence, UNKNOWN 0). Regenerate
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

# name: (posture, coverage, score_status, pfs value, risk_band)
EXPECTED = {
    "plain-web": (None, 0.0, "WITHHELD", False, None),
    "real-v1-voip": (88, 0.4985, "WITHHELD", "unknown", None),
    "real-v18-voip": (88, 0.5255, "PUBLISHED", "unknown", "LOW"),
    "v1-voip": (89, 0.6684, "PUBLISHED", True, "LOW"),
    "v10-voip": (76, 0.6486, "PUBLISHED", True, "LOW"),
    "v11-voip": (66, 0.6269, "PUBLISHED", True, "MODERATE"),
    "v12-voip": (78, 0.5742, "PUBLISHED", "unknown", "LOW"),
    "v13-voip": (89, 0.6759, "PUBLISHED", True, "LOW"),
    "v14-voip": (89, 0.6758, "PUBLISHED", True, "LOW"),
    "v15-voip": (89, 0.6613, "PUBLISHED", True, "LOW"),
    "v16-voip": (89, 0.6759, "PUBLISHED", True, "LOW"),
    "v17-voip": (89, 0.6759, "PUBLISHED", True, "LOW"),
    "v18-voip": (89, 0.6759, "PUBLISHED", True, "LOW"),
    "v2-voip": (92, 0.6389, "PUBLISHED", True, "LOW"),
    "v3-voip": (85, 0.6347, "PUBLISHED", False, "LOW"),
    "v4-voip": (100, 0.6204, "PUBLISHED", True, "LOW"),
    "v5-voip": (100, 0.6063, "PUBLISHED", True, "LOW"),
    "v6-voip": (76, 0.6025, "PUBLISHED", False, "LOW"),
    "v7-voip": (68, 0.6738, "PUBLISHED", True, "MODERATE"),
    "v8-voip": (78, 0.6591, "PUBLISHED", True, "HIGH"),
    "v9-voip": (78, 0.6605, "PUBLISHED", True, "HIGH"),
}


def test_live_scores_pinned():
    models = ROOT / "engine" / "models"
    assert len(EXPECTED) == 21
    for name, (posture, cov, status, pfs, band) in EXPECTED.items():
        out = analyze(str(ROOT / "demo" / "samples" / f"{name}.pcap"), models)
        a = assess(out)
        assert a["posture_score"] == posture, (name, a["posture_score"])
        assert a["coverage"] == cov, (name, a["coverage"])
        assert a["score_status"] == status, (name, a["score_status"])
        assert out["pfs"]["value"] == pfs, (name, out["pfs"])
        assert a["risk_band"] == band, (name, a["risk_band"])
        if status == "PUBLISHED":
            assert a["security_score"] == posture
        else:
            assert a["security_score"] is None
            assert a["risk_level"] is None

"""Pin live tool outputs (MAJOR-4): security score + PFS per sample.

Regenerate docs/expected-live-scores.md if the pipeline changes, then
update these literals deliberately (never silently).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
from predict import analyze  # noqa: E402
from assess import assess  # noqa: E402

EXPECTED = {
    "plain-web": (5, False),
    "real-v1-voip": (63, "unknown"),
    "real-v18-voip": (63, "unknown"),
    "v1-voip": (73, True),
    "v10-voip": (65, True),
    "v11-voip": (58, True),
    "v12-voip": (57, "unknown"),
    "v13-voip": (73, True),
    "v14-voip": (73, True),
    "v15-voip": (73, True),
    "v16-voip": (73, True),
    "v17-voip": (73, True),
    "v18-voip": (73, True),
    "v2-voip": (80, True),
    "v3-voip": (69, False),
    "v4-voip": (85, True),
    "v5-voip": (80, True),
    "v6-voip": (62, False),
    "v7-voip": (58, True),
    "v8-voip": (60, True),
    "v9-voip": (65, True),
}


def test_live_scores_pinned():
    models = ROOT / "engine" / "models"
    assert len(EXPECTED) == 21
    for name, (score, pfs) in EXPECTED.items():
        out = analyze(str(ROOT / "demo" / "samples" / f"{name}.pcap"), models)
        a = assess(out)
        assert a["security_score"] == score, (name, a["security_score"])
        assert out["pfs"]["value"] == pfs, (name, out["pfs"])

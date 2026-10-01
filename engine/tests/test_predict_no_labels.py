"""Guardrail 1 (predictions): hiding data/labels must not change outputs."""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from predict import analyze  # noqa: E402

SAMPLES = [
    "data/pcaps/synth/v1/r1/voip.pcap",
    "data/pcaps/synth/v12/r2/web.pcap",
]
OPTIONAL_SAMPLES = [
    "data/real/v5/r1/icmp.pcap",
]
MODELS = ROOT / "engine" / "models"


def test_predictions_identical_without_labels():
    samples = [s for s in SAMPLES + OPTIONAL_SAMPLES
               if (ROOT / s).exists()]
    assert samples, "no sample pcaps (run generate-data first)"
    before = [analyze(str(ROOT / s), MODELS) for s in samples]
    lab = ROOT / "data" / "labels"
    import os
    hidden = ROOT / "data" / f".labels-hidden2-{os.getpid()}"
    shutil.move(str(lab), str(hidden))
    try:
        for s, b in zip(samples, before):
            assert analyze(str(ROOT / s), MODELS) == b, s
    finally:
        if lab.exists():
            shutil.copytree(str(hidden), str(lab), dirs_exist_ok=True)
            shutil.rmtree(str(hidden), ignore_errors=True)
        else:
            shutil.move(str(hidden), str(lab))

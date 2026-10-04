"""Unit tests for scripts/eval_external.py metric code (v1.2.6).

Hand-worked fixture: 10 rows, mixed mappable/answered/correct and
provenances. Unknown predictions count as error; coverage and
accuracy-when-answered are separate.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from eval_external import (compute_field_metrics, confusion,  # noqa: E402
                           map_label)


def rows():
    # 6 mappable: 3 correct (2 observed, 1 inferred), 1 wrong inferred,
    # 2 abstained (unknown). 4 unmappable (excluded everywhere).
    return [
        {"mappable": True, "answered": True, "correct": True,
         "provenance": "observed", "true": "a", "pred": "a"},
        {"mappable": True, "answered": True, "correct": True,
         "provenance": "observed", "true": "a", "pred": "a"},
        {"mappable": True, "answered": True, "correct": True,
         "provenance": "inferred", "true": "b", "pred": "b"},
        {"mappable": True, "answered": True, "correct": False,
         "provenance": "inferred", "true": "b", "pred": "c"},
        {"mappable": True, "answered": False, "correct": False,
         "provenance": "abstained", "true": "a", "pred": "unknown"},
        {"mappable": True, "answered": False, "correct": False,
         "provenance": "abstained", "true": "c", "pred": "unknown"},
        {"mappable": False, "answered": True, "correct": True,
         "provenance": "observed", "true": "x", "pred": "x"},
        {"mappable": False, "answered": False, "correct": False,
         "provenance": "abstained", "true": None, "pred": "unknown"},
        {"mappable": False, "answered": True, "correct": False,
         "provenance": "inferred", "true": None, "pred": "y"},
        {"mappable": False, "answered": False, "correct": False,
         "provenance": "abstained", "true": None, "pred": "unknown"},
    ]


def test_accuracy_counts_unknown_as_error():
    m = compute_field_metrics(rows())
    assert m["n"] == 6
    assert m["accuracy"] == 0.5  # 3/6; unknowns are errors
    assert m["coverage"] == round(4 / 6, 4)
    assert m["accuracy_when_answered"] == 0.75  # 3/4
    assert m["by_provenance"]["observed"]["accuracy"] == 1.0
    assert m["by_provenance"]["inferred"]["accuracy"] == 0.5
    assert m["by_provenance"]["abstained"]["accuracy"] == 0.0


def test_empty_field():
    m = compute_field_metrics([r for r in rows() if not r["mappable"]])
    assert m == {"n": 0, "accuracy": None, "coverage": None,
                 "accuracy_when_answered": None, "by_provenance": {}}


def test_confusion_counts_truth_vs_pred():
    c = confusion(rows())
    assert c == {"a": {"a": 2, "unknown": 1},
                 "b": {"b": 1, "c": 1},
                 "c": {"unknown": 1}}


def test_label_mapping_equalities():
    assert map_label("enc_alg", "AES-256-GCM-16") == "aes-256-gcm"
    assert map_label("auth_alg", "AEAD-GCM-128-bit-ICV") == "aead"
    assert map_label("dh_group", "19-ECP256") == 19
    assert map_label("pfs", "on") is True
    assert map_label("traffic_type", "voip") == "voip"
    # ambiguities are excluded, never guessed
    assert map_label("auth_alg", "HMAC-SHA384") is None
    assert map_label("dh_group", "15-MODP3072") is None
    assert map_label("traffic_type", "file_transfer") is None
    assert map_label("traffic_type", "messaging") is None

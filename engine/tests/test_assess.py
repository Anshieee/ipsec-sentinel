"""Assessment oracles: hand-computed rubric expectations (M3)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testbed"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
import matrix  # noqa: E402
from assess import assess  # noqa: E402


def classify_from_label(variant_id: str) -> tuple[dict, dict]:
    if variant_id == "plain":
        lab = {"variant": "plain", "ipsec_protocol": "none",
               "ike_version": "none", "mode": "none", "encryption": "none",
               "auth": "none", "dh_group": 0, "pfs": False}
        life = {"ike_rekey_s": 0, "child_rekey_s": 0, "replay_window": 0}
    else:
        v = matrix.BY_ID[variant_id]
        lab = matrix.label_row(v)
        life = {"ike_rekey_s": v["ike_rekey_s"],
                "child_rekey_s": v["child_rekey_s"],
                "replay_window": v["replay_window"]}
    cls = {k: {"value": lab[k], "source": "parsed", "confidence": 1.0}
           for k in ("encryption", "auth", "dh_group", "pfs", "ike_version",
                     "mode", "variant")}
    return cls, life


def test_golden_scores():
    # hand-computed from docs/security-rubric.md
    assert assess(*classify_from_label("v1"))["security_score"] == 88
    assert assess(*classify_from_label("v7"))["security_score"] == 73
    assert assess(*classify_from_label("v11"))["security_score"] == 73
    assert assess(*classify_from_label("v8"))["security_score"] == 75
    assert assess(*classify_from_label("plain"))["security_score"] == 5


def test_orderings_and_bounds():
    scores = {}
    for vid in matrix.VARIANT_IDS + ["plain"]:
        r = assess(*classify_from_label(vid))
        scores[vid] = r["security_score"]
        assert 0 <= r["security_score"] <= 100
        assert r["risk_score"] == 100 - r["security_score"]
    assert scores["v1"] > scores["v11"]   # 3DES
    assert scores["v1"] > scores["v8"]    # DH2
    assert scores["v1"] > scores["v10"]   # SHA1
    assert scores["v1"] > scores["v15"]   # replay off
    assert scores["v1"] > scores["v12"]   # IKEv1
    assert scores["v2"] >= scores["v1"]   # AES-256/DH20
    assert scores["plain"] < scores["v7"]  # AH still authenticates


def test_findings():
    r11 = assess(*classify_from_label("v11"))
    ids = {f["id"]: f for f in r11["findings"]}
    assert ids["weak-cipher"]["severity"] == "critical"
    assert any("AES-GCM" in f["solution"] for f in r11["findings"])
    r7 = assess(*classify_from_label("v7"))
    assert "no-conf" in {f["id"] for f in r7["findings"]}
    for name, res in (("v11", r11), ("v7", r7)):
        tm = {t["id"]: t for t in res["threat_matrix"]}
        for f in res["findings"]:
            assert tm[f["id"]]["risk"] == f["likelihood"] * f["impact"], name


def test_unknown_conservative():
    cls, life = classify_from_label("v1")
    cls["dh_group"] = {"value": "unknown", "source": "model", "confidence": 0}
    r = assess(cls, life)
    assert r["security_score"] == 88 - 15
    assert "unknown-dh_group" in {f["id"] for f in r["findings"]}

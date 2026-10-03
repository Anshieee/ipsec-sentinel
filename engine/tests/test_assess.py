"""Assessment oracles: hand-computed control expectations (v1.1).

Classifications are built from labels in the NEW SA shape (ike_sa /
child_sa / detection + flat dh_group + label lifetimes). Full-visibility
oracles are unchanged where the semantics did not move (v1=88, v7=73,
v11=73, v8=75); plain is now NOT_APPLICABLE (no IPsec score).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testbed"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
import matrix  # noqa: E402
from assess import assess  # noqa: E402


def _obs(value):
    return {"value": value, "status": "OBSERVED", "source": "parsed",
            "confidence": 1.0}


def _inf(value):
    return {"value": value, "status": "INFERRED", "source": "model",
            "confidence": 0.95}


def classify_from_label(variant_id: str) -> tuple[dict, dict]:
    if variant_id == "plain":
        return ({"ike_sa": {}, "child_sa": {},
                 "detection": {"ipsec_detected": False}},
                {"ike_rekey_s": 0, "child_rekey_s": 0, "replay_window": 0})
    v = matrix.BY_ID[variant_id]
    lab = matrix.label_row(v)
    ike_c, ike_a, ike_dh = matrix.ike_suite(v)
    ike_sa = {"version": _obs(lab["ike_version"]),
              "enc_alg": _obs(ike_c),
              "enc_key_len": _obs(matrix.CIPHERS[ike_c]["len"]),
              "auth_alg": _obs(ike_a),
              "dh_group": _obs(ike_dh)}
    child_sa = {"proto": _obs(lab["ipsec_protocol"]),
                "mode": _obs(lab["mode"]),
                "enc_alg": _obs(lab["encryption"]),
                "enc_key_len": _obs(lab["key_length_bits"]),
                "auth_alg": _obs(lab["auth"]),
                "pfs": {"value": lab["pfs"], "status": "OBSERVED",
                        "source": "parsed", "confidence": 1.0},
                "replay": _obs(lab["replay_window"]),
                "lifetime": _obs(lab["child_rekey_s"])}
    cls = {"ike_sa": ike_sa, "child_sa": child_sa,
           "dh_group": _obs(lab["dh_group"]),
           "detection": {"ipsec_detected": True}}
    life = {"ike_rekey_s": v["ike_rekey_s"],
            "child_rekey_s": v["child_rekey_s"],
            "replay_window": v["replay_window"]}
    return cls, life


def test_golden_scores():
    # hand-computed from docs/review/security-rubric.md (v1.1 controls)
    assert assess(*classify_from_label("v1"))["posture_score"] == 88
    assert assess(*classify_from_label("v7"))["posture_score"] == 73
    assert assess(*classify_from_label("v11"))["posture_score"] == 73
    # v8 (DH2): child PFS group FAIL (2) + IKE SA group FAIL (2).
    assert assess(*classify_from_label("v8"))["posture_score"] == 67
    r8 = assess(*classify_from_label("v8"))
    assert {"weak-dh", "weak-ike-dh"} <= {f["id"] for f in r8["findings"]}
    r = assess(*classify_from_label("plain"))
    assert r["score_status"] == "WITHHELD"
    assert r["security_score"] is None
    assert r["findings"] == []
    assert all(c["status"] == "NOT_APPLICABLE" for c in r["controls"])


def test_mismatch_oracles_score_own_sa():
    # v19: strong IKE, weak ESP -> weak posture (3DES child).
    a19 = assess(*classify_from_label("v19"))
    assert a19["breakdown"]["cipher"] == 5, a19["breakdown"]
    assert "weak-cipher" in {f["id"] for f in a19["findings"]}
    assert a19["posture_score"] == 73, a19["breakdown"]
    # v20: weak IKE, strong ESP -> strong child posture, IKE FAIL listed.
    a20 = assess(*classify_from_label("v20"))
    assert a20["breakdown"]["cipher"] == 25, a20["breakdown"]
    assert "weak-cipher" not in {f["id"] for f in a20["findings"]}
    # Max child suite (GCM-256/DH20/PFS): the IKE control scores the IKE
    # *version* only, so the weak IKE cipher does not drag posture down.
    assert a20["posture_score"] == 100, a20["breakdown"]


def test_orderings_and_bounds():
    scores = {}
    for vid in matrix.VARIANT_IDS:
        r = assess(*classify_from_label(vid))
        if r["posture_score"] is None:
            continue
        scores[vid] = r["posture_score"]
        assert 0 <= r["posture_score"] <= 100
        assert r["risk_score"] == 100 - r["posture_score"]
        # Full-visibility oracles: coverage 1.0, except transport variants
        # (mode-exposure is policy-dependent UNKNOWN, weight excluded).
        assert r["coverage"] >= 0.95, (vid, r["coverage"])
        assert r["score_status"] == "PUBLISHED"
    assert scores["v1"] > scores["v11"]   # 3DES
    assert scores["v1"] > scores["v8"]    # DH2
    assert scores["v1"] > scores["v10"]   # SHA1
    assert scores["v1"] > scores["v15"]   # replay off
    assert scores["v1"] > scores["v12"]   # IKEv1
    assert scores["v2"] >= scores["v1"]   # AES-256/DH20
    assert scores["v19"] < scores["v1"]   # weak child, however strong the IKE
    assert scores["v20"] > scores["v19"]  # strong child outranks weak child
    rp = assess(*classify_from_label("plain"))
    assert rp["score_status"] == "WITHHELD"  # plain has no posture to compare


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
    for c in r11["controls"]:
        assert c["rule_version"] == "1.1.0", c
        assert c["evidence"] is not None, c


def test_unknown_is_not_conservative_penalty():
    # An unobserved field lowers coverage, not posture: no "assuming weak"
    # findings, no risk penalties, resolve_by present on every UNKNOWN.
    cls, life = classify_from_label("v1")
    cls["dh_group"] = {"value": "unknown", "status": "UNKNOWN",
                       "source": "none", "confidence": 0.0}
    r = assess(cls, life)
    assert not [f for f in r["findings"] if f["id"].startswith("unknown-")]
    assert not any("assuming weak" in f["text"] for f in r["findings"])
    assert r["coverage"] == 0.8, r["coverage"]
    assert r["score_status"] == "PUBLISHED"
    assert r["posture_score"] == 91, r["breakdown"]
    ctl = {c["id"]: c for c in r["controls"]}
    assert ctl["dh-strength"]["status"] == "UNKNOWN"
    assert ctl["dh-strength"]["resolve_by"], ctl["dh-strength"]

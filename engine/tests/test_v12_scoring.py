"""v1.2 scoring corrections, Part 1a: IKE SA coverage (test-first).

assess() v1.1 scores only ike_sa.version and ike_sa.dh_group. An OBSERVED
weak IKE cipher / integrity / PRF is silent. These tests pin the missing
controls (ike-cipher, ike-integrity; weak-ike-dh kept), scored from
ike_sa only, never touching the ESP controls and vice versa.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "assess"))
from assess import assess  # noqa: E402


def _obs(value):
    return {"value": value, "status": "OBSERVED", "source": "parsed",
            "confidence": 1.0}


def _inf(value, conf=0.9):
    return {"value": value, "status": "INFERRED", "source": "model",
            "confidence": conf}


def _unknown():
    return {"value": "unknown", "status": "UNKNOWN", "source": "none",
            "confidence": 0.0}


def _no():
    return {"value": "none", "status": "NOT_APPLICABLE", "source": "none",
            "confidence": 1.0}


def strong_esp_child():
    return {"proto": _obs("esp"),
            "mode": _obs("tunnel"),
            "enc_alg": _inf("aes-256-gcm", 0.9),
            "enc_key_len": _inf(256, 0.9),
            "auth_alg": _inf("aead", 0.9),
            "pfs": _inf(True, 0.95),
            "replay": _unknown(),
            "lifetime": _unknown()}


def strong_ike(version="ikev2", enc="aes-256-gcm", keylen=256, auth="aead",
               prf="hmac-sha384", dh=20):
    return {"version": _obs(version),
            "enc_alg": _obs(enc),
            "enc_key_len": _obs(keylen),
            "auth_alg": _obs(auth),
            "prf": _obs(prf),
            "dh_group": _obs(dh)}


def cls_for(ike, child=None, dh_flat=None):
    return {"ike_sa": ike,
            "child_sa": child or strong_esp_child(),
            "dh_group": dh_flat or _unknown(),
            "detection": {"ipsec_detected": True}}


def controls(a):
    return {c["id"]: c for c in a["controls"]}


def test_weak_ike_cipher_3des_fails():
    ike = strong_ike(enc="3des-cbc", keylen=168)
    a = assess(cls_for(ike))
    c = controls(a)["ike-cipher"]
    assert c["status"] == "FAIL", c
    assert "weak-ike-cipher" in {f["id"] for f in a["findings"]}
    # ESP controls untouched by the weak IKE suite:
    assert controls(a)["child-cipher"]["status"] == "PASS"
    assert controls(a)["child-cipher"]["points"] == 25


def test_weak_ike_cipher_des_and_short_key_fail():
    for enc, keylen in (("des-cbc", 56), ("aes-128-cbc", 40)):
        ike = strong_ike(enc=enc, keylen=keylen)
        a = assess(cls_for(ike))
        assert controls(a)["ike-cipher"]["status"] == "FAIL", (enc, keylen)


def test_weak_ike_integrity_sha1_fails():
    ike = strong_ike(auth="hmac-sha1", prf="hmac-sha1")
    a = assess(cls_for(ike))
    c = controls(a)["ike-integrity"]
    assert c["status"] == "FAIL", c
    assert "weak-ike-integ" in {f["id"] for f in a["findings"]}


def test_weak_ike_integrity_md5_fails():
    ike = strong_ike(auth="hmac-md5", prf="hmac-md5")
    a = assess(cls_for(ike))
    c = controls(a)["ike-integrity"]
    assert c["status"] == "FAIL", c
    f = {f["id"]: f for f in a["findings"]}["weak-ike-integ"]
    assert f["severity"] == "high", f


def test_weak_ike_prf_fails_even_with_strong_auth():
    ike = strong_ike(auth="hmac-sha256", prf="hmac-sha1")
    a = assess(cls_for(ike))
    assert controls(a)["ike-integrity"]["status"] == "FAIL"


def test_weak_ike_dh_groups_fail():
    for dh in (1, 2, 5):
        ike = strong_ike(dh=dh)
        a = assess(cls_for(ike))
        assert "weak-ike-dh" in {f["id"] for f in a["findings"]}, dh


def test_v20_ike_suite_stays_acceptable():
    # v20: IKE AES-128-CBC + HMAC-SHA256 + DH14 (no weak primitives).
    ike = strong_ike(enc="aes-128-cbc", keylen=128, auth="hmac-sha256",
                     prf="hmac-sha256", dh=14)
    a = assess(cls_for(ike))
    c = controls(a)
    assert c["ike-cipher"]["status"] == "PASS", c["ike-cipher"]
    assert c["ike-integrity"]["status"] == "PASS", c["ike-integrity"]
    assert c["ike-version"]["status"] == "PASS", c["ike-version"]
    assert "weak-ike-cipher" not in {f["id"] for f in a["findings"]}
    assert "weak-ike-integ" not in {f["id"] for f in a["findings"]}
    assert "weak-ike-dh" not in {f["id"] for f in a["findings"]}


def test_esp_and_ike_scored_independently():
    # Weak IKE + strong ESP: ESP cipher PASS at full points, IKE FAILs.
    ike = strong_ike(enc="3des-cbc", keylen=168, auth="hmac-sha1",
                     prf="hmac-sha1", dh=2)
    a = assess(cls_for(ike))
    c = controls(a)
    assert c["child-cipher"]["points"] == 25, c["child-cipher"]
    assert c["ike-cipher"]["status"] == "FAIL"
    assert c["ike-integrity"]["status"] == "FAIL"
    # Strong IKE + weak ESP: ESP FAIL stands, IKE PASSes.
    weak_child = strong_esp_child()
    weak_child["enc_alg"] = _inf("3des-cbc", 0.9)
    weak_child["enc_key_len"] = _inf(168, 0.9)
    a2 = assess(cls_for(strong_ike(), child=weak_child))
    c2 = controls(a2)
    assert c2["child-cipher"]["status"] in ("FAIL", "LIKELY")
    assert c2["child-cipher"]["points"] == 5, c2["child-cipher"]
    assert c2["ike-cipher"]["status"] == "PASS"
    assert c2["ike-integrity"]["status"] == "PASS"


# --------------------------------------------------------------------------
# Part 1b: inferred evidence is symmetric (test-first)
# --------------------------------------------------------------------------

def test_inferred_fail_surfaces_as_likely_capped():
    # INFERRED 3DES child: LIKELY (not FAIL), severity one below observed.
    child = strong_esp_child()
    child["enc_alg"] = _inf("3des-cbc", 0.87)
    child["enc_key_len"] = _inf(168, 0.87)
    a = assess(cls_for(strong_ike(), child=child))
    c = controls(a)["child-cipher"]
    assert c["status"] == "LIKELY", c
    assert c["source"] == "inferred", c
    assert c["confidence"] == 0.87, c
    f = {x["id"]: x for x in a["findings"]}["weak-cipher"]
    assert f["verdict"] == "LIKELY", f
    # observed 3DES is critical; inferred is capped one level below.
    assert f["severity"] == "high", f


def test_observed_fail_stays_confirmed_critical():
    child = strong_esp_child()
    child["enc_alg"] = _obs("3des-cbc")
    child["enc_key_len"] = _obs(168)
    a = assess(cls_for(strong_ike(), child=child))
    assert controls(a)["child-cipher"]["status"] == "FAIL"
    f = {x["id"]: x for x in a["findings"]}["weak-cipher"]
    assert f["verdict"] == "CONFIRMED", f
    assert f["severity"] == "critical", f


def test_inferred_pass_counts_partial_credit():
    # Hand-worked: single evaluated control, INFERRED PASS conf 0.8,
    # 20/25 points. posture = 100*(20*.8)/(25*.8) = 80; coverage over the
    # applicable set of 8 controls (25+20+15+10+10+5+10+5=100 + new
    # ike-cipher 5 + ike-integrity 3 = 108): only cipher has evidence.
    ike = {"version": _unknown(), "enc_alg": _unknown(),
           "enc_key_len": _unknown(), "auth_alg": _unknown(),
           "prf": _unknown(), "dh_group": _unknown()}
    child = {"proto": _obs("esp"), "mode": _unknown(),
             "enc_alg": _inf("aes-128-cbc", 0.8),
             "enc_key_len": _inf(128, 0.8),
             "auth_alg": _unknown(), "pfs": _unknown(),
             "replay": _unknown(), "lifetime": _unknown()}
    a = assess(cls_for(ike, child=child))
    assert a["posture_score"] == 80, (a["posture_score"], a["breakdown"])
    assert a["coverage"] == round(25 * 0.8 / 108, 4), a["coverage"]
    assert a["score_status"] == "WITHHELD"
    assert a["risk_level"] is None


def test_observed_pass_counts_full_credit():
    ike = {"version": _unknown(), "enc_alg": _unknown(),
           "enc_key_len": _unknown(), "auth_alg": _unknown(),
           "prf": _unknown(), "dh_group": _unknown()}
    child = {"proto": _obs("esp"), "mode": _unknown(),
             "enc_alg": _obs("aes-128-cbc"),
             "enc_key_len": _obs(128),
             "auth_alg": _unknown(), "pfs": _unknown(),
             "replay": _unknown(), "lifetime": _unknown()}
    a = assess(cls_for(ike, child=child))
    assert a["posture_score"] == 80, a["breakdown"]
    assert a["coverage"] == round(25 / 108, 4), a["coverage"]


def test_pfs_states_honestly_observed_vs_inferred():
    child_o = strong_esp_child()
    child_o["pfs"] = {"value": True, "status": "OBSERVED",
                      "source": "parsed", "confidence": 1.0}
    ao = assess(cls_for(strong_ike(), child=child_o))
    co = controls(ao)["pfs"]
    assert co["source"] == "observed", co
    assert co["confidence"] == 1.0, co
    assert co["status"] == "PASS", co
    child_i = strong_esp_child()  # default pfs is _inf(True, 0.95)
    ai = assess(cls_for(strong_ike(), child=child_i))
    ci = controls(ai)["pfs"]
    assert ci["source"] == "inferred", ci
    assert ci["confidence"] == 0.95, ci
    assert ci["status"] == "PASS", ci


def test_unknown_earns_nothing_and_resolves():
    a = assess(cls_for(strong_ike()))
    c = controls(a)["lifetime"]
    assert c["status"] == "UNKNOWN"
    assert c["source"] == "none"
    assert c["confidence"] == 0.0
    assert c.get("resolve_by")


# --------------------------------------------------------------------------
# Corpus pins: v20 stays acceptable, v21 (weak IKE, strong ESP) FAILs IKE
# --------------------------------------------------------------------------
def test_v20_live_before_after():
    """v1.1 pinned v20 live at posture 100 @ coverage 0.65, no findings.
    v1.2 (IKE-suite controls + confidence weighting): posture 99 @
    0.6327, still PUBLISHED with zero findings — acceptable."""
    import sys as _sys
    from pathlib import Path as _Path
    _ROOT = _Path(__file__).resolve().parents[2]
    _sys.path.insert(0, str(_ROOT / "engine" / "classifier"))
    from predict import analyze
    out = analyze(str(_ROOT / "data/pcaps/synth/v20/r1/voip.pcap"),
                  _ROOT / "engine" / "models")
    assert out["ike_sa"]["enc_alg"]["value"] == "aes-128-cbc"
    assert out["child_sa"]["enc_alg"]["value"] == "aes-256-gcm"
    a = assess({"ike_sa": out["ike_sa"], "child_sa": out["child_sa"],
                "dh_group": out["dh_group"],
                "detection": {"ipsec_detected": True}})
    assert a["posture_score"] == 99, a["breakdown"]
    assert a["coverage"] == 0.6327, a["coverage"]
    assert a["score_status"] == "PUBLISHED"
    assert a["findings"] == [], a["findings"]


def test_v21_live_weak_ike_strong_esp():
    """Corpus v21: OBSERVED weak IKE (3DES/SHA1/DH2), INFERRED strong ESP
    (GCM-256). Three CONFIRMED IKE FAILs; child cipher PASS at 25."""
    import sys as _sys
    from pathlib import Path as _Path
    _ROOT = _Path(__file__).resolve().parents[2]
    _sys.path.insert(0, str(_ROOT / "engine" / "classifier"))
    from predict import analyze
    out = analyze(str(_ROOT / "data/pcaps/synth/v21/r1/voip.pcap"),
                  _ROOT / "engine" / "models")
    assert out["ike_sa"]["enc_alg"]["value"] == "3des-cbc"
    assert out["ike_sa"]["enc_alg"]["status"] == "OBSERVED"
    assert out["ike_sa"]["auth_alg"]["value"] == "hmac-sha1"
    assert out["ike_sa"]["dh_group"]["value"] == 2
    assert out["child_sa"]["enc_alg"]["value"] == "aes-256-gcm"
    assert out["child_sa"]["enc_alg"]["status"] == "INFERRED"
    a = assess({"ike_sa": out["ike_sa"], "child_sa": out["child_sa"],
                "dh_group": out["dh_group"],
                "detection": {"ipsec_detected": True}})
    ids = {f["id"]: f for f in a["findings"]}
    assert {"weak-ike-cipher", "weak-ike-integ",
            "weak-ike-dh"} <= set(ids), ids
    assert all(f["verdict"] == "CONFIRMED" for f in ids.values())
    assert a["posture_score"] == 80, a["breakdown"]
    assert a["coverage"] == 0.6576, a["coverage"]
    assert a["score_status"] == "PUBLISHED"
    assert a["breakdown"]["cipher"] == 25, a["breakdown"]

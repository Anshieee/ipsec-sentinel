"""Deterministic parser unit tests on known pcaps (v1.1 SA split).

The IKE SA is parsed from handshake bytes (with packet evidence); the
CHILD suite is NEVER filled from IKE_SA_INIT (stays None for the model).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from parse import parse_fields  # noqa: E402


def _blinded(variant, run, traffic):
    sys.path.insert(0, str(ROOT / "engine" / "eval"))
    from evaluate import blind_ike
    return parse_fields(blind_ike(
        extract(str(ROOT / f"data/pcaps/synth/{variant}/{run}/{traffic}.pcap"))))


def _p(variant, run, traffic, fam=None):
    base = f"data/pcaps/synth/{variant}/{run}/{traffic}.pcap"
    if variant == "plain":
        base = f"data/pcaps/synth/plain/v{fam}/{run}/{traffic}.pcap"
    return parse_fields(extract(str(ROOT / base)))


def test_v1_ike_parsed_child_left_to_model():
    o = _p("v1", "r1", "voip")
    ike = o["ike_sa"]
    assert ike["version"]["value"] == "ikev2"
    assert ike["version"]["status"] == "OBSERVED"
    assert ike["enc_alg"]["value"] == "aes-128-cbc"
    assert ike["enc_key_len"]["value"] == 128
    assert ike["auth_alg"]["value"] == "hmac-sha256"
    assert ike["dh_group"]["value"] == 14
    assert ike["enc_alg"]["evidence"]["packet"] > 0
    child = o["child_sa"]
    assert child["proto"]["value"] == "esp"
    assert child["proto"]["status"] == "OBSERVED"
    # IKE_SA_INIT never populates the child suite:
    assert child["enc_alg"] is None
    assert child["enc_key_len"] is None
    assert child["auth_alg"] is None
    assert child["pfs"] is None  # SK-only rekeys: PFS is a model field now
    assert child["mode"] is None  # ESP mode is never on the wire -> model
    assert o["nat_t"]["value"] is False
    assert o["ip_version"]["value"] == 4


def test_v3_gcm_no_integ():
    o = _p("v3", "r1", "voip")
    assert o["ike_sa"]["enc_alg"]["value"] == "aes-128-gcm"
    assert o["ike_sa"]["auth_alg"]["value"] == "aead"
    assert o["child_sa"]["enc_alg"] is None
    assert o["child_sa"]["pfs"] is None


def test_v19_mismatch_suites_kept_apart():
    o = _p("v19", "r1", "voip")
    assert o["ike_sa"]["enc_alg"]["value"] == "aes-256-gcm"
    assert o["ike_sa"]["dh_group"]["value"] == 20
    assert o["child_sa"]["enc_alg"] is None  # 3DES child: model fills it
    assert o["child_sa"]["proto"]["value"] == "esp"


def test_v7_ah_mode_parsed_no_mirroring():
    o = _p("v7", "r1", "voip")
    assert o["child_sa"]["proto"]["value"] == "ah"
    assert o["child_sa"]["enc_alg"]["value"] == "none"  # RFC 4302
    assert o["child_sa"]["enc_key_len"]["value"] == 0
    # AH auth comes from the CHILD proposal (encrypted): never mirrored
    # from the IKE proposal.
    assert o["child_sa"]["auth_alg"] is None
    assert o["child_sa"]["mode"]["value"] == "tunnel"
    assert o["ike_sa"]["enc_alg"]["value"] == "aes-128-cbc"  # baseline IKE


def test_ah_without_rekey_pfs_unknown():
    """MINOR-3: AH captures report pfs unknown unless a rekey length
    signal exists (real v7/r1 has no rekey)."""
    import pytest
    pcap = ROOT / "data/real/v7/r1/voip.pcap"
    if not pcap.exists():
        pytest.skip("no real captures in this checkout (tarball not extracted)")
    sys.path.insert(0, str(ROOT / "engine" / "classifier"))
    from predict import analyze
    models = ROOT / "engine" / "models"
    o = analyze(str(pcap), models)
    assert o["child_sa"]["pfs"] == {"value": "unknown", "status": "NOT_OBSERVED",
                                    "source": "none", "confidence": 0.0,
                                    "evidence": {"note": "no-rekey-on-wire",
                                                 "resolve_by": "capture a "
                                                 "CREATE_CHILD_SA rekey exchange"}}
    assert o["child_sa"]["mode"]["value"] == "tunnel"  # AH nh structural


def test_v12_ikev1():
    o = _p("v12", "r1", "icmp")
    assert o["ike_sa"]["version"]["value"] == "ikev1"
    assert o["ike_sa"]["enc_alg"]["value"] == "aes-128-cbc"
    assert o["child_sa"]["pfs"] is None  # QM encrypted: honestly unknown


def test_pfs_model_lengths():
    """PFS comes from rekey SK length (source: model, honest confidence)."""
    sys.path.insert(0, str(ROOT / "engine" / "classifier"))
    from predict import analyze
    models = ROOT / "engine" / "models"
    on = analyze(str(ROOT / "data/pcaps/synth/v1/r1/voip.pcap"), models)
    assert on["child_sa"]["pfs"]["value"] is True
    assert on["child_sa"]["pfs"]["source"] == "model"
    off = analyze(str(ROOT / "data/pcaps/synth/v3/r1/voip.pcap"), models)
    assert off["child_sa"]["pfs"]["value"] is False
    assert off["child_sa"]["pfs"]["source"] == "model"


def test_v18_nat_t():
    o = _p("v18", "r1", "voip")
    assert o["nat_t"]["value"] is True


def test_plain():
    o = _p("plain", "r1", "web", fam=4)
    assert o["ike_sa"]["version"]["value"] == "none"
    assert o["child_sa"]["proto"]["value"] == "none"
    assert o["child_sa"]["pfs"]["value"] is False
    assert o["child_sa"]["pfs"]["status"] == "NOT_APPLICABLE"


def test_esp_only_blinded_feats():
    """Blinded IKE features (ablation view): handshake is NOT_OBSERVED,
    never a certain no-IKE; child crypto stays model-bound (None)."""
    o = _blinded("v1", "r1", "voip")
    assert o["ike_sa"]["version"]["value"] == "unknown"
    assert o["ike_sa"]["version"]["status"] == "NOT_OBSERVED"
    assert o["child_sa"]["proto"]["value"] == "esp"
    assert o["child_sa"]["enc_alg"] is None

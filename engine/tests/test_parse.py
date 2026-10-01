"""Deterministic parser unit tests on known pcaps (M3 guardrail 2)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from parse import parse_fields  # noqa: E402


def _p(variant, run, traffic, fam=None):
    base = f"data/pcaps/synth/{variant}/{run}/{traffic}.pcap"
    if variant == "plain":
        base = f"data/pcaps/synth/plain/v{fam}/{run}/{traffic}.pcap"
    return parse_fields(extract(str(ROOT / base)))


def test_v1_parsed():
    o = _p("v1", "r1", "voip")
    assert o["ike_version"]["value"] == "ikev2"
    assert o["ipsec_proto"]["value"] == "esp"
    assert o["enc_alg"]["value"] == "aes-128-cbc"
    assert o["enc_key_len"]["value"] == 128
    assert o["auth_alg"]["value"] == "hmac-sha256"
    assert o["dh_group"]["value"] == 14
    assert o["pfs"] is None  # SK-only rekeys: PFS is a model field now
    assert o["nat_t"]["value"] is False
    assert o["ip_version"]["value"] == 4
    assert all(v["source"] == "parsed" for v in o.values() if v is not None)
    assert o["mode"] is None  # ESP mode is never on the wire -> model


def test_v3_gcm_no_integ():
    o = _p("v3", "r1", "voip")
    assert o["enc_alg"]["value"] == "aes-128-gcm"
    assert o["auth_alg"]["value"] == "aead"
    assert o["pfs"] is None  # SK-only rekeys: PFS is a model field now


def test_v7_ah_mode_parsed():
    o = _p("v7", "r1", "voip")
    assert o["ipsec_proto"]["value"] == "ah"
    assert o["enc_alg"]["value"] == "none"  # AH never encrypts (RFC 4302)
    assert o["enc_key_len"]["value"] == 0
    assert o["auth_alg"]["value"] == "hmac-sha256"
    assert o["mode"]["value"] == "tunnel"


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
    assert o["pfs"] == {"value": "unknown", "source": "model",
                        "confidence": 0.0}
    assert o["mode"]["value"] == "tunnel"  # AH nh is structural


def test_v12_ikev1():
    o = _p("v12", "r1", "icmp")
    assert o["ike_version"]["value"] == "ikev1"
    assert o["enc_alg"]["value"] == "aes-128-cbc"
    assert o["pfs"] is None  # QM encrypted: honestly unknown


def test_pfs_model_lengths():
    """PFS comes from rekey SK length (source: model, honest confidence)."""
    sys.path.insert(0, str(ROOT / "engine" / "classifier"))
    from predict import analyze
    models = ROOT / "engine" / "models"
    on = analyze(str(ROOT / "data/pcaps/synth/v1/r1/voip.pcap"), models)
    assert on["pfs"]["value"] is True and on["pfs"]["source"] == "model"
    off = analyze(str(ROOT / "data/pcaps/synth/v3/r1/voip.pcap"), models)
    assert off["pfs"]["value"] is False and off["pfs"]["source"] == "model"


def test_v18_nat_t():
    o = _p("v18", "r1", "voip")
    assert o["nat_t"]["value"] is True


def test_plain():
    o = _p("plain", "r1", "web", fam=4)
    assert o["ike_version"]["value"] == "none"
    assert o["ipsec_proto"]["value"] == "none"
    assert o["pfs"]["value"] is False

"""v1.1 correctness regression fixtures (test-first).

Governing rule: IKE SA and ESP/CHILD SA are different objects. An
IKE_SA_INIT proposal describes the IKE SA, never the installed ESP suite.
Every fact carries OBSERVED | INFERRED | UNKNOWN | NOT_OBSERVED |
NOT_APPLICABLE status; absence of evidence is never a confident value.
"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
sys.path.insert(0, str(ROOT / "capture" / "synth"))
from extract import extract  # noqa: E402
from parse import parse_fields  # noqa: E402
from predict import analyze  # noqa: E402
from assess import assess  # noqa: E402

MODELS = ROOT / "engine" / "models"
V1_VOIP = ROOT / "data" / "pcaps" / "synth" / "v1" / "r1" / "voip.pcap"
V4_VOIP = ROOT / "data" / "pcaps" / "synth" / "v4" / "r1" / "voip.pcap"
V11_VOIP = ROOT / "data" / "pcaps" / "synth" / "v11" / "r1" / "voip.pcap"
PLAIN_VOIP = ROOT / "data" / "pcaps" / "synth" / "plain" / "v4" / "r1" / "voip.pcap"


# --------------------------------------------------------------------------
# pcap crafting helpers (isolated tmp_path copies only, never data/)
# --------------------------------------------------------------------------
def _is_ike_packet(p):
    from scapy.all import IP, IPv6, UDP
    ip = p.getlayer(IP) or p.getlayer(IPv6)
    if ip is None:
        return False
    fam = 4 if ip.__class__.__name__ == "IP" else 6
    pr = ip.proto if fam == 4 else ip.nh
    if pr != 17 or UDP not in p:
        return False
    u = p[UDP]
    if u.sport not in (500, 4500) and u.dport not in (500, 4500):
        return False
    try:
        pay = bytes(u.payload)
    except Exception:
        return False
    if len(pay) == 1 and pay == b"\xff":
        return False  # NAT-T keepalive is neither IKE nor ESP
    return u.dport == 500 or u.sport == 500 or pay[:4] == b"\x00" * 4


def _l3(p):
    """IP/IPv6 layer only (pcaps under test mix Ether and raw-IP writers;
    normalizing avoids inconsistent-linktype misdissection)."""
    from scapy.all import IP, IPv6
    q = (p.getlayer(IP) or p.getlayer(IPv6)).copy()
    q.time = float(p.time)
    return q


def strip_ike(src: Path, dst: Path):
    from scapy.all import rdpcap, wrpcap
    pkts = [_l3(p) for p in rdpcap(str(src)) if not _is_ike_packet(p)]
    assert pkts, "stripping IKE left zero packets"
    wrpcap(str(dst), pkts)
    return dst


def ike_packets(src: Path):
    from scapy.all import rdpcap
    return [_l3(p) for p in rdpcap(str(src)) if _is_ike_packet(p)]


def esp_packets(src: Path):
    from scapy.all import IP, IPv6, rdpcap
    out = []
    for p in rdpcap(str(src)):
        ip = p.getlayer(IP) or p.getlayer(IPv6)
        if ip is None:
            continue
        pr = ip.proto if ip.__class__.__name__ == "IP" else ip.nh
        if pr == 50:
            out.append(_l3(p))
    return out


def write_pkts(dst: Path, pkts, retime=True):
    from scapy.all import wrpcap
    if retime:
        base = float(pkts[0].time)
        for i, p in enumerate(pkts):
            p.time = base + i * 0.01
    wrpcap(str(dst), pkts)
    return dst


def ike_sa_init_pair(enc_req, auth_req, dh_req, enc_resp, auth_resp, dh_resp):
    """One IKE_SA_INIT request + response with possibly DIFFERENT suites
    (offered vs selected). Returns (req_bytes, resp_bytes)."""
    import synth_pcap as S
    spi_i, spi_r = b"\x11" * 8, b"\x22" * 8
    sa = S._v2_sa(34, 1, enc_req, auth_req, dh_req)
    ke = S._v2_ke(40, dh_req, b"\x33" * S.DH_PUB_LEN[dh_req])
    no = S._v2_nonce(0, b"\x44" * 32)
    req = S._ike_hdr(spi_i, b"\x00" * 8, 33, 34, 0x08, 0, sa + ke + no)
    sa_r = S._v2_sa(34, 1, enc_resp, auth_resp, dh_resp)
    ke_r = S._v2_ke(40, dh_resp, b"\x55" * S.DH_PUB_LEN[dh_resp])
    no_r = S._v2_nonce(0, b"\x66" * 32)
    resp = S._ike_hdr(spi_i, spi_r, 33, 34, 0x20, 0, sa_r + ke_r + no_r)
    return req, resp


def udp_ike_pkt(req_bytes, sport=500, dport=500):
    from scapy.all import IP, UDP, Raw
    return IP(src="10.30.0.10", dst="10.30.0.20") / \
        UDP(sport=sport, dport=dport) / Raw(load=req_bytes)


# --------------------------------------------------------------------------
# 1. mismatch: strong IKE / weak ESP (and reverse)
# --------------------------------------------------------------------------
def test_mismatch_strong_ike_weak_esp():
    """Corpus v19: IKE AES-256-GCM/DH20 + ESP 3DES/PFS-DH14. The IKE
    cipher must never populate child_sa, and the assessment must score
    the weak child (not inherit the strong IKE)."""
    out = analyze(str(ROOT / "data/pcaps/synth/v19/r1/voip.pcap"), MODELS)
    assert out["ike_sa"]["enc_alg"]["value"] == "aes-256-gcm"
    assert out["ike_sa"]["enc_alg"]["status"] == "OBSERVED"
    assert out["ike_sa"]["dh_group"]["value"] == 20
    child = out["child_sa"]["enc_alg"]
    assert not (child["value"] == "aes-256-gcm"
                and child["status"] == "OBSERVED"), \
        f"IKE suite leaked into child_sa: {child}"
    assert child["value"] == "3des-cbc", child
    assert child["status"] == "INFERRED", child
    assert child["source"] == "model", child
    assert out["enc_alg"]["value"] == "3des-cbc"
    assert out["enc_alg"]["source"] == "model"
    a = assess(out)
    assert a["breakdown"]["cipher"] == 5, a["breakdown"]
    assert "weak-cipher" in {f["id"] for f in a["findings"]}


def test_mismatch_weak_ike_strong_esp():
    """Corpus v20: IKE AES-128-CBC/DH14 + ESP AES-256-GCM/PFS-DH20. The
    weaker IKE suite must not drag the child assessment down; IKE
    weakness is scored on the IKE SA alone (version control)."""
    out = analyze(str(ROOT / "data/pcaps/synth/v20/r1/voip.pcap"), MODELS)
    assert out["ike_sa"]["enc_alg"]["value"] == "aes-128-cbc"
    assert out["ike_sa"]["enc_alg"]["status"] == "OBSERVED"
    assert out["ike_sa"]["dh_group"]["value"] == 14
    child = out["child_sa"]["enc_alg"]
    assert not (child["value"] == "aes-128-cbc"
                and child["status"] == "OBSERVED"), \
        f"IKE suite leaked into child_sa: {child}"
    assert child["value"] == "aes-256-gcm", child
    a = assess(out)
    assert a["breakdown"]["cipher"] == 25, a["breakdown"]
    assert "weak-cipher" not in {f["id"] for f in a["findings"]}


def test_mismatch_assessment_scores_own_sa():
    """Pure assessment unit check: weak child + strong IKE scores weak."""
    cls = {"ike_sa": {
        "version": {"value": "ikev2", "status": "OBSERVED",
                    "source": "parsed", "confidence": 1.0},
        "enc_alg": {"value": "aes-256-gcm", "status": "OBSERVED",
                    "source": "parsed", "confidence": 1.0},
        "dh_group": {"value": 20, "status": "OBSERVED",
                     "source": "parsed", "confidence": 1.0}},
        "child_sa": {
        "proto": {"value": "esp", "status": "OBSERVED",
                  "source": "parsed", "confidence": 1.0},
        "mode": {"value": "tunnel", "status": "INFERRED",
                 "source": "model", "confidence": 0.99},
        "enc_alg": {"value": "3des-cbc", "status": "INFERRED",
                    "source": "model", "confidence": 0.9},
        "enc_key_len": {"value": 168, "status": "INFERRED",
                        "source": "model", "confidence": 0.9},
        "auth_alg": {"value": "hmac-sha256", "status": "INFERRED",
                     "source": "model", "confidence": 0.9},
        "pfs": {"value": True, "status": "INFERRED",
                "source": "model", "confidence": 0.9},
        "replay": {"value": 32, "status": "NOT_OBSERVED",
                   "source": "none", "confidence": 0.0},
        "lifetime": {"value": "unknown", "status": "NOT_OBSERVED",
                     "source": "none", "confidence": 0.0}},
        "detection": {"ipsec_detected": True}}
    a = assess(cls)
    assert a["breakdown"]["cipher"] == 5, a["breakdown"]
    assert "weak-cipher" in {f["id"] for f in a["findings"]}
    assert not any("aes-256-gcm" in f.get("text", "")
                   for f in a["findings"])


# --------------------------------------------------------------------------
# 2. ESP-only: missing handshake is NOT_OBSERVED, never certain no-IKE
# --------------------------------------------------------------------------
def test_esp_only_ike_not_observed(tmp_path):
    p = strip_ike(V1_VOIP, tmp_path / "esp-only.pcap")
    out = analyze(str(p), MODELS)
    ike = out["ike_sa"]["version"]
    assert ike["value"] == "unknown", ike
    assert ike["status"] == "NOT_OBSERVED", ike
    assert ike["confidence"] == 0.0, ike
    assert out["ike_version"]["value"] == "unknown"
    assert out["ike_version"]["value"] != "none"
    assert out["child_sa"]["proto"]["value"] == "esp"
    ctl = {c["id"]: c for c in assess(out)["controls"]}
    assert ctl["ike-version"]["status"] == "UNKNOWN"


def test_selected_vs_offered(tmp_path):
    """Responder selects AES-128-CBC/DH14 out of a stronger offer:
    ike_sa reports the SELECTED suite with responder evidence."""
    req, resp = ike_sa_init_pair("aes-256-cbc", "hmac-sha256", 20,
                                 "aes-128-cbc", "hmac-sha256", 14)
    esp = esp_packets(V1_VOIP)[:20]
    write_pkts(tmp_path / "offered.pcap",
               [udp_ike_pkt(req), udp_ike_pkt(resp)] + esp)
    out = analyze(str(tmp_path / "offered.pcap"), MODELS)
    assert out["ike_sa"]["enc_alg"]["value"] == "aes-128-cbc", \
        out["ike_sa"]["enc_alg"]
    assert out["ike_sa"]["dh_group"]["value"] == 14
    assert out["ike_sa"]["enc_alg"]["status"] == "OBSERVED"


# --------------------------------------------------------------------------
# malformed / truncated / empty: clear error or honest unknown, never
# fabricated certainty
# --------------------------------------------------------------------------
def test_empty_pcap_is_not_confident_plain(tmp_path):
    from scapy.all import wrpcap
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [])
    out = analyze(str(p), MODELS)
    assert out["detection"]["ipsec_detected"] is False
    assert not any(v.get("status") == "OBSERVED"
                   for v in list(out["ike_sa"].values())
                   + list(out["child_sa"].values())), out
    a = assess(out)
    assert a["score_status"] == "WITHHELD"
    assert a["security_score"] is None
    assert a["risk_level"] is None


def test_garbage_pcap_raises_cleanly(tmp_path):
    p = tmp_path / "garbage.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\xde\xad\xbe\xef" * 64)
    try:
        out = analyze(str(p), MODELS)
    except Exception as e:
        assert str(e).strip(), "empty error message"
        return
    assert out["detection"]["ipsec_detected"] is False
    assert not any(v.get("status") == "OBSERVED"
                   for v in list(out["ike_sa"].values())
                   + list(out["child_sa"].values()))


# --------------------------------------------------------------------------
# IPv6 extension headers: ESP behind HopByHop must still be found
# --------------------------------------------------------------------------
def test_ipv6_extension_headers(tmp_path):
    from scapy.all import IPv6, IPv6ExtHdrHopByHop, UDP, Raw, wrpcap
    esp = esp_packets(V1_VOIP)[:5]
    pkts = []
    for i, p in enumerate(esp):
        raw = bytes(p["Raw"].load) if "Raw" in p else bytes(p.payload.payload)
        q = IPv6(src="fd00:ff::1", dst="fd00:ff::2", nh=0) / \
            IPv6ExtHdrHopByHop(nh=50, len=0) / Raw(load=raw)
        q.time = float(i) * 0.01
        pkts.append(q)
    ike = ike_packets(V4_VOIP)[:2]
    allp = pkts + ike
    write_pkts(tmp_path / "v6ext.pcap", allp)
    f = extract(str(tmp_path / "v6ext.pcap"))
    assert f["n_esp"] >= 5, f
    out = analyze(str(tmp_path / "v6ext.pcap"), MODELS)
    assert out["detection"]["ipsec_detected"] is True
    assert out["child_sa"]["proto"]["value"] == "esp"


# --------------------------------------------------------------------------
# NAT-T: non-ESP marker (IKE) vs ESP-in-UDP vs keepalive (neither)
# --------------------------------------------------------------------------
def test_nat_t_marker_keepalive(tmp_path):
    req, _ = ike_sa_init_pair("aes-128-cbc", "hmac-sha256", 14,
                              "aes-128-cbc", "hmac-sha256", 14)
    from scapy.all import IP, UDP, Raw
    marker = b"\x00" * 4 + req  # IKE behind non-ESP marker on 4500
    esp_like = struct.pack("!II", 0x12345678, 1) + b"\x00" * 32
    pkts = [
        IP(src="10.30.0.10", dst="10.30.0.20") / UDP(sport=500, dport=500)
        / Raw(load=req),
        IP(src="10.30.0.10", dst="10.30.0.20") / UDP(sport=4500, dport=4500)
        / Raw(load=marker),
        IP(src="10.30.0.10", dst="10.30.0.20") / UDP(sport=4500, dport=4500)
        / Raw(load=esp_like),
        IP(src="10.30.0.10", dst="10.30.0.20") / UDP(sport=4500, dport=4500)
        / Raw(load=b"\xff"),  # NAT-T keepalive: neither IKE nor ESP
    ]
    write_pkts(tmp_path / "natt.pcap", pkts)
    f = extract(str(tmp_path / "natt.pcap"))
    assert f["n_ike"] == 2, f
    assert f["n_esp_in_udp"] == 1, f
    assert f["n_packets"] == 4, f


# --------------------------------------------------------------------------
# non-IPsec: detection false, assessment NOT_APPLICABLE, no IPsec findings
# --------------------------------------------------------------------------
def test_non_ipsec_plain(tmp_path):
    import shutil
    p = tmp_path / "plain.pcap"
    shutil.copy(PLAIN_VOIP, p)
    out = analyze(str(p), MODELS)
    assert out["detection"]["ipsec_detected"] is False
    a = assess(out)
    assert a["score_status"] == "WITHHELD"
    assert a["security_score"] is None
    assert a["risk_level"] is None
    assert a["findings"] == [], a["findings"]
    assert all(c["status"] == "NOT_APPLICABLE" for c in a["controls"]), \
        a["controls"]
    assert "ah" not in {f["id"] for f in a["findings"]}


# --------------------------------------------------------------------------
# absent model file: clear error naming training, no fabricated output
# --------------------------------------------------------------------------
def test_absent_model_file(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError, match="train"):
        analyze(str(V1_VOIP), tmp_path / "no-models-here")


# --------------------------------------------------------------------------
# sparse / out-of-distribution: abstain (WITHHELD), confirmed FAILs surface
# --------------------------------------------------------------------------
def test_sparse_capture_withheld(tmp_path):
    from scapy.all import IP, Raw
    spi, seq = 0xAABBCCDD, 1
    pkt = IP(src="10.30.0.10", dst="10.30.0.20", proto=50) / \
        Raw(load=struct.pack("!II", spi, seq) + b"\x00" * 16)
    write_pkts(tmp_path / "sparse.pcap", [pkt])
    out = analyze(str(tmp_path / "sparse.pcap"), MODELS)
    assert out["child_sa"]["enc_alg"]["status"] != "OBSERVED"
    a = assess(out)
    assert a["score_status"] == "WITHHELD", a
    assert a["risk_level"] is None
    assert "coverage" in a and a["coverage"] < 0.5


def test_withheld_still_surfaces_confirmed_fails():
    cls = {"ike_sa": {
        "version": {"value": "unknown", "status": "NOT_OBSERVED",
                    "source": "none", "confidence": 0.0},
        "enc_alg": {"value": "unknown", "status": "NOT_OBSERVED",
                    "source": "none", "confidence": 0.0},
        "dh_group": {"value": "unknown", "status": "NOT_OBSERVED",
                     "source": "none", "confidence": 0.0}},
        "child_sa": {
        "proto": {"value": "esp", "status": "OBSERVED",
                  "source": "parsed", "confidence": 1.0},
        "mode": {"value": "unknown", "status": "UNKNOWN",
                 "source": "none", "confidence": 0.0},
        "enc_alg": {"value": "3des-cbc", "status": "INFERRED",
                    "source": "model", "confidence": 0.9},
        "enc_key_len": {"value": 168, "status": "INFERRED",
                        "source": "model", "confidence": 0.9},
        "auth_alg": {"value": "unknown", "status": "UNKNOWN",
                     "source": "none", "confidence": 0.0},
        "pfs": {"value": "unknown", "status": "UNKNOWN",
                "source": "none", "confidence": 0.0},
        "replay": {"value": "unknown", "status": "UNKNOWN",
                   "source": "none", "confidence": 0.0},
        "lifetime": {"value": "unknown", "status": "UNKNOWN",
                     "source": "none", "confidence": 0.0}},
        "detection": {"ipsec_detected": True}}
    a = assess(cls)
    assert a["score_status"] == "WITHHELD"
    assert a["risk_level"] is None
    assert "weak-cipher" in {f["id"] for f in a["findings"]}


# --------------------------------------------------------------------------
# rekey / SPI ambiguity: one rekey + three concurrent SPIs is
# unattributable; a 2-SPI directional pair stays attributable
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# rekey / SPI ambiguity: one rekey + three concurrent SPIs is
# unattributable; a 2-SPI directional pair stays attributable
# --------------------------------------------------------------------------
def test_rekey_spi_ambiguity(tmp_path):
    esp1 = esp_packets(V1_VOIP)[:200]
    esp2 = esp_packets(ROOT / "data/pcaps/synth/v1/r2/voip.pcap")[:200]
    esp3 = esp_packets(ROOT / "data/pcaps/synth/v1/r3/voip.pcap")[:200]
    # Keep original capture times so all SPIs span the whole window
    # (concurrent lifetimes); sequential re-timing would fake handoffs.
    ike = ike_packets(V1_VOIP)  # rekey belongs to r1's SPIs only
    t1 = min(float(p.time) for p in esp1)
    for other in (esp2, esp3):  # normalize onto esp1's timeline
        t2 = min(float(p.time) for p in other)
        for p in other:
            p.time = float(p.time) - t2 + t1
    write_pkts(tmp_path / "ambiguous.pcap", ike + esp1 + esp2 + esp3,
               retime=False)
    f = extract(str(tmp_path / "ambiguous.pcap"))
    assert f["n_spis"] >= 3, f
    assert f["spi_overlap"] == 1, f
    out = analyze(str(tmp_path / "ambiguous.pcap"), MODELS)
    assert out["child_sa"]["pfs"]["status"] == "UNKNOWN", \
        out["child_sa"]["pfs"]
    # Control: a normal 2-SPI directional pair (v1 email) still infers.
    mail = analyze(str(ROOT / "data/pcaps/synth/v1/r1/email.pcap"), MODELS)
    assert mail["child_sa"]["pfs"]["value"] is True
    assert mail["child_sa"]["pfs"]["status"] == "INFERRED"


# --------------------------------------------------------------------------
# assessment unit semantics
# --------------------------------------------------------------------------
def _unknown_cls():
    f = {"value": "unknown", "status": "UNKNOWN",
         "source": "none", "confidence": 0.0}
    return {"ike_sa": {"version": dict(f), "enc_alg": dict(f),
                       "dh_group": dict(f)},
            "child_sa": {"proto": {"value": "esp", "status": "OBSERVED",
                                   "source": "parsed", "confidence": 1.0},
                         "mode": dict(f), "enc_alg": dict(f),
                         "enc_key_len": dict(f), "auth_alg": dict(f),
                         "pfs": dict(f), "replay": dict(f),
                         "lifetime": dict(f)},
            "detection": {"ipsec_detected": True}}


def test_no_assuming_weak_findings():
    a = assess(_unknown_cls())
    assert not [f for f in a["findings"] if f["id"].startswith("unknown-")], \
        a["findings"]
    assert not any("assuming weak" in f.get("text", "") for f in a["findings"])
    for c in a["controls"]:
        if c["status"] == "UNKNOWN":
            assert c.get("resolve_by"), c
            assert c.get("rule_version"), c
            assert c.get("evidence") is not None, c
    assert a["coverage"] == 0.0
    assert a["score_status"] == "WITHHELD"


def test_absent_replay_pfs_lifetime_never_confirmed_disabled():
    a = assess(_unknown_cls())
    ids = {f["id"] for f in a["findings"]}
    assert "no-replay" not in ids
    assert "no-pfs" not in ids
    assert "long-sa" not in ids
    ctl = {c["id"]: c for c in a["controls"]}
    assert ctl["replay"]["status"] == "UNKNOWN"
    assert ctl["pfs"]["status"] == "UNKNOWN"
    assert ctl["lifetime"]["status"] == "UNKNOWN"


def _good_cls():
    g = lambda v, s="OBSERVED", src="parsed": {  # noqa: E731
        "value": v, "status": s, "source": src, "confidence": 1.0}
    return {"ike_sa": {"version": g("ikev2"), "enc_alg": g("aes-128-cbc"),
                       "dh_group": g(14)},
            "dh_group": g(14),
            "child_sa": {"proto": g("esp"),
                         "mode": g("tunnel", "INFERRED", "model"),
                         "enc_alg": g("aes-128-cbc", "INFERRED", "model"),
                         "enc_key_len": g(128, "INFERRED", "model"),
                         "auth_alg": g("hmac-sha256", "INFERRED", "model"),
                         "pfs": {"value": True, "status": "INFERRED",
                                 "source": "model", "confidence": 0.9},
                         "replay": {"value": 32, "status": "NOT_OBSERVED",
                                    "source": "none", "confidence": 0.0},
                         "lifetime": {"value": 3600, "status": "OBSERVED",
                                      "source": "measured", "confidence": 1.0}},
            "detection": {"ipsec_detected": True}}


def test_replay_window_above_32_passes():
    cls = _good_cls()
    cls["child_sa"]["replay"] = {"value": 64, "status": "OBSERVED",
                                 "source": "measured", "confidence": 1.0}
    a = assess(cls, {"child_rekey_s": 3600, "replay_window": 64})
    ctl = {c["id"]: c for c in a["controls"]}
    assert ctl["replay"]["status"] == "PASS", ctl["replay"]
    assert a["breakdown"]["replay"] == 5, a["breakdown"]
    assert "no-replay" not in {f["id"] for f in a["findings"]}


def test_replay_zero_fails():
    cls = _good_cls()
    cls["child_sa"]["replay"] = {"value": 0, "status": "OBSERVED",
                                 "source": "measured", "confidence": 1.0}
    a = assess(cls, {"child_rekey_s": 3600, "replay_window": 0})
    ctl = {c["id"]: c for c in a["controls"]}
    assert ctl["replay"]["status"] == "FAIL", ctl["replay"]
    assert "no-replay" in {f["id"] for f in a["findings"]}


def test_transport_mode_is_info_not_penalty():
    cls = _good_cls()
    cls["child_sa"]["mode"] = {"value": "transport", "status": "INFERRED",
                               "source": "model", "confidence": 0.9}
    a = assess(cls, {"child_rekey_s": 3600, "replay_window": 32})
    ctl = {c["id"]: c for c in a["controls"]}
    assert ctl["mode-exposure"]["status"] == "UNKNOWN", ctl["mode-exposure"]
    assert "transport" not in {f["id"] for f in a["findings"]}
    assert a["breakdown"]["mode"] == 0, a["breakdown"]


def test_oracle_v1_full_visibility():
    a = assess(_good_cls(), {"child_rekey_s": 3600, "replay_window": 32})
    assert a["posture_score"] == 88, a["breakdown"]
    assert a["coverage"] == 1.0
    assert a["score_status"] == "PUBLISHED"
    assert a["risk_level"] == "low"


# --------------------------------------------------------------------------
# API + report invariants: unknowns survive to JSON and PDF
# --------------------------------------------------------------------------
def test_api_report_invariants(tmp_path):
    sys.path.insert(0, str(ROOT / "engine" / "api"))
    from app import app, to_response
    from fastapi.testclient import TestClient
    c = TestClient(app)
    p = strip_ike(V1_VOIP, tmp_path / "esp-only.pcap")
    r = c.post("/analyze", files={"file": ("esp-only.pcap", p.read_bytes())})
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["fields"]["ike_version"]["value"] == "unknown"
    assert body["fields"]["dh_group"]["value"] == "unknown"
    assert "ike_sa" in body and "child_sa" in body
    assert "detection" in body
    assert body["ike_sa"]["version"]["status"] == "NOT_OBSERVED"
    assert body["assessment"]["score_status"] in ("PUBLISHED", "WITHHELD")
    assert "coverage" in body["assessment"]
    sys.path.insert(0, str(ROOT / "reports"))
    from build import technical
    out_pdf = tmp_path / "t.pdf"
    technical(body, out_pdf, "esp-only.pcap")
    assert out_pdf.exists() and out_pdf.stat().st_size > 1000
    # CLI JSON carries the same objects
    sys.path.insert(0, str(ROOT / "cli"))
    from typer.testing import CliRunner
    from main import app as cli_app
    rr = CliRunner().invoke(cli_app, ["analyze", str(p), "--json"])
    assert rr.exit_code == 0, rr.output
    cli_body = json.loads(rr.output)
    assert cli_body["ike_sa"]["version"]["status"] == "NOT_OBSERVED"
    assert cli_body["child_sa"]["enc_alg"]["status"] in ("INFERRED", "UNKNOWN")

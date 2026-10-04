"""v1.2.7 robustness: invariant, framing, OOD gate (test-first).

Root causes (DEV-only diagnosis, external strongSwan corpus):
(a) the mode RF learned a 'none' (plain) class; OOD captures (n=5000,
    19 s spans) land in plain-dominated leaves -> 'none'@0.62 on ESP;
(b) real 45 s traffic mixes hit uncalibrated whatsapp pockets;
(c) AES-128-CBC vs AES-256-CBC are wire-identical in ESP size
    structure (verified identical means/mods on our v1/v2 pairs), so
    the model falls back to the majority class off-distribution.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from predict import analyze  # noqa: E402
from model import ood_violations, ood_ranges  # noqa: E402

MODELS = ROOT / "engine" / "models"


def _esp_only_pcap(dst: Path):
    """Single-SPI ESP-only capture (crafted L3, no IKE)."""
    from scapy.all import IP, Raw, wrpcap
    import struct
    pkts = []
    base = 1700000000.0
    for i in range(60):
        pay = struct.pack("!II", 0xAABBCCDD, i + 1) + bytes(32)
        p = IP(src="10.30.0.10", dst="10.30.0.20", proto=50) / Raw(load=pay)
        p.time = base + i * 0.02
        pkts.append(p)
    wrpcap(str(dst), pkts)
    return dst


def test_invariant_detected_ipsec_never_plain_mode(tmp_path):
    p = _esp_only_pcap(tmp_path / "esp.pcap")
    out = analyze(str(p), MODELS)
    assert out["detection"]["ipsec_detected"] is True
    mode = out["child_sa"]["mode"]
    assert mode["value"] != "none", mode
    assert mode["value"] == "unknown", mode
    assert mode["status"] == "NOT_OBSERVED", mode
    assert mode["evidence"] and "reason" in mode["evidence"], mode


def test_property_no_detected_plain_mode_corpus():
    """Property: every corpus capture with IPsec detected reports a
    mode other than plain/none (or an explicit unknown)."""
    import csv
    rows = list(csv.DictReader((ROOT / "data" / "manifest.csv").open()))
    checked, converted = 0, 0
    for r in rows:
        if r["source"] != "synthetic":
            continue
        out = analyze(str(ROOT / r["file"]), MODELS)
        if not out["detection"]["ipsec_detected"]:
            continue
        checked += 1
        m = out["child_sa"]["mode"]
        assert m["value"] != "none", (r["file"], m)
        if m["value"] == "unknown":
            converted += 1
    assert checked > 300, checked
    print(f"property: {checked} detected captures, {converted} unknowns")


def test_framing_esp_in_udp_matches_native(tmp_path):
    """Same ESP bytes as native proto-50 vs UDP/4500 (no marker):
    ESP size/flow features must match exactly (framing stripped)."""
    from scapy.all import IP, UDP, Raw, wrpcap
    import struct
    pay = struct.pack("!II", 0x11223344, 7) + bytes(48)
    base = 1700000000.0

    def mk(dst, make):
        pkts = []
        for i in range(20):
            p = make(i)
            p.time = base + i * 0.05
            pkts.append(p)
        wrpcap(str(dst), pkts)

    mk(tmp_path / "native.pcap",
       lambda i: IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / Raw(load=pay))
    mk(tmp_path / "encap.pcap",
       lambda i: IP(src="10.0.0.1", dst="10.0.0.2", proto=17) /
       UDP(sport=4500, dport=4500) / Raw(load=pay))
    a, b = (extract(str(tmp_path / f)) for f in ("native.pcap", "encap.pcap"))
    assert a["n_esp"] == b["n_esp"] == 20
    for k in ("esplen_mean", "esplen_min", "esplen_max", "n_spis"):
        assert a[k] == b[k], (k, a[k], b[k])
    assert [a[f"mod16_{i}"] for i in range(16)] == \
        [b[f"mod16_{i}"] for i in range(16)]


def test_framing_ipv6_esp_matches_ipv4(tmp_path):
    """Same ESP bytes over IPv4 vs IPv6: identical ESP features."""
    from scapy.all import IP, IPv6, Raw, wrpcap
    import struct
    pay = struct.pack("!II", 0x55667788, 3) + bytes(24)
    base = 1700000000.0
    v4, v6 = [], []
    for i in range(20):
        a = IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / Raw(load=pay)
        a.time = base + i * 0.05
        v4.append(a)
        b = IPv6(src="fd00::1", dst="fd00::2", nh=50) / Raw(load=pay)
        b.time = base + i * 0.05
        v6.append(b)
    wrpcap(str(tmp_path / "v4.pcap"), v4)
    wrpcap(str(tmp_path / "v6.pcap"), v6)
    a, b = (extract(str(tmp_path / f)) for f in ("v4.pcap", "v6.pcap"))
    assert a["n_esp"] == b["n_esp"] == 20
    assert a["esplen_mean"] == b["esplen_mean"]
    assert a["n_spis"] == b["n_spis"]


def test_ood_gate_abstains_with_reason():
    """A capture far outside training ranges abstains explicitly."""
    import json
    ranges = json.loads((MODELS / "feature_ranges.json").read_text())
    feats = {"n_packets": 10_000_000, "duration": 99999.0,
             "pktlen_mean": 1e9, "n_esp": 5, "esplen_mean": 10.0,
             "n_ike": 0, "ip6_ext": 0, "n_esp_in_udp": 0,
             "spi_overlap": 0, "rk_sk_req_len": 0}
    bad = ood_violations(feats, ranges)
    assert len(bad) >= 1, bad
    assert any("n_packets" in w or "duration" in w for w in bad), bad


def test_ood_gate_passes_our_captures():
    """In-distribution captures (our corpus) pass clean."""
    import json
    ranges = json.loads((MODELS / "feature_ranges.json").read_text())
    f = extract(str(ROOT / "data/pcaps/synth/v1/r1/voip.pcap"))
    assert ood_violations(f, ranges) == [], ood_violations(f, ranges)


def _inf_field(value, conf):
    return {"value": value, "status": "INFERRED", "source": "model",
            "confidence": conf}


def test_ood_gate_abstains_only_when_tripped_and_below_floor():
    from predict import apply_ood_gate
    bad = ["n_packets=5000 outside [18,2975]", "duration=19 outside [6,60]",
           "n_esp=4990 outside [0,489]", "iat_mean=0.003 outside [0.01,0.5]",
           "esplen_mean=997 outside [100,900]"]
    # tripped + below floor -> UNKNOWN with reason
    t = [_inf_field("tunnel", 0.55)]
    apply_ood_gate(t, True, bad, 0.6)
    assert t[0]["value"] == "unknown", t[0]
    assert t[0]["status"] == "UNKNOWN", t[0]
    assert "outside the training distribution" in t[0]["evidence"]["reason"]
    assert t[0]["evidence"]["resolve_by"]
    assert t[0]["confidence"] == 0.55  # never lowered quietly
    # tripped but confident -> stands
    t = [_inf_field("tunnel", 0.95)]
    apply_ood_gate(t, True, bad, 0.6)
    assert t[0]["value"] == "tunnel", t[0]
    # below floor but in-distribution -> stands (calibrated risk)
    t = [_inf_field("tunnel", 0.55)]
    apply_ood_gate(t, False, [], 0.6)
    assert t[0]["value"] == "tunnel", t[0]
    # non-INFERRED untouched
    t = [{"value": "tunnel", "status": "OBSERVED", "source": "parsed",
          "confidence": 1.0}]
    apply_ood_gate(t, True, bad, 0.6)
    assert t[0]["value"] == "tunnel", t[0]


def test_ood_ranges_cover_training_data():
    import csv
    import json
    from model import OOD_MIN_VIOLATIONS, OOD_MARGIN
    assert OOD_MIN_VIOLATIONS == 5
    assert OOD_MARGIN == 0.1
    ranges = json.loads((MODELS / "feature_ranges.json").read_text())
    rows = list(csv.DictReader(
        (ROOT / "data" / "manifest.csv").open()))
    envelope = sum(1 for r in rows if r["source"] in ("synthetic", "real"))
    assert ranges["n_train"] == envelope, (ranges["n_train"], envelope)
    assert "n_packets" in ranges["keys"] and "duration" in ranges["keys"]

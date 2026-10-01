"""Guardrail 1: features come only from packet bytes.

- test_features_identical_without_labels: hiding data/labels (+ manifest)
  must not change extract() output by a single bit.
- test_no_feature_derived_from_label: no feature key names an endpoint /
  label concept; no high-entropy wire value (endpoint IP/MAC, SPI,
  cookie, absolute epoch) appears among feature values.
"""
import shutil
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
from extract import extract  # noqa: E402

SAMPLES = [
    "data/pcaps/synth/v1/r1/voip.pcap",
    "data/pcaps/synth/v5/r2/web.pcap",
    "data/pcaps/synth/v12/r3/icmp.pcap",
    "data/pcaps/synth/plain/v6/r1/email.pcap",
]
# real captures are NOT in git (regenerable only via the testbed); the
# e2e clean checkout lacks them, so they are covered opportunistically.
OPTIONAL_SAMPLES = [
    "data/real/v18/r1/voip.pcap",
]

BANNED_KEY_SUBSTR = ("_src", "_dst", "src_", "dst_", "saddr", "daddr",
                     "hwaddr", "ether", "cookie",
                     "epoch", "time_abs", "run_id", "file", "label")


def _wire_secrets(pcap: str):
    """High-entropy values straight from packet bytes."""
    from scapy.all import PcapReader, IP, IPv6, UDP, Ether
    secrets = set()
    with PcapReader(pcap) as rd:
        for p in rd:
            if Ether in p:
                secrets.add(p[Ether].src)
                secrets.add(p[Ether].dst)
            ip = p.getlayer(IP) or p.getlayer(IPv6)
            if ip is None:
                continue
            secrets.add(ip.src)
            secrets.add(ip.dst)
            if UDP in p:
                u = p[UDP]
                if u.sport in (500, 4500) or u.dport in (500, 4500):
                    pay = bytes(u.payload)
                    body = pay[4:] if pay[:4] == b"\x00" * 4 else pay
                    if len(body) >= 16:
                        secrets.add(body[:8].hex())   # IKE cookies
                        secrets.add(body[8:16].hex())
            pr = ip.proto if ip.__class__.__name__ == "IP" else ip.nh
            if pr == 50:
                raw = bytes(ip.payload)
                if len(raw) >= 4:
                    secrets.add(struct.unpack("!I", raw[:4])[0])
            secrets.add(int(float(p.time)))
    return secrets


def _present(s):
    return (ROOT / s).exists()


def test_features_identical_without_labels(tmp_path):
    samples = [s for s in SAMPLES + OPTIONAL_SAMPLES if _present(s)]
    assert samples, "no sample pcaps (run generate-data first)"
    before = {s: extract(str(ROOT / s)) for s in samples}
    lab = ROOT / "data" / "labels"
    man = ROOT / "data" / "manifest.csv"
    # Unique hide-dir + merge restore: a concurrent generator recreating
    # data/labels must never cause nesting (incident: pytest raced a
    # background validator self-test).
    import os
    hidden = ROOT / "data" / f".labels-hidden-{os.getpid()}"
    man_hidden = ROOT / "data" / f".manifest-hidden-{os.getpid()}"
    shutil.move(str(lab), str(hidden))
    moved_man = False
    if man.exists():
        shutil.move(str(man), str(man_hidden))
        moved_man = True
    try:
        for s in samples:
            after = extract(str(ROOT / s))
            assert after == before[s], f"features changed for {s}"
    finally:
        if lab.exists():
            shutil.copytree(str(hidden), str(lab), dirs_exist_ok=True)
            shutil.rmtree(str(hidden), ignore_errors=True)
        else:
            shutil.move(str(hidden), str(lab))
        if moved_man:
            shutil.move(str(man_hidden), str(man))


def test_no_feature_derived_from_label():
    for s in [x for x in SAMPLES + OPTIONAL_SAMPLES if _present(x)]:
        feats = extract(str(ROOT / s))
        for k in feats:
            kl = k.lower()
            assert not any(b in kl for b in BANNED_KEY_SUBSTR), \
                f"banned key {k} in {s}"
        secrets = _wire_secrets(str(ROOT / s))
        str_vals = [v for v in feats.values() if isinstance(v, str)]
        num_vals = [v for v in feats.values() if isinstance(v, (int, float))]
        blob = "\n".join(str_vals)
        for sec in secrets:
            if isinstance(sec, str) and (":" in sec or "-" in sec or
                                         len(sec) == 16):
                assert sec not in blob, f"wire secret {sec} in {s}"
            elif isinstance(sec, int) and sec > 65535:
                assert sec not in num_vals, f"wire secret {sec} in {s}"

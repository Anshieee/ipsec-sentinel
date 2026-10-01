"""Corpus-count guards (independent review MAJOR-3/MAJOR-5).

- test_doc_counts_match_manifest: the canonical numbers printed in docs
  (360 synthetic + 66 real = 426 rows; 853 checksum entries) must match
  data/manifest.csv and dataset/checksums.sha256. Fails on drift.
- test_regeneration_deterministic: building the same pcap twice yields
  identical bytes; the RNG streams (ike|data) isolate IKE edits from
  traffic timing/counts.
"""
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EXPECTED = {"synthetic": 360, "real": 66, "total": 426, "checksums": 853}
DOC_SPOTS = [
    ("README.md", ["360 synthetic + 66 real"]),
    ("docs/dataset-datasheet.md", ["426 pcaps", "360 synthetic + 66 real"]),
    ("docs/model-evaluation.md", ["test 66 real", "66 pcaps incl."]),
    ("AGENTS.md", ["66 real pcaps", "426 rows"]),
    ("dataset/README.md", ["426 pcaps", "853 checksum entries"]),
]


def test_doc_counts_match_manifest():
    rows = list(csv.DictReader((ROOT / "data" / "manifest.csv").open()))
    by_src = {}
    for r in rows:
        by_src[r["source"]] = by_src.get(r["source"], 0) + 1
    assert by_src.get("synthetic") == EXPECTED["synthetic"], by_src
    if by_src.get("real", 0) == 0:
        import pytest
        pytest.skip("no real captures in this checkout (tarball not extracted)")
    assert by_src.get("real") == EXPECTED["real"], by_src
    assert len(rows) == EXPECTED["total"]
    n_sums = sum(1 for _ in (ROOT / "dataset" / "checksums.sha256").open())
    assert n_sums == EXPECTED["checksums"], n_sums
    for rel, needles in DOC_SPOTS:
        text = (ROOT / rel).read_text()
        for n in needles:
            assert n in text, f"{rel} missing {n!r}"


def test_regeneration_deterministic():
    sys.path.insert(0, str(ROOT / "capture" / "synth"))
    from synth_pcap import build_pcap, build_plain
    from scapy.all import wrpcap, rdpcap
    import tempfile, os
    for vid, tr, run in (("v1", "voip", "r1"), ("v11", "email", "r2"),
                         ("v18", "whatsapp", "r3")):
        a, _ = build_pcap(vid, tr, run)
        b, _ = build_pcap(vid, tr, run)
        assert [bytes(p) for p in a] == [bytes(p) for p in b], (vid, tr, run)
        assert [float(p.time) for p in a] == [float(p.time) for p in b]
    for fam, tr, run in ((4, "web", "r1"), (6, "icmp", "r2")):
        a, _ = build_plain(tr, fam, run)
        b, _ = build_plain(tr, fam, run)
        assert [bytes(p) for p in a] == [bytes(p) for p in b]
    # manifest row stability: same inputs -> same counts/labels
    rows = list(csv.DictReader((ROOT / "data" / "manifest.csv").open()))
    key = [r for r in rows if r["file"] == "data/pcaps/synth/v1/r1/voip.pcap"]
    assert key and key[0]["variant"] == "v1" and int(key[0]["packets"]) > 0

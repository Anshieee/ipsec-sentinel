"""README/dataset counts must match the manifest (Part 3 hygiene).

Fails loudly if a count in README.md, dataset/README.md or
docs/dataset-datasheet.md drifts from data/manifest.csv — edit the
generator and the docs together.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _manifest_counts():
    rows = list(csv.DictReader((ROOT / "data" / "manifest.csv").open()))
    by_src = {}
    for r in rows:
        by_src[r["source"]] = by_src.get(r["source"], 0) + 1
    return len(rows), by_src.get("synthetic", 0), by_src.get("real", 0)


def test_readme_counts_match_manifest():
    total, synth, real = _manifest_counts()
    text = (ROOT / "README.md").read_text()
    m = re.search(r"(\d+) synthetic \+ (\d+) real labels", text)
    assert m, "README quickstart count line missing"
    assert (int(m.group(1)), int(m.group(2))) == (synth, real), \
        (m.group(0), synth, real)
    m2 = re.search(r"builds the (\d+) synthetic pcaps", text)
    assert m2 and int(m2.group(1)) == synth, \
        (m2.group(0) if m2 else None, synth)
    m3 = re.search(r"data/real.*?\(\d+ captures\)", text, re.S)
    assert m3 and str(real) in m3.group(0), (m3.group(0) if m3 else None, real)
    ds = (ROOT / "dataset" / "README.md").read_text()
    assert f"({synth + real} pcaps)" in ds or f"{synth + real} pcaps" in ds, ds[:60]
    sheet = (ROOT / "docs" / "dataset-datasheet.md").read_text()
    assert f"**{total} pcaps**" in sheet, sheet[:200]
    assert f"{synth} synthetic + {real} real" in sheet


def test_ingest_real_fails_without_data_real(tmp_path):
    """generate-data --real exits non-zero with an actionable message
    when data/real is absent (real tarball not extracted)."""
    import shutil
    import subprocess
    real = ROOT / "data" / "real"
    hide = ROOT / "data" / f".real-hidden-{__import__('os').getpid()}"
    shutil.move(str(real), str(hide))
    try:
        r = subprocess.run(
            [sys.executable, "capture/synth/synth_pcap.py", "--ingest-real"],
            cwd=str(ROOT), capture_output=True, text=True)
        assert r.returncode != 0, (r.returncode, r.stdout[-500:])
        assert "data/real" in r.stdout + r.stderr, r.stdout[-500:]
        assert "RELEASE" in r.stdout + r.stderr or \
            "tarball" in r.stdout + r.stderr, r.stdout[-500:]
    finally:
        shutil.move(str(hide), str(real))

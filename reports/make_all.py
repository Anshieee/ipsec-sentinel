#!/usr/bin/env python3
"""Build all report PDFs (M4 req 3, v1.1): executive (1-2 p), technical for 6+
varied pcaps (weak, AH, plain, real, IKEv1, GCM), comparative over all 20
variants + plain. Every PDF shows status, unknowns, posture vs coverage,
and the synthetic-vs-real caveat. Output: reports/out/.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
sys.path.insert(0, str(ROOT / "engine" / "api"))
sys.path.insert(0, str(ROOT / "reports"))
from app import to_response  # noqa: E402
from predict import analyze  # noqa: E402
from build import executive, technical, comparative  # noqa: E402

MODELS = ROOT / "engine" / "models"

TECHNICAL = [
    ("data/pcaps/synth/v11/r1/voip.pcap", "weak-3des"),
    ("data/pcaps/synth/v7/r1/voip.pcap", "ah"),
    ("data/pcaps/synth/plain/v4/r1/web.pcap", "plain"),
    ("data/real/v18/r1/voip.pcap", "real-natt"),
    ("data/pcaps/synth/v12/r1/voip.pcap", "ikev1"),
    ("data/pcaps/synth/v3/r1/voip.pcap", "gcm"),
]


def _analyze_opt(rel: str):
    p = ROOT / rel
    if not p.exists():
        print(f"SKIP missing {rel} (e.g. synthetic-only checkout)")
        return None
    return analyze(str(p), MODELS)


def main() -> int:
    out = ROOT / "reports" / "out"
    out.mkdir(parents=True, exist_ok=True)
    one = _analyze_opt("data/pcaps/synth/v1/r1/voip.pcap")
    executive(to_response(one), out / "executive.pdf")
    print("executive.pdf")
    for rel, tag in TECHNICAL:
        r = _analyze_opt(rel)
        if r is None:
            continue
        technical(to_response(r), out / f"technical-{tag}.pdf", Path(rel).name)
        print(f"technical-{tag}.pdf")
    rows = []
    for vid in [f"v{i}" for i in range(1, 21)]:
        r = analyze(str(ROOT / f"data/pcaps/synth/{vid}/r1/voip.pcap"), MODELS)
        rows.append({"variant": vid, "analysis": to_response(r)})
    r = analyze(str(ROOT / "data/pcaps/synth/plain/v4/r1/voip.pcap"), MODELS)
    rows.append({"variant": "plain", "analysis": to_response(r)})
    comparative(rows, out / "comparative.pdf")
    print("comparative.pdf")
    total = sum(p.stat().st_size for p in out.glob("*.pdf"))
    print(f"{len(list(out.glob('*.pdf')))} PDFs, {total} bytes in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

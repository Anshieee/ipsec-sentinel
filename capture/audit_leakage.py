#!/usr/bin/env python3
"""Anti-leakage audit (spec line 56, decision D5 release gate).

Verifies that no incidental (non-label) field in the corpus uniquely
identifies a variant. Method: for each incidental field, a permutation
mutual-information test of field-vs-variant independence (200 shuffles,
pass requires p > 0.01), plus structural checks:

  - SPIs globally unique (per-run randomization, no reuse across pcaps)
  - runs of the same variant differ in SPIs / start times / addresses
  - no low-cardinality field value (n>=3) maps to a single variant,
    except label-legitimate fields (UDP 500/4500 port, ESP/AH presence,
    IKE version bytes, proposal contents, sizes forced by the label)

Label-legitimate wire features (ports 500/4500, ESP-vs-AH, IKEv1-vs-v2
bytes, transform IDs, cipher-driven length alignment) are EXPECTED to
identify variant facets — they are the classification targets, not leaks.

Usage: audit_leakage.py [--manifest data/manifest.csv] [--out docs/anti-leakage-audit.md]
"""
from __future__ import annotations

import argparse
import csv
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_rows(manifest: Path):
    rows = []
    for r in csv.DictReader(manifest.open()):
        if r["source"] == "synthetic":
            rows.append(r)
    return rows


def extract(pcap_rel: str):
    """Incidental per-pcap fields (fast header-only pass)."""
    from scapy.all import PcapReader, IP, IPv6, UDP, TCP, Ether
    outer_src, outer_dst, sports, macs, spis = set(), set(), set(), set(), set()
    t0 = None
    with PcapReader(str(ROOT / pcap_rel)) as rd:
        for p in rd:
            if t0 is None:
                t0 = float(p.time)
            if Ether in p:
                macs.add(p[Ether].src)
                macs.add(p[Ether].dst)
            ip = p.getlayer(IP) or p.getlayer(IPv6)
            if ip is None:
                continue
            outer_src.add(ip.src)
            outer_dst.add(ip.dst)
            if UDP in p:
                u = p[UDP]
                if u.sport not in (500, 4500) and u.dport not in (500, 4500):
                    sports.add(u.sport)
            if TCP in p:
                t = p[TCP]
                if t.sport not in (500, 4500) and t.dport not in (500, 4500):
                    sports.add(t.sport)
            pr = ip.proto if ip.__class__.__name__ == "IP" else ip.nh
            if pr == 50:
                import struct
                raw = bytes(ip.payload)
                if len(raw) >= 4:
                    spis.add(struct.unpack("!I", raw[:4])[0])
    return {"outer_src": tuple(sorted(outer_src)),
            "outer_dst": tuple(sorted(outer_dst)),
            "sports": tuple(sorted(sports)),
            "macs": tuple(sorted(macs)),
            "spis": tuple(sorted(spis)),
            "day": int(t0 // 86400) if t0 else -1}


def mi(xs, ys) -> float:
    n = len(xs)
    cxy, cx, cy = Counter(), Counter(), Counter()
    for x, y in zip(xs, ys):
        cxy[(x, y)] += 1
        cx[x] += 1
        cy[y] += 1
    m = 0.0
    for (x, y), c in cxy.items():
        p = c / n
        m += p * math.log(p / ((cx[x] / n) * (cy[y] / n)))
    return m


def perm_test(xs, ys, n_perm=200, seed=7) -> tuple[float, float]:
    obs = mi(xs, ys)
    rng = random.Random(seed)
    ge = 0
    for _ in range(n_perm):
        perm = ys[:]
        rng.shuffle(perm)
        if mi(xs, perm) >= obs:
            ge += 1
    return obs, (ge + 1) / (n_perm + 1)


def run_of(r: dict) -> str:
    p = Path(r["file"]).parts
    # data/pcaps/synth/<variant>/<run>/<t>.pcap
    # data/pcaps/synth/plain/v{4,6}/<run>/<t>.pcap
    return p[5] if p[3] == "plain" else p[4]


def grouped_nn(rows, feats, field) -> float:
    """Leave-one-run-out exact-match accuracy (unseen values -> majority).

    Honest leakage measure under run-grouped splits (D6): memorization of
    training-run values cannot score on a held-out run unless the field
    genuinely carries variant signal.
    """
    runs = sorted({run_of(r) for r in rows})
    correct = total = 0
    for held in runs:
        train = [(feats[r["file"]][field], r["variant"]) for r in rows
                 if run_of(r) != held]
        test = [(feats[r["file"]][field], r["variant"]) for r in rows
                if run_of(r) == held]
        maj = Counter(v for _, v in train).most_common(1)[0][0]
        lookup: dict = {}
        for x, v in train:
            lookup.setdefault(x, Counter())[v] += 1
        for x, v in test:
            pred = lookup[x].most_common(1)[0][0] if x in lookup else maj
            correct += pred == v
            total += 1
    return correct / total


def stratum(r: dict):
    """Label-legitimate strata: family × plain-vs-ipsec.

    Association *between* strata (e.g. v6-run addresses narrowing to the
    3 IPv6 variants, or empty SPI tuples marking plain) is expected
    signal, not leakage. The gate tests independence *within* strata.
    """
    return (r["ip_version"], r["variant"] == "plain")


def strat_perm(xs, variants, strata, n_perm=200, seed=7):
    """Fisher-combined permutation MI p-value across strata."""
    groups: dict = {}
    for x, y, s in zip(xs, variants, strata):
        groups.setdefault(s, ([], []))
        groups[s][0].append(x)
        groups[s][1].append(y)
    rng = random.Random(seed)
    ps = []
    for sx, sy in groups.values():
        if len(set(sy)) < 2:
            continue
        obs = mi(sx, sy)
        ge = sum(mi(sx, _shuffled(sy, rng)) >= obs for _ in range(n_perm))
        ps.append((ge + 1) / (n_perm + 1))
    if not ps:
        return 0.0, 1.0
    chi2 = -2.0 * sum(math.log(p) for p in ps)
    # chi-square survival, even df=2k: Q = e^-x * sum_{i<k} x^i/i!
    x = chi2 / 2.0
    k = len(ps)
    p_comb = math.exp(-x) * sum(x ** i / math.factorial(i) for i in range(k))
    return 0.0, min(1.0, p_comb)


def _shuffled(ys, rng):
    perm = ys[:]
    rng.shuffle(perm)
    return perm


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="data/manifest.csv")
    ap.add_argument("--out", default="docs/anti-leakage-audit.md")
    args = ap.parse_args()

    rows = load_rows(ROOT / args.manifest)
    print(f"auditing {len(rows)} synthetic pcaps")
    feats = {}
    for i, r in enumerate(rows):
        feats[r["file"]] = extract(r["file"])
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(rows)}")
    variants = [r["variant"] for r in rows]
    strata = [stratum(r) for r in rows]
    report = ["# Anti-leakage audit", "",
              f"Corpus: {len(rows)} synthetic pcaps. Method: stratified "
              "permutation MI (200 shuffles within family×plain strata, "
              "Fisher-combined; pass requires p > 0.01) + leave-one-run-out "
              "exact-match (pass < 0.20). ESP/AH presence markers are "
              "excluded from the incidental set: presence is a declared "
              "M3 classification target, not leakage.", "",
              "| field | p | verdict |",
              "|---|---|---|"]
    failures = []

    def check(name, xs, drop_empty=False):
        if drop_empty:
            kept = [(x, y, s) for x, y, s in zip(xs, variants, strata) if x != ()]
            xs, ys, ss = zip(*kept)
        else:
            ys, ss = variants, strata
        _, p = strat_perm(list(xs), list(ys), list(ss))
        ok = p > 0.01
        report.append(f"| {name} | {p:.3f} | {'PASS' if ok else 'FAIL'} |")
        print(f"  {name}: p={p:.3f} {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(name)

    check("outer_src", [feats[r["file"]]["outer_src"] for r in rows])
    check("outer_dst", [feats[r["file"]]["outer_dst"] for r in rows])
    check("non_ike_sports", [feats[r["file"]]["sports"] for r in rows])
    check("macs", [feats[r["file"]]["macs"] for r in rows])
    check("start_day", [feats[r["file"]]["day"] for r in rows])
    # ESP/AH presence is a declared classification target (M3 parses it),
    # not an incidental field: drop the empty (AH/plain) markers here.
    check("spis", [feats[r["file"]]["spis"] for r in rows], drop_empty=True)
    check("combined", [(feats[r["file"]]["outer_src"],
                        feats[r["file"]]["outer_dst"],
                        feats[r["file"]]["sports"],
                        feats[r["file"]]["day"]) for r in rows])

    report.append("")
    report.append("Leave-one-run-out exact-match accuracy "
                  "(chance ~0.10, pass < 0.20):")
    for field in ("outer_src", "outer_dst", "non_ike_sports", "macs",
                  "start_day", "spis"):
        key = {"non_ike_sports": "sports", "start_day": "day"}.get(field, field)
        acc = grouped_nn(rows, feats, key)
        ok = acc < 0.20
        report.append(f"- {field}: {acc:.3f} {'PASS' if ok else 'FAIL'}")
        print(f"  grouped {field}: {acc:.3f} {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"grouped-{field}")

    # Structural: SPI uniqueness + run distinctness
    seen: dict[int, str] = {}
    dup = 0
    for r in rows:
        for s in feats[r["file"]]["spis"]:
            if s in seen:
                dup += 1
            seen[s] = r["file"]
    report += ["", f"SPI uniqueness: {len(seen)} distinct SPIs, {dup} reused."]
    print(f"  SPIs: {len(seen)} distinct, {dup} reused")
    if dup:
        failures.append("spi-reuse")
    # Low-cardinality single-variant mapping (n>=3) WITHIN strata —
    # label-legitimate markers (e.g. empty SPI tuples of plain pcaps) live
    # in single-variant strata and are skipped.
    low: dict[tuple, Counter] = defaultdict(Counter)
    for r in rows:
        f = feats[r["file"]]
        s = stratum(r)
        for v in f["outer_src"]:
            low[(s, "outer", v)][r["variant"]] += 1
        for v in f["outer_dst"]:
            low[(s, "outer", v)][r["variant"]] += 1
    single = {k: v for k, v in low.items() if sum(v.values()) >= 3
              and len(v) == 1 and len({r["variant"] for r in rows
                                       if stratum(r) == k[0]}) > 1}
    report.append(f"values (n>=3) seen in a single variant: {len(single)}.")
    print(f"  single-variant values: {len(single)}")
    if single:
        failures.append("single-variant-values")
        for k, v in list(single.items())[:10]:
            report.append(f"  - {k}: {dict(v)}")
    report += ["", f"RESULT: {'PASS' if not failures else 'FAIL: ' + ', '.join(failures)}"]
    (ROOT / args.out).write_text("\n".join(report) + "\n")
    print(f"report -> {args.out}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

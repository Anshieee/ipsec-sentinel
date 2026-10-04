#!/usr/bin/env python3
"""One-shot head-to-head: our frozen analyzer on an external corpus.

Reads THEIR metadata (path given, never copied into our repo), runs
analyze() with the already-trained engine/models, and scores only
fields whose label semantics are equal (docs/head-to-head.md §1).
No retraining, no thresholds, no rule changes.

Writes results/external-eval.json: aggregates + per-file records with
ONLY pcap sha256 and our predictions (their labels/paths excluded —
their repo carries no license).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine" / "classifier"))
sys.path.insert(0, str(REPO / "engine" / "assess"))
from predict import analyze  # noqa: E402
from assess import assess  # noqa: E402

THEIR_REF = {"url": "https://github.com/naman9271/ipsec-pcap-lab",
             "commit": "c0cf25647b88c1cdb0649a43049e192e269f4cc6"}

# their value -> ours (None = unmappable, excluded never guessed)
MAP = {
    "ike_version": {"IKEv2": "ikev2", "IKEv1": "ikev1"},
    "mode": {"tunnel": "tunnel", "transport": "transport"},
    "enc_alg": {"AES-128-CBC": "aes-128-cbc", "AES-256-CBC": "aes-256-cbc",
                "AES-256-GCM-16": "aes-256-gcm"},
    "enc_key_len": {"AES-128-CBC": 128, "AES-256-CBC": 256,
                    "AES-256-GCM-16": 256},
    "auth_alg": {"HMAC-SHA256": "hmac-sha256",
                 "AEAD-GCM-128-bit-ICV": "aead"},
    "dh_group": {"14-MODP2048": 14, "19-ECP256": 19, "20-ECP384": 20},
    "pfs": {"on": True, "off": False},
    "ip_version": {"IPv4": 4, "IPv6": 6},
    "nat_t": {"on": True, "off": False},
    "traffic_type": {"web": "web", "video": "video", "voip": "voip",
                     "email": "email", "icmp": "icmp"},
}
# which of THEIR columns feeds each mapped field
SRC = {"ike_version": "ike_version", "mode": "mode", "enc_alg": "cipher",
       "enc_key_len": "cipher", "auth_alg": "integrity",
       "dh_group": "dh_group", "pfs": "pfs", "ip_version": "ip_version",
       "nat_t": "nat_t", "traffic_type": "canonical_label"}
FIELDS = list(MAP)


def map_label(field: str, raw: str):
    """Their label value -> ours, or None when unmappable."""
    return MAP[field].get(raw)


def extract_prediction(out: dict, field: str):
    """(value, provenance) from analyze() output; provenance in
    {observed, inferred, abstained}."""
    if field in ("enc_alg", "enc_key_len", "auth_alg"):
        f = out["child_sa"][field]
    elif field == "dh_group":
        f = out["dh_group"]
    elif field == "pfs":
        f = out["child_sa"]["pfs"]
    elif field == "traffic_type":
        f = out["traffic_type"]
    elif field == "nat_t":
        f = out["nat_t"]
    elif field == "ip_version":
        f = out["ip_version"]
    elif field == "mode":
        f = out["child_sa"]["mode"]
    elif field == "ike_version":
        f = out["ike_sa"]["version"]
    else:  # pragma: no cover
        raise KeyError(field)
    v, st = f.get("value"), f.get("status")
    if v == "unknown" or st in ("UNKNOWN", "NOT_OBSERVED", "NOT_APPLICABLE"):
        return "unknown", "abstained"
    if st == "INFERRED":
        return v, "inferred"
    return v, "observed"


def compute_field_metrics(rows: list[dict]) -> dict:
    """rows: {mappable, answered, correct, provenance}. accuracy counts
    unknown as error; coverage and accuracy-when-answered kept separate."""
    mappable = [r for r in rows if r["mappable"]]
    n = len(mappable)
    if not n:
        return {"n": 0, "accuracy": None, "coverage": None,
                "accuracy_when_answered": None, "by_provenance": {}}
    correct = sum(1 for r in mappable if r["correct"])
    answered = [r for r in mappable if r["answered"]]
    prov: dict[str, dict] = {}
    for p in ("observed", "inferred", "abstained"):
        sub = [r for r in mappable if r["provenance"] == p]
        a = [r for r in sub if r["answered"]]
        prov[p] = {"n": len(sub),
                   "accuracy": round(sum(1 for r in sub if r["correct"])
                                     / len(sub), 4) if sub else None,
                   "coverage": round(len(a) / len(sub), 4) if sub else None}
    return {"n": n, "accuracy": round(correct / n, 4),
            "coverage": round(len(answered) / n, 4),
            "accuracy_when_answered": round(
                sum(1 for r in answered if r["correct"]) / len(answered), 4)
            if answered else None,
            "by_provenance": prov}


def confusion(rows: list[dict]) -> dict:
    """{truth: {pred: count}} over mappable rows with known truth."""
    table: dict[str, dict[str, int]] = {}
    for r in rows:
        if not r["mappable"]:
            continue
        table.setdefault(str(r["true"]), {}).setdefault(str(r["pred"]), 0)
        table[str(r["true"])][str(r["pred"])] += 1
    return table


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_scope(their_root: Path):
    meta = list(csv.DictReader(
        (their_root / "metadata.csv").open()))
    known = [r for r in meta if r["dataset_role"] == "train_known"]
    proto = [r for r in meta if r["dataset_role"] == "protocol_validation"]
    return meta, known, proto


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--their-root", default=str(
        Path.home() / ".tmp-work" / "ipsec-pcap-lab"))
    ap.add_argument("--models", default="engine/models")
    ap.add_argument("--out", default="results/external-eval.json")
    ap.add_argument("--include-protocol-sessions", action="store_true",
                    help="also score the 5 handshake-visible protocol_validation rows (ike/crypto only)")
    args = ap.parse_args()
    their = Path(args.their_root)
    meta_path = their / "metadata.csv"
    if not meta_path.exists():
        print(f"no metadata.csv under {their} (clone {THEIR_REF['url']} "
              f"at {THEIR_REF['commit']})", file=sys.stderr)
        return 2
    models = REPO / args.models
    meta, known, proto = load_scope(their)
    scope = [(r, False) for r in known]
    if args.include_protocol_sessions:
        scope += [(r, True) for r in proto]
    print(f"their rows: {len(meta)} total, {len(known)} train_known, "
          f"{len(proto)} protocol_validation; scoring {len(scope)} files")

    # overlap: none of their pcaps may coincide with our corpus
    their_hashes = {r["sha256"] for r in meta if r.get("sha256")}
    ours, missing = set(), 0
    for row in csv.DictReader((REPO / "data" / "manifest.csv").open()):
        p = REPO / row["file"]
        if p.exists():
            ours.add(sha256_file(p))
        else:
            missing += 1
    overlap = sorted(ours & their_hashes)
    print(f"our corpus files hashed: {len(ours)} (missing: {missing}); "
          f"hash overlap with their corpus: {len(overlap)}")
    if overlap:
        print(f"OVERLAP: {overlap}", file=sys.stderr)

    per_file, rows_by_field = [], {f: [] for f in FIELDS}
    failures = {"parse_error": 0, "no_ipsec": 0, "withheld": 0}
    for rec, is_proto in scope:
        pcap = their / rec["pcap_path"]
        entry: dict = {"sha256": rec.get("sha256") or
                       (sha256_file(pcap) if pcap.exists() else None),
                       "protocol_session": is_proto, "predictions": {},
                       "assessment": {}, "error": None}
        try:
            out = analyze(str(pcap), models)
        except Exception as e:  # noqa: BLE001
            entry["error"] = f"parse-error: {type(e).__name__}: {e}"
            failures["parse_error"] += 1
            per_file.append(entry)
            continue
        a = assess(out)
        entry["assessment"] = {
            "score_status": a["score_status"],
            "posture_score": a["posture_score"],
            "coverage": a["coverage"],
            "risk_band": a["risk_band"]}
        if not out["detection"]["ipsec_detected"]:
            failures["no_ipsec"] += 1
        if a["score_status"] == "WITHHELD":
            failures["withheld"] += 1
        for f in FIELDS:
            if is_proto and f == "traffic_type":
                continue  # IGNORE label: unscored by design
            pred, prov = extract_prediction(out, f)
            truth = map_label(f, rec[SRC[f]])
            entry["predictions"][f] = {"value": pred, "provenance": prov}
            rows_by_field[f].append({
                "mappable": truth is not None,
                "answered": pred != "unknown",
                "correct": pred != "unknown" and pred == truth,
                "provenance": prov, "true": truth, "pred": pred})
        per_file.append(entry)

    aggregates = {}
    for f in FIELDS:
        aggregates[f] = compute_field_metrics(rows_by_field[f])
    aggregates["enc_alg_confusion"] = confusion(rows_by_field["enc_alg"])
    aggregates["traffic_confusion"] = confusion(rows_by_field["traffic_type"])
    doc = {"their_ref": THEIR_REF, "mapping": "docs/head-to-head.md §1",
           "method": "frozen models, no retraining/tuning; unknown counts "
                     "as error; unmappable fields excluded with counts",
           "n_scored": len(scope), "n_protocol_sessions": sum(
               1 for _, p in scope if p),
           "failures": failures, "hash_overlap": overlap,
           "aggregates": aggregates, "per_file": per_file}
    out_path = REPO / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=1))
    print(f"wrote {out_path} ({len(per_file)} files)")
    for f in FIELDS:
        m = aggregates[f]
        print(f"  {f:13s} n={m['n']:<4} acc={m['accuracy']} cov={m['coverage']} "
              f"awa={m['accuracy_when_answered']}")
    return 0 if not overlap else 3


if __name__ == "__main__":
    sys.exit(main())

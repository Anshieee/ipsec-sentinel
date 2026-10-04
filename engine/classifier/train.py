#!/usr/bin/env python3
"""Train per-field classifiers on synthetic pcaps (labels = targets only).

Features come from engine/features/extract.py (packet bytes only).
Usage: .venv/bin/python engine/classifier/train.py [--models DIR]
Writes vectorizer.joblib, <field>.joblib, classes.json, meta.json and
prints a model card fragment. Deterministic (seed 7).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from model import (build_vectorizer, train_field, esp_only_keys,  # noqa: E402
                   MAIN_MODEL_FIELDS, ABLATION_EXTRA_FIELDS)

LABEL_FIELDS = ["traffic_type", "mode", "enc_alg", "enc_key_len",
                "auth_alg", "dh_group", "pfs"]
# Child-suite fields train on the ESP-only feature view: IKE proposal
# bytes must not teach the model to copy IKE -> child (v1.1 boundary).
ESP_VIEW_FIELDS = {"enc_alg", "enc_key_len", "auth_alg"}
LABEL_KEY = {"traffic_type": "traffic_type", "mode": "mode",
             "enc_alg": "encryption", "enc_key_len": "key_length_bits",
             "auth_alg": "auth", "dh_group": "dh_group", "pfs": "pfs"}
CACHE_NAME = "feature_cache.json"


def load_rows():
    rows = [r for r in csv.DictReader(
        (ROOT / "data" / "manifest.csv").open()) if r["source"] == "synthetic"]
    return rows


def label_for(row: dict) -> dict:
    parts = Path(row["file"]).parts
    lab = ROOT / "data" / "labels" / Path(*parts[2:]).with_suffix(".json")
    return json.loads(lab.read_text())


def features_all(rows, cache_path: Path):
    from extract import FEAT_VERSION
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    if cache.get("version") != FEAT_VERSION:
        cache = {"version": FEAT_VERSION}
    feats, dirty = {}, True
    for i, r in enumerate(rows):
        p = ROOT / r["file"]
        mtime = p.stat().st_mtime
        hit = cache.get(r["file"])
        if hit and hit["mtime"] == mtime:
            feats[r["file"]] = hit["feats"]
        else:
            f = extract(str(p))
            feats[r["file"]] = f
            cache[r["file"]] = {"mtime": mtime, "feats": f}
            dirty = True
        if (i + 1) % 100 == 0:
            print(f"  features {i + 1}/{len(rows)}", flush=True)
    if dirty:
        cache_path.write_text(json.dumps(cache))
    return feats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="engine/models")
    args = ap.parse_args()
    mdir = ROOT / args.models
    mdir.mkdir(parents=True, exist_ok=True)
    rows = load_rows()
    print(f"training rows: {len(rows)} (synthetic only)")
    feats = features_all(rows, mdir / CACHE_NAME)
    import joblib
    vec = build_vectorizer([feats[r["file"]] for r in rows])
    joblib.dump(vec, mdir / "vectorizer.joblib")
    X = vec.transform([feats[r["file"]] for r in rows])
    # ESP-only view for child-suite fields (no IKE proposal bytes).
    all_keys = list(feats[rows[0]["file"]].keys())
    esp_keys = esp_only_keys(all_keys)
    vec_esp = build_vectorizer(
        [{k: v for k, v in feats[r["file"]].items() if k in esp_keys}
         for r in rows])
    joblib.dump(vec_esp, mdir / "vectorizer_esp.joblib")
    X_esp = vec_esp.transform(
        [{k: v for k, v in feats[r["file"]].items() if k in esp_keys}
         for r in rows])
    keys = list(vec.feature_names_in_
                if hasattr(vec, "feature_names_in_") else vec.get_feature_names_out())
    classes = {}
    for field in LABEL_FIELDS:
        y_raw = [label_for(r)[LABEL_KEY[field]] for r in rows]
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        y = le.fit_transform([json.dumps(v) for v in y_raw])
        classes[field] = list(le.classes_)
        clf = train_field(X_esp if field in ESP_VIEW_FIELDS else X, y)
        joblib.dump(clf, mdir / f"{field}.joblib")
        print(f"  {field}: {len(le.classes_)} classes"
              f"{' (esp-only view)' if field in ESP_VIEW_FIELDS else ''}")
    (mdir / "classes.json").write_text(json.dumps(classes, indent=1))
    # OOD range gate inputs (v1.2.7): percentiles over the validated
    # envelope — synthetic train rows plus our own real captures when
    # present (same features, no labels, never external data). Models
    # (weights) still train on synthetic only. Without data/real the
    # envelope is synthetic-only and the gate is stricter (noted).
    from model import ood_ranges as _ood_ranges  # noqa: E402
    import csv as _csv
    env_rows = list(rows)
    real_rows = [r for r in _csv.DictReader(
        (ROOT / "data" / "manifest.csv").open()) if r["source"] == "real"]
    if real_rows:
        real_feats = features_all(real_rows, mdir / CACHE_NAME)
        feats.update(real_feats)
        env_rows = list(rows) + real_rows
        print(f"envelope rows: {len(env_rows)} (synthetic + real)")
    else:
        print("envelope rows: synthetic only (no data/real; gate stricter)")
    (mdir / "feature_ranges.json").write_text(json.dumps(
        _ood_ranges([feats[r["file"]] for r in env_rows]), indent=1))
    (mdir / "meta.json").write_text(json.dumps({
        "seed": 7, "n_estimators": 300, "train_rows": len(rows),
        "feature_keys": keys,
        "esp_only_drop_prefix": ["ike"],
        "esp_only_drop_exact": sorted(
            ["has_ike", "has_rekey", "rk_sk_req_len", "rk_sk_resp_len",
             "n_ike", "n_udp500", "n_udp4500_marked"]),
        "esp_view_fields": sorted(ESP_VIEW_FIELDS),
        "esp_view_keys": sorted(esp_keys),
        "model_fields": MAIN_MODEL_FIELDS,
        "ablation_extra": ABLATION_EXTRA_FIELDS,
    }, indent=1))
    print(f"models -> {mdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

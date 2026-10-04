#!/usr/bin/env python3
"""M3 evaluation (guardrail 3): grouped k-fold, synth->real, ESP ablation.

- Grouped 5-fold CV over synthetic pcaps, groups = (variant, run_id):
  no variant-run straddles train/test. Parsed fields are deterministic;
  model fields use per-fold models (same config as production training).
- synth->real: production models (all synthetic) tested on the 42 real
  pcaps, reported separately. Real covers only v1,v3,v5,v7,v12,v18:
  no generalization claim beyond those variants from real data.
- ESP-only ablation: same CV with all IKE-derived features dropped.
- Unknown predictions count as errors (honest: the system declined).
- Outputs: engine/eval/metrics.json, docs/model-evaluation.md,
  docs/plots/cm_*.png.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from parse import parse_fields  # noqa: E402
from model import (build_vectorizer, train_field, esp_only_keys,  # noqa: E402
                   MAIN_MODEL_FIELDS, ABLATION_EXTRA_FIELDS,
                   UNKNOWN_THRESHOLD, ood_violations, ood_ranges,
                   OOD_MARGIN, OOD_MIN_VIOLATIONS)

SCORED = ["ipsec_proto", "ike_version", "mode", "enc_alg", "enc_key_len",
          "auth_alg", "dh_group", "pfs", "ip_version", "traffic_type",
          "nat_t", "ike_enc_alg", "ike_dh_group"]
LABEL_KEY = {"traffic_type": "traffic_type", "mode": "mode",
             "enc_alg": "encryption", "enc_key_len": "key_length_bits",
             "auth_alg": "auth", "dh_group": "dh_group",
             "ipsec_proto": "ipsec_protocol", "ike_version": "ike_version",
             "pfs": "pfs", "ip_version": "ip_version", "nat_t": "nat_t",
             "ike_enc_alg": "ike_encryption", "ike_dh_group": "ike_dh_group"}
# Child-suite fields use the ESP-only feature view (production parity).
ESP_VIEW_FIELDS = ("enc_alg", "enc_key_len", "auth_alg")


def load_split(source: str):
    rows = [r for r in csv.DictReader(
        (ROOT / "data" / "manifest.csv").open()) if r["source"] == source]
    return rows


def label_of(row: dict) -> dict:
    parts = Path(row["file"]).parts
    if parts[1] == "pcaps":
        lab = ROOT / "data" / "labels" / Path(*parts[2:]).with_suffix(".json")
    else:
        lab = ROOT / "data" / "labels" / "real" / \
            Path(*parts[2:]).with_suffix(".json")
    return json.loads(lab.read_text())


def feats_cached(rows, cache_path: Path):
    sys.path.insert(0, str(ROOT / "engine" / "classifier"))
    from train import features_all
    return features_all(rows, cache_path)


def _fold_predict(vec, classes, clfs, field, feats):
    X = vec.transform([feats])
    proba = clfs[field].predict_proba(X)[0]
    j = int(proba.argmax())
    conf = float(proba[j])
    val = json.loads(classes[field][j])
    return {"value": val if conf >= UNKNOWN_THRESHOLD else "unknown",
            "source": "model", "confidence": conf}


def predict_row(feats, parsed, clfs, vec, vec_esp, classes, esp_only=False,
                ranges=None):
    """Flat field predictions mirroring predict.analyze (fold models).

    parsed is the new SA split; child crypto uses the ESP-only view.
    ike_enc_alg / ike_dh_group score the IKE SA parse (not the child).
    Mirrors the plain/none invariant and the OOD gate (ranges = fold
    training percentiles, or production ranges).
    """
    ike_sa, child_sa = parsed["ike_sa"], parsed["child_sa"]
    out = {}
    out["ipsec_proto"] = {"value": child_sa["proto"]["value"]}
    out["ike_version"] = {"value": ike_sa["version"]["value"]}
    out["ike_enc_alg"] = {"value": ike_sa["enc_alg"]["value"]}
    out["ike_dh_group"] = {"value": ike_sa["dh_group"]["value"]}
    out["ip_version"] = {"value": parsed["ip_version"]["value"]}
    out["nat_t"] = {"value": parsed["nat_t"]["value"]}
    # mode: structural for AH, else size-overhead model (full view).
    if child_sa.get("mode") is None:
        if "mode" in clfs:
            out["mode"] = _fold_predict(vec, classes, clfs, "mode", feats)
        else:
            out["mode"] = {"value": "unknown"}
    else:
        out["mode"] = {"value": child_sa["mode"]["value"]}
    # invariant: detected IPsec is never plain/none
    detected = child_sa.get("proto", {}).get("value") in ("esp", "ah")
    if detected and out["mode"]["value"] == "none":
        out["mode"] = {"value": "unknown"}
    esp_feats = {k: v for k, v in feats.items()
                 if k in esp_only_keys(list(feats.keys()))}
    for field in ESP_VIEW_FIELDS:
        if child_sa.get(field) is None:
            if field in clfs:
                out[field] = _fold_predict(vec_esp, classes, clfs, field,
                                           esp_feats)
            else:
                out[field] = {"value": "unknown"}
        else:
            out[field] = {"value": child_sa[field]["value"]}
    # PFS-from-length needs an attributable rekey SK (production parity:
    # 3+ concurrent SPIs make a single rekey unattributable; a 2-SPI
    # directional pair is normal and attributable).
    if child_sa.get("pfs") is None:
        n_sa = feats.get("n_spis", 0) + feats.get("n_ah_spis", 0)
        ambiguous = feats.get("spi_overlap", 0) and n_sa >= 3
        if feats.get("rk_sk_req_len", 0) > 0 and "pfs" in clfs \
                and not ambiguous:
            out["pfs"] = _fold_predict(vec, classes, clfs, "pfs", feats)
        else:
            out["pfs"] = {"value": "unknown"}
    else:
        out["pfs"] = {"value": child_sa["pfs"]["value"]}
    # CHILD PFS group is never on the wire (rekeys encrypted): honestly
    # unknown in every live prediction. The IKE group is scored above.
    out["dh_group"] = {"value": "unknown"}
    if "traffic_type" in clfs:
        out["traffic_type"] = _fold_predict(vec, classes, clfs,
                                            "traffic_type", feats)
    else:
        out["traffic_type"] = {"value": "unknown"}
    if ranges is not None:
        from predict import apply_ood_gate as _gate  # noqa: E402
        bad = ood_violations(feats, ranges)
        floor = UNKNOWN_THRESHOLD + OOD_MARGIN
        tripped = len(bad) >= OOD_MIN_VIOLATIONS
        # only model fills abstain here: parsed/defined values stay
        parsed_keys = {k for k, v in child_sa.items()
                       if v is not None and k != "proto"}
        pairs = []
        for f in ("mode", "enc_alg", "enc_key_len", "auth_alg", "pfs",
                  "traffic_type"):
            if f in parsed_keys:
                continue
            v = out.get(f, {})
            if not isinstance(v, dict) or v.get("value", "unknown") == \
                    "unknown":
                continue  # abstained or model-unknown already
            pairs.append((f, {"value": v["value"], "status": "INFERRED",
                             "source": "model",
                             "confidence": v.get("confidence", 1.0)}))
        _gate([g for _, g in pairs], tripped, bad, floor)
        for f, g in pairs:
            if g["value"] == "unknown":
                out[f] = {"value": "unknown"}
    return out


def score_rows(rows, feats, labels, predict_fn):
    """Return {field: {y_true, y_pred}} with unknowns as errors."""
    res = {f: {"y_true": [], "y_pred": []} for f in SCORED}
    for r in rows:
        pred = predict_fn(feats[r["file"]], r["file"])
        lab = labels[r["file"]]
        for f in SCORED:
            res[f]["y_true"].append(json.dumps(lab[LABEL_KEY[f]]))
            res[f]["y_pred"].append(json.dumps(pred[f]["value"]))
    return res


def metrics_table(scored):
    from sklearn.metrics import precision_recall_fscore_support, accuracy_score
    table = {}
    for f, d in scored.items():
        yt, yp = d["y_true"], d["y_pred"]
        acc = accuracy_score(yt, yp)
        # macro over TRUE label classes only: "unknown" predictions count
        # as errors (they hurt their true class's recall) but "unknown"
        # is not scored as a class of its own.
        labels = sorted(set(yt))
        p, r, f1, _ = precision_recall_fscore_support(yt, yp, labels=labels,
                                                     average="macro",
                                                     zero_division=0)
        table[f] = {"n": len(yt), "accuracy": round(acc, 4),
                    "macro_p": round(float(p), 4), "macro_r": round(float(r), 4),
                    "macro_f1": round(float(f1), 4),
                    "unknown_rate": round(sum(1 for v in yp
                                              if v == '"unknown"') / len(yp), 4)}
    return table


def plot_cm(scored, labels_map, outdir: Path, tag: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import confusion_matrix
    outdir.mkdir(parents=True, exist_ok=True)
    paths = []
    for f, d in scored.items():
        if f not in labels_map:
            continue
        yt, yp = d["y_true"], d["y_pred"]
        cls = sorted(set(yt) | set(yp))
        if len(cls) < 2:
            continue
        cm = confusion_matrix(yt, yp, labels=cls)
        fig, ax = plt.subplots(figsize=(max(4, len(cls)), max(3, len(cls) * 0.7)))
        ax.imshow(cm)
        ax.set_xticks(range(len(cls)))
        ax.set_yticks(range(len(cls)))
        short = [c.strip('"')[:12] for c in cls]
        ax.set_xticklabels(short, rotation=45, ha="right", fontsize=7)
        ax.set_yticklabels(short, fontsize=7)
        for i in range(len(cls)):
            for j in range(len(cls)):
                ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=7)
        ax.set_xlabel("pred")
        ax.set_ylabel("true")
        ax.set_title(f"{tag} {f} (n={len(yt)})")
        fig.tight_layout()
        p = outdir / f"cm_{tag}_{f}.png"
        fig.savefig(p, dpi=100)
        plt.close(fig)
        paths.append(str(p))
    return paths


IKE_BLIND_EXACT = {"n_ike", "ike_n", "has_ike", "n_udp500",
                   "n_udp4500_marked", "has_rekey", "rk_sk_req_len",
                   "rk_sk_resp_len", "ike_exchanges", "ikev1_mm", "ikev1_qm",
                   "ikev1_attrs"}
IKE_BLIND_PREFIX = ("ike",)


def blind_ike(feats: dict) -> dict:
    """Scrub every IKE-derived feature: the ablation must not see IKE
    packets at all — not even through the deterministic parser.
    Numeric sentinels follow the extractor convention (-1 = absent)."""
    g = dict(feats)
    for k in g:
        if k in IKE_BLIND_EXACT or k.startswith(IKE_BLIND_PREFIX):
            if isinstance(g[k], str):
                g[k] = ""
            elif k.startswith(("ike", "rk_")):
                g[k] = -1
            else:
                g[k] = 0
    return g


def run_cv(rows, feats, labels, esp_only=False):
    from sklearn.model_selection import GroupKFold
    groups = [r["variant"] + "/" + labels[r["file"]]["run_id"] for r in rows]
    kf = GroupKFold(n_splits=5)
    agg = {f: {"y_true": [], "y_pred": []} for f in SCORED}
    for fold, (tri, tei) in enumerate(kf.split(rows, groups=groups)):
        tr = [rows[i] for i in tri]
        te = [rows[i] for i in tei]
        fields = MAIN_MODEL_FIELDS + (ABLATION_EXTRA_FIELDS if esp_only else [])
        keep = esp_only_keys(sorted(feats[rows[0]["file"]].keys()))
        tr_full = [feats[r["file"]] for r in tr]
        tr_esp = [{k: feats[r["file"]][k] for k in keep} for r in tr]
        if esp_only:
            # ablation: drop every IKE-derived feature before parsing AND
            # modeling, as if IKE packets were never captured.
            tr_full = [{k: v for k, v in d.items() if k in keep}
                       for d in tr_full]
        vec = build_vectorizer(tr_full)
        vec_esp = build_vectorizer(tr_esp)
        Xtr = vec.transform(tr_full)
        Xtr_esp = vec_esp.transform(tr_esp)
        clfs, classes = {}, {}
        for field in fields:
            y_raw = [labels[r["file"]][LABEL_KEY[field]] for r in tr]
            from sklearn.preprocessing import LabelEncoder
            le = LabelEncoder()
            y = le.fit_transform([json.dumps(v) for v in y_raw])
            classes[field] = list(le.classes_)
            if field in ESP_VIEW_FIELDS:
                clfs[field] = train_field(Xtr_esp, y)
            else:
                clfs[field] = train_field(Xtr, y)

        def predict_fn(fe, _file, _vec=vec, _vesp=vec_esp, _clfs=clfs,
                       _classes=classes, _esp=esp_only,
                       _ranges=ood_ranges(tr_full)):
            if _esp:
                keep = esp_only_keys(list(fe.keys()))
                fe = {k: v for k, v in fe.items() if k in keep}
            parsed = parse_fields(fe)
            return predict_row(fe, parsed, _clfs, _vec, _vesp, _classes,
                               esp_only=_esp, ranges=_ranges)
        fold_scored = score_rows(te, feats, labels, predict_fn)
        for f in SCORED:
            agg[f]["y_true"].extend(fold_scored[f]["y_true"])
            agg[f]["y_pred"].extend(fold_scored[f]["y_pred"])
        print(f"  fold {fold + 1}/5 done (test {len(te)})", flush=True)
    return agg


def run_synth2real(synth_rows, real_rows, feats, labels, models_dir: Path):
    import joblib
    vec = joblib.load(models_dir / "vectorizer.joblib")
    vec_esp = joblib.load(models_dir / "vectorizer_esp.joblib")
    classes = json.loads((models_dir / "classes.json").read_text())
    ranges = json.loads((models_dir / "feature_ranges.json").read_text())
    clfs = {f: joblib.load(models_dir / f"{f}.joblib")
            for f in ("traffic_type", "mode", "enc_alg", "enc_key_len",
                      "auth_alg", "dh_group", "pfs")}

    def predict_fn(fe, _file):
        return predict_row(fe, parse_fields(fe), clfs, vec, vec_esp,
                           classes, ranges=ranges)
    return score_rows(real_rows, feats, labels, predict_fn)


def real_run_of(row: dict) -> str:
    return Path(row["file"]).parts[3]  # data/real/<variant>/<run>/...


def run_real_holdout(synth_rows, real_rows, feats, labels):
    """Train synthetic + real r1 runs; test real r2/r3 runs (runs apart).

    The test set holds the forced-rekey voip-long pcaps and the extra
    web/email/whatsapp captures. Sample counts are small; reported as-is.
    """
    train_rows = list(synth_rows) + [r for r in real_rows
                                     if real_run_of(r) == "r1"]
    test_rows = [r for r in real_rows if real_run_of(r) != "r1"]
    tr_dicts = [feats[r["file"]] for r in train_rows]
    keep = esp_only_keys(sorted(feats[train_rows[0]["file"]].keys()))
    tr_esp = [{k: feats[r["file"]][k] for k in keep} for r in train_rows]
    vec = build_vectorizer(tr_dicts)
    vec_esp = build_vectorizer(tr_esp)
    Xtr = vec.transform(tr_dicts)
    Xtr_esp = vec_esp.transform(tr_esp)
    fields = MAIN_MODEL_FIELDS + ["dh_group"]
    clfs, classes = {}, {}
    for field in fields:
        y_raw = [labels[r["file"]][LABEL_KEY[field]] for r in train_rows]
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        y = le.fit_transform([json.dumps(v) for v in y_raw])
        classes[field] = list(le.classes_)
        if field in ESP_VIEW_FIELDS:
            clfs[field] = train_field(Xtr_esp, y)
        else:
            clfs[field] = train_field(Xtr, y)

    def predict_fn(fe, _file, _ranges=ood_ranges(tr_dicts)):
        return predict_row(fe, parse_fields(fe), clfs, vec, vec_esp,
                           classes, ranges=_ranges)
    scored = score_rows(test_rows, feats, labels, predict_fn)
    info = {"n_train": len(train_rows), "n_test": len(test_rows),
            "test_runs": sorted({real_run_of(r) for r in test_rows}),
            "test_traffic": sorted({r["traffic"] for r in test_rows})}
    return scored, info


def write_report(path: Path, sections: list[tuple[str, str]]):
    with path.open("w") as f:
        f.write("# Model evaluation (M3)\n\n")
        for title, body in sections:
            f.write(f"## {title}\n\n{body}\n\n")


def table_md(table: dict) -> str:
    lines = ["| field | n | acc | macro-P | macro-R | macro-F1 | unknown |",
             "|---|---|---|---|---|---|---|"]
    for f, m in table.items():
        lines.append(f"| {f} | {m['n']} | {m['accuracy']} | {m['macro_p']} | "
                     f"{m['macro_r']} | {m['macro_f1']} | {m['unknown_rate']} |")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="engine/models")
    args = ap.parse_args()
    mdir = ROOT / args.models
    synth = load_split("synthetic")
    real = load_split("real")
    print(f"synthetic rows: {len(synth)}, real rows: {len(real)}")
    feats = feats_cached(synth + real, mdir / "feature_cache.json")
    labels = {}
    for r in synth + real:
        labels[r["file"]] = label_of(r)
    print("== grouped 5-fold CV (synthetic, groups=variant/run) ==")
    cv = run_cv(synth, feats, labels, esp_only=False)
    print("== ESP-only ablation CV ==")
    ab = run_cv(synth, feats, labels, esp_only=True)
    print("== synth-train -> real-test ==")
    s2r = run_synth2real(synth, real, feats, labels, mdir)
    print("== real holdout (train synth + real r1, test real r2/r3) ==")
    hold, hold_info = run_real_holdout(synth, real, feats, labels)
    metrics = {"cv_full": metrics_table(cv), "cv_esp_only": metrics_table(ab),
               "synth2real": metrics_table(s2r),
               "real_holdout": metrics_table(hold), "holdout_info": hold_info}
    (ROOT / "engine" / "eval" / "metrics.json").write_text(json.dumps(metrics, indent=1))
    plots = plot_cm(cv, {"traffic_type": 1, "mode": 1, "enc_alg": 1},
                    ROOT / "docs" / "plots", "cv")
    plots += plot_cm(ab, {"traffic_type": 1, "mode": 1, "enc_alg": 1,
                          "dh_group": 1}, ROOT / "docs" / "plots", "abl")
    plots += plot_cm(s2r, {"traffic_type": 1, "mode": 1},
                     ROOT / "docs" / "plots", "s2r")
    plots += plot_cm(hold, {"traffic_type": 1, "mode": 1},
                     ROOT / "docs" / "plots", "hold")
    synth_vars = sorted({r["variant"] for r in synth})
    n_groups = len(set(r["variant"] + "/" + labels[r["file"]]["run_id"]
                       for r in synth))
    n_var = len([v for v in synth_vars if v != "plain"])
    sections = [
        ("Protocol", f"Grouped 5-fold CV over {len(synth)} synthetic pcaps "
         f"({n_groups} variant-run groups); synth->real trains on all "
         "synthetic, tests the real pcaps (test 66 real); real holdout "
         "trains synthetic + real r1 runs and tests real r2/r3 runs (runs "
         "kept apart); ESP-only ablation drops every IKE-derived feature. "
         "Unknown predictions count as errors."),
        ("Sample counts", f"CV: {len(synth)} synthetic ({n_var} variants + plain "
         f"x 3 runs x 6 types). synth->real: train {len(synth)} synthetic, "
         f"test {len(real)} real. "
         f"holdout: train {hold_info['n_train']}, test {hold_info['n_test']}."),
        ("Grouped CV (full features)", table_md(metrics["cv_full"])),
        ("ESP-only ablation CV", table_md(metrics["cv_esp_only"])),
        ("Synthetic -> real", table_md(metrics["synth2real"])),
        ("Real holdout (train synth + real r1 → test real "
         f"r2/r3; n_train={hold_info['n_train']}, n_test={hold_info['n_test']}, "
         f"runs {hold_info['test_runs']}, traffic {hold_info['test_traffic']})",
         table_md(metrics["real_holdout"])),
        ("Reading the numbers (v1.2 boundary)",
         "- Robustness (v1.2.7): detected IPsec is never plain/none (a "
         "model vote for plain on IPsec becomes NOT_OBSERVED), and "
         "INFERRED votes abstain when the capture trips >= 5 training "
         "range checks with confidence below 0.6 (OOD gate, calibrated "
         "for <= 2% false-abstain on held-out folds + real captures). "
         "Unknowns count as errors below, honestly.\n"
         "- ike_version / ike_enc_alg / ike_dh_group: the IKE SA parse, "
         "still ~100% deterministic (proposal + KE travel in the clear). "
         "These score the IKE SA only — they never fill child fields.\n"
         "- enc_alg / enc_key_len / auth_alg (child suite): model-INFERRED "
         "from the ESP-only feature view (IKE proposal bytes excluded, so "
         "mirrored training suites cannot teach copy-IKE->child). Expect "
         "below the old 1.0 (which came from reading the IKE proposal): "
         "the tables above are the honest ESP-size signal, and the "
         "mismatch variants (v19/v20) prove no inheritance.\n"
         "- ike_enc_alg is parsed from IKE_SA_INIT at ~100%: the v1.2 "
         "ike-cipher / ike-integrity assessment controls read this parse, "
         "never the child suite.\n"
         "- dh_group (CHILD PFS group): 0.0 by design — rekey content is "
         "encrypted, so the child group is never on the wire in short "
         "captures; every live prediction is honestly `unknown` (counted "
         "wrong here). The IKE group is scored separately in "
         "ike_dh_group. The old ablation's dh pockets (priors + "
         "cipher correlation) are gone: no dh model runs in production.\n"
         "- Macro P/R/F1 average over TRUE label classes only; `unknown` "
         "predictions count as errors against their true class but are not "
         "scored as a class.\n"
         "- pfs: a length model over rekey SK blobs (KE inflates the "
         "encrypted blob ~260 B CBC). Correct whenever an attributable "
         "rekey is on the wire — synthetic AND real (forced rekeys prove "
         "presence; sizes transfer); `unknown` with no rekey (IKEv1 QM, "
         "quiet captures) or with concurrent SPIs (rekey unattributable), "
         "counted wrong, honestly. Never a confident error.\n"
         "- traffic_type drops synth->real with ZERO wrong guesses on TCP "
         "(abstains). Calibration works as designed; exact splits are in "
         "the tables above.\n"
         "- Real data covers ONLY v1,v3,v5,v7,v12,v18 (66 pcaps incl. "
         "forced-rekey and extra-TCP runs): the synth->real and holdout "
         f"numbers say nothing about the other {n_var - 6} variants; synthetic-only "
         "and real-included numbers are reported in separate tables above.\n"
         "- What synthetic-only evaluation proves: the pipeline works on "
         "the synthetic distribution. What it does NOT prove: performance "
         "on other stacks, middlebox-mangled traffic, or longer captures "
         "with rekeys. The 66 real pcaps are the only "
         f"out-of-distribution evidence and they cover 6 of {n_var + 1} classes."),
    ]
    write_report(ROOT / "docs" / "model-evaluation.md", sections)
    print("plots:", len(plots))
    print("report -> docs/model-evaluation.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())


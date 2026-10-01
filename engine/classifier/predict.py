"""Single-pcap analysis: parsed fields + model fills (M3 guardrail 2).

`analyze(pcap_path, models_dir)` -> {field: {value, source, confidence}}
plus `ai_confidence` (mean field confidence, unknown counts as 0).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from parse import parse_fields  # noqa: E402
from model import UNKNOWN_THRESHOLD  # noqa: E402

SCORED = ["ipsec_proto", "ike_version", "mode", "enc_alg", "enc_key_len",
          "auth_alg", "dh_group", "pfs", "ip_version", "traffic_type",
          "nat_t"]


def _load_models(models_dir: Path):
    import joblib
    vec = joblib.load(models_dir / "vectorizer.joblib")
    classes = json.loads((models_dir / "classes.json").read_text())
    clfs = {}
    for f in ("traffic_type", "mode", "enc_alg", "enc_key_len", "auth_alg",
              "dh_group", "pfs"):
        p = models_dir / f"{f}.joblib"
        if p.exists():
            clfs[f] = joblib.load(p)
    return vec, classes, clfs


def _model_predict(vec, classes, clfs, field, feats):
    X = vec.transform([feats])
    proba = clfs[field].predict_proba(X)[0]
    j = int(proba.argmax())
    conf = float(proba[j])
    val = json.loads(classes[field][j])
    if conf < UNKNOWN_THRESHOLD:
        return {"value": "unknown", "source": "model", "confidence": conf}
    return {"value": val, "source": "model", "confidence": conf}


def analyze(pcap_path: str | Path, models_dir: str | Path):
    mdir = Path(models_dir)
    vec, classes, clfs = _load_models(mdir)
    feats = extract(str(pcap_path))
    out = parse_fields(feats)
    # mode basis (M4 addition 1): always report the header-structure
    # verdict alongside the size-overhead model signal, and which decided.
    size_sig = _model_predict(vec, classes, clfs, "mode", feats)
    size_info = {"value": size_sig["value"],
                 "confidence": size_sig["confidence"]}
    if out.get("mode") is None:
        out["mode"] = dict(size_sig)
        out["mode"]["detail"] = {
            "header_parse": "n/a",
            "reason": "ESP payload encrypted: inner IP header and "
                      "next-header are not visible on the wire",
            "size_signal": size_info,
            "decided_by": "size-overhead-model"}
    else:
        detail = dict(out["mode"].get("detail", {}))
        detail["size_signal"] = size_info
        if out["mode"]["value"] == "none":
            detail["decided_by"] = "no-ipsec"
        else:
            detail["decided_by"] = "ah-next-header"
        out["mode"]["detail"] = detail
    # model fills (None = not visible on the wire)
    if out.get("mode") is None:
        out["mode"] = _model_predict(vec, classes, clfs, "mode", feats)
    out["traffic_type"] = _model_predict(vec, classes, clfs, "traffic_type",
                                         feats)
    for k in ("enc_alg", "enc_key_len", "auth_alg"):
        if out.get(k) is None:
            out[k] = _model_predict(vec, classes, clfs, k, feats)
    # PFS-from-length needs a rekey SK on the wire; without one there is
    # no evidence at all -> unknown (never a coin-flip). See also
    # evaluate.predict_row, which mirrors this rule for fold models.
    if out.get("pfs") is None:
        if feats.get("rk_sk_req_len", 0) > 0 and "pfs" in clfs:
            out["pfs"] = _model_predict(vec, classes, clfs, "pfs", feats)
        else:
            out["pfs"] = {"value": "unknown", "source": "model",
                          "confidence": 0.0}
    for k in ("dh_group",):
        if out.get(k) is None:
            out[k] = {"value": "unknown", "source": "model",
                      "confidence": 0.0}
    confs = [(out[f]["confidence"] if out[f]["value"] != "unknown" else 0.0)
             for f in SCORED]
    out["ai_confidence"] = sum(confs) / len(confs)
    # Metadata inference (spec M3 line 67): what a passive observer learns
    # from ESP metadata alone. Direct measurements (source: measured).
    dur = feats.get("duration", 0.0) or 0.0
    n = feats.get("n_packets", 0)
    out["metadata"] = {
        "duration_s": {"value": dur, "source": "measured", "confidence": 1.0},
        "n_packets": {"value": n, "source": "measured", "confidence": 1.0},
        "packet_rate": {"value": (n / dur if dur > 0 else 0.0),
                        "source": "measured", "confidence": 1.0},
        "mean_bytes": {"value": feats.get("pktlen_mean", 0.0),
                       "source": "measured", "confidence": 1.0},
        "direction_ratio": {"value": feats.get("flow_dom_ratio", 0.0),
                            "source": "measured", "confidence": 1.0},
    }
    return out

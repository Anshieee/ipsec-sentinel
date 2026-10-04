"""Single-pcap analysis: parsed SA objects + model fills (M3 guardrail 2).

`analyze(pcap_path, models_dir)` -> flat compat fields (each with
value/source/confidence/status) plus `ike_sa` / `child_sa` objects,
`detection`, `ai_confidence` and `metadata`.

Protocol boundary: IKE_SA_INIT describes the IKE SA only. Child crypto
(enc/auth/keylen) is predicted from the ESP-only feature view (IKE
proposal bytes excluded, so mirrored training suites cannot teach the
model to copy IKE -> child); results are labeled INFERRED (model),
never parsed. With zero packets, no inference runs at all.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "features"))
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
from extract import extract  # noqa: E402
from parse import parse_fields, NOT_OBSERVED, NOT_APPLICABLE, UNKNOWN  # noqa: E402
from model import UNKNOWN_THRESHOLD, esp_only_keys  # noqa: E402
from model import ood_violations, OOD_MARGIN, OOD_MIN_VIOLATIONS  # noqa: E402

SCORED = ["ipsec_proto", "ike_version", "mode", "enc_alg", "enc_key_len",
          "auth_alg", "dh_group", "pfs", "ip_version", "traffic_type",
          "nat_t"]

# Child-suite fields: IKE proposal bytes must not leak into them.
CHILD_ESP_VIEW = ("enc_alg", "enc_key_len", "auth_alg")

REQUIRED_MODELS = ("vectorizer.joblib", "vectorizer_esp.joblib",
                   "classes.json", "feature_ranges.json")


def _load_models(models_dir: Path):
    import joblib
    missing = [m for m in REQUIRED_MODELS if not (models_dir / m).exists()]
    if missing:
        raise FileNotFoundError(
            f"models missing ({', '.join(missing)}): run "
            f"`ipsec-analyze train` first.")
    vec = joblib.load(models_dir / "vectorizer.joblib")
    vec_esp = joblib.load(models_dir / "vectorizer_esp.joblib")
    classes = json.loads((models_dir / "classes.json").read_text())
    ranges = json.loads((models_dir / "feature_ranges.json").read_text())
    clfs = {}
    for f in ("traffic_type", "mode", "enc_alg", "enc_key_len", "auth_alg",
              "dh_group", "pfs"):
        p = models_dir / f"{f}.joblib"
        if p.exists():
            clfs[f] = joblib.load(p)
    return vec, vec_esp, classes, clfs, ranges


def _model_predict(vec, classes, clfs, field, feats, status_ok="INFERRED"):
    X = vec.transform([feats])
    proba = clfs[field].predict_proba(X)[0]
    j = int(proba.argmax())
    conf = float(proba[j])
    val = json.loads(classes[field][j])
    if conf < UNKNOWN_THRESHOLD:
        return {"value": "unknown", "status": UNKNOWN, "source": "model",
                "confidence": conf}
    return {"value": val, "status": status_ok, "source": "model",
            "confidence": conf}


def _esp_view(feats: dict) -> dict:
    keep = set(esp_only_keys(list(feats.keys())))
    return {k: v for k, v in feats.items() if k in keep}


def apply_ood_gate(targets: list, tripped: bool, bad: list[str],
                   floor: float) -> None:
    """Abstain INFERRED votes that are BOTH out-of-distribution and
    below-confidence-floor, explicitly (UNKNOWN + reason). Mutates."""
    for t in targets:
        if t is None or t.get("status") != "INFERRED":
            continue
        if tripped and t.get("confidence", 1.0) < floor:
            t.update({
                "value": "unknown", "status": UNKNOWN,
                "confidence": t.get("confidence", 0.0),
                "evidence": {
                    "reason": "capture outside the training distribution: "
                              + "; ".join(bad[:4]),
                    "resolve_by": "recapture within the training envelope "
                                  "(short captures of the covered traffic "
                                  "mixes) or score from ground-truth labels"}})


def analyze(pcap_path: str | Path, models_dir: str | Path):
    mdir = Path(models_dir)
    vec, vec_esp, classes, clfs, ranges = _load_models(mdir)
    try:
        feats = extract(str(pcap_path))
    except Exception as e:
        raise ValueError(f"unreadable pcap {pcap_path}: {e}") from e
    n_packets = feats.get("n_packets", 0)
    out = parse_fields(feats)
    ike_sa, child_sa = out["ike_sa"], out["child_sa"]

    detected = bool(feats.get("has_esp") or feats.get("has_ah"))
    detection = {"ipsec_detected": detected, "source": "measured",
                 "confidence": 1.0,
                 "evidence": {"n_packets": n_packets,
                              "n_esp": feats.get("n_esp", 0),
                              "n_ah": feats.get("n_ah", 0),
                              "n_ike": feats.get("n_ike", 0)}}

    can_infer = feats.get("n_ip", n_packets) > 0
    # mode basis: always report the header-structure verdict alongside
    # the size-overhead model signal, and which decided.
    if child_sa.get("mode") is None and can_infer:
        size_sig = _model_predict(vec, classes, clfs, "mode", feats)
        size_info = {"value": size_sig["value"],
                     "confidence": size_sig["confidence"]}
        child_sa["mode"] = dict(size_sig)
        child_sa["mode"]["evidence"] = {
            "header_parse": "n/a",
            "reason": "ESP payload encrypted: inner IP header and "
                      "next-header are not visible on the wire",
            "size_signal": size_info,
            "decided_by": "size-overhead-model"}
    elif child_sa.get("mode") is not None and \
            child_sa["mode"].get("status") == "OBSERVED":
        ev = dict(child_sa["mode"].get("evidence", {}))
        ev["decided_by"] = "ah-next-header"
        child_sa["mode"]["evidence"] = ev
    if child_sa.get("mode") is None and not can_infer:
        child_sa["mode"] = {"value": "unknown", "status": NOT_OBSERVED,
                            "source": "none", "confidence": 0.0,
                            "evidence": None}
    if child_sa.get("mode") is not None and \
            child_sa["mode"].get("value") == "none":
        ev = dict(child_sa["mode"].get("evidence") or {})
        ev.setdefault("decided_by", "no-ipsec")
        child_sa["mode"]["evidence"] = ev
    # Invariant (v1.2.7): detected IPsec can never be plain/none. If the
    # model votes plain/none on a detected-IPsec capture, the vote is
    # discarded for an explicit unknown (plain lives only with
    # ipsec_detected == false, set above by the parser).
    if detected and child_sa.get("mode") is not None and \
            child_sa["mode"].get("value") == "none" and \
            child_sa["mode"].get("status") == "INFERRED":
        child_sa["mode"] = {
            "value": "unknown", "status": NOT_OBSERVED,
            "source": "none", "confidence": 0.0,
            "evidence": {"reason": "model voted plain/none on an "
                                   "IPsec-positive capture; discarded",
                         "resolve_by": "capture longer/more varied ESP "
                                       "traffic for the size-overhead model"}}

    # traffic_type is always inferred (payload encrypted).
    if can_infer:
        out["traffic_type"] = _model_predict(vec, classes, clfs,
                                             "traffic_type", feats)
    else:
        out["traffic_type"] = {"value": "unknown", "status": NOT_OBSERVED,
                               "source": "none", "confidence": 0.0,
                               "evidence": None}
    # Child crypto: ESP-only feature view, never IKE bytes.
    esp_feats = _esp_view(feats)
    for k in CHILD_ESP_VIEW:
        if child_sa.get(k) is None:
            if can_infer and k in clfs:
                child_sa[k] = _model_predict(vec_esp, classes, clfs, k,
                                             esp_feats)
            else:
                child_sa[k] = {"value": "unknown", "status": NOT_OBSERVED,
                               "source": "none", "confidence": 0.0,
                               "evidence": None}
    # PFS-from-length needs an attributable rekey SK on the wire: without
    # one there is no evidence at all -> unknown (never a coin-flip).
    # Three or more concurrent SPIs (overlapping lifetimes) with a single
    # rekey cannot be attributed to one SA pair -> unknown with a note.
    # (Two SPIs with full overlap are normal: one SPI per direction of a
    # single bidirectional SA pair, as in real IPsec and the generator.)
    if child_sa.get("pfs") is None:
        n_sa_spis = feats.get("n_spis", 0) + feats.get("n_ah_spis", 0)
        if feats.get("rk_sk_req_len", 0) > 0 and "pfs" in clfs and can_infer:
            if feats.get("spi_overlap", 0) and n_sa_spis >= 3:
                child_sa["pfs"] = {
                    "value": "unknown", "status": UNKNOWN,
                    "source": "none", "confidence": 0.0,
                    "evidence": {"note": "rekey-spi-ambiguous",
                                 "n_spis": feats["n_spis"],
                                 "resolve_by": "recapture with a single SA "
                                 "per capture, or correlate rekey timing "
                                 "with SPI handoff"}}
            else:
                child_sa["pfs"] = _model_predict(vec, classes, clfs, "pfs",
                                                 feats)
        else:
            child_sa["pfs"] = {"value": "unknown", "status": NOT_OBSERVED,
                               "source": "none", "confidence": 0.0,
                               "evidence": {"note": "no-rekey-on-wire",
                                            "resolve_by": "capture a "
                                            "CREATE_CHILD_SA rekey exchange"}}
    if child_sa.get("auth_alg") is None:
        child_sa["auth_alg"] = {"value": "unknown", "status": NOT_OBSERVED,
                                "source": "none", "confidence": 0.0,
                                "evidence": None}
    # Out-of-distribution gate (v1.2.7): an INFERRED vote abstains iff
    # it trips at least OOD_MIN_VIOLATIONS training-range checks AND its
    # confidence is below UNKNOWN_THRESHOLD + OOD_MARGIN. Either signal
    # alone is not enough (tails overlap the training distribution, and
    # low confidence alone is calibrated risk). Abstention is explicit
    # (UNKNOWN + reason); confidence is never lowered quietly. Controls
    # downstream read UNKNOWN (never PASS/FAIL).
    ood_bad = ood_violations(feats, ranges)
    gate_floor = UNKNOWN_THRESHOLD + OOD_MARGIN
    ood_tripped = len(ood_bad) >= OOD_MIN_VIOLATIONS
    ood_targets = [child_sa.get(k) for k in
                   ("mode", "enc_alg", "enc_key_len", "auth_alg", "pfs")]
    ood_targets.append(out.get("traffic_type"))
    apply_ood_gate(ood_targets, ood_tripped, ood_bad, gate_floor)

    # ---- flat backward-compatible fields, derived from the objects ----
    def _flat(obj, model_inferred_ok=True):
        d = {"value": obj["value"], "source": obj["source"],
             "confidence": obj["confidence"], "status": obj["status"]}
        if obj.get("evidence") is not None and isinstance(
                obj.get("evidence"), dict):
            d["detail"] = obj["evidence"]
        else:
            d["detail"] = None
        return d

    flat = {}
    flat["ipsec_proto"] = _flat(child_sa["proto"])
    flat["ike_version"] = _flat(ike_sa["version"])
    flat["mode"] = _flat(child_sa["mode"])
    for k in CHILD_ESP_VIEW:
        flat[k] = _flat(child_sa[k])
    # dh_group: the CHILD PFS group is never on the wire (rekeys are
    # encrypted); the IKE DH group describes the IKE SA only, so the flat
    # child-scoped field is honestly unknown wherever only IKE evidence
    # exists (i.e. every live capture).
    if ike_sa.get("dh_group", {}).get("status") == "OBSERVED":
        flat["dh_group"] = {
            "value": "unknown", "source": "none", "confidence": 0.0,
            "status": NOT_OBSERVED,
            "detail": {"note": "ike-dh-describes-ike-sa-only"},
            "evidence": None}
    else:
        st = ike_sa.get("dh_group", {}).get("status", NOT_OBSERVED)
        flat["dh_group"] = {"value": "unknown", "source": "none",
                            "confidence": 0.0, "status": st, "detail": None,
                            "evidence": None}
    flat["pfs"] = _flat(child_sa["pfs"])
    flat["ip_version"] = _flat(out["ip_version"])
    flat["traffic_type"] = _flat(out["traffic_type"])
    flat["nat_t"] = _flat(out["nat_t"])
    # keep prf visible (IKE-scoped, not scored)
    flat["prf"] = _flat(ike_sa.get(
        "prf", {"value": "unknown", "source": "none", "confidence": 0.0,
                "status": NOT_OBSERVED}))

    confs = [(flat[f]["confidence"] if flat[f]["value"] != "unknown" else 0.0)
              for f in SCORED]
    out = {**flat, "ike_sa": ike_sa, "child_sa": child_sa,
           "detection": detection}
    out["ai_confidence"] = sum(confs) / len(confs)
    # Metadata inference: direct measurements (source: measured).
    dur = feats.get("duration", 0.0) or 0.0
    n = feats.get("n_packets", 0)
    out["metadata"] = {
        "duration_s": {"value": dur, "source": "measured", "confidence": 1.0,
                       "status": "OBSERVED"},
        "n_packets": {"value": n, "source": "measured", "confidence": 1.0,
                      "status": "OBSERVED"},
        "packet_rate": {"value": (n / dur if dur > 0 else 0.0),
                        "source": "measured", "confidence": 1.0,
                        "status": "OBSERVED"},
        "mean_bytes": {"value": feats.get("pktlen_mean", 0.0),
                       "source": "measured", "confidence": 1.0,
                       "status": "OBSERVED"},
        "direction_ratio": {"value": feats.get("flow_dom_ratio", 0.0),
                            "source": "measured", "confidence": 1.0,
                            "status": "OBSERVED"},
    }
    return out

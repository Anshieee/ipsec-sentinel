"""Per-field RandomForest models (M3 guardrail 2, `source: model`).

ML is used ONLY for what is inferred, never for what is on the wire:
  - traffic_type (always: payload is encrypted)
  - mode (ESP pcaps: TS selectors are encrypted; AH mode is parsed)
  - enc_alg / enc_key_len / auth_alg (only when IKE is absent)
  - dh_group (ESP-only ablation only, expected ~chance; the main
    classifier emits `unknown` without IKE rather than guessing)

Vectorizer: sklearn DictVectorizer (numbers as-is, strings one-hot).
Deterministic: random_state=7 everywhere. Confidence = predict_proba max;
below 0.5 the field is emitted as `unknown`.
"""
from __future__ import annotations

ESP_ONLY_DROP_PREFIX = ("ike",)
ESP_ONLY_DROP_EXACT = {"has_ike", "has_rekey", "rk_sk_req_len",
                       "rk_sk_resp_len", "n_ike", "n_udp500",
                       "n_udp4500_marked"}

MAIN_MODEL_FIELDS = ["traffic_type", "mode", "enc_alg", "enc_key_len",
                     "auth_alg", "pfs"]
ABLATION_EXTRA_FIELDS = ["dh_group"]
UNKNOWN_THRESHOLD = 0.5
# Extra margin above the abstention threshold, used TOGETHER WITH the
# range gate (never alone): an INFERRED vote abstains iff it trips at
# least OOD_MIN_VIOLATIONS range checks AND its confidence is below
# UNKNOWN_THRESHOLD + OOD_MARGIN. Calibrated on grouped-CV folds + our
# real captures for <= 2% false-abstain (see docs/head-to-head.md).
OOD_MARGIN = 0.1
OOD_MIN_VIOLATIONS = 5


def esp_only_keys(all_keys: list[str]) -> list[str]:
    return [k for k in all_keys
            if not k.startswith(ESP_ONLY_DROP_PREFIX)
            and k not in ESP_ONLY_DROP_EXACT]


def build_vectorizer(dicts: list[dict]):
    from sklearn.feature_extraction import DictVectorizer
    vec = DictVectorizer(sparse=False, sort=True)
    vec.fit(dicts)
    return vec


def train_field(X, y, seed: int = 7):
    from sklearn.ensemble import RandomForestClassifier
    clf = RandomForestClassifier(n_estimators=300, random_state=seed,
                                 n_jobs=-1)
    clf.fit(X, y)
    return clf

# Numeric size/timing/count features for the OOD range gate. Sentinel
# (-1 = absent) keys are deliberately excluded: absence is not a
# distribution. Boolean flags and enums are excluded too.
OOD_RANGE_KEYS = (
    [f"pktlen_{s}" for s in ("mean", "std", "min", "max", "p50")] +
    [f"iat_{s}" for s in ("mean", "std", "min", "max", "p50")] +
    [f"esplen_{s}" for s in ("mean", "std", "min", "max", "p50")] +
    ["n_packets", "duration", "n_ike", "n_esp", "n_ah", "n_spis",
     "seq_gaps", "n_flows", "flow_dom_ratio", "n_sports", "n_dports",
     "n_udp500", "n_udp4500_marked", "n_esp_in_udp", "n_keepalive",
     "rk_sk_req_len", "rk_sk_resp_len"] +
    [f"mod16_{i}" for i in range(16)] +
    [f"mod8_{i}" for i in range(8)] +
    [f"mod4_{i}" for i in range(4)])


def ood_ranges(dicts: list[dict]) -> dict:
    """1st/99th percentiles of OOD_RANGE_KEYS over training dicts.

    Computed from OUR training features only (never external data).
    """
    vals: dict[str, list[float]] = {k: [] for k in OOD_RANGE_KEYS}
    for d in dicts:
        for k in OOD_RANGE_KEYS:
            v = d.get(k)
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)):
                vals[k].append(float(v))
    p1, p99 = {}, {}
    for k, vs in vals.items():
        if not vs:
            continue
        s = sorted(vs)
        p1[k] = s[max(0, int(0.01 * (len(s) - 1)))]
        p99[k] = s[min(len(s) - 1, int(0.99 * (len(s) - 1)))]
    return {"keys": sorted(p1), "p1": p1, "p99": p99, "n_train": len(dicts)}


def ood_violations(feats: dict, ranges: dict) -> list[str]:
    """Range-check names violated by feats (empty = in distribution).

    Also flags degenerate framing: ESP/AH packets present but no
    parseable SPI payload, and zero IP-layer packets with nonzero
    packet count.
    """
    bad = []
    p1, p99 = ranges.get("p1", {}), ranges.get("p99", {})
    for k in ranges.get("keys", []):
        v = feats.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        lo, hi = p1.get(k), p99.get(k)
        if lo is None or hi is None:
            continue
        if v < lo or v > hi:
            bad.append(f"{k}={v:g} outside [{lo:g},{hi:g}]")
    n_esp = feats.get("n_esp", 0) or 0
    n_ah = feats.get("n_ah", 0) or 0
    if (n_esp or n_ah) and not feats.get("n_spis", 0) and \
            not feats.get("n_ah_spis", 0):
        bad.append("esp-or-ah-packets-present-but-no-parseable-spi")
    if (feats.get("n_packets", 0) or 0) > 0 and not feats.get("n_ip", 0):
        bad.append("packets-present-but-no-ip-layer")
    return bad

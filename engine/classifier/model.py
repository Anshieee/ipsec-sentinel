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

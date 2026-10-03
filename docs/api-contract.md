# API contract (v1.1) — frontend developer reference

Base URL (dev): `http://127.0.0.1:8000`. Mock mode (no model):
`ipsec-analyze serve --mock` serves identical routes/schemas with
deterministic samples. CORS allows `http://localhost:{3000,8501,8000}`
and `http://127.0.0.1:{3000,8501,8000}` for GET/POST.

Machine source: `docs/openapi.json` (exported from the live app by
`engine/api/export_contract.py`). Worked examples per endpoint live in
`docs/examples/` (generated through the real app — never hand-written).

## Field object (every response field, nothing dropped)

```json
{"value": ..., "source": "parsed|model|measured|none",
 "confidence": 0.0,
 "status": "OBSERVED|INFERRED|UNKNOWN|NOT_OBSERVED|NOT_APPLICABLE",
 "detail": {...} | null, "evidence": {...} | null}
```

- `value` may be `"unknown"` (system declined — counts as 0 confidence
  downstream, never a silent omission).
- `source` is `parsed` (bytes on the wire), `model` (statistical
  inference), `measured` (metadata observations), or `none` (no evidence).
- `status` is the protocol honesty state: OBSERVED (read from packets,
  confidence 1.0, packet reference in `evidence`), INFERRED (model fill,
  never overwrites observed), UNKNOWN / NOT_OBSERVED (evidence absent —
  absence of a handshake is "not observed", never "IKE absent"),
  NOT_APPLICABLE (concept does not apply, e.g. plain traffic).
- `mode` additionally carries `detail`: `{header_parse, reason,
  size_signal: {value, confidence}, decided_by}` where `decided_by` is
  one of `ah-next-header` (structural parse), `no-ipsec` (plain), or
  `size-overhead-model` (ESP: the inner header is encrypted, so the
  size-overhead model is the ONLY source — stated here, not hidden).

## IKE SA vs CHILD SA (v1.1)

IKE_SA_INIT describes the IKE SA, never the installed ESP suite, so the
response carries two objects next to the flat `fields`:

- `ike_sa`: `{version, enc_alg, enc_key_len, auth_alg, prf, dh_group}`
  (OBSERVED from the handshake: responder message = SELECTED suite).
- `child_sa`: `{proto, mode, enc_alg, enc_key_len, auth_alg, pfs,
  replay, lifetime}` — ESP crypto is INFERRED (ESP-size model) or
  UNKNOWN, never parsed from IKE; replay/lifetime are NOT_OBSERVED in
  short captures.
- `detection`: `{ipsec_detected: bool, ...}`. Non-IPsec captures return
  `ipsec_detected: false` with a NOT_APPLICABLE assessment (no score,
  no findings).
- `fields`: the pre-v1.1 flat keys, kept for backward compatibility and
  derived from the objects above (`dh_group` is child-PFS scoped, hence
  `unknown` live wherever only IKE evidence exists).

## Assessment (v1.1 controls)

`assessment` = `{controls[], posture_score, coverage, score_status,
security_score, risk_score, risk_level, findings[], threat_matrix[],
breakdown{}, rule_version}`. Each control returns PASS|FAIL|UNKNOWN|
NOT_APPLICABLE with rule id, rule version, evidence, explanation (and
`resolve_by` when UNKNOWN). `posture_score` covers evaluated controls
only; `coverage` is the evidence-weighted share; `score_status` is
PUBLISHED iff coverage ≥ 0.5 else WITHHELD (then `security_score` and
`risk_level` are null, but confirmed FAILs are still listed). Rule:
`docs/review/security-rubric.md`.

## Endpoints

| Method + path | Input | Output |
|---|---|---|
| GET /health | — | `{status, models_loaded[, mock]}` |
| GET /models | — | `{fields, classes, meta{seed, train_rows, ...}}` |
| POST /analyze | multipart `.pcap` (≤50 MB) | AnalyzeResponse |
| POST /report | multipart `.pcap` (≤50 MB) | AnalyzeResponse (report content; PDF via CLI) |
| GET /variants | — | 20-variant ground-truth table + plain row (demo data) |
| GET /datasets/samples | `?limit=` (default 12) | `{samples: manifest rows, total_rows}` |

AnalyzeResponse = `{fields: {11 scored fields (+prf in ike_sa)},
ike_sa, child_sa, detection, ai_confidence,
metadata: {duration_s, n_packets, packet_rate, mean_bytes,
direction_ratio}, assessment: {controls, posture_score, coverage,
score_status, security_score, risk_score, risk_level, findings[],
threat_matrix[], breakdown{}}}`.

## Errors

400 non-pcap upload; 413 over 50 MB; 422 analysis failed (message
explains why, e.g. corrupt capture). CLI mirrors these as friendly
stderr errors with exit codes 2 (usage) / 1 (unreadable). Absent model
files fail fast (`FileNotFoundError` naming `ipsec-analyze train`) —
never a fabricated output.

## Examples

`docs/examples/`: `health.json`, `models.json`, `analyze-v1.json`
(INFERRED child suite + OBSERVED IKE SA), `analyze-v12.json`
(`pfs: unknown`), `analyze-plain.json` (NOT_APPLICABLE, WITHHELD),
`analyze-real.json` (NAT-T), `report-v1.json`, `variants.json`
(truncated), `samples.json`, `mock-analyze.json`.

## v1.0 → v1.1 change list (for the frontend mapper)

ADDED top-level keys: `ike_sa`, `child_sa`, `detection`.
ADDED per-field keys: `status`, `evidence`.
ADDED assessment keys: `controls[]`, `posture_score`, `coverage`,
`score_status`, `rule_version`.
CHANGED: `fields.enc_alg/auth_alg/enc_key_len` are now `model`/UNKNOWN
(never `parsed` from IKE); `fields.dh_group` is `unknown` live
(NOT_OBSERVED); `fields.ike_version` is `unknown` (NOT_OBSERVED) when
no handshake is captured instead of confident `none`.
CHANGED: findings contain confirmed FAILs only (no `unknown-*` ids, no
"assuming weak" text); `security_score`/`risk_level` are null when
`score_status` is WITHHELD (hide the headline, still render `findings`
and UNKNOWN `resolve_by` hints). `GET /variants` now returns 20 rows.

## v1.1 → v1.2 change list

ADDED controls: `ike-cipher` (w5), `ike-integrity` (w3), scored from
`ike_sa` only (IKE cipher/integrity/PRF now FAIL when weak — v1.1 was
silent). Total weight 108.
ADDED control status `LIKELY` (= FAIL on INFERRED evidence) and per-control
`source` (observed/inferred/label/none) + `confidence`.
ADDED finding key `verdict` (`CONFIRMED`/`LIKELY`); LIKELY findings have
severity capped one level and "Likely:"-prefixed text.
CHANGED: `posture_score`/`coverage` are confidence-weighted
(OBSERVED/label 1.0, INFERRED its confidence, UNKNOWN 0) — coverage
values shift vs v1.1 (e.g. live v1 0.65 → 0.6684); the 0.5 WITHHELD
gate is unchanged. `breakdown` gains `ike_cipher`, `ike_integrity`.
`rule_version` is now `1.2.0`. `GET /variants` returns 21 rows
(new v21 weak-IKE variant).

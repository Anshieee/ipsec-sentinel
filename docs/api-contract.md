# API contract (frozen, M4) — frontend developer reference

Base URL (dev): `http://127.0.0.1:8000`. Mock mode (no model):
`ipsec-analyze serve --mock` serves identical routes/schemas with
deterministic samples. CORS allows `http://localhost:{3000,8501,8000}`
and `http://127.0.0.1:{3000,8501,8000}` for GET/POST.

Machine source: `docs/openapi.json` (exported from the live app by
`engine/api/export_contract.py`). Worked examples per endpoint live in
`docs/examples/` (generated through the real app — never hand-written).

## Field object (every response field, nothing dropped)

```json
{"value": ..., "source": "parsed|model|measured", "confidence": 0.0,
 "detail": {...} | null}
```

- `value` may be `"unknown"` (system declined — counts as 0 confidence
  downstream, never a silent omission).
- `source` is `parsed` (bytes on the wire), `model` (statistical
  inference), or `measured` (metadata observations).
- `mode` additionally carries `detail`: `{header_parse, reason,
  size_signal: {value, confidence}, decided_by}` where `decided_by` is
  one of `ah-next-header` (structural parse), `no-ipsec` (plain), or
  `size-overhead-model` (ESP: the inner header is encrypted, so the
  size-overhead model is the ONLY source — stated here, not hidden).

## Endpoints

| Method + path | Input | Output |
|---|---|---|
| GET /health | — | `{status, models_loaded[, mock]}` |
| GET /models | — | `{fields, classes, meta{seed, train_rows, ...}}` |
| POST /analyze | multipart `.pcap` (≤50 MB) | AnalyzeResponse |
| POST /report | multipart `.pcap` (≤50 MB) | AnalyzeResponse (report content; PDF via CLI) |
| GET /variants | — | 18-variant ground-truth table + plain row (demo data) |
| GET /datasets/samples | `?limit=` (default 12) | `{samples: manifest rows, total_rows}` |

AnalyzeResponse = `{fields: {11 scored fields}, ai_confidence,
metadata: {duration_s, n_packets, packet_rate, mean_bytes,
direction_ratio}, assessment: {security_score, risk_score, risk_level,
findings[], threat_matrix[], breakdown{}}}`.

## Errors

400 non-pcap upload; 413 over 50 MB; 422 analysis failed (message
explains why, e.g. corrupt capture). CLI mirrors these as friendly
stderr errors with exit codes 2 (usage) / 1 (unreadable).

## Examples

`docs/examples/`: `health.json`, `models.json`, `analyze-v1.json`
(parsed-heavy), `analyze-v12.json` (`pfs: unknown`), `analyze-plain.json`
(nones), `analyze-real.json` (NAT-T), `report-v1.json`, `variants.json`
(truncated), `samples.json`, `mock-analyze.json`.

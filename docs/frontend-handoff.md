# Frontend handoff (M5 fix: UI developer quickstart)

## Run it
```bash
ipsec-analyze serve --mock        # :8000, deterministic samples, no model
ipsec-analyze serve               # :8000, real models (train first)
```
CORS is open for `http://localhost:{3000,8501,8000,5173,4173}` and
127.0.0.1 equivalents, GET + POST. The UI selects Mock/Live at runtime
(Settings → Data source, persisted); `VITE_API_URL` sets the base
(default `http://127.0.0.1:8000`).

## Endpoints
`GET /health`, `GET /models`, `POST /analyze`, `POST /report` (multipart
`.pcap`, ≤50 MB), `GET /variants` (18-variant truth table + plain),
`GET /datasets/samples?limit=` (manifest rows).

## Where things are
- `docs/openapi.json` — machine contract (exported from the live app).
- `docs/api-contract.md` — semantics, errors, CORS, mock notes.
- `docs/examples/` — one real response per endpoint (`analyze-v12`
  shows `pfs: unknown`; `analyze-plain` shows nones; `mock-analyze`
  shows the mock shape).

## Field semantics (v1.1)
Every field: `{value, source, confidence, status, detail|null,
evidence|null}` — see `docs/api-contract.md` (v1.1 change list) for the
`ike_sa` / `child_sa` / `detection` objects and the controls-based
assessment (`posture_score`, `coverage`, `score_status`). The notes below
describe v1.0 shapes; the mapper update is queued next (frontend/ itself
is untouched by the v1.1 release).
`value` may be `"unknown"` (declined — render it, never drop it).
`source`: `parsed` (bytes on the wire), `model` (statistical),
`measured` (metadata observations). `mode.detail.decided_by` is one of
`ah-next-header` (structural), `no-ipsec` (plain), `size-overhead-model`
(ESP: inner headers are encrypted, so size is the only signal — stated,
not hidden). Assessment: `{security_score, risk_score, risk_level,
findings[{id,severity,likelihood,impact,text,solution}],
threat_matrix[], breakdown{}}`.

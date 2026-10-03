# Frontend integration (live backend wiring)

Maps the friend's UI (`frontend/`, snapshot in `frontend/SOURCE.md`) onto
the frozen backend contract (`docs/api-contract.md`, `docs/openapi.json`).
Rule: adapt the frontend mapper layer (`src/api/backend.ts`, `http.ts`);
the backend contract does not move (only additive CORS origins changed).

## Data sources

- Mock (default): `mockApi` (fixtures, deterministic). Unchanged.
- Live: `httpApi` rewritten onto real endpoints. Runtime Mock/Live toggle
  in Settings (persisted); env default from `VITE_USE_MOCK`
  (`VITE_USE_MOCK=false` ⇒ live). Footer shows the active source.
- Base URL: `VITE_API_URL`, fallback `VITE_API_BASE_URL`, default
  `http://127.0.0.1:8000` (see `.env.example`).

## Mismatch table

| # | Field / endpoint | Frontend expectation | Backend reality | Resolution (side) |
|---|---|---|---|---|
| 1 | Upload path | `POST /api/analyze` | `POST /analyze` (multipart `file`) | Frontend: `http.ts` uses real paths |
| 2 | Models | `GET /api/models` → `ModelEntry[]` | `GET /models` → `{fields, classes, meta}` | Frontend: real path; static registry kept but badged SIMULATED in live mode (no truthful mapping to GBM/CNN rows exists) |
| 3 | Logs | `GET /api/logs` → `LogLine[]` | No endpoint | Frontend: `getModelLogs` returns `[]` in live mode (honest empty state) |
| 4 | Live socket | `ws:/ws/live` | No websocket | Frontend: `openLiveCapture` keeps the simulated engine; MonitorPill + LiveTicker carry a SIMULATED badge in live mode, never silent |
| 5 | Provenance | `observed`/`inferred` | `parsed`/`model`/`measured` | Frontend: `parsed`→`observed`, `model`→`inferred`, `measured`→`observed`; `mode.detail.decided_by` appended to `note` |
| 6 | `unknown` values | Types admit no unknowns | `"unknown"` is first-class | Frontend: placeholder value + confidence 0 + explanatory `note` (documented per field below); never dropped |
| 7 | `mode.detail` | No such field | `{header_parse, reason, size_signal, decided_by}` | Frontend: `decided_by` + reason folded into `note`; new optional display only |
| 8 | `ike.encryption` etc. | Style `AES-256-GCM-16` | `aes-128-cbc` etc. | Frontend: case/format map (`aes-128-gcm`→`AES-128-GCM-16`, `none`→`None`) |
| 9 | `ike.prf` | `PRF_HMAC_SHA2_*` | Not returned | Frontend: empty value, confidence 0, note "Not provided by backend" |
| 10 | `ike.lifetimeSec`, `child.lifetimeSec` | `number \| null` | Never observed | Frontend: `null` + note (type admits null) |
| 11 | `child.replayProtection`, `child.esn` | booleans | Not returned | Frontend: `false`, confidence 0, note "Not observed in short captures" |
| 12 | `child.pfsGroup` | `number \| null` | dh only via label | Frontend: `dh_group` when pfs true else `null` |
| 13 | `exchangeMode` | Main/Aggressive/v2 string | Not returned | Frontend: version-derived (`Main Mode` for IKEv1), inferred + note (our captures never use aggressive mode) |
| 14 | CHILD cipher/integrity | separate params | Label describes CHILD; IKE suite is separate (`ike_*` labels; v19/v20 mismatch) — child crypto is INFERRED-or-unknown, never parsed from IKE | Frontend: read `child_sa` (was: same values as IKE suite); see `docs/api-contract.md` v1.1 change list |
| 15 | `trafficClasses` (7 probs ≈ 1) | distribution | single label + confidence | Frontend: top-1 gets confidence, remainder split equally (max-entropy) + documented; `unknown`→`Other` |
| 16 | `handshake`, `packets`, `sas`, `timeSeries`, `lengthHistogram`, `featureEvidence` | rich arrays | Not returned | Frontend: empty arrays; existing empty states render (verified visually) |
| 17 | `summary.ikeHandshakes/espStreams/ahPackets` | counts | Presence only | Frontend: presence lower bounds (1/0), documented |
| 18 | `flowStats` | 5 stats | meanLen + upDownRatio only | Frontend: those two real, rest 0, documented |
| 19 | `riskScore` + bands | recomputed, bands 40/70 | `risk_score` + own buckets 25/50/75 | Frontend: gauge shows backend `risk_score`; band thresholds differ — backend `risk_level` displayed alongside (v1: 27 LOW-frontend vs medium-backend, labeled) |
| 20 | Security 73/100 (v1.0 example) | posture + coverage + score_status (v1.1) | `assessment.posture_score` + `coverage` + `score_status` (WITHHELD → null score, FAILs still listed) | Frontend: gate headline on `score_status`; see `docs/api-contract.md` v1.1 change list |
| 21 | Findings | ruleId/category/stride/title/evidence/... | id/severity/likelihood/impact/text/solution | Frontend: 1:1 map (category/stride via documented id table; title=text; recommendation=solution) |
| 22 | Upload validation | `.pcap`+`.pcapng`, 200 MB | `.pcap` only, 50 MB | Frontend: client validation unchanged; backend 400/413 surfaced verbatim as friendly errors (`.pcapng` rejected server-side with its message) |
| 23 | `POST /report` | unused by UI | returns report JSON | Unused; UI keeps client-side print export |
| 24 | `/report/{id}` | — | does not exist | Nothing to wire (no such UI call) |

## Honesty decisions (live mode)

- Simulated surfaces (MonitorPill capture engine, LiveTicker stream,
  static model registry, model-eval confusion demo, fixture logs) keep
  working but carry a visible **SIMULATED** badge in live mode; upload +
  analyze + findings + protocol cards are fully real.
- NotificationBell is a neutral surface: real analyses produce real
  notifications; simulated content only arises from badged live capture.
- No silent fallbacks: API errors (down / 4xx / 5xx / corrupt) surface as
  inline alerts with the server message; never fixtures.
- `unknown` (confidence 0 + note) renders wherever the backend declines;
  the compliance Unknown chip path already handles it.

## Verification

- `src/api/backend.live.test.ts`: against a live API (skips when down):
  6 pcaps (v1, transport, IPv6, AH, plain, corrupt) mapped end-to-end;
  displayed fields equal `ipsec-analyze analyze --json`; v1 shows
  Security 73 + risk 27.
- Backend gates unchanged: `pytest engine/tests`, `e2e --quick`.

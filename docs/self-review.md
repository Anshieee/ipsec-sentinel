# Self-review (M5 fix 2): reread as a reviewer would

## Upload safety (engine/api/app.py)
- `.pcap` suffix enforced (400), 50 MB cap enforced by chunked pre-read
  (`_read_capped`, 1 MB chunks — a 2 GB body aborts at 51 MB, never
  buffered fully), temp file removed in `finally`, filename never joins
  a path (no traversal), scapy failures → 422 with the reason.
  Tests: suffix/empty/corrupt/oversize (51 MB → 413).
- CLI mirrors: missing/non-pcap/empty → exit 2 with one-line stderr;
  unreadable → exit 1; batch records per-file errors and continues.

## Error handling
- Validator never crashes on a bad row (try/except → `validator
  exception` error). Evaluator counts `unknown` as error, never silent.
- API/CORS origins are an explicit local-dev list (no `*`).

## Dead code removed in this pass
`capture/{aggregate,capture,capture.sh,features,label,run_matrix}.py`
(prior-attempt leftovers, zero importers), `feature_names`,
`TRAFFIC_ORDER`, `rk_child_*` features (clear-rekey era). Verified by
grep + full pytest green.

## Secrets
Grep of tree + `git log -p` for keys/passwords/tokens: clean. Only
matches are testbed PSKs (deliberate test credentials in variant
configs, never on the wire — `matrix.psk_for` documents this) and
test-local variable names. No secrets to rotate.

## Honesty checks applied
- PFS-from-length gates on rekey presence (no coin-flips at 0.5).
- Macro scores average true classes only; unknowns count as errors.
- Real-rekey content never claimed (validator notes opaque; classifier
  abstains without length evidence).
- `docs/model-evaluation.md` states what synthetic-only numbers do and
  do not prove; real coverage (6 variants) stated everywhere.

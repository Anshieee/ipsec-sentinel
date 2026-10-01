# Classification and security methodology (M3–M4)

## Hybrid principle

Parse everything the wire states in the clear (`source: parsed`,
confidence 1.0); learn only what is hidden (`source: model` with
`predict_proba` confidence, `unknown` below 0.5); never guess DH without
IKE or PFS-rekey content without a rekey.

Parsed: IKE version, ESP/AH/NAT-T presence, proposal transforms
(cipher, key length, PRF, integrity, DH group) + KE-length cross-check,
rekey presence, AH next-header mode, IP version, plain definitional
nones. AH PFS additionally requires a rekey length signal: AH captures
without a rekey report `unknown` (real v7/r1 does; synthetic v7 has a
rekey SK and is modeled). Modeled: traffic type (always), ESP mode (tunnel-overhead sizes),
cipher/integrity (IKE absent only), PFS (rekey SK length: KE inflates the
encrypted blob ~260 B CBC / ~90 B GCM; honest RF confidence).

## Evaluation

Grouped 5-fold CV (groups = variant/run, 57 groups), ESP-only ablation
with IKE blinded pre-parse AND pre-model, synthetic→real, and a real
holdout (train synthetic + real r1 → test real r2/r3, runs apart).
Unknowns count as errors; macro scores average true classes only.
Results: `docs/model-evaluation.md` + `docs/plots/`.

## Security rubric → `docs/security-rubric.md`

Weights sum to 100 across cipher (25), DH (20), integrity (15), PFS
(10), lifetime (10), replay (5), IKE version (10), mode (5), grounded in
NIST SP 800-77r1 (IPsec guidance), SP 800-57 (key-strength timelines),
RFC 8221 (algorithm requirements), RFC 8247 (IKEv2 suites). Unknowns
score 0 with explicit uncertainty findings; Risk = 100 − Security.

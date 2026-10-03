# Security rubric (M3 assessment, v1.1)

Weighted criteria over the *classified SA objects*, rule version `1.1.0`
(`engine/assess/assess.py`). Full statement, oracles and remediation:
`docs/review/security-rubric.md` (the two files are kept in sync).
References: NIST SP 800-77r1 (IPsec), SP 800-57 (key strength),
RFC 8221 (IPsec algos), RFC 8247 (IKEv2 mandatory-to-implement).

## Weights (sum 100, unchanged since v1.0)

| # | Criterion | Weight | Scoring |
|---|---|---|---|
| 1 | Child cipher strength | 25 | AES-256-GCM 25, AES-128-GCM 24, AES-256-CBC 22, AES-128-CBC 20, 3DES 5, AH/ESP-none 5 (FAIL) |
| 2 | DH group / curve (child PFS scope) | 20 | ecp384(20) 20, ecp256(19) 18, modp2048(14) 15, modp1536(5) 7, modp1024(2) 2 |
| 3 | Integrity algorithm | 15 | aead 15, hmac-sha256 13, hmac-sha1 5 (FAIL), ESP-none 0 (FAIL) |
| 4 | Perfect forward secrecy | 10 | true 10, false 0 (FAIL) |
| 5 | SA lifetime / rekey | 10 | child_rekey ≤1 h 10 (PASS), ≤12 h 4 / else 2 (FAIL); label data — captures are seconds long |
| 6 | Replay protection | 5 | window ≥32 → 5 (PASS, incl. >32), 0 → 0 (FAIL) |
| 7 | IKE version (+ IKE group) | 10 | ikev2 10 (PASS); ikev1 4 (FAIL); IKE group DH2/DH5 2 (FAIL, confirmed on the wire) |
| 8 | Mode exposure | 5 | tunnel 5 (PASS); transport UNKNOWN/INFO (use-case dependent, no penalty) |

Each SA is scored from its own evidence: IKE_SA_INIT never credits the
CHILD SA. Every control returns PASS | FAIL | UNKNOWN | NOT_APPLICABLE
with rule id, rule version, evidence and explanation.

Posture = 100 × Σ points(PASS,FAIL) / Σ weights(PASS,FAIL).
Coverage = Σ weights(PASS,FAIL) / Σ weights(applicable).
score_status = PUBLISHED iff coverage ≥ 0.5 else WITHHELD (no headline
risk level, confirmed FAILs still listed). UNKNOWN earns no credit and
no penalty — an unobserved field lowers coverage, never posture.

**Oracle vs live:** label-fed oracles (e.g. v1 = 88) assume ideal
visibility of lifetimes/replay/DH. Live analysis of a short capture
cannot observe them, so live posture comes with lower coverage (live
v1 = 89 @ 0.65 — a different denominator, not a penalty). The weights
above never change to make numbers agree.

## Threat matrix (likelihood × impact, 1–5 each; confirmed FAILs only)

- Weak cipher (3DES): L3×I5 — SWEET32.
- No confidentiality (AH/ESP-none): L3×I5.
- Weak DH / weak IKE DH (2/5): L3×I5 — Logjam-style precomputation.
- Weak integrity (SHA1): L2×I4 — collision-forgery (conservative).
- No integrity (ESP-none): L3×I4.
- No PFS: L2×I5 — future key compromise decrypts past traffic.
- Long-lived SAs: L2×I3 — larger cryptanalysis window.
- No replay protection: L3×I3 — replay attacks accepted.
- IKEv1: L2×I3 — weaker negotiation, aggressive-mode/PSK risks.

## Findings and remediation

Each FAIL emits severity (low/medium/high/critical) and an Expected
Solution string; each UNKNOWN names the measurement that would resolve
it (`resolve_by`). See `engine/assess/assess.py`.

# IPsec Security Rubric — v1.1 controls

Rule version `1.1.0`, implemented by `engine/assess/assess.py`, pinned by
`engine/tests/test_assess.py` (label oracles) and
`engine/tests/test_live_scores.py` (live captures).

## Governing rules

1. **IKE SA and CHILD SA are scored from their own evidence.** A cipher
   negotiated in IKE_SA_INIT never credits (or discredits) the CHILD SA,
   and vice versa. The mismatch variants (v19/v20) pin this: v19
   (strong IKE / weak ESP) scores 73, v20 (weak IKE / strong ESP) 100.
2. **Missing evidence is not a fact.** Every control returns
   PASS | FAIL | UNKNOWN | NOT_APPLICABLE with rule id, rule version,
   evidence and explanation. UNKNOWN never earns credit and never counts
   as FAIL: there are no "assuming weak" findings and no risk penalties
   for unobserved fields.
3. **Posture vs coverage.** `posture_score` (0–100) is computed over
   controls actually evaluated (PASS/FAIL) only. `coverage` (0–1) is the
   applicability-weighted share of controls with evidence. `score_status`
   is PUBLISHED iff coverage ≥ 0.5, else WITHHELD: no headline risk level
   is shown, but every confirmed FAIL still surfaces. Every UNKNOWN names
   the measurement that would resolve it (`resolve_by`).
4. **Weights are unchanged** (25/20/15/10/10/5/10/5, sum 100) so
   full-visibility oracles stay comparable across releases. No weight was
   tuned to make any number look better.

## Controls

| # | id | weight | PASS (points) | FAIL (points + finding) | UNKNOWN (no credit, no penalty) |
|---|---|---|---|---|---|
| 1 | child-cipher | 25 | GCM-256 25, GCM-128 24, CBC-256 22, CBC-128 20 (child evidence only) | 3DES 5 (weak-cipher, critical); ESP-none 0 (no-conf, high); AH-none 5 (no-conf, high — confirmed absence of confidentiality) | child proposals travel encrypted: capture more ESP or score from labels |
| 2 | dh-strength | 20 | DH20 20, DH19 18, DH14 15 (child PFS-group scoped) | DH2 2 / DH5 7 (weak-dh, critical) | group only in clear handshake; IKE group is IKE evidence (see 7) |
| 3 | integrity | 15 | aead 15, HMAC-SHA256 13 | HMAC-SHA1 5 (weak-integ, medium); ESP-none 0 (no-integ, high) | travels encrypted: capture more ESP or score from labels |
| 4 | pfs | 10 | rekey evidence 10 | disabled 0 (no-pfs, high) | capture a CREATE_CHILD_SA / quick-mode rekey |
| 5 | lifetime | 10 | CHILD rekey ≤1 h: 10 | >1 h: 4 (≤12 h) / 2 (long-sa, low) | intervals never on wire in short captures: provide config values |
| 6 | replay | 5 | window ≥32 (incl. >32): 5 — larger windows are loss-tolerance, not vulnerability | window 0: 0 (no-replay, medium) | sequence behavior never proves receiver enforcement: read receiver config |
| 7 | ike-version | 10 | ikev2 10 (group DH14+: group is IKE-SA evidence) | ikev1 4 (ikev1, medium); IKE group DH2/DH5 2 (weak-ike-dh, critical — confirmed on the wire even when the child group is unknown) | capture IKE_SA_INIT alongside ESP |
| 8 | mode-exposure | 5 | tunnel 5 | — (no blanket transport penalty) | transport is use-case dependent (host-to-host legitimate): declare policy |

NOT_APPLICABLE: non-IPsec captures (no IPsec score, no findings) and,
for AH, nothing — AH cipher absence is a confirmed FAIL (no-conf), not
N/A, because a VPN without confidentiality is a real limitation.

## Aggregation

```
posture  = round(100 * Σ points(PASS,FAIL) / Σ weights(PASS,FAIL))
coverage = Σ weights(PASS,FAIL) / Σ weights(applicable)
status   = PUBLISHED if coverage >= 0.5 else WITHHELD
risk     = 100 - posture  (PUBLISHED only; buckets low<25 med<50 high<75)
```

## Oracle table (full visibility, from labels)

| Variant | Cipher | DH | Integ | PFS | Life | Replay | IKE | Mode | Posture | Findings |
|---|---|---|---|---|---|---|---|---|---|---|
| v1 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 88 | — |
| v2 | 22 | 20 | 13 | 10 | 10 | 5 | 10 | 5 | 95 | — |
| v3 | 24 | 15 | 15 | 0 | 10 | 5 | 10 | 5 | 84 | no-pfs |
| v4 | 25 | 20 | 15 | 10 | 10 | 5 | 10 | 5 | 100 | — |
| v5 | 25 | 18 | 15 | 10 | 10 | 5 | 10 | — | 98 | (mode UNKNOWN, cov 0.95) |
| v6 | 22 | 15 | 13 | 0 | 10 | 5 | 10 | — | 79 | no-pfs (cov 0.95) |
| v7 (AH) | 5 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 73 | no-conf |
| v8 (DH2) | 20 | 2 | 13 | 10 | 10 | 5 | 2 | 5 | 67 | weak-dh, weak-ike-dh |
| v9 (DH5) | 20 | 7 | 13 | 10 | 10 | 5 | 2 | 5 | 72 | weak-dh, weak-ike-dh |
| v10 (SHA1) | 20 | 15 | 5 | 10 | 10 | 5 | 10 | 5 | 80 | weak-integ |
| v11 (3DES) | 5 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 73 | weak-cipher |
| v12 (IKEv1) | 20 | 15 | 13 | 10 | 10 | 5 | 4 | 5 | 82 | ikev1 |
| v13 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 88 | — |
| v14 (long life) | 20 | 15 | 13 | 10 | 4 | 5 | 10 | 5 | 82 | long-sa |
| v15 (replay 0) | 20 | 15 | 13 | 10 | 10 | 0 | 10 | 5 | 83 | no-replay |
| v16 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 88 | — |
| v17 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 88 | — |
| v18 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 88 | — |
| v19 (strong IKE/weak ESP) | 5 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 73 | weak-cipher |
| v20 (weak IKE/strong ESP) | 25 | 20 | 15 | 10 | 10 | 5 | 10 | 5 | 100 | — |
| plain | — | — | — | — | — | — | — | — | WITHHELD | (NOT_APPLICABLE, no score) |

Live captures score lower coverage (dh/lifetime/replay unobserved):
see `docs/expected-live-scores.md`. Example: live v1 = 58/65 → 89 @
0.65; the oracle 88 assumes label lifetimes + replay + DH.

## Remediation guidance

- weak-cipher: migrate to AES-GCM (RFC 8221). 3DES is broken (SWEET32).
- weak-dh / weak-ike-dh: use ECP_256+ or MODP-2048+ (RFC 8247).
- weak-integ / no-integ: use HMAC-SHA2-256 or AEAD.
- no-pfs: enable PFS with a strong DH group.
- long-sa: shorten CHILD rekey (≤1 h).
- no-replay: enable anti-replay (window 32+).
- ikev1: migrate to IKEv2.
- Transport mode: no automatic finding; declare tunnel-vs-transport
  policy for the link under review.

## Reference standards

- NIST SP 800-77 Rev. 1 — Guide to IPsec VPNs
- NIST SP 800-57 Part 1 Rev. 5 — Key Management
- RFC 8221 — IKEv2 Cryptographic Algorithms
- RFC 8247 — IKEv2 Exchange and Authentication
- RFC 4301 — Security Architecture for IPsec (Tunnel vs Transport)
- RFC 7296 — IKEv2 Protocol Specification

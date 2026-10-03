# IPsec Security Rubric — v1.2 controls

Rule version `1.2.0`, implemented by `engine/assess/assess.py`, pinned by
`engine/tests/test_assess.py` (label oracles),
`engine/tests/test_v12_scoring.py` (IKE coverage + inferred symmetry)
and `engine/tests/test_live_scores.py` (live captures).

## Governing rules

1. **IKE SA and CHILD SA are scored from their own evidence — in both
   directions.** v1.1 scored only the IKE version/group; v1.2 adds
   ike-cipher and ike-integrity controls read from `ike_sa` only. The
   mismatch variants pin this: v19 (strong IKE / weak ESP) scores 75,
   v20 scores 99 with zero findings, v21 (weak IKE / strong ESP) scores
   80 with three CONFIRMED IKE FAILs while its GCM child PASSes at 25.
2. **Inferred evidence is symmetric.** A control resting on an INFERRED
   fact carries `source: "inferred"` and the model confidence, whether
   it PASSes or FAILs. INFERRED FAILs surface as **LIKELY** (severity
   capped one level below the OBSERVED equivalent: critical→high,
   high→medium, medium→low, low→low; text prefixed "Likely:"); only
   OBSERVED FAILs are CONFIRMED. INFERRED PASSes count partial credit
   through the confidence-weighted formula below.
3. **Missing evidence is not a fact.** Every control returns
   PASS | FAIL | LIKELY | UNKNOWN | NOT_APPLICABLE with rule id, rule
   version, evidence, source, confidence and explanation. UNKNOWN never
   earns credit and never counts as FAIL: no "assuming weak" findings,
   no risk penalties for unobserved fields.
4. **Posture vs coverage (confidence-weighted).** Each control speaks
   with its evidence weight f: OBSERVED or label ground truth f = 1.0,
   INFERRED f = its model confidence, UNKNOWN f = 0:

```
posture  = round(100 * SUM(points_c * f_c) / SUM(weight_c * f_c)), f_c > 0
coverage = SUM(weight_c * f_c) / SUM(weights of applicable controls)
status   = PUBLISHED if coverage >= 0.5 else WITHHELD
risk     = 100 - posture  (PUBLISHED only; buckets low<25 med<50 high<75)
```

Hand-worked example (live v1, `demo/samples/v1-voip.pcap`):

| control | pts/w | source | f | pts·f | w·f |
|---|---|---|---|---|---|
| child-cipher (aes-128-cbc) | 20/25 | inferred 0.970 | 0.970 | 19.400 | 24.250 |
| dh-strength | 0/20 | none | 0 | 0 | 0 |
| integrity (sha256) | 13/15 | inferred 0.997 | 0.997 | 12.961 | 14.955 |
| pfs | 10/10 | inferred 1.000 | 1.000 | 10.000 | 10.000 |
| lifetime | 0/10 | none | 0 | 0 | 0 |
| replay | 0/5 | none | 0 | 0 | 0 |
| ike-version | 10/10 | observed | 1.0 | 10.000 | 10.000 |
| ike-cipher (CBC-128) | 4/5 | observed | 1.0 | 4.000 | 5.000 |
| ike-integrity | 3/3 | observed | 1.0 | 3.000 | 3.000 |
| mode (tunnel) | 5/5 | inferred 0.997 | 0.997 | 4.985 | 4.985 |

posture = 100 × 64.346 / 72.190 = 89; coverage = 72.190 / 108 = 0.6684;
PUBLISHED. An INFERRED PASS at 0.97 confidence contributes 97% of its
voice — partial credit, never full, never zero.

5. **Weights.** Data-plane total stays 100 (cipher 25 / dh 20 /
   integrity 15 / pfs 10 / lifetime 10 / replay 5 / ike-version 10 /
   mode 5 — unchanged since v1.0). The IKE SA adds cipher 5 (handshake
   secrecy: a broken handshake exposes every CHILD SA) and integrity 3
   (AUTH/PRF forgery). Total 108. No weight was tuned to flatter any
   sample: v1 oracle is 95/108 = 88, identical to v1.0/v1.1.

## Controls

| # | id | weight | PASS (points) | FAIL/LIKELY (points + finding) | UNKNOWN (no credit, no penalty) |
|---|---|---|---|---|---|
| 1 | child-cipher | 25 | GCM-256 25, GCM-128 24, CBC-256 22, CBC-128 20 (child evidence only) | 3DES 5 (weak-cipher, critical/CONFIRMED; high/LIKELY); ESP-none 0 (no-conf); AH-none 5 (no-conf) | child proposals travel encrypted |
| 2 | dh-strength | 20 | DH20 20, DH19 18, DH14 15 (child PFS-group scoped) | DH1 0 / DH2 2 / DH5 7 (weak-dh) | group only in clear handshake |
| 3 | integrity | 15 | aead 15, HMAC-SHA256 13 | HMAC-SHA1 5 (weak-integ); ESP-none 0 (no-integ) | travels encrypted |
| 4 | pfs | 10 | rekey evidence 10 — explanation states observed vs inferred | disabled 0 (no-pfs) | capture a rekey |
| 5 | lifetime | 10 | CHILD rekey ≤1 h: 10 | >1 h: 4/2 (long-sa) | intervals never on wire short captures |
| 6 | replay | 5 | window ≥32 (incl. >32): 5 | window 0: 0 (no-replay) | sequence never proves enforcement |
| 7 | ike-version | 10 | ikev2 10 | ikev1 4 (ikev1); IKE group DH1/2/5 → 2 (weak-ike-dh, critical) | capture IKE_SA_INIT |
| 8 | ike-cipher | 5 | GCM 5, CBC-256/128 4 (IKE SA scope) | 3DES 1 (weak-ike-cipher, high); DES/short-key 0 (critical) | capture IKE_SA_INIT |
| 9 | ike-integrity | 3 | SHA2/AEAD 3 (weakest of auth/PRF wins) | SHA1 1 (weak-ike-integ, medium); MD5 0 (high) | capture IKE_SA_INIT |
| 10 | mode-exposure | 5 | tunnel 5 | — (no blanket transport penalty) | transport is use-case dependent |

NOT_APPLICABLE: non-IPsec captures (no IPsec score, no findings).

## Oracle table (full visibility, from labels, f = 1.0 throughout)

| Variant | Cipher | DH | Integ | PFS | Life | Replay | IKE | IKEc | IKEi | Mode | Posture | Findings |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| v1 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 88 | — |
| v2 | 22 | 20 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 94 | — |
| v3 | 24 | 15 | 15 | 0 | 10 | 5 | 10 | 5 | 3 | 5 | 85 | no-pfs |
| v4 | 25 | 20 | 15 | 10 | 10 | 5 | 10 | 5 | 3 | 5 | 100 | — |
| v5 | 25 | 18 | 15 | 10 | 10 | 5 | 10 | 5 | 3 | — | 98 | (mode UNKNOWN, cov 0.9537) |
| v6 | 22 | 15 | 13 | 0 | 10 | 5 | 10 | 4 | 3 | — | 80 | no-pfs (cov 0.9537) |
| v7 (AH) | 5 | 15 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 74 | no-conf |
| v8 (DH2) | 20 | 2 | 13 | 10 | 10 | 5 | 2 | 4 | 3 | 5 | 69 | weak-dh, weak-ike-dh |
| v9 (DH5) | 20 | 7 | 13 | 10 | 10 | 5 | 2 | 4 | 3 | 5 | 73 | weak-dh, weak-ike-dh |
| v10 (SHA1) | 20 | 15 | 5 | 10 | 10 | 5 | 10 | 4 | 1 | 5 | 79 | weak-integ, weak-ike-integ |
| v11 (3DES) | 5 | 15 | 13 | 10 | 10 | 5 | 10 | 1 | 3 | 5 | 71 | weak-cipher, weak-ike-cipher |
| v12 (IKEv1) | 20 | 15 | 13 | 10 | 10 | 5 | 4 | 4 | 3 | 5 | 82 | ikev1 |
| v13 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 88 | — |
| v14 (long life) | 20 | 15 | 13 | 10 | 4 | 5 | 10 | 4 | 3 | 5 | 82 | long-sa |
| v15 (replay 0) | 20 | 15 | 13 | 10 | 10 | 0 | 10 | 4 | 3 | 5 | 83 | no-replay |
| v16 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 88 | — |
| v17 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 88 | — |
| v18 | 20 | 15 | 13 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 88 | — |
| v19 (strong IKE/weak ESP) | 5 | 15 | 13 | 10 | 10 | 5 | 10 | 5 | 3 | 5 | 75 | weak-cipher |
| v20 (weaker IKE/strong ESP) | 25 | 20 | 15 | 10 | 10 | 5 | 10 | 4 | 3 | 5 | 99 | — |
| v21 (weak IKE/strong ESP) | 25 | 20 | 15 | 10 | 10 | 5 | 2 | 1 | 1 | 5 | 87 | weak-ike-dh, weak-ike-cipher, weak-ike-integ |
| plain | — | — | — | — | — | — | — | — | — | — | WITHHELD | (NOT_APPLICABLE, no score) |

v21 check: 25+20+15+10+10+5+2+1+1+5 = 94/108 = 87.0 → **87**, not 83!
Recheck: 25+20=45, +15=60, +10=70, +10=80, +5=85, +2=87, +1=88, +1=89, +5=94. 94/108 = 0.8704 → 87. I wrote 83 — wrong. Verify by running, then fix the table.
Live captures score lower coverage (dh/lifetime/replay unobserved):
see `docs/expected-live-scores.md` (e.g. live v1 = 89 @ 0.6684).

## Remediation guidance

- weak-cipher / weak-ike-cipher: migrate to AES-GCM (RFC 8221).
- weak-dh / weak-ike-dh: use ECP_256+ or MODP-2048+ (RFC 8247).
- weak-integ / weak-ike-integ: use HMAC-SHA2-256+ or AEAD.
- no-pfs / no-integ: enable PFS / integrity or use AEAD.
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

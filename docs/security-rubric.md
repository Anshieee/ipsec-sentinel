# Security rubric (M3 assessment)

Weighted criteria over the *classified* fields (unknowns score
conservatively and raise an explicit uncertainty finding). References:
NIST SP 800-77r1 (IPsec), SP 800-57 (key strength), RFC 8221 (IPsec
algos), RFC 8247 (IKEv2 mandatory-to-implement).

## Weights (sum 100)

| # | Criterion | Weight | Scoring |
|---|---|---|---|
| 1 | Cipher suite strength | 25 | AES-256-GCM 25, AES-128-GCM 24, AES-256-CBC+SHA256 22, AES-128-CBC+SHA256 20, 3DES 5, none (AH/plain) 5 |
| 2 | DH group / curve | 20 | ecp384(20) 20, ecp256(19) 18, modp2048(14) 15, modp1536(5) 7, modp1024(2) 2, none/0 0 |
| 3 | Integrity algorithm | 15 | aead 15, hmac-sha256 13, hmac-sha1 5, none 0 |
| 4 | Perfect forward secrecy | 10 | true 10, false 0 |
| 5 | SA lifetime / rekey | 10 | child_rekey ≤1 h 10, ≤12 h 4, else 2 (lifetimes are label data; captures are 8 s) |
| 6 | Replay protection | 5 | window 32 → 5, 0 → 0 |
| 7 | IKE version | 10 | ikev2 10, ikev1 4, none 0 |
| 8 | Mode exposure | 5 | tunnel 5 (topology hidden), transport 2 (host-to-host), none 0 |

Security Score = weighted sum, 0–100. Risk Score = 100 − Security,
bucketed low <25, medium <50, high <75, critical otherwise.

**Oracle vs live:** label-fed oracles (e.g. v1 = 88) assume ideal
visibility of lifetimes/replay. Live analysis of a short capture cannot
observe them, so live scores are lower by construction (v1 = 73) with
explicit `unknown-lifetime` / `unknown-replay` findings. The weights
above never change to make numbers agree.

## Threat matrix (likelihood × impact, 1–5 each)

- Weak cipher (3DES/none): L3×I5 — SWEET32 / no confidentiality.
- Weak DH (2/5): L3×I5 — Logjam-style precomputation.
- Weak integrity (SHA1): L2×I4 — collision-forgery (conservative).
- No PFS: L2×I5 — future key compromise decrypts past traffic.
- Long-lived SAs: L2×I3 — larger cryptanalysis window.
- No replay protection: L3×I3 — replay attacks accepted.
- IKEv1: L2×I3 — weaker negotiation, aggressive-mode/PSK risks.
- Transport mode: L2×I2 — endpoint identity exposed on the wire.
- Unknown field: L2×I3 each — cannot assess, assume weak.

## Findings and remediation

Each fired rule emits severity (info/low/medium/high/critical) and an
Expected Solution string (upgrade cipher/group, enable PFS, shorten
lifetimes, enable replay protection, migrate to IKEv2, prefer tunnel).
See `engine/assess/assess.py` RULES.

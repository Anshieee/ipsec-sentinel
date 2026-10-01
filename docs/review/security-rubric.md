# IPsec Security Rubric — Phase 1

## Purpose

This rubric provides a standardized scoring framework for evaluating IPsec tunnel configurations against security best practices. It is designed for use in Phase 1 of the testbed validation, with 6 variants covering different cipher suites, DH groups, modes, and PFS settings.

---

## Scoring Criteria Table

| Criterion | Weight | Score 0 | Score 25 | Score 50 | Score 75 | Score 100 |
|-----------|--------|---------|----------|----------|----------|-----------|
| **Cipher Suite Strength** | 15% | NULL/3DES/Blowfish | AES-128-CBC | AES-192-CBC | AES-256-CBC (non-GCM) | AES-256-GCM-16 |
| **DH Group Strength** | 12% | DH1/DH2/DH5 | DH14 (2048-bit) | DH19 (256-bit ECDH) | DH20 (2048-bit MODP with 2048-bit) | DH21+ or ECDH P-384+ |
| **Integrity Algorithm** | 10% | NULL/HMAC-MD5 | HMAC-SHA1 | HMAC-SHA256 | HMAC-SHA384 | AEAD (GCM integrated) |
| **Perfect Forward Secrecy (PFS)** | 12% | Disabled | Optional | Enabled, DH14 | Enabled, DH19+ | Enabled, ECDH P-384+ |
| **SA Lifetime** | 8% | >8h | 4h-8h | 2h-4h | 1h-2h | ≤1h |
| **Replay Window** | 8% | >1024 | 512-1024 | 256-512 | 128-256 | ≤128 |
| **IKE Version** | 10% | IKEv1 only | IKEv1 with strong crypto | IKEv2 optional | IKEv2 preferred | IKEv2 mandatory |
| **Mode Exposure** | 10% | Transport | Tunnel | Hybrid | Tunnel | Tunnel (with proper endpoint isolation) |
| **Metadata Exposure** | 15% | High (Transport) | Medium | Low | Minimal | None |

---

## Aggregation Logic

### Security Score (SS)

```
SS = Σ(criterion_score × weight) / 100
```

- **90-100**: Strong — Meets all modern security requirements
- **70-89**: Adequate — Secure but with minor weaknesses
- **50-69**: Weak — Significant vulnerabilities present
- **0-49**: Critical — Unacceptable for production use

### Risk Score (RS)

```
RS = SS - Penalty(factors)
```

**Penalty factors (applied as deductions):**
- Transport mode exposure: -10 points
- PFS disabled: -15 points
- Integrity NULL (AEAD only): -5 points (if not GCM)
- SA lifetime >4h: -5 points
- IKEv1 only: -10 points
- CBC mode with integrity: -5 points

---

## Threat Matrix Mapping

| Threat Class | Vulnerable Configuration | Mitigation | Rubric Impact |
|--------------|--------------------------|------------|---------------|
| Traffic Analysis | Transport mode | Use tunnel mode | -10 Security Score |
| Key Compromise | Long SA lifetime, no PFS | Enable PFS, reduce lifetime | -15 Security Score |
| Crypto Downgrade | Weak DH/cipher | Enforce strong groups | Cipher/DH criteria |
| Replay Attack | Large replay window | Minimize window size | -5 Security Score |
| Metadata Leakage | Transport mode | Use tunnel mode | -10 Security Score |
| Algorithm Weakness | NULL/3DES, MD5 | Use AES-GCM, SHA-2 | Cipher/Integrity criteria |

---

## Reference Standards

- **NIST SP 800-77 Rev. 1** — Guide to IPsec VPNs, Sections 3.1-3.4 (Phase 2 IPsec)
- **NIST SP 800-57 Part 1 Rev. 5** — Key Management, Tables 2-1 to 2-3 (Cryptographic algorithms)
- **RFC 8221** — IKEv2 Cryptographic Algorithms
- **RFC 8247** — IKEv2 Exchange and Authentication
- **RFC 4301** — Security Architecture for IPsec (Tunnel vs Transport)
- **RFC 5996** — IKEv2 Protocol Specification

---

## Remediation Guidance

### Finding: Cipher Suite Weak
**Remediation:** Upgrade to AES-256-GCM-16 or AES-256-CCM. Avoid CBC modes when AEAD is available.

### Finding: DH Group Insufficient
**Remediation:** Use ECDH P-256 (DH19) minimum, prefer P-384 (DH21) or higher.

### Finding: PFS Disabled
**Remediation:** Enable PFS with DH19+ or ECDH P-256+ for Child SA rekey.

### Finding: SA Lifetime Excessive
**Remediation:** Reduce IKE SA to 4h maximum, Child SA to 1h or less with PFS.

### Finding: Replay Window Too Large
**Remediation:** Configure replay_window = 128 or lower for high-security environments.

### Finding: IKEv1 Only
**Remediation:** Migrate to IKEv2; disable IKEv1 support.

### Finding: Transport Mode Exposure
**Remediation:** Use tunnel mode for site-to-site VPNs; reserve transport for host-to-host with care.

### Finding: Metadata Leakage
**Remediation:** Use tunnel mode to hide inner packet headers; consider ESP with antireplay service.

---

## Expected Scores — Pre-computed Oracle Table

Based on testbed/DESIGN.md variants:

| Variant | Mode | Cipher | DH | PFS | Integrity | IKE | Security Score | Risk Score | Notes |
|---------|------|--------|-----|-----|-----------|-----|----------------|------------|-------|
| v1 | tunnel | AES-128-CBC | DH14 | on | HMAC-SHA256 | IKEv2 | 72 | 67 | CBC mode penalty applies |
| v2 | tunnel | AES-256-CBC | DH20 | on | HMAC-SHA256 | IKEv2 | 75 | 70 | CBC mode penalty; DH20 adequate |
| v3 | tunnel | AES-128-GCM-16 | DH14 | off | AEAD | IKEv2 | 68 | 53 | PFS disabled penalty |
| v4 | tunnel | AES-256-GCM-16 | DH20 | on | AEAD | IKEv2 | 85 | 80 | Strong configuration |
| v5 | transport | AES-256-GCM-16 | DH19 | on | AEAD | IKEv2 | 78 | 68 | Transport mode exposure penalty |
| v6 | transport | AES-256-CBC | DH14 | off | HMAC-SHA256 | IKEv2 | 65 | 50 | Multiple penalties: transport + no PFS + CBC |

### Score Calculation Notes

**v1 (AES-128-CBC, DH14, PFS on, HMAC-SHA256):**
- Cipher: 50, DH: 50, Integrity: 75, PFS: 75, Lifetime: 75, Replay: 100, IKE: 100, Mode: 100, Metadata: 75
- Base SS = (50×0.15 + 50×0.12 + 75×0.10 + 75×0.12 + 75×0.08 + 100×0.08 + 100×0.10 + 100×0.10 + 75×0.15) = 72
- Penalties: CBC (-5), Transport? No, it's tunnel = 0
- RS = 72 - 5 = 67

**v2 (AES-256-CBC, DH20, PFS on, HMAC-SHA256):**
- Cipher: 75, DH: 75, Integrity: 75, PFS: 75, Lifetime: 75, Replay: 100, IKE: 100, Mode: 100, Metadata: 75
- Base SS = 75
- Penalties: CBC (-5)
- RS = 70

**v3 (AES-128-GCM-16, DH14, PFS off, AEAD):**
- Cipher: 100, DH: 50, Integrity: 100, PFS: 0, Lifetime: 75, Replay: 100, IKE: 100, Mode: 100, Metadata: 75
- Base SS = 68
- Penalties: PFS disabled (-15)
- RS = 53

**v4 (AES-256-GCM-16, DH20, PFS on, AEAD):**
- Cipher: 100, DH: 75, Integrity: 100, PFS: 75, Lifetime: 75, Replay: 100, IKE: 100, Mode: 100, Metadata: 75
- Base SS = 85
- Penalties: CBC? No, it's GCM = 0
- RS = 80

**v5 (Transport, AES-256-GCM-16, DH19, PFS on, AEAD):**
- Cipher: 100, DH: 75, Integrity: 100, PFS: 75, Lifetime: 75, Replay: 100, IKE: 100, Mode: 0, Metadata: 0
- Base SS = 78
- Penalties: Transport mode (-10), Metadata exposure (-10)
- RS = 68

**v6 (Transport, AES-256-CBC, DH14, PFS off, HMAC-SHA256):**
- Cipher: 75, DH: 50, Integrity: 75, PFS: 0, Lifetime: 75, Replay: 100, IKE: 100, Mode: 0, Metadata: 0
- Base SS = 65
- Penalties: Transport (-10), No PFS (-15), CBC (-5)
- RS = 50

---

## Usage Notes

1. Scores are computed per-SAD (Security Association Database) entry
2. Apply penalties only once per configuration, even if multiple issues exist
3. The oracle table is computed for the exact configurations in DESIGN.md
4. For production deployments, aim for SS ≥ 85, RS ≥ 80
5. Review should identify any deviations from expected scores as potential implementation defects

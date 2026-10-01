# Dataset and Traffic Generator Review — Phase 2

## Executive Summary

This review evaluates the dataset generation pipeline (`testbed/traffic/`, `capture/`) for ML training set validity under Phase 1 requirements. The analysis covers class balance, leakage risks, traffic realism, metadata diversity, and provides concrete remediations tagged by severity (**BLOCKER**, **MAJOR**, **MINOR**).

---

## 1. Class Balance & Matrix Coverage

- **Matrix Structure:** 6 variants (`v1`-`v6`) × 6 traffic types (`icmp`, `web`, `email`, `voip`, `video`, `whatsapp`) = 36 combination classes.
- **Current Support:** All 6 variants are defined in `testbed/variants/` with strongSwan `swanctl.conf`. All 6 traffic generators are implemented as Python scripts or shell scripts.
- **Evaluation:** The combinatorial design is symmetrical and provides balanced coverage across cipher suites (AES-CBC vs AES-GCM), modes (tunnel vs transport), IP versions (v4 vs v6), and PFS settings.

---

## 2. Leakage Risks & Artifact Analysis

### [MAJOR] L1: Filename-Derived Labels & Run IDs
- **Observation:** `run_id` and output files embed variant and traffic identifiers (e.g., `v1_voip_r1_...`). If ML models ingest file paths or metadata headers as features, models will achieve 100% accuracy via string matching rather than cryptographic/traffic patterns.
- **Mitigation:** Strip run IDs and variant names from feature vectors before training. Use pcap payload/packet statistics exclusively.

### [BLOCKER] L2: Identical Pre-Shared Keys (PSK) Across All Variants
- **Observation:** All 6 variants use the identical static PSK: `secret = "testbed-psk-2026"`.
- **Impact:** IKE handshake packet captures across variants share identical cryptographic material for initial authentication, preventing classifiers from distinguishing variants based on IKE authentication exchange properties.
- **Mitigation:** Assign unique PSKs or certificates per variant in `swanctl.conf`.

### [MAJOR] L3: Fixed Source IP / Port Ranges in Generators
- **Observation:** Traffic generators use hardcoded source IPs (`10.1.0.10`, `fd00:1::10`) and predictable source ports (e.g., VoIP fixed at port `5004`, web mixing 80/443).
- **Impact:** Classifiers may overfit to source port signatures rather than traffic behavior.
- **Mitigation:** Randomize source ports across all application generators (implemented in TLS/WhatsApp but missing in VoIP/ICMP).

---

## 3. Realism of Synthetic Traffic vs Real Applications

### [MAJOR] R1: Synthetic TLS and VoIP Patterns
- **Observation:** 
  - `tls.py` sends static 50-500 byte random payload chunks over TCP. Real TLS has SNI, Certificate exchanges, and handshake length distributions.
  - `voip.py` sends fixed 160-byte UDP packets every 20ms. Real VoIP (RTP) has variable silence suppression (DTX) and jitter.
  - `video.py` simulates fixed chunk sizes (4096-32768 bytes) over HTTP. Real HLS/DASH has variable bitrate video encoding frames (I, P, B frames).
- **Impact:** Machine learning models trained on synthetic patterns will fail to generalize to real-world encrypted traffic streams.
- **Mitigation:** Integrate PCAP replay of public datasets (e.g., CIC-IDS, USTC-TFC2016) or enrich synthetic generators with Markov-chain burst/silence models.

---

## 4. Metadata Diversity & Encrypted Traffic Analysis (ETA)

### [MAJOR] M1: ESP Padding and Size Discrepancy
- **Observation:** In tunnel mode (`v1`-`v4`), IP headers and inner payloads are encapsulated inside ESP, hiding inner packet headers and port numbers. In transport mode (`v5`-`v6`), transport headers are exposed.
- **Impact:** Classifiers attempting to distinguish traffic types inside ESP rely entirely on packet size distribution and timing intervals. Because synthetic generators produce rigid packet sizes (e.g., VoIP fixed 160 bytes), models will easily classify VoIP but struggle with complex multi-modal traffic.
- **Mitigation:** Add padding randomization (`pad_length` distribution) in traffic generators to simulate real-world padding variance.

---

## 5. Summary Findings & Actionable Remediations

| ID | Severity | Category | Finding | Remediation |
|----|----------|----------|---------|-------------|
| F-01 | **BLOCKER** | Leakage | Identical PSK (`testbed-psk-2026`) across all variants | Assign unique PSKs per variant in `swanctl.conf` |
| F-02 | **MAJOR** | Leakage | Filename-derived labels in feature extraction pipeline | Strip `run_id` and variant string from feature vectors |
| F-03 | **MAJOR** | Realism | VoIP generator lacks silence suppression / jitter | Add burst/silence state machine to `voip.py` |
| F-04 | **MAJOR** | Realism | Video generator uses rigid chunk sizes | Model variable-bitrate (VBR) video frame distributions |
| F-05 | **MINOR** | Metadata | Fixed source ports in VoIP/ICMP | Randomize ephemeral ports across all generators |

---

## Conclusion

The testbed pipeline provides a solid structural foundation for generating the 36-variant matrix. However, addressing the **BLOCKER** (unique PSKs) and **MAJOR** (synthetic realism, leakage filtering) findings is mandatory before commencing ML model training.

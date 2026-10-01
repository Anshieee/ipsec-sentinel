# Phase 3 Methodology Review — AI Classification Engine

## Executive Summary

Review of the AI engine methodology across feature engineering, classification approach, security assessment, and evaluation rigor. The synthetic dataset (114 pcaps) is ready; engine modules are scaffolded but not yet implemented.

**Overall Assessment:** Methodology is **directionally sound** but has **critical gaps** that must be resolved before implementation proceeds.

---

## 1. Feature Engineering

### 1.1 Current Feature Coverage (capture/features.py)

| Label | Feature Source | Sufficiency |
|-------|---------------|-------------|
| `ipsec_proto` | ESP/AH detection | ✅ Sufficient |
| `ike_version` | IKE packet detection (UDP 500/4500) | ⚠️ Partial — only infers v2, no parsing |
| `mode` | tunnel/transport from labels | ❌ **Leakage risk** — not extracted from packets |
| `enc_alg` | from labels | ❌ **Leakage risk** — not extracted from IKE proposals |
| `auth_alg` | from labels | ❌ **Leakage risk** — not extracted |
| `dh_group` | from labels | ❌ **Leakage risk** — not extracted |
| `pfs` | from labels | ❌ **Leakage risk** — not extracted |
| `ip_version` | IP/IPv6 headers | ✅ Sufficient |
| `traffic_type` | Packet size/timing stats | ⚠️ Partial — synthetic only, may not generalize |
| `variant_id` | from labels | ❌ **Leakage risk** — not a classification target |

### [BLOCKER] F-01: Label Fields Copied Directly from Ground Truth
- **Observation:** `extract_features()` copies 7 of 10 labels directly from label JSON without any packet-level extraction.
- **Impact:** Classifier trained on these features achieves 100% accuracy by memorizing label-to-feature mappings, not learning packet patterns.
- **Required:** Extract IKE proposals (SA payloads), ESP parameters, and mode indicators from actual packets.

### [MAJOR] F-02: No IKE Proposal Parsing
- **Observation:** IKE packets are detected as UDP on 500/4500, but SA payload parsing is absent.
- **Required:** Parse IKEv2 SA_INIT and IKE_AUTH exchanges to extract ENCR, PRF, INTEG, DH transforms.

### [MAJOR] F-03: Tunnel vs Transport Not Determined from Packets
- **Observation:** Mode is read from labels, not inferred from packet structure (outer vs inner IP headers).
- **Required:** Detect outer/inner IP header relationship to infer mode.

### [MINOR] F-04: Traffic Type Features Limited to Synthetic Patterns
- **Observation:** Packet size/timing features trained on synthetic generators with fixed patterns.
- **Mitigation:** Add statistical tests to validate feature distributions against real traffic.

---

## 2. Classification Approach

### 2.1 Hybrid Design (dispatch 005)

| Component | Approach | Assessment |
|-----------|----------|------------|
| Deterministic | Parse IKE proposals → exact algorithm mapping | ✅ Sound — IKE proposals are deterministic |
| ML | RandomForest/XGBoost for traffic_type, inferred fields | ✅ Appropriate — traffic type needs statistical learning |
| Multi-label | 10 outputs (ipsec_proto, ike_version, mode, enc_alg, enc_key_len, auth_alg, dh_group, pfs, ip_version, traffic_type) | ⚠️ **Over-specified** — enc_key_len not in labels |

### [BLOCKER] F-05: enc_key_len Not in Label Schema
- **Observation:** Classifier spec requires `enc_key_len` output, but synthetic labels only have `enc_alg` (e.g., `aes128cbc`, `aes256gcm`).
- **Required:** Either add `enc_key_len` to label extraction or remove from classifier outputs.

### [MAJOR] F-06: Multi-Label Strategy Underspecified
- **Observation:** Dispatch mentions "multi-label output" but doesn't specify if it's multi-output classifier, classifier chains, or independent models per label.
- **Required:** Define architecture — recommend independent classifiers per label with shared features for deterministic fields.

### [MAJOR] F-07: Confidence Calibration Absent
- **Observation:** No calibration method specified (Platt scaling, isotonic regression, temperature scaling).
- **Required:** Implement confidence calibration on validation set for production reliability.

---

## 3. Security Assessment

### 3.1 Rubric Alignment (docs/review/security-rubric.md)

| Rubric Criterion | Classifier Support | Gap |
|------------------|-------------------|-----|
| Cipher Suite Strength | enc_alg + enc_key_len needed | enc_key_len missing |
| DH Group Strength | dh_group extracted | Not in current features |
| Integrity Algorithm | auth_alg extracted | Not in current features |
| PFS | pfs field needed | Not extracted from packets |
| SA Lifetime | Not in features | Rekey timing analysis needed |
| Replay Window | Not in features | Sequence gap analysis needed |
| IKE Version | ike_version from labels | Should be parsed from IKE packets |
| Mode Exposure | mode from labels | Should be inferred from headers |
| Metadata Exposure | Requires mode + traffic | Composite score |

### [BLOCKER] F-08: Security Assessment Cannot Operate on Current Features
- **Observation:** 6 of 9 rubric criteria require fields not extracted from packets.
- **Required:** Feature extractor must produce all rubric inputs before security module can be built.

### [MAJOR] F-09: Oracle Score Validation Missing
- **Observation:** No automated test validates oracle scores from security-rubric.md against actual variant configs.
- **Required:** Add test that computes rubric scores from extracted features and compares to oracle table.

### [MINOR] F-10: Threat Matrix Methodology Not Machine-Checkable
- **Observation:** Threat matrix is descriptive; no computational mapping from findings to score deductions.
- **Mitigation:** Encode threat matrix as executable rules for auditability.

---

## 4. Evaluation Rigor

### 4.1 Dataset Split Strategy

| Aspect | Current Design | Assessment |
|--------|----------------|------------|
| Split Method | "Grouped by run_id" (dispatch 005) | ✅ Correct — prevents same-run leakage |
| Train/Val/Test | Not specified | ❌ Missing |
| Cross-variant eval | Not specified | ⚠️ Needed for generalization check |

### [MAJOR] F-11: No Defined Train/Val/Test Split
- **Observation:** Dispatch says "grouped by run_id" but doesn't specify ratios or stratification.
- **Required:** 60/20/20 split grouped by (variant, run_id) with stratification on traffic_type.

### [MAJOR] F-12: Leakage Checks Incomplete
- **Observation:** Feature importance analysis mentioned but no systematic leakage detection (filename, port, IP, SPI patterns).
- **Required:** Add leakage audit:
  - Verify no variant/traffic strings in features
  - Check SPI values don't correlate with variant
  - Verify source ports randomized across runs

### [MAJOR] F-13: Confidence Calibration Not Specified
- **Observation:** No calibration method or evaluation metric (ECE, MCE, reliability diagrams).
- **Required:** Add calibration step and report Expected Calibration Error (ECE).

---

## 5. Summary of Findings

| ID | Severity | Category | Finding |
|----|----------|----------|---------|
| F-01 | **BLOCKER** | Features | 7/10 labels copied from ground truth — not extracted from packets |
| F-02 | **MAJOR** | Features | No IKE SA proposal parsing |
| F-03 | **MAJOR** | Features | Tunnel/transport mode not inferred from packet structure |
| F-04 | **MINOR** | Features | Traffic type features only validated on synthetic data |
| F-05 | **BLOCKER** | Classifier | `enc_key_len` output not in label schema |
| F-06 | **MAJOR** | Classifier | Multi-label architecture undefined |
| F-07 | **MAJOR** | Classifier | No confidence calibration method |
| F-08 | **BLOCKER** | Security | Assessment module cannot run on current feature set |
| F-09 | **MAJOR** | Security | No automated oracle score validation |
| F-10 | **MINOR** | Security | Threat matrix not executable |
| F-11 | **MAJOR** | Evaluation | No defined train/val/test split ratios |
| F-12 | **MAJOR** | Evaluation | Leakage audit incomplete |
| F-13 | **MAJOR** | Evaluation | Confidence calibration not specified |

---

## 6. Recommended Remediation Order

1. **Fix F-01, F-05** — Update label schema and feature extractor to produce all 10 classification targets from packets
2. **Fix F-02, F-03** — Implement IKE proposal parsing and mode detection from packet headers
3. **Fix F-06, F-07** — Define multi-label architecture (recommend independent classifiers + deterministic parser) and add calibration
4. **Fix F-08** — Build security assessment after feature extractor produces all rubric inputs
5. **Fix F-09, F-10** — Add oracle validation test and encode threat matrix as rules
6. **Fix F-11, F-12, F-13** — Define splits, implement leakage audit, add calibration evaluation

---

## Conclusion

The methodology has the right structural intent (hybrid deterministic/ML, grouped splits, rubric-based assessment) but **three BLOCKERs** prevent implementation from producing valid results:

1. Feature extractor copies labels instead of parsing packets
2. Classifier spec includes non-existent label field (`enc_key_len`)
3. Security assessment requires features that don't exist

**Recommendation:** Pause implementation until BLOCKERs F-01, F-05, F-08 are resolved. MAJOR findings should be addressed in parallel during implementation.

# Phase 3 Code Review — Feature Extraction & Classifier

**Reviewer:** r1 (code review)
**Date:** 2026-09-30
**Scope:** `engine/features/`, `engine/classifier/`, and all related implementation code in `capture/`
**Verdict:** 3 BLOCKERs, 8 MAJORs, 5 MINORs — no implementation exists yet

---

## Executive Summary

The dispatch tasks 004 and 005 requested implementation of `engine/features/extractor.py`, `engine/classifier/model.py`, `engine/classifier/train.py`, `engine/classifier/evaluate.py`, and `engine/classifier/__init__.py`. **None of these files exist.** The directories contain only `.gitkeep`. All functional code lives in `capture/` as procedural scripts with no modular architecture, no tests, no type hints, and significant label-leakage bugs in `capture/features.py`.

This review covers the existing code as proxy for the intended implementation, flagging both the missing scaffold and the defects in the procedural code it should be replaced by.

---

## BLOCKER Findings

### BLOCKER B-01: Implementation Directives Unfulfilled — Engine Modules Do Not Exist

**Files:** `engine/features/.gitkeep`, `engine/models/.gitkeep`, `engine/api/.gitkeep` (all empty)
**Issue:** Dispatch 004 required `engine/features/extractor.py`, `engine/features/__init__.py`, `engine/features/test_extractor.py`. Dispatch 005 required `engine/classifier/model.py`, `engine/classifier/train.py`, `engine/classifier/evaluate.py`, `engine/classifier/__init__.py`. Zero implementation files were created.

**Evidence:**
```
$ find engine/features -type f
engine/features/.gitkeep
$ find engine/classifier -type f 2>/dev/null
(no output — directory does not exist)
```

**Impact:** Phase 3 cannot proceed. No feature extraction module, no classifier, no training pipeline, no evaluation. All synthetic data (114 pcaps) is unusable without an extractor.

**Required:** Implement all files listed in dispatch 004 and 005. The procedural `capture/features.py` is the reference but must be rewritten as a proper module with class-based API, unit tests, and no label leakage.

---

### BLOCKER B-02: Label Leakage in `capture/features.py`

**File:** `capture/features.py:18-29`
**Issue:** 7 of 10 classification targets are copied directly from the label JSON, not extracted from packets.

**Evidence:**
```python
features = {
    "variant_id": labels.get("variant_id", ...),      # ← from label
    "ipsec_proto": labels.get("ipsec_proto", ...),     # ← from label
    "ike_version": labels.get("ike_version", 2),       # ← from label
    "mode": labels.get("mode", "tunnel"),              # ← from label
    "enc_alg": labels.get("enc_alg", "unknown"),       # ← from label
    "auth_alg": labels.get("auth_alg", "unknown"),     # ← from label
    "dh_group": labels.get("dh_group", 14),            # ← from label
    "pfs": labels.get("pfs", "unknown"),               # ← from label
    "ip_version": labels.get("ip_version", 4),         # ← from label
    "traffic_type": labels.get("traffic_type", ...),   # ← from label
}
```

Only `packet_count`, `packet_sizes`, `timing_intervals`, `spi_patterns`, and `seq_stats` are actually extracted from packet data. A classifier trained on this will learn label-to-feature mappings, achieving 100% train accuracy with zero generalization.

**Impact:** Any model trained on these features is a memorization device, not a classifier. Results are meaningless.

**Required:** Extract all fields from packet structure:
- `ipsec_proto`: detect from `ESP in pkt` / `AH in pkt`
- `ike_version`: parse IKE header version field (not just UDP 500/4500)
- `mode`: infer from presence of inner IP headers inside ESP payload
- `enc_alg`, `auth_alg`, `dh_group`: parse IKE SA proposal payloads
- `pfs`: detect from IKE payload flags
- `traffic_type`: statistical inference from packet sizes/timing (already partially present)

---

### BLOCKER B-03: Syntax Error in `capture/features.py`

**File:** `capture/features.py:100`
**Issue:** Malformed f-string in the `if __name__ == "__main__"` block.

**Evidence:**
```python
parser.add_argument("--output-csv", default="/home/ansh/Projects/sih-2/ipsec-analysis/data/features/training_dataset.csv",
                    help="Output CSV file")
parser.add_argument("--output-jsonl", default="/home/ansh/Projects/sih-2/ipsec-analysis/data/features/training_dataset.jsonl",
                    help="Output JSONL file")
args = parser.parse_args()
aggregate_features(args.features_dir, args.output_csv, args.output_jsonl)
```

Wait — that's `aggregate.py`. Let me recheck `features.py`:

```python
    print(f"[features] Written to {args.output}")
    else:
        print(json.dumps(features, indent=2))
```

Missing `if` statement. Line 100 reads: `print(f"[features] Written to {args.output}")` outside any conditional block — the preceding `if args.output:` on line 98 has no closing statement before the `else:` on line 101, creating a syntax error.

**Impact:** `capture/features.py` cannot run. Any pipeline depending on it fails immediately.

**Required:** Fix the missing `if` / structural indentation. Correct form:
```python
    if args.output:
        with open(args.output, "w") as f:
            json.dump(features, f, indent=2)
        print(f"[features] Written to {args.output}")
    else:
        print(json.dumps(features, indent=2))
```

---

## MAJOR Findings

### MAJOR M-01: No Unit Tests for Any Module

**Files:** All Python modules in `capture/` and `testbed/traffic/`
**Issue:** Zero test files exist. `tests/` directory contains only `.gitkeep`.
**Evidence:**
```
$ find tests -type f
tests/.gitkeep
```
No pytest, no unittest, no test configuration. The dispatch 006 task assigned QA tests but produced no deliverable.
**Impact:** No regression protection. Any change to feature extraction, label generation, or traffic simulation is unverified.
**Required:** Implement `tests/test_features.py`, `tests/test_synth.py`, `tests/test_label.py` with pytest.

---

### MAJOR M-02: Print Statements Instead of Logging Throughout Codebase

**Files:** `capture/features.py:107`, `capture/label.py:44`, `capture/capture.py:26-27,44,54`, `capture/run_matrix.py:59,80,104,122,159,173,184-186,192-193`, `capture/synth/synth_pcap.py:177,245-246`, all traffic generators
**Issue:** Every module uses `print()` for status messages. No `logging` module usage anywhere.
**Evidence:**
```python
# capture/features.py:107
print(f"[features] Written to {args.output}")
# capture/run_matrix.py:59
print(f"\n[matrix] Running {run_id}: {variant} x {traffic} for {duration}s")
```
**Impact:** Cannot control verbosity, cannot redirect to file, cannot integrate with CI. Debug output floods stdout.
**Required:** Replace all `print()` calls with `logging.info/debug/warning` using a configured logger.

---

### MAJOR M-03: Hardcoded Absolute Paths Throughout

**Files:** `capture/features.py:12-13`, `capture/label.py:10`, `capture/run_matrix.py:14-34`, `capture/aggregate.py:66-67`, all traffic generators
**Issue:** Every path is hardcoded to `/home/ansh/Projects/sih-2/ipsec-analysis/...`. No configuration, no environment variables, no relative paths.
**Evidence:**
```python
# capture/features.py:12
pcap_dir = Path("/home/ansh/Projects/sih-2/ipsec-analysis/data/pcaps")
label_dir = Path("/home/ansh/Projects/sih-2/ipsec-analysis/data/labels")
# capture/run_matrix.py:14
VARIANTS = ["v1", "v2", "v3", "v4", "v5", "v6"]
TRAFFIC_SCRIPTS = {
    "icmp": "/home/ansh/Projects/sih-2/ipsec-analysis/testbed/traffic/icmp.sh",
    ...
}
```
**Impact:** Code is non-portable. Cannot run on any machine other than this one. CI/CD impossible.
**Required:** Use `Path(__file__).resolve().parent` or environment variables for all paths. Root the project at a configurable base path.

---

### MAJOR M-04: No Error Handling in Traffic Generators

**Files:** `testbed/traffic/icmp_gen.py:20-30`, `testbed/traffic/web_gen.py:20-35`, `testbed/traffic/voip_gen.py:22-29`, `capture/synth/synth_pcap.py:25-66`
**Issue:** No exception handling in packet generation loops. If `wrpcap()` fails mid-write, partial pcaps are produced with no cleanup.
**Evidence:**
```python
# capture/synth/synth_pcap.py:140
wrpcap(str(pcap_path), all_packets)  # no try/except
# label_gen.py:160
with open(label_path, 'w') as f:
    json.dump(label, f, indent=2)  # no try/except
```
**Impact:** Corrupt PCAPs and orphaned label files on any failure. No recovery mechanism.
**Required:** Wrap all file I/O in try/except with cleanup on failure. Validate output before considering it complete.

---

### MAJOR M-05: Synthetic Data Has No Reproducibility Controls

**File:** `capture/synth/synth_pcap.py`
**Issue:** No random seed set. Every run produces different packets, different SPIs, different sequence numbers.
**Evidence:**
```python
spi = random.randint(0x10000000, 0xFFFFFFFF)  # line 27
iv = os.urandom(iv_size)                       # line 32
actual_payload = os.urandom(payload_size)      # line 34
```
**Impact:** Cannot reproduce results. Cannot validate deterministic behavior. Regression testing impossible.
**Required:** Accept optional `--seed` argument. Set `random.seed()` and use deterministic PRNG for packet generation.

---

### MAJOR M-06: IKE Handshake Generation Is Fake

**File:** `capture/synth/synth_pcap.py:90-113`
**Issue:** `generate_ike_handshake()` creates UDP packets with random payload — no IKE header structure, no SA payloads, no DH exchanges, no nonce generation. The packets are structurally invalid IKE.
**Evidence:**
```python
sa_init_req = IP(src="10.1.0.1", dst="10.2.0.1") / \
    UDP(sport=500, dport=500) / Raw(load=os.urandom(200))  # line 99
```
**Impact:** Feature extractor cannot learn IKE parsing from this data. Real IKE has structured SA payloads with ENCR, PRF, INTEG, DH transforms that a parser must handle.
**Required:** Generate valid IKEv2 packet structures (at minimum: IKE header with version=2, exchange type, flags, payload headers). Use Scapy's IKE layers if available, or construct manually.

---

### MAJOR M-07: No Classification Pipeline Exists

**Files:** `engine/classifier/` (does not exist)
**Issue:** Dispatch 005 required `model.py`, `train.py`, `evaluate.py`, `__init__.py`. None were created. The project has no classifier, no training pipeline, no evaluation script.
**Evidence:**
```
$ find engine/classifier -type f 2>/dev/null
(no output)
```
**Impact:** Phase 3 cannot produce predictions. The entire ML component is absent.
**Required:** Implement the full classifier pipeline per dispatch 005 specifications, addressing the label leakage issue (B-02) in the feature extractor first.

---

### MAJOR M-08: `aggregate.py` Has No Schema Validation

**File:** `capture/aggregate.py:20-23`
**Issue:** Aggregates all `.json` files from the features directory without validating their schema. Missing keys, wrong types, or nested structures cause silent data corruption.
**Evidence:**
```python
for f in feature_files:
    with open(f, "r") as fp:
        data = json.load(fp)
    all_features.append(data)  # no validation
```
**Impact:** Bad feature data silently enters the training dataset.
**Required:** Validate each feature dict against the expected schema before aggregation. Reject or log malformed entries.

---

## MINOR Findings

### MINOR m-01: Missing `__init__.py` in `engine/` Subdirectories

**Files:** `engine/features/__init__.py` (missing), `engine/classifier/__init__.py` (missing), `engine/api/__init__.py` (missing)
**Issue:** All engine subdirectories lack `__init__.py`, preventing `import engine.features` style imports.
**Impact:** Modular imports fail. Forces absolute imports or package reorganization.
**Required:** Add `__init__.py` to each engine subdirectory when implementation is done.

---

### MINOR m-02: Inconsistent Naming Between Synthetic and Real Label Schemas

**Files:** `capture/synth/synth_pcap.py:142-157`, `capture/label.py:29-38`
**Issue:** Synthetic labels use keys like `enc_alg`, `auth_alg`, `ip_version`. Real labels from `label.py` use `cipher`, `integrity`, `family`. A classifier needs a unified schema.
**Evidence:**
```python
# synth label
"label": { "enc_alg": "aes128cbc", "auth_alg": "hmac_sha256", ... }
# real label (from label.py)
"labels": { "cipher": "aes128-sha256-modp2048", "integrity": "hmac-sha256", ... }
```
**Impact:** Downstream code must handle two schemas. Classifier training data is inconsistent.
**Required:** Define a canonical label schema and normalize both sources to it.

---

### MINOR m-03: Unused Variant Definitions in `run_matrix.py`

**File:** `capture/run_matrix.py:11-17`
**Issue:** `SYNTH_VARIANTS` dict duplicates the same variant definitions from `synth_pcap.py`. Three copies of the same config exist across the codebase.
**Evidence:**
```python
# run_matrix.py:37-44
SYNTH_VARIANTS = { "v1": {...}, "v2": {...}, ... }
# synth_pcap.py:14-21
VARIANTS = { "v1": {...}, "v2": {...}, ... }
```
**Impact:** Config drift — updating one copy requires updating all. Risk of inconsistency.
**Required:** Consolidate variant definitions into a single source (e.g., `engine/features/configs.py`) and import where needed.

---

### MINOR m-04: No Requirements File or Dependency Management

**Files:** Project root
**Issue:** No `requirements.txt`, `pyproject.toml`, or `Pipfile`. Dependencies are implicit.
**Evidence:**
```
$ find . -name "requirements*.txt" -o -name "pyproject.toml" -o -name "Pipfile" 2>/dev/null
(no output)
```
**Impact:** Cannot reproduce environment. New developer has no install instructions.
**Required:** Add `requirements.txt` with pinned versions for scapy, pandas, numpy, scikit-learn, xgboost (optional).

---

### MINOR m-05: Entry Point Confusion Between `capture.sh` and `entrypoint.sh`

**Files:** `testbed/scripts/entrypoint.sh`, `capture/capture.sh`
**Issue:** Two different entrypoints with similar names serve different purposes (Docker container startup vs. capture orchestration), creating naming collision risk.
**Evidence:**
```
testbed/scripts/entrypoint.sh    # Docker container startup
capture/capture.sh               # Capture orchestration wrapper
```
**Impact:** New contributors may confuse the two scripts.
**Required:** Rename `capture/capture.sh` to something like `capture/orchestrate.sh` to avoid ambiguity.

---

## Appendix: Missing Implementation Checklist

Per dispatch 004 and 005, the following files were required but never created:

| Required File | Status | Priority |
|--------------|--------|----------|
| `engine/features/__init__.py` | Missing | BLOCKER |
| `engine/features/extractor.py` | Missing | BLOCKER |
| `engine/features/test_extractor.py` | Missing | BLOCKER |
| `engine/classifier/__init__.py` | Missing | BLOCKER |
| `engine/classifier/model.py` | Missing | BLOCKER |
| `engine/classifier/train.py` | Missing | BLOCKER |
| `engine/classifier/evaluate.py` | Missing | BLOCKER |
| `tests/test_features.py` | Missing | MAJOR |
| `tests/test_classifier.py` | Missing | MAJOR |
| `requirements.txt` | Missing | MINOR |

---

## Recommendations

1. **Block on B-01, B-02, B-03 before any model training.** The existing `capture/features.py` is both buggy and fundamentally broken (label leakage). It must be rewritten as a proper module.
2. **Create `engine/features/configs.py`** as the single source of truth for variant definitions.
3. **Implement `engine/features/extractor.py`** with genuine packet parsing — no label copying.
4. **Implement `engine/classifier/`** as a clean multi-label pipeline with deterministic + ML hybrid approach.
5. **Add tests before model training** — the testability gap (M-01) makes all subsequent work unverified.

**Verdict:** Work cannot proceed to model training until BLOCKERs are resolved.

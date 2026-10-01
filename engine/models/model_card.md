# Model card — IPsec hybrid classifier (M3)

## Architecture
Deterministic wire parsers (`engine/classifier/parse.py`, `source:
parsed`, confidence 1.0) for everything sent in the clear — IKE version,
ESP/AH/NAT-T presence, proposal transforms (cipher, key length, PRF,
integrity, DH group), KE length cross-check, rekey/PFS, AH mode — plus
per-field RandomForest classifiers (`source: model`) for what is only
inferred: traffic type (always), ESP mode, cipher/integrity (IKE absent).
DH without IKE and IKEv1/real PFS are emitted as `unknown`, never guessed.

## Training data
360 synthetic pcaps (18 variants + plain × 3 runs × 6 traffic types).
Features: packet bytes only (`engine/features/extract.py`) — counts,
size/IAT/ESP-length distributions, flow ratios, cleartext IKE fields.
No addresses, ports, SPIs, cookies, epochs, filenames, or labels are
stored as features (tests: `engine/tests/test_no_labels.py`,
`test_predict_no_labels.py`).

## Hyperparameters
RandomForest, n_estimators=300, random_state=7, n_jobs=-1;
DictVectorizer (numbers as-is, strings one-hot). Confidence =
predict_proba max; below 0.5 the field is `unknown`.

## Evaluation (see docs/model-evaluation.md)
Grouped 5-fold CV (groups = variant/run), ESP-only ablation (all
IKE-derived features blinded pre-parse and pre-model), and
synthetic-train → 42-real-test reported separately. Real covers only
v1,v3,v5,v7,v12,v18. Unknown predictions count as errors.

## Limitations
Traffic/mode models transfer partially to real stacks (timing dynamics
differ); lifetimes/replay/ESN are never observed in 8 s captures;
synthetic-only scores do not prove real-world performance.

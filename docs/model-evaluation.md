# Model evaluation (M3)

## Protocol

Grouped 5-fold CV over 396 synthetic pcaps (63 variant-run groups); synth->real trains on all synthetic, tests the real pcaps (test 66 real); real holdout trains synthetic + real r1 runs and tests real r2/r3 runs (runs kept apart); ESP-only ablation drops every IKE-derived feature. Unknown predictions count as errors.

## Sample counts

CV: 396 synthetic (20 variants + plain x 3 runs x 6 types). synth->real: train 396 synthetic, test 66 real. holdout: train 432, test 30.

## Grouped CV (full features)

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 396 | 0.9015 | 0.8934 | 0.7807 | 0.817 | 0.0253 |
| enc_key_len | 396 | 0.9066 | 0.9327 | 0.91 | 0.9202 | 0.0152 |
| auth_alg | 396 | 0.9798 | 0.9872 | 0.9773 | 0.982 | 0.0 |
| dh_group | 396 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 396 | 0.9545 | 1.0 | 0.9722 | 0.9857 | 0.0455 |
| ip_version | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 396 | 0.9949 | 0.9975 | 0.9949 | 0.9962 | 0.0025 |
| nat_t | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_dh_group | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## ESP-only ablation CV

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 396 | 0.0909 | 0.3333 | 0.3333 | 0.3333 | 0.9091 |
| mode | 396 | 0.9949 | 0.9897 | 0.9897 | 0.9897 | 0.0 |
| enc_alg | 396 | 0.9015 | 0.8934 | 0.7807 | 0.817 | 0.0253 |
| enc_key_len | 396 | 0.9066 | 0.9327 | 0.91 | 0.9202 | 0.0152 |
| auth_alg | 396 | 0.9798 | 0.9872 | 0.9773 | 0.982 | 0.0 |
| dh_group | 396 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 396 | 0.0909 | 0.5 | 0.25 | 0.3333 | 0.9091 |
| ip_version | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 396 | 0.9975 | 0.9975 | 0.9975 | 0.9975 | 0.0 |
| nat_t | 396 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 396 | 0.0909 | 0.1667 | 0.1667 | 0.1667 | 0.9091 |
| ike_dh_group | 396 | 0.0909 | 0.1667 | 0.1667 | 0.1667 | 0.9091 |

## Synthetic -> real

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 66 | 0.7121 | 0.7 | 0.5792 | 0.6225 | 0.2424 |
| enc_key_len | 66 | 0.803 | 0.9907 | 0.8536 | 0.9142 | 0.1667 |
| auth_alg | 66 | 0.9697 | 0.9792 | 0.95 | 0.963 | 0.0 |
| dh_group | 66 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 66 | 0.0758 | 1.0 | 0.0857 | 0.1576 | 0.9242 |
| ip_version | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 66 | 0.5 | 0.6667 | 0.5769 | 0.6053 | 0.5 |
| nat_t | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_dh_group | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Real holdout (train synth + real r1 → test real r2/r3; n_train=432, n_test=30, runs ['r2', 'r3'], traffic ['email', 'icmp', 'video', 'voip', 'web', 'whatsapp'])

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 30 | 0.9667 | 1.0 | 0.9375 | 0.9643 | 0.0333 |
| enc_key_len | 30 | 0.9667 | 0.9333 | 0.9848 | 0.9552 | 0.0 |
| auth_alg | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| dh_group | 30 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 30 | 0.1667 | 1.0 | 0.2019 | 0.3333 | 0.8333 |
| ip_version | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 30 | 0.8667 | 0.9762 | 0.9048 | 0.9356 | 0.1 |
| nat_t | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_dh_group | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Reading the numbers (v1.1 boundary)

- ike_version / ike_enc_alg / ike_dh_group: the IKE SA parse, still ~100% deterministic (proposal + KE travel in the clear). These score the IKE SA only — they never fill child fields.
- enc_alg / enc_key_len / auth_alg (child suite): model-INFERRED from the ESP-only feature view (IKE proposal bytes excluded, so mirrored training suites cannot teach copy-IKE->child). Expect below the old 1.0 (which came from reading the IKE proposal): the tables above are the honest ESP-size signal, and the mismatch variants (v19/v20) prove no inheritance.
- dh_group (CHILD PFS group): 0.0 by design — rekey content is encrypted, so the child group is never on the wire in short captures; every live prediction is honestly `unknown` (counted wrong here). The IKE group is scored separately in ike_dh_group. The old ablation's dh pockets (priors + cipher correlation) are gone: no dh model runs in production.
- Macro P/R/F1 average over TRUE label classes only; `unknown` predictions count as errors against their true class but are not scored as a class.
- pfs: a length model over rekey SK blobs (KE inflates the encrypted blob ~260 B CBC). Correct whenever an attributable rekey is on the wire — synthetic AND real (forced rekeys prove presence; sizes transfer); `unknown` with no rekey (IKEv1 QM, quiet captures) or with concurrent SPIs (rekey unattributable), counted wrong, honestly. Never a confident error.
- traffic_type drops synth->real with ZERO wrong guesses on TCP (abstains). Calibration works as designed; exact splits are in the tables above.
- Real data covers ONLY v1,v3,v5,v7,v12,v18 (66 pcaps incl. forced-rekey and extra-TCP runs): the synth->real and holdout numbers say nothing about the other 14 variants; synthetic-only and real-included numbers are reported in separate tables above.
- What synthetic-only evaluation proves: the pipeline works on the synthetic distribution. What it does NOT prove: performance on other stacks, middlebox-mangled traffic, or longer captures with rekeys. The 66 real pcaps are the only out-of-distribution evidence and they cover 6 of 21 classes.


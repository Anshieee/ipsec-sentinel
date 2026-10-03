# Model evaluation (M3)

## Protocol

Grouped 5-fold CV over 414 synthetic pcaps (66 variant-run groups); synth->real trains on all synthetic, tests the real pcaps (test 66 real); real holdout trains synthetic + real r1 runs and tests real r2/r3 runs (runs kept apart); ESP-only ablation drops every IKE-derived feature. Unknown predictions count as errors.

## Sample counts

CV: 414 synthetic (21 variants + plain x 3 runs x 6 types). synth->real: train 414 synthetic, test 66 real. holdout: train 450, test 30.

## Grouped CV (full features)

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 414 | 0.8889 | 0.8038 | 0.7414 | 0.7607 | 0.0145 |
| enc_key_len | 414 | 0.8865 | 0.914 | 0.8924 | 0.9025 | 0.0145 |
| auth_alg | 414 | 0.9855 | 0.9906 | 0.987 | 0.9888 | 0.0 |
| dh_group | 414 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 414 | 0.9565 | 1.0 | 0.9737 | 0.9865 | 0.0435 |
| ip_version | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 414 | 0.9952 | 0.9953 | 0.9952 | 0.9952 | 0.0 |
| nat_t | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_dh_group | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## ESP-only ablation CV

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 414 | 0.087 | 0.3333 | 0.3333 | 0.3333 | 0.913 |
| mode | 414 | 0.9928 | 0.9895 | 0.9805 | 0.9849 | 0.0024 |
| enc_alg | 414 | 0.8889 | 0.8038 | 0.7414 | 0.7607 | 0.0145 |
| enc_key_len | 414 | 0.8865 | 0.914 | 0.8924 | 0.9025 | 0.0145 |
| auth_alg | 414 | 0.9855 | 0.9906 | 0.987 | 0.9888 | 0.0 |
| dh_group | 414 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 414 | 0.087 | 0.5 | 0.25 | 0.3333 | 0.913 |
| ip_version | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 414 | 0.9952 | 0.9976 | 0.9952 | 0.9963 | 0.0024 |
| nat_t | 414 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 414 | 0.087 | 0.1667 | 0.1667 | 0.1667 | 0.913 |
| ike_dh_group | 414 | 0.087 | 0.1667 | 0.1667 | 0.1667 | 0.913 |

## Synthetic -> real

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 66 | 0.7576 | 0.65 | 0.6361 | 0.6429 | 0.1515 |
| enc_key_len | 66 | 0.8182 | 0.875 | 0.913 | 0.8731 | 0.0758 |
| auth_alg | 66 | 0.9697 | 0.9792 | 0.95 | 0.963 | 0.0 |
| dh_group | 66 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 66 | 0.0758 | 1.0 | 0.0857 | 0.1576 | 0.9242 |
| ip_version | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 66 | 0.5 | 0.6667 | 0.5769 | 0.6053 | 0.5 |
| nat_t | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_dh_group | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Real holdout (train synth + real r1 → test real r2/r3; n_train=450, n_test=30, runs ['r2', 'r3'], traffic ['email', 'icmp', 'video', 'voip', 'web', 'whatsapp'])

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 30 | 0.9333 | 1.0 | 0.875 | 0.9167 | 0.0667 |
| enc_key_len | 30 | 0.9667 | 1.0 | 0.9848 | 0.9922 | 0.0333 |
| auth_alg | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| dh_group | 30 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| pfs | 30 | 0.1667 | 1.0 | 0.2019 | 0.3333 | 0.8333 |
| ip_version | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 30 | 0.9 | 0.9762 | 0.9286 | 0.9484 | 0.0667 |
| nat_t | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_enc_alg | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_dh_group | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Reading the numbers (v1.2 boundary)

- ike_version / ike_enc_alg / ike_dh_group: the IKE SA parse, still ~100% deterministic (proposal + KE travel in the clear). These score the IKE SA only — they never fill child fields.
- enc_alg / enc_key_len / auth_alg (child suite): model-INFERRED from the ESP-only feature view (IKE proposal bytes excluded, so mirrored training suites cannot teach copy-IKE->child). Expect below the old 1.0 (which came from reading the IKE proposal): the tables above are the honest ESP-size signal, and the mismatch variants (v19/v20) prove no inheritance.
- ike_enc_alg is parsed from IKE_SA_INIT at ~100%: the v1.2 ike-cipher / ike-integrity assessment controls read this parse, never the child suite.
- dh_group (CHILD PFS group): 0.0 by design — rekey content is encrypted, so the child group is never on the wire in short captures; every live prediction is honestly `unknown` (counted wrong here). The IKE group is scored separately in ike_dh_group. The old ablation's dh pockets (priors + cipher correlation) are gone: no dh model runs in production.
- Macro P/R/F1 average over TRUE label classes only; `unknown` predictions count as errors against their true class but are not scored as a class.
- pfs: a length model over rekey SK blobs (KE inflates the encrypted blob ~260 B CBC). Correct whenever an attributable rekey is on the wire — synthetic AND real (forced rekeys prove presence; sizes transfer); `unknown` with no rekey (IKEv1 QM, quiet captures) or with concurrent SPIs (rekey unattributable), counted wrong, honestly. Never a confident error.
- traffic_type drops synth->real with ZERO wrong guesses on TCP (abstains). Calibration works as designed; exact splits are in the tables above.
- Real data covers ONLY v1,v3,v5,v7,v12,v18 (66 pcaps incl. forced-rekey and extra-TCP runs): the synth->real and holdout numbers say nothing about the other 15 variants; synthetic-only and real-included numbers are reported in separate tables above.
- What synthetic-only evaluation proves: the pipeline works on the synthetic distribution. What it does NOT prove: performance on other stacks, middlebox-mangled traffic, or longer captures with rekeys. The 66 real pcaps are the only out-of-distribution evidence and they cover 6 of 22 classes.


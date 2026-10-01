# Model evaluation (M3)

## Protocol

Grouped 5-fold CV over 360 synthetic pcaps (57 variant-run groups); synth->real trains on all synthetic, tests the real pcaps; real holdout trains synthetic + real r1 runs and tests real r2/r3 runs (runs kept apart); ESP-only ablation drops every IKE-derived feature. Unknown predictions count as errors.

## Sample counts

CV: 360 synthetic (18 variants + plain x 3 runs x 6 types). synth->real: train 360 synthetic, test 66 real. holdout: train 396, test 30.

## Grouped CV (full features)

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_key_len | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| auth_alg | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| dh_group | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| pfs | 360 | 0.95 | 1.0 | 0.9688 | 0.9839 | 0.05 |
| ip_version | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 360 | 0.9889 | 0.9943 | 0.9889 | 0.9916 | 0.0056 |
| nat_t | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## ESP-only ablation CV

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 360 | 0.1 | 0.0333 | 0.3333 | 0.0606 | 0.0 |
| mode | 360 | 0.9944 | 0.9896 | 0.9896 | 0.9896 | 0.0 |
| enc_alg | 360 | 0.9389 | 0.9794 | 0.8872 | 0.9201 | 0.0167 |
| enc_key_len | 360 | 0.9333 | 0.9561 | 0.8738 | 0.9094 | 0.0139 |
| auth_alg | 360 | 0.9444 | 0.9979 | 0.9729 | 0.985 | 0.05 |
| dh_group | 360 | 0.8194 | 0.7731 | 0.63 | 0.6743 | 0.05 |
| pfs | 360 | 0.1 | 0.5 | 0.25 | 0.3333 | 0.9 |
| ip_version | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 360 | 0.9917 | 0.9972 | 0.9917 | 0.9944 | 0.0056 |
| nat_t | 360 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Synthetic -> real

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_key_len | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| auth_alg | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| dh_group | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| pfs | 66 | 0.0758 | 1.0 | 0.0857 | 0.1576 | 0.9242 |
| ip_version | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 66 | 0.5152 | 0.8333 | 0.5897 | 0.6291 | 0.4848 |
| nat_t | 66 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Real holdout (train synth + real r1 → test real r2/r3; n_train=396, n_test=30, runs ['r2', 'r3'], traffic ['email', 'icmp', 'video', 'voip', 'web', 'whatsapp'])

| field | n | acc | macro-P | macro-R | macro-F1 | unknown |
|---|---|---|---|---|---|---|
| ipsec_proto | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| ike_version | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| mode | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_alg | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| enc_key_len | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| auth_alg | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| dh_group | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| pfs | 30 | 0.1667 | 1.0 | 0.2019 | 0.3333 | 0.8333 |
| ip_version | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| traffic_type | 30 | 0.8667 | 0.9762 | 0.9048 | 0.9356 | 0.1 |
| nat_t | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

## Reading the numbers

- ~100%: deterministic wire parses (IKE proposal/KE, presence, AH next-header). Expected: the values are sent in the clear. Mode at ~100% is tunnel-overhead signal (inner IP header shifts every ESP size by 20/40 B); it transfers to real captures, but it depends on the traffic mix, not on variant identity (folds never share a variant-run; features store no addresses).
- Macro P/R/F1 average over TRUE label classes only; `unknown` predictions count as errors against their true class but are not scored as a class.
- pfs: a length model over rekey SK blobs (KE inflates the encrypted blob ~260 B CBC). Correct whenever a rekey is on the wire — synthetic AND real (forced rekeys prove presence; sizes transfer); `unknown` with no rekey (IKEv1 QM, quiet captures), counted wrong, honestly. Never a confident error.
- The ESP-only ablation blinds ALL IKE-derived features before both parsing and modeling (as if IKE packets were never captured): dh_group there scores 0.82/0.67: majority prior 14 (215/234) plus cipher-correlated pockets (dh19 17/18 via GCM-transport sizes, dh20 21/36 via AES-256 sizes) — correlation and priors, not DH signal; dh5 0/18, dh2 6/18. Expected: DH leaves no trace in ESP sizes/timing.
- traffic_type drops synth->real (0.52, 48% unknown) with ZERO wrong guesses: voip 13/13, video/icmp 7/7, whatsapp 6/13, email 1/13, web 0/13 — TCP abstains, so the model abstains. Calibration works as designed.
- Real data covers ONLY v1,v3,v5,v7,v12,v18 (66 pcaps incl. forced-rekey and extra-TCP runs): the synth->real and holdout numbers say nothing about the other 12 variants; synthetic-only and real-included numbers are reported in separate tables above.
- What synthetic-only evaluation proves: the pipeline works on the synthetic distribution. What it does NOT prove: performance on other stacks, middlebox-mangled traffic, or longer captures with rekeys. The 42 real pcaps are the only out-of-distribution evidence and they cover 6 of 19 classes.


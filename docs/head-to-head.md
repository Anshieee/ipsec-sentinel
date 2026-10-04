# Head-to-head: our analyzer on someone else's data (v1.2.6)

## 0. Recon (external repo, read-only — nothing copied into our repo)

- URL: https://github.com/naman9271/ipsec-pcap-lab
- Commit: `c0cf25647b88c1cdb0649a43049e192e269f4cc6` ("dataset completed")
- LICENSE: **none found** (no LICENSE/COPYING/NOTICE; `find` clean).
  Case applied: **no pcaps, no label files, no label values enter our
  repo.** Committed: `scripts/eval_external.py`, aggregate results, and
  `results/external-eval.json` with per-file records holding only pcap
  sha256 + our predictions (their labels excluded). Reproduce with their
  repo at the commit above.
- README (`README.md`): reproducible two-container strongSwan lab,
  outer-side encrypted captures (native ESP or UDP/4500), 20 preserved
  originals + generated samples, never decoded/modified after capture.
- Layout: `pcaps/known/<label>/` (`<class>_p<profile>_r<run>.pcap`,
  classes web/video/voip/email/file_transfer/messaging/icmp),
  `pcaps/ood/` (DNS/terminal/gaming, `canonical_label=IGNORE`),
  `pcaps/anomaly/` (floods/beacons, `is_anomaly=true`),
  `pcaps/protocol_validation/` (negotiation-first IKE/ESP per profile).
- Labels: single `metadata.csv` (239 rows, 46 columns) — no per-pcap
  label files. Label columns: `traffic_class`, `mode`, `ike_version`,
  `ike_proposal`, `esp_proposal`, `cipher`, `integrity`, `dh_group`,
  `pfs`, `ip_version`, `nat_t` (+ `nat_t_forced`,
  `udp_encapsulation_forced`, `actual_nat_present`), `canonical_label`,
  `dataset_role`, `profile_id`, `run_id`, `split`, `protocol_facts`,
  per-file `sha256`, packet stats, generator JSON.
- Roles: train_known 175, anomaly_eval 30, ood_eval 25,
  protocol_validation 5, archived_provenance 4.
- Profiles: P01 IKEv2/tunnel/IPv4 native ESP; P02 IKEv2/tunnel/IPv4
  forced UDP/4500; P03 IKEv1/tunnel/IPv4 native ESP; P04 IKEv1/
  transport/IPv4 forced UDP/4500; P05 IKEv2/tunnel/IPv6 native ESP.
- Ciphers: AES-128-CBC (96), AES-256-CBC (95), AES-256-GCM-16 (48).
  Integrity: HMAC-SHA256 (144), AEAD-GCM-128-bit-ICV (48), HMAC-SHA384 (47).
  DH: 14-MODP2048 (96), 19-ECP256 (48), 15-MODP3072 (48), 20-ECP384 (47).
  PFS on 96 / off 143. IKEv2 143 / IKEv1 96. Tunnel 191 / transport 48.
  IPv4 192 / IPv6 47. nat_t on 96 / off 143.
- Produced by: real strongSwan U5.9.13 in two privileged Docker
  containers, tcpdump on the host veth, BPF `esp or udp port 4500`,
  fresh bring-up per traffic type. Configured 45 s captures, observed
  wire spans ~10–19 s. Ethernet classic pcap. Traffic: smtp/aiosmtpd,
  HLS segments, ffmpeg RTP, websockets, web objects, ICMP.
- Verified here: all 175 train_known pcaps present; every known capture
  probed contains **zero IKE packets** (the BPF excludes UDP/500, so
  native profiles lost the handshake; forced-encap captures carry
  ESP-in-UDP only). Handshakes exist only in `protocol_validation`
  (`ike_session_p0{1..5}.pcap`: 4–9 IKE packets each).
- Published results table / accuracy numbers: **none found** (repo-wide
  grep for accuracy/precision/recall/results empty). Nothing to quote
  side-by-side from their side; §3 states this explicitly.

## 1. Label mapping (semantics-equal only; rest excluded, never guessed)

| their column | our field | mapping |
|---|---|---|
| `ike_version` IKEv2/IKEv1 | `ike_version` ikev2/ikev1 | equal, where a handshake is on the wire; else we abstain (UNKNOWN) |
| `mode` tunnel/transport | `mode` | equal |
| `cipher` AES-128-CBC / AES-256-CBC / AES-256-GCM-16 | `enc_alg` aes-128-cbc / aes-256-cbc / aes-256-gcm (+ keylen 128/256/256) | equal |
| `integrity` HMAC-SHA256 | `auth_alg` hmac-sha256 | equal |
| `integrity` AEAD-GCM-128-bit-ICV | `auth_alg` aead | equal (AEAD semantics) |
| `integrity` HMAC-SHA384 | — | EXCLUDED: no equal value in our schema (47 rows) |
| `dh_group` 14-MODP2048 / 19-ECP256 / 20-ECP384 | `dh_group` 14 / 19 / 20 | numeric equal, with scope caveat: theirs is the negotiated group for both phases (matches `ike_proposal` on PFS-on rows); ours is child-PFS-scoped and honestly UNKNOWN live (rekeys encrypted), so this column measures our abstention, not our error |
| `dh_group` 15-MODP3072 | — | EXCLUDED: not in our schema (48 rows) |
| `pfs` on/off | `pfs` true/false | equal as ground truth; we infer only with a rekey on the wire (their captures show none so far) |
| `ip_version` IPv4/IPv6 | `ip_version` 4/6 | equal |
| `nat_t` on/off | `nat_t` bool | CONDITIONAL: theirs records forced-UDP4500 config (their own `actual_nat_present=no`); ESP-in-UDP is really on the wire for on-rows, which is exactly what our field means |
| `canonical_label` web/video/voip/email/icmp | `traffic_type` | equal (5 of 7 classes) |
| `canonical_label` file_transfer/messaging/IGNORE | — | EXCLUDED: no equal class (50 known rows + all ood/anomaly) |
| profile/run/split | — | not scored; split membership reported, not used |

## 2. Method (one-shot, frozen)

`scripts/eval_external.py --their-root ~/.tmp-work/ipsec-pcap-lab`
runs `analyze()` from `engine/classifier/predict.py` with the
already-trained `engine/models` (no retraining, no thresholds, no rule
changes — the script cannot change them; it only reads). Scope:
175 `train_known` rows for all mappable fields + 5
`protocol_validation` rows for `ike_version`/child-crypto parse checks
only (their traffic label is IGNORE). ood/anomaly/archived excluded
(unlabeled by design). Per-file failures (parse errors, no-IPsec,
WITHHELD assessments) are recorded and counted, not dropped.
Overlap: sha256 of every file in our `data/manifest.csv` vs their
metadata sha256 set (expect 0 — different stacks, subnets, tools).
Training provenance: our models train on our synthetic corpus
(deterministic seeds in `capture/synth/`) plus our own real r1 runs;
nothing is derived from their repo (different address space
172.30/10.10 vs ours, different generators, different captures).

## 3. Results

Run: one-shot, frozen models, `--include-protocol-sessions`.
0 parse errors, 0 no-IPsec (all captures contain ESP).
Hash overlap with our 480-file corpus: **0**. Their repo publishes no
numbers, so there is no side-by-side table: the figures below come from
our frozen pipeline on their frozen commit, not from any held-out split
of theirs.

### v1.2.6 baseline (from results/external-eval.json, 180 files)

| field | n (mappable) | accuracy (unknown=error) | coverage | acc-when-answered |
|---|---|---|---|---|
| ike_version | 180 | 0.028 | 0.028 | 1.000 |
| mode | 180 | 0.011 | 1.000 | 0.011 |
| enc_alg | 180 | 0.322 | 0.467 | 0.690 |
| enc_key_len | 180 | 0.428 | 0.656 | 0.653 |
| auth_alg | 144 | 0.910 | 0.931 | 0.978 |
| dh_group | 144 | 0.000 | 0.000 | — |
| pfs | 180 | 0.000 | 0.000 | — |
| ip_version | 180 | 1.000 | 1.000 | 1.000 |
| nat_t | 180 | 1.000 | 1.000 | 1.000 |
| traffic_type | 125 | 0.000 | 0.120 | 0.000 |

Provenance split: every `ike_version` answer (5/5, protocol sessions)
is OBSERVED and correct; every child-crypto/traffic answer is INFERRED;
`dh_group`/`pfs` abstain 100% by design (rekeys encrypted / absent).

Confusion (`enc_alg`, rows truth): AES-128-CBC → 50 aes-128-cbc /
22 unknown (zero wrong); AES-256-CBC → 25 aes-128-cbc (wrong) /
47 unknown; AES-256-GCM → 8 aes-256-gcm / 1 aes-128-cbc / 27 unknown.
When the model answers CBC it always says AES-128; GCM mostly abstains.

Confusion (`traffic_type`, rows truth): email 25 unknown; icmp 22
unknown + 3 whatsapp (wrong); video 25 unknown; voip 25 unknown; web 13
unknown + 12 whatsapp (wrong). 15 answered, 0 correct.

Notable failures: `mode` predicts `none` (the plain class) on 175/180
ESP captures — the tunnel-overhead size signal learned on 8 s synthetic
captures does not survive 45 s real traffic mixes; only the tiny
protocol sessions get tunnel/transport. `traffic_type` transfers not at
all (their SMTP/HLS/RTP/websocket traffic is nothing like our six
synthetic profiles; the 15 answers are all confident `whatsapp` errors).

Excluded, not scored: HMAC-SHA384 auth (47 rows), DH15 (48 rows),
file_transfer/messaging traffic (50 rows), ood/anomaly/archived and
protocol-session traffic labels (by design).

## 6. v1.2.7 robustness: root causes, fixes, DEV/TEST protocol, results

Status note: after v1.2.6 the external set is no longer untouched —
DEV (P01+P04+P05, 108 files, frozen in docs/head-to-head-split.json
before any fix) was used for diagnosis and gate calibration. Only the
TEST split (P02+P03, 72 files) is a clean measurement; it was run
EXACTLY ONCE with frozen v1.2.7 code (see below).

### Root causes (all diagnosed on DEV only, with evidence)

(a) `mode = plain/none` on ESP captures although
`detection.ipsec_detected` is true: the mode RandomForest learned a
`none` class from plain pcaps. On OOD captures (e.g. DEV
`email_p01_R01`: n=5016 packets, 19 s span) the trees land in
plain-dominated leaves → `none` at 0.62 confidence while 399 ESP
packets sit beside it. ESP size features ARE extracted correctly
(`n_esp`, per-SPI discipline intact); the model outvotes them on
ancillary duration/count features.
(b) `traffic_type` confident WhatsApp errors (DEV: 5 files, conf
0.52–0.58): real 45 s mixes (web objects, ICMP) land in the synthetic
whatsapp pocket (small bidirectional + sparse large blobs) with
uncalibrated confidence above the 0.5 abstention line.
(c) `enc_alg` CBC always AES-128: AES-128-CBC vs AES-256-CBC are
wire-identical in ESP size structure — verified byte-identical means
and mod16 histograms on our own v1/v2 same-traffic pairs (both 232.0 /
[(399, 8)] for voip, 1373.9/1372.4 for video) — yet production calls
v1→128 @0.97 and v2→256 @0.86. With no size-structure signal, the
distinction rides traffic/timing realizations that do not transfer
(seeds differ per variant), so off-distribution the model falls back
to the majority class (DEV: 25 wrong, all →128; TEST holds the rest).

### Fixes (engine only; models, rubric, API untouched)

- Invariant (no calibration needed): detected IPsec can never be
  plain/none — a model vote for `none` on a detected capture becomes
  NOT_OBSERVED with a reason. Property-tested over the whole corpus.
- Framing (verified, not assumed): ESP-in-UDP/4500 (marker/keepalive
  rules unchanged) and IPv6 produce byte-identical ESP size/flow
  features to native ESP (synthetic fixture tests, exact equality).
- OOD gate for INFERRED fields (mode, enc/keylen/auth, pfs, traffic):
  abstain iff the capture trips ≥ 5 training-range checks (1st/99th
  percentiles over the validated envelope: 414 synthetic + 66 real
  training features, `engine/models/feature_ranges.json`, regenerated
  by train, never external) AND confidence is below 0.6 (margin 0.1).
  Abstention is explicit UNKNOWN + reason
  ("capture outside the training distribution: …") with resolve-by;
  the control becomes UNKNOWN, never PASS/FAIL; confidence is never
  lowered quietly. Either signal alone never abstains (tails overlap
  the envelope; low confidence alone is calibrated risk).
- No retraining on external data, ever. `train.py` only additionally
  writes the ranges file; all model weight files are byte-identical
  before/after (verified by md5).

### Calibration (false-abstain ≤ 2% budget)

Joint offline measurement (correctness × confidence × violations):
K=5/floor=0.6 gives 0/2232 (0.0000) on synthetic folds-proxy and 2/242
(0.0083) on real — inside budget with headroom (tighter floors and
lower counts either miss DEV errors or break the real budget; looser
settings add nothing on DEV). True fold rate comes from the §7
evaluation re-run below.

### DEV results (v1.2.7 frozen rule, 108 files, committed script)

0 parse errors, 0 no-IPsec, 108/108 WITHHELD (coverage-driven, as
designed — every capture lacks lifetimes/replay/DH evidence).

| field | n | accuracy | coverage | acc-when-answered |
|---|---|---|---|---|
| ike_version | 108 | 0.028 | 0.028 | 1.000 (3/3 handshake sessions) |
| mode | 108 | 0.009 | 0.028 | 0.333 |
| enc_alg | 108 | 0.398 | 0.398 | 1.000 (43/43 kept answers correct) |
| enc_key_len | 108 | 0.509 | 0.611 | 0.833 |
| auth_alg | 72 | 0.944 | 0.944 | 1.000 (68/68 kept answers correct) |
| dh_group | 72 | 0.000 | 0.000 | — (abstain by design) |
| pfs | 108 | 0.000 | 0.000 | — (no rekeys on the wire) |
| ip_version | 108 | 1.000 | 1.000 | 1.000 |
| nat_t | 108 | 1.000 | 1.000 | 1.000 |
| traffic_type | 75 | 0.000 | 0.053 | 0.000 (4 kept whatsapp errors) |

The invariant converted all 105 former `none` mode votes to
NOT_OBSERVED; residual confident errors (2 mode, 11 keylen, 4 traffic)
live in the low-violation, moderate-confidence band where our own
correct answers live — no unsupervised rule separates them; stated as
the method's boundary, not tuned away.

### TEST results (one shot, frozen code, 72 files)

Run window 2026-10-04T11:48:10Z → 11:50:14Z, rc=0, code frozen since
the DEV measurement (only docs/frontend changed after — no engine
touches). 0 parse errors, 0 no-IPsec, 72/72 WITHHELD, hash overlap 0.

| field | n | v1.2.6 acc / cov / awa | v1.2.7 acc / cov / awa |
|---|---|---|---|
| ike_version | 72 | 0.028 / 0.028 / 1.000 | 0.028 / 0.028 / 1.000 |
| mode | 72 | 0.014 / 1.000 / 0.014 | 0.014 / 0.028 / 0.500 |
| enc_alg | 72 | 0.111 / 0.472 / 0.235 | 0.042 / 0.347 / 0.120 |
| enc_key_len | 72 | 0.208 / 0.625 / 0.333 | 0.153 / 0.472 / 0.324 |
| auth_alg | 72 | 0.861 / 0.903 / 0.954 | 0.861 / 0.889 / 0.969 |
| dh_group | 72 | 0 / 0 / — | 0 / 0 / — |
| pfs | 72 | 0 / 0 / — | 0 / 0 / — |
| ip_version | 72 | 1.000 / 1.000 / 1.000 | unchanged |
| nat_t | 72 | 1.000 / 1.000 / 1.000 | unchanged |
| traffic_type | 50 | 0.000 / 0.200 / 0.000 | 0.000 / 0.160 / 0.000 |

Reading: accuracy (unknown = error) falls wherever correct answers
abstain — the gate trades accuracy for honesty. What improves is the
error TYPE: TEST confident-wrong counts fall from 71 mode + 26 enc +
30 keylen + 10 traffic (v1.2.6) to 1 + 22 + 23 + 8 (v1.2.7); the rest
become explicit UNKNOWNs with reasons instead of confident votes.
Residual confident errors sit in the low-violation, moderate-confidence
band (§6 calibration) — stated, not tuned away.

### DEV side-by-side (calibration split, not clean)

| field | v1.2.6 acc / cov / awa | v1.2.7 acc / cov / awa |
|---|---|---|
| ike_version | 0.028 / 0.028 / 1.000 | unchanged |
| mode | 0.009 / 1.000 / 0.009 | 0.009 / 0.028 / 0.333 |
| enc_alg | 0.463 / 0.463 / 1.000 | 0.398 / 0.398 / 1.000 |
| enc_key_len | 0.574 / 0.676 / 0.849 | 0.509 / 0.611 / 0.833 |
| auth_alg | 0.958 / 0.958 / 1.000 | 0.944 / 0.944 / 1.000 |
| traffic_type | 0.000 / 0.067 / 0.000 | 0.000 / 0.053 / 0.000 |

DEV accuracy drops are expected (7 correct enc answers and similar
converted to abstentions on the calibration split — the price of the
gate, inside the false-abstain budget below).

### False-abstain rate on our own corpora (final code)

Grouped-CV folds (414 rows, fold-specific ranges): 0 converted answers.
Real rows: 4 correct answers converted (synth→real mode/auth ×2,
holdout enc/keylen ×2) of ~490 inferred answers on 96 real captures
(≈0.8%). Synthetic folds-proxy: 0/2232. All inside the 2% budget.
Per field: the 4 conversions are mode/enc/keylen/auth singletons on
long/TCP real captures, each listed with its violated checks in the
evaluation log. Our oracle tables are untouched (label inputs, no gate
path) and live scores are byte-identical (v1 89 @ 0.6684, v19 72,
v21 80 — verified post-change).

### False-abstain on our own corpora (final code)

(from the §7 evaluation re-run: grouped-CV folds + real holdout —
numbers go here.)

### Limitations (updated)

Different generator, config-declared labels assumed correct (spot
checks), no handshakes in known captures, forced (not real) NAT-T,
45 s vs 8 s capture scales. After v1.2.6 the external set is no longer
untouched: DEV was used for diagnosis/calibration, so only TEST is a
clean measurement — and TEST was run exactly once
(results/external-eval-test.json; DEV in results/external-eval-dev.json;
v1.2.6 full-corpus numbers stay in results/external-eval.json).
Residual confident errors persist in the low-violation,
moderate-confidence band.

## 4. Honesty

This is out-of-distribution transfer: a different generator (real
strongSwan hosts, 45 s captures, no handshakes in known captures,
SHA384/DH15 suites we never emit). Our own synthetic-to-real number is
0.7121 for encryption (synth→real, N=66): same metric definition
(unknown = error), different target distribution. Weak results below
are reported as weak; no field is cherry-picked (unmappable fields are
listed in §1 with counts, not silently dropped from denominators —
every exclusion is explicit).

Limitations: their known captures contain no IKE (BPF), so every
IKE-scoped verdict is NOT_OBSERVED by construction; PFS needs a rekey
the captures do not show; traffic classes file_transfer/messaging have
no counterpart in our schema; HMAC-SHA384 and DH15 rows are unscored
for those fields; 45 s captures vs our 8 s training changes timing
features; their labels are config-declared (assumed correct, spot
checks only).

## 5. Reproduce

```bash
git clone https://github.com/naman9271/ipsec-pcap-lab ~/.tmp-work/ipsec-pcap-lab
cd ~/.tmp-work/ipsec-pcap-lab && git checkout c0cf25647b88c1cdb0649a43049e192e269f4cc6
cd ~/Projects/ipsec-sentinel && .venv/bin/python scripts/eval_external.py --their-root ~/.tmp-work/ipsec-pcap-lab
```

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

Run: one-shot, frozen models, `--include-protocol-sessions` (180 files:
175 train_known + 5 protocol_validation). 0 parse errors, 0 no-IPsec
(all captures contain ESP), **180/180 WITHHELD** (dh/lifetime/replay
unobserved everywhere — expected, counted not dropped). Hash overlap
with our 480-file corpus: **0**. Their repo publishes no numbers, so
there is no side-by-side table: the figures below come from our frozen
pipeline on their frozen commit, not from any held-out split of theirs.

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

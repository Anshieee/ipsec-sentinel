# DECISIONS

Environment facts and decisions with reasons. Append; never rewrite history.

## D1 — Environment inventory (2026-09-30, verified by execution)

| Capability | Status | Evidence |
|---|---|---|
| OS | CachyOS (Linux 6.18.52-1-cachyos-lts) | `uname -sr`, /etc/os-release |
| Root / sudo | ❌ password required, `sudo -n true` fails | shell test |
| Docker | ✅ daemon running, user in `docker` group | `docker info` OK |
| Python | system 3.14.7; venv uses **3.12.13** (uv-managed) | `uv venv` |
| pip in venv | ❌ not seeded by uv → use `uv pip install --python .venv/bin/python` | `.venv/bin/pip` missing |
| PEP 668 | system pip refuses installs → venv mandatory | pip error observed |
| scapy | ✅ 2.7.0 (venv) | smoke import |
| tcpdump / ffmpeg / git / node | ✅ present | `command -v` |
| tshark / dumpcap | ❌ missing; pacman install blocked (no root) | `command -v`, pacman needs sudo |
| strongSwan host | ❌ missing (pacman has 6.1.0 but needs root) | `command -v`, `pacman -Si` |
| strongSwan image | ✅ `testbed-strongswan:latest` exists from prior attempt | `docker images` |
| Kernel IPsec | ✅ `xfrm_user`, `xfrm_algo`, `nf_tables` modules loaded | `lsmod` |
| `ip xfrm state` as user | ❌ Operation not permitted (needs root) | shell test |
| Playwright CLI | ✅ present; browsers not yet downloaded (user-local OK) | `command -v`, empty cache |
| Xvfb | ❌ missing | `command -v` |
| Hardware | 2 CPUs, 15 GiB RAM (~4 GiB free), 419 GiB free disk | `nproc`, `free`, `df` |
| Network | PyPI reachable (HTTP 200) | curl |

**Decision:** all Python deps in `.venv` via uv, pinned in `requirements.txt` +
`requirements.lock.txt`. Verified: full smoke import + WeasyPrint PDF render (`rc=0`).

## D2 — Reuse of prior attempt at `/home/ansh/Projects/sih-2/ipsec-analysis`

**Decision (user-confirmed):** copy reusable files in, verify everything.

Copied: testbed DESIGN.md, variants v1..v6 configs (swanctl + legacy ipsec.conf),
Dockerfile.strongswan, docker-compose.yml, entrypoint, scripts/, traffic generators,
capture/{synth_pcap.py, validate_pcap.py, run_matrix.py, label.py, aggregate.py,
capture.py, capture.sh, features.py, README.md}, docs/review/*, docs/design/*.

NOT copied: `.supervisor/` orchestration state, empty engine//tests/, stale
manifest (schema too narrow — missing esp_packets, ike_packets, run_id, duration),
README claims, `__pycache__`.

**Not touched:** the `sih-2` repo itself; its running containers (shared Docker
state — do not remove without asking).

## D3 — Real-capture testbed approach: NET_ADMIN container, not host netns

**Reason:** host `ip netns` needs root (unavailable). Prior attempt's documented
blocker was Docker *bridge multi-subnet* limitation (docs/review/testbed-known-issues.md)
— irrelevant if the whole client-a—gw-a—gw-b—client-b topology lives as netns+veth
*inside one NET_ADMIN container*.

**Fallback (spec-mandated, time-boxed):** if SAs cannot ESTABLISH in reasonable
time → document precisely in `docs/review/testbed-known-issues.md`, proceed
synthetic-only, label dataset honestly.

## D4 — Validation without tshark

Spec allows: `tcpdump -nn -vvv -r` + independent Scapy/dpkt parsing.
**Decision:** dual-parser validation (scapy + dpkt) with tcpdump cross-check.
No tshark dependency.

## D5 — Anti-leakage is a release gate

Prior attempt's own dataset-review found: identical PSK across variants
(BLOCKER L2), filename-embedded labels (L1), fixed source IPs/ports (L3).
**Decision:** generator must randomize SPIs, addresses within subnets, non-IKE
ports, start times, per-run seeds; no incidental field may identify a variant;
filename/manifest columns never enter feature vectors. Audited before any
training run.

## D6 — Evaluation methodology (spec-mandated)

Grouped splits **by capture run** (never packets from one run across train/test);
per-field metrics; ablations; any near-perfect score = suspected leakage until
proven otherwise; synthetic-only evaluation stated plainly for what it does and
does not prove.

## D7 — Copied assets: verification verdicts (M0, executed)

- `synth_pcap.py` runs in this repo (path bug fixed): 114 pcaps in 3.3 s, manifest written. **But** its IKE handshake is random bytes on UDP/500 and ESP structure is not spec-conformant → must be rewritten to spec in M2 (real IKEv2 header, SA proposal with true transform IDs, KE length per DH group, CREATE_CHILD_SA rekey iff PFS, ESP CBC/GCM trailer structure, tunnel/transport header layout).
- `validate_pcap.py` runs (114/114) but **negative-tested as a rubber stamp**: synthetic files with no ESP and no IKE still pass (`valid=True`; missing IPsec is only a warning). M2 must harden: per-spec checks (IKE_SA_INIT/IKE_AUTH presence, transform IDs vs label, KE lengths, rekey, ESP structure, header layout, AH presence, negatives contain NO IPsec, counts match) with missing-mandatory-structure = error.
- Variant configs v1–v6 match the spec baseline; weak-coverage rows (DH2/DH5, SHA1, 3DES, IKEv1 MM, lifetime extremes, replay off, ESN, NAT-T, AH) are M1 work; unique PSKs already fixed; legacy ipsec.conf only for v1.
- Rule learned: **never trust a validator's pass count without negative-testing it first.**

## D8 — M1 variant matrix design (2026-09-30)

**Decision:** 18 variants in `testbed/matrix.py` as the single source of
truth; all configs/labels generated by `testbed/gen_configs.py`.

- v1–v6 = spec example baselines verbatim; v7–v18 each differ from the
  v1 baseline in **one** parameter family (AH, DH2, DH5, SHA1, 3DES,
  IKEv1 MM, short/long lifetimes, replay off, ESN on, ESN off explicit,
  NAT-T) → attribution in M3 is possible (one-factor diffs).
- **IKE suite mirrors the CHILD suite** (except v7/AH, whose CHILD has no
  cipher → IKE keeps the v1 suite) so labels like `encryption=3des-cbc`
  describe both phases unambiguously.
- **Endpoints = gw↔gw transit addresses for every variant**
  (10.30.0.10↔10.30.0.20, fd00:ff::1↔::2): visible addressing is then
  identical across modes/variants (no address-based label leakage), and
  one capture point on the transit link sees all IPsec traffic.
- PFS expressed only as a DH token in `esp_proposals`/`ah_proposals`
  (`pfs=` is a no-op in both formats — verified in source + load tests).
- ESN via `-esn`/`-noesn` tokens (v16/v17 explicit; default verified =
  noesn). Replay via `replay_window` (32; v15=0).

## D9 — Transport-mode addressing: gateway endpoints with host selectors

**Decision:** transport variants use the gateway-owned transit addresses
as BOTH IKE endpoints and traffic selectors (`/32`, `/128`).

**Evidence (2026-09-30, two-charon probe + strongSwan 5.9.1 source):**
transport + subnet TS fails with `TS_UNACCEPT` /
`no acceptable traffic selectors found`; source shows why:
`child_cfg.c:284` derives transport TS from the IKE endpoint hosts when
proposing, and `child_create.c:check_mode()` requires `ts_list_is_host()`
(host-to-host) unless proxy mode. Transport + host TS = CHILD INSTALLED,
tcpdump showed `192.168.77.10 > 192.168.77.20: ESP(...)` with no inner
header. A gateway charon *cannot* protect client↔client flows in
transport mode (would require owning the client addresses).
**This supersedes** the claim in `docs/review/testbed-review.md` that
transport mode should use `local_addrs = 10.1.0.10` (client endpoints) —
that contradicts both the source and the empirical result.

## D10 — M1 validation gates and the starter rc trap

**Decision:** `testbed/validate_configs.py` gates M1 (exit 0 only if all
checks pass; currently 1437/1437):

- Gate A: every swanctl file must load into a live charon
  (`swanctl --load-conns` + `--load-creds`), checking rc **and** output
  text (unknown keys discard the connection: rc≠0, `config discarded`).
- Gate B: legacy `ipsec.conf` → `starter --conftest`, grepping stdout
  for `parsing error`, because **starter exits rc=0 even for unknown
  keywords** (documented trap, proven by a negative control).
- Negative controls are part of the gate: deliberately broken files must
  be rejected, otherwise the gate itself fails. Schema-invalid labels
  must fail validation too.

## D11 — M1 empirical findings that constrain M2 (all executed)

- **Variant switching:** `swanctl --load-conns` replacement does NOT
  update children referenced by an already-established IKE_SA
  (responder matched the stale child proposal → NO_PROPOSAL_CHOSEN).
  Switching variants must terminate the IKE_SA / restart charon
  (encoded in `switch-variant.sh`).
- **IKEv2 PFS timing:** the initial CHILD_SA (IKE_AUTH) never carries a
  KE payload even with PFS on; PFS DH happens at CREATE_CHILD_SA rekey.
  IKEv1 does KE in the first quick mode. Synthetic generator + feature
  extraction must model this asymmetry.
- **ESN needs `replay_window != 0`**: kernel_netlink only sets
  `XFRM_STATE_ESN` inside `if (data->replay_window != 0 && (esn ||
  window > 32))`. v16 (esn + window 32) shows the `esn` flag; esn +
  window 0 silently has no ESN. `ip xfrm state` prints
  `replay-window 0` for ESN states (window lives in the ESN bitmap
  attr) — cosmetic.
- **AH** establishes as proto 51 with the inner IP header **in
  cleartext** (tcpdump: `AH(...): IP 10.1.0.10 > 10.2.0.10: ICMP ...`).
- **Weak algorithms** (3DES+SHA1+modp1024) establish on this build;
  NAT-T (`encap=yes`) puts ESP in UDP/4500; IKEv1 main mode establishes.
- **charon stdout logging is block-buffered** when redirected to a file
  (log ends mid-line) — don't diagnose from a truncated tail; generate
  more log output first.
- **vimagick image entrypoint hijacks `command:`** (compose now uses
  `entrypoint:` override); charon binary is `/usr/lib/strongswan/charon`;
  container `/proc/sys` is read-only (use compose `sysctls:`), and the
  image has busybox `ping` but no `tcpdump` (use
  `docker run --network container:<gw> corfr/tcpdump` instead).
- **Compose lab was structurally broken** (two isolated bridges, capture
  on a network nothing else joined, hardcoded `VARIANT=v1`): rebuilt in
  M1 with a shared transit net 10.30.0.0/24, static addressing matching
  `matrix.py`, `${VARIANT:-v1}` interpolation, entrypoint override —
  validated by `docker compose config -q` only; real run is M2 work.

## D13 — Synthetic wire formats (verified vs real captures + swanctl src)
- IKEv2 payload numbers: SA=33 KE=34 IDi=35 Nonce=40 Notify=41 SK=46
  (strongSwan `payload.h`; RFC 7296 has AUTH=39, no HASH/SIG). Header
  ver=0x20; req flags=0x08, resp=0x20; exch 34/35/36; msgid 0/1/2.
- Proposal: `[next=0 res len prop#=1 proto spisz ntr]`; transform
  `[next res len type res id]` + TV attrs, next=3 non-last / 0 last.
  Order ENCR,INTEG,PRF,DH (no INTEG for AEAD). IDs: ENCR 3/12/20,
  PRF 5/6, INTEG 2/12, DH 2/5/14/19/20; keylen attr type 14.
- KE pub lens: modp1024=128, modp1536=192, modp2048=256, ecp256=64,
  ecp384=96. Nonce 32 B. IKE notifies omitted for ALL variants.
- ESP CBC pads to block (16 AES / 8 3DES) incl. padlen+nh trailer;
  GCM pads to **4** (proven by icmp-1400: 1430→1432, not 1440).
  ICV16 sha256 / ICV12 sha1; GCM tag16, AAD=SPI|Seq.
- AH (tunnel v4): nh=4, len_field=5, ICV=16 (HMAC-SHA256-128; the
  `(len-2)*4` formula is wrong, correct is `(len+2)*4-12`).
- IKEv1 SA payload = generic + DOI=1 + Situation=1 + proposal;
  transform = tnum/tid/res2 + TV attrs (ENCR_AES=7, HASH sha256=4,
  GROUP=dh, AUTH PSK=1, LIFE sec + duration=1.1x rekey).
  NAT-D = payload type 20 with 32 B hash. Vendor-ID bytes copied verbatim.
- Synthetic ESP/AH keys are deterministic
  (`SHA256("synth-ipsec-v1"|variant|run|traffic|spi|usage)`) so the
  validator decrypts and verifies layout/padding/ICV; IKE SK keys are
  per-pcap random. Declared in the datasheet, not a leak (ciphertext).
- Real captures: outer-IP fragmentation happens (v18 icmp 1400-ping:
  first frag present, tail lost) and single adjacent ESP seq
  transpositions occur (capture reorder, no loss) — validator reassembles
  what exists, tolerates incomplete datagrams as noted loss, and requires
  contiguous (not strictly monotonic) seq sets for real rows.

## D14 — ICMPv6 echo types + inner checksums
- Synthetic ICMPv6 uses types 128/129 (was: v4 types 8/0 — caught by
  tcpdump triple-parse; v6 large-ping capped 1400→1340 and TCP/UDP chunks
  capped per variant so outer ESP stays ≤1500 B — real v4 captures never
  exceed 1500 except v18 ESP-in-UDP 1400-pings, which fragment and are
  handled by validator reassembly).
- Tunnel-inner L4 checksums are computed against inner endpoints
  (transport/plain always were); validator checks ICMP types per family.

## D15 — Anti-leakage: shared per-run topology + stratified audit
- The first audit correctly flagged per-(variant,run) addresses: each
  address value identified one variant to a corpus-memorizing classifier.
  Fix: topology (addresses/MACs) is randomized per run and SHARED across
  variants within a run (spec wording is "per run"). SPIs, IKE cookies,
  ports, start times stay per-pcap. Grouped-by-run splits (D6) remain the
  primary defense; sharing removes even ungrouped memorization signal.
- Plain negatives use transit-link addresses (unencrypted gw-to-gw
  traffic): LAN addresses on the wire previously identified `plain`.
- Audit gate (`capture/audit_leakage.py`): permutation MI *stratified by
  family x plain-status* (Fisher-combined, p > 0.01) + leave-one-run-out
  exact-match accuracy (< 0.20, chance ~0.10) + SPI uniqueness +
  within-stratum single-variant-value check. Inter-stratum association
  (e.g. v6-run addresses, empty plain SPI tuples) is label-legitimate
  signal, not leakage.

## D16 — Presence markers are legitimate signal, not leakage
- Audit MI flagged SPIs (p=0.031) via the *empty* SPI tuple shared by all
  18 v7 (AH, no ESP) pcaps. "Has ESP / has AH / has IKE" is a declared M3
  classification target (spec: "counts and presence of IKE/ESP/AH/NAT-T"),
  so presence markers are excluded from the incidental set; the gate
  tests variant identification *beyond* the labels. Same logic already
  covered plain (empty tuples in its own stratum).

## D17 — Scope change: frontend out of scope, API contract in
- Dashboard/UI (Streamlit pages, screenshots/polish, dashboard demo
  video) is built by someone else — removed from M4/M5.
- Replacement deliverables (same quality bar): frozen API contract
  (`docs/api-contract.md` + exported `openapi.json` + per-endpoint
  example JSON in `docs/examples/`), CORS for local dev origins, mock
  mode (`serve --mock`) with deterministic samples, extra demo-data
  endpoints (`GET /variants`, `GET /datasets/samples`), and a CLI+API
  terminal-walkthrough demo (`demo/DEMO_SCRIPT.md` + recording if
  tooling allows). Everything else unchanged.

## D18 — Test/generator concurrency incident (recovered, tests hardened)
- pytest `test_no_labels` (moves `data/labels` aside) raced a background
  validator `--self-test` (recreates `data/labels/synth` mirrors); the
  move-back nested the tree (`labels/.labels-hidden/`). Recovered by
  merging back; verified 402 labels + all manifest rows resolve.
- Rule: never run mutating tests concurrently with generators. Tests now
  use pid-unique hide-dirs with merge restore (`copytree dirs_exist_ok`)
  so even a race cannot nest or lose data.

## D19 — Real CREATE_CHILD_SA is fully encrypted (PFS unparseable live)
- strongSwan `message.c` create_child_sa_{i,r}_rules mark EVERY payload
  (SA/Nonce/KE/TS) encr=TRUE; wire confirms SK-only rekeys (exch 36,
  single SK, e.g. len 480). The M2 spec line 55 mental model (clear KE
  iff PFS) describes the synthetic generator only.
- Consequences: PFS stays `unknown` for ALL real rows (even forced-rekey
  runs); the validator verifies rekey *content* only with a clear SA and
  notes opaque rekeys without failing; synthetic rekeys keep clear
  SA/KE per the spec letter (documented deviation in the datasheet);
  forced rekeys still prove rekey *presence* on real wire (v1/v3/v5/v7
  exch-36 pairs, v18 marked pair, v12 second QM).

## D20 — Independent-review fix round: determinism streams + SK-only final
- Generator RNG split into ike|data streams (`_seed(...|ike|data)`):
  IKE edits can never reshuffle traffic timing/counts again. The 407 vs
  405 sighting was a code-version artifact (shared stream), not
  nondeterminism — same code+seed regenerates byte-for-byte (tested).
- Synthetic rekeys are SK-only with deterministic IKE keys (validator
  decrypts AUTH+rekey inners and verifies SA/KE/TS); PFS is a
  rekey-length model gated on rekey presence (never coin-flips).
- Secrets: legacy ipsec.secrets deleted from tree (history kept),
  swanctl.conf carries REDACTED placeholders, `gen_secrets.py` fills at
  deploy (netns-up hook, container-verified); validate_configs gates
  the generator + asserts no psk-* in tracked testbed/ files.
- Live vs oracle: live = oracle − 15 (lifetimes/replay unobservable),
  v12 − 25 (+PFS unknown); pinned in test_live_scores (21 samples).

## D21 — v1.1 correctness release: prompt-vs-repo contradictions (2026-10-03)

The task prompt says `docs/DECISIONS.md`; the repo keeps `DECISIONS.md`
at root — appending here (code reality wins).

- Baseline expectation in the prompt (`pytest engine/tests`: 30 passed,
  2 skipped, skips = real-data tests without tarball) does not match
  this checkout: `data/real/` IS present (6 variants, 66 pcaps), so the
  real-data tests run. Observed baseline: **33 passed, 0 skipped**.
  Safest option: accept the greener baseline, no reinstall.
- Prompt SETUP says recreate `.venv` via `python -m venv` + `pip install`.
  This repo's venv is uv-managed (no seeded pip; AGENTS.md D1) and green,
  and `.venv/bin/python` is 3.14 (AGENTS.md D1 says 3.12.13 — env drift,
  harmless: tests pass). Recreating risks breaking a green tree, so:
  verify only, no venv rebuild. `pip install -e .` state verified via
  `ipsec-analyze --help` working from `.venv/bin`.
- `/tmp` at 1% — big jobs stay in place, no `~/.tmp-work` redirect needed.
- `git status` clean, tag `v1.0` present; `v1.0` will not be moved.
- Label semantics decision (new in v1.1): legacy label keys
  (`encryption`/`auth`/`dh_group`) describe the CHILD suite (what ESP
  carries and what the size model predicts). New keys `ike_encryption` /
  `ike_auth` / `ike_dh_group` describe the IKE SA. For the 18 mirrored
  variants both are identical; v19/v20 (mismatch) differ; v7 (AH) keeps
  the v1-baseline IKE suite. Child enc/auth are NEVER parsed from
  IKE_SA_INIT — with SK-only rekeys they are model-INFERRED or UNKNOWN.
- Child crypto models (enc/auth/keylen) train and predict on the ESP-only
  feature view (IKE proposal bytes excluded): with mirrored suites in the
  corpus, IKE-proposal features would teach the model the very mirroring
  assumption v1.1 removes. Presence/count features (n_ike, has_rekey,
  rk lengths as PFS gate) are kept. No architecture change (RF, seed 7).
- Assessment v1.1: per-control PASS|FAIL|UNKNOWN|NOT_APPLICABLE with rule
  id + rule version + evidence + explanation; posture_score over evaluated
  controls only; coverage = applicability-weighted share with evidence;
  WITHHELD below 0.5 coverage (no headline risk level, confirmed FAILs
  still listed). UNKNOWN earns no credit and no penalty. Rule version
  `1.1.0`. Weights unchanged (25/20/15/10/10/5/10/5); transport mode is
  use-case dependent (UNKNOWN/INFO, no penalty); replay window >= 32
  passes; AH cipher absence is a confirmed FAIL (no-conf, 5 pts — a VPN
  without confidentiality is a real limitation, not N/A); plain captures
  get ipsec_detected=false and NOT_APPLICABLE assessment with no IPsec
  score.

## D22 — v1.1 follow-ups found during implementation (2026-10-03)

- Live DH2/DH5 went silent (child PFS group honestly UNKNOWN live, so
  posture matched the baseline). An OBSERVED weak group on the IKE SA is
  a confirmed fact, so the ike-version control now FAILs (2/10) with a
  `weak-ike-dh` critical finding when the IKE group is 2/5 — same
  weight, no tuning; oracle v8 moves 75 -> 67 (hand-recomputed), live
  v8/v9 surface the FAIL at posture 77 vs v1 89. Justification: each SA
  is scored from its own evidence, in both directions.
- `posture_score` stays numeric when WITHHELD (it is defined over
  evaluated controls); only the *headline* (`security_score`/`risk`
  aliases... actually the same value under compat keys, plus
  `risk_level`) is nulled. Frontends must gate display on
  `score_status`, not on the presence of a number.
- Crafted merge pcaps (foreign IKE + truncated ESP stitched by hand)
  confuse the size model into abstention — expected OOD behavior, not a
  bug: the genuine generator-built mismatch variants (v19/v20,
  validator-checked) classify confidently and correctly, so regression
  tests use corpus pcaps, not hand merges.
- SPI-ambiguity rule corrected during implementation: the generator (like
  real IPsec) emits one SPI per direction, so 2 fully-overlapping SPIs
  are a NORMAL bidirectional pair (v1 email/web/whatsapp/icmp all have
  2; the first >=3 draft wrongly abstained PFS on them and collapsed CV
  pfs to 0.44). Final rule: 3+ concurrent SPIs + single rekey ->
  UNKNOWN; pairs stay attributable (real forced-rekey handoffs show 2
  SPIs with ~0.02 s gaps, never overlapping).
- Label schema gained required ike_* keys; `label_schema.json` variant
  pattern extended to v20; plain labels carry ike none/0. Validator
  INIT expectations + SK-decryption suite now use ike_* keys; child
  expectations use child keys. M1 gate re-verified 1636/1636 (ss-verify
  container restarted, pre-existing stopped container).

## D23 — v1.2 scoring corrections: why these weights, this formula (2026-10-04)

Task prompt says `docs/DECISIONS.md`; the repo keeps root `DECISIONS.md`
(D21) — appending here.

- IKE coverage gap (Part 1a): v1.1 scored only ike_sa.version/dh_group,
  so an OBSERVED 3DES/SHA1 handshake was silent. New controls ike-cipher
  (5) and ike-integrity (3), read from ike_sa only. Weights: handshake
  secrecy outweighs AUTH/PRF forgery resistance, both below the
  data-plane cipher (25) because CHILD controls already judge carried
  traffic; total 108. Data-plane weights untouched, so full-visibility
  oracles move only by the IKE terms (v1 88->88, v11 73->71, v19 73->75).
  v20 (CBC-128/SHA256/DH14) earns 4/5+3/3 with zero FAILs — stays
  acceptable, shown before/after in tests (100 @ 0.65 -> 99 @ 0.6327).
- Inferred symmetry (Part 1b): posture = 100*S(points*f)/S(weight*f),
  coverage = S(weight*f)/S(applicable weights), f = 1.0 observed/label,
  model confidence when inferred, 0 unknown. Rationale: an INFERRED PASS
  must not count as full credit (it speaks softer), and an INFERRED FAIL
  must still surface (silence would be the old confident-absence error in
  reverse) — hence LIKELY with severity capped one level, CONFIRMED kept
  for observed bytes. LIKELY is a control status (evaluated in math) and
  a finding verdict. The 0.5 WITHHELD gate is unchanged; real-v1 lands at
  0.4985 (WITHHELD) vs real-v18 0.5255 (PUBLISHED) — same variant, honest
  boundary, pinned in tests.
- PFS honesty: the control explanation now states observed (label oracle)
  vs inferred-from-rekey-length (model, group unconfirmed).

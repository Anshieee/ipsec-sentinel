# Dataset datasheet (M2)

Composition, generation, labels, splits, limitations, real vs synthetic.
Corpus: **480 pcaps** — 414 synthetic + 66 real — with per-pcap JSON labels
(`data/labels/...`) and `data/manifest.csv`
(`file,variant,traffic,ip_version,packets,esp_packets,ike_packets,source,valid`).

## Composition

| source | pcaps | variants × runs × types |
|---|---|---|
| synthetic | 414 | 21 variants × r1–r3 × 6 types (378) + plain × {v4,v6} × r1–r3 × 6 types (36) |
| real | 66 | v1 × {r1 (6 types), r2 (6), r3 (4: voip-long + extra TCP)} + v3,v5,v7,v12,v18 × {r1 (6), r2 (4: rekey + extra TCP)} |

Plain negatives are unencrypted gateway-to-gateway traffic on the transit
link (same wire addresses as transport-mode ESP): the only wire signal
for `plain` is the absence of ESP/AH/IKE, never an address.

Per-type packet counts (min/med/max) and durations (~6–9 s each):

| traffic | synthetic pkts | real pkts | synthetic dur (s) | real dur (s) |
|---|---|---|---|---|
| voip | 394/406/417 | 376/379/381 | 7.98/8.34/8.35 | 7.93/7.95/7.96 |
| video | 397/407/415 | 398/402/412 | 6.99/7.35/7.35 | 7.55/7.57/7.62 |
| web | 128/199/304 | 82/113/127 | 6.38/7.80/8.89 | 6.91/8.04/8.53 |
| email | 105/174/258 | 172/277/296 | 5.37/7.40/8.51 | 6.32/7.54/8.95 |
| whatsapp | 28/200/311 | 180/359/498 | 7.30/8.08/8.73 | 7.68/8.14/8.45 |
| icmp | 16/22/27 | 23/26/28 | 7.19/7.93/8.35 | 7.57/7.58/7.63 |

(med = median; full per-row counts in `data/manifest.csv`.)

## Generation — synthetic (`capture/synth/synth_pcap.py`, Scapy)

Single source of truth: `testbed/matrix.py` (21 variants, topology,
proposals). Per-(variant, run, traffic) seeds (`sha256("synth"|...)`).

- **IKEv2** (all but v12): UDP 500 both ports (v18: INIT on 500, AUTH +
  rekey on UDP 4500 with 4-zero NON-ESP marker). Header SPIs / ver 0x20 /
  exch 34-36 / flags 0x08 req + 0x20 resp / msgid 0-1-2. SA_INIT =
  SA (true proposal: ENCR+keylen, INTEG unless AEAD, PRF, DH) + KE
  (correct DH length: 128/192/256/64/96) + 32 B Nonce; notifies omitted
  for ALL variants. IKE_AUTH = SK (IV + AES-CBC/AES-GCM ciphertext +
  ICV, realistic 150–600 B). One CREATE_CHILD_SA rekey with KE iff PFS.
  (Deviations, verified: real strongSwan encrypts the whole CREATE_CHILD_SA
  exchange — SK-only on the wire — so unlike synthetic rekeys, real rekeys
  expose no SA/KE and PFS is not parseable from real IKE. r2/r3 runs of
  v1,v3,v5,v7,v12,v18 include a forced `swanctl --rekey`.)
- **IKEv1** (v12): MM1 (SA + 5 vendor IDs) / MM2 (SA + 4 VIDs) /
  MM3-MM4 (KE + Nonce + 2×NAT-D type 20) / MM5-MM6 (encrypted ID+HASH,
  E flag) / QM1-QM2 (encrypted HASH+SA+KE+Nonce) + QM3 (HASH-only).
  Vendor-ID bytes copied from the real capture.
- **ESP**: one SPI per direction (seq from 1, strictly increasing).
  CBC: IV16 (AES) / IV8 (3DES), pad to block with padlen+nh trailer,
  ICV = HMAC-SHA256-128 (16 B) or -96 for hmac-sha1 (12 B).
  GCM: IV8, salt4, pad to 4, AAD = SPI|Seq, tag16.
  Tunnel encrypts the full inner IP packet (nh = 4 / 41); transport
  encrypts L4 only. Outer ≤ 1500 B (TCP/UDP chunk caps per variant).
  v18 = ESP-in-UDP 4500 without marker; else IP proto 50.
- **AH** (v7): nh=4, len=5, SPI, seq, ICV16 = HMAC-SHA256-128 over
  SPI|Seq|inner (simplified coverage — NOT RFC 4302; synthetic only).
- **Keys** (deterministic so the validator can decrypt):
  `SHA256("synth-ipsec-v1"|variant|run|traffic|spi|usage)` → enc/mac/salt.
  IKE SK keys are per-pcap random (presence + length validated only).
  Ciphertext can never repeat across variants.
- **Anti-leakage**: topology (addresses/MACs) randomized per run and
  SHARED across variants within a run, so no address/MAC value can
  identify a variant even to a corpus-memorizing classifier; SPIs, IKE
  cookies, non-IKE ports, start times per-pcap with identical
  distributions across variants (audit: `capture/audit_leakage.py` —
  permutation MI + leave-one-run-out exact-match, report
  `docs/anti-leakage-audit.md`).
- **Traffic**: mirrors `testbed/traffic/live_gen.py` schedules —
  voip 160 B @20 ms; video 1200–1400 B @10 ms in 1 s bursts / 1 s idle;
  web TCP keep-alive bursts (2–5 req/resp, 2–16 kB responses); email SMTP
  with every-3rd 64–256 kB attachment; whatsapp TLS records + 100–400 kB
  blobs every 5–8 s; ICMP echo req/reply 64/512/1400 (1340 for IPv6 to
  avoid outer fragmentation). Jitter ±10–30 % per pcap. Addresses within
  subnets, non-IKE ports, MACs, start epochs randomized per run with
  identical distributions across variants (audit:
  `capture/audit_leakage.py`, report `docs/anti-leakage-audit.md`).

## Generation — real (`data/real`, 66 pcaps)

Netns-in-privileged-container testbed (decision D3): one container, 4
netns, 3 veth pairs, one charon per gateway netns, tcpdump on the transit
link (BPF `udp 500/4500, proto 50/51`), fresh bring-up per traffic type
(fresh SPIs/cookies per pcap), SAs verified ESTABLISHED/INSTALLED before
traffic. strongSwan 5.9.1, PSK auth. Scripts:
`testbed/scripts/netns-up.sh`, `netns-down.sh`, `real-run.sh`;
generators `testbed/traffic/live_gen.py`. All captures IPv4.
Labels folded in by `synth_pcap.py --ingest-real` (variant fields from
`matrix.py`, traffic/run from path, duration/count measured).

## Labels & manifest

Labels conform to `testbed/label_schema.json` (`additionalProperties:
false`; `plain` rows are all none/0/false). Manifest columns:
`file,variant,traffic,ip_version,packets,esp_packets,ike_packets,source,valid`.
`esp_packets` counts IP-proto-50 + ESP-in-UDP; `ike_packets` counts UDP
500 + UDP 4500 with NON-ESP marker. `valid` is written by
`capture/validate_pcap.py` (gate: exit 0, see `data/validation.json`).

## Splits (decision D6)

Group by **run**: synthetic `r1|r2|r3`, real `r1|r2` (7 real runs).
Never split one pcap's packets or one run across train/test. Never mix
sources in one split without declaring it — see real-vs-synthetic below.

## Limitations (honest)

- ESN, replay-window, lifetimes: not visible on the wire in an 8 s
  capture (kernel-side state). Models should report low confidence /
  `unknown` for these; the rubric uses label values.
- IKE_AUTH / Quick-Mode inner payloads are encrypted: presence + length
  validated, contents not.
- Real ESP/AH cannot be decrypted (keys unknown): validated structurally
  (SPI consistency, seq monotonicity, block alignment, IKE proposal vs
  label). Tunnel/transport layout proven only for synthetic.
- Synthetic deviations from strongSwan: no IKE notifies (all variants),
  no INFORMATIONAL DELETEs, no TCP options, no outer fragmentation,
  QM3 length 92 vs real 76 (implementation variance), IPv6 ICMP large
  size capped 1400→1340, AH ICV coverage simplified.
- Traffic is emulated (fixed profiles), not recorded user behavior.

## Real vs synthetic (declared dimension)

| aspect | real (strongSwan) | synthetic |
|---|---|---|
| IKE notifies (NAT-D etc.) | present (unconditional) | absent (all variants) |
| UDP 4500 | all post-INIT IKE floats to 4500 | only v18 (NAT-T) |
| teardown | INFORMATIONAL DELETEs | none |
| SPIs per pcap | 1 observed (one direction captured) | 1–2 (per direction used) |
| ESP keys | secret | deterministic (documented above) |
| families | IPv4 only | IPv4 + IPv6 |

M3 must run the real-vs-synthetic ablation and state plainly what
synthetic-only evaluation does and does not prove.

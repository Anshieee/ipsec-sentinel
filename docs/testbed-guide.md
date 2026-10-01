# Testbed guide

## Real captures (authoritative)

One `--privileged` Docker container (`tb-real`, image
`vimagick/strongswan:5.9.1`), 4 netns (`tb-cl-a`, `tb-gw-a`, `tb-gw-b`,
`tb-cl-b`), 3 veth pairs, one charon per gateway netns with private
`/var/run` (bind-mount) and separate vici sockets (`/tb-run/*.vici`).
Topology and addressing: `testbed/matrix.py` TOPOLOGY
(transit 10.30.0.0/24, LANs 10.1.0.0/24 + 10.2.0.0/24).

Scripts (run via `docker exec tb-real sh /tb/testbed/scripts/...`):

| Script | Purpose |
|---|---|
| `netns-up.sh <variant>` | bring-up, tcpdump on transit, initiate, ESTABLISHED/INSTALLED gate |
| `netns-down.sh` | idempotent teardown (incl. stray python3) |
| `real-run.sh <variant> <run>` | 6 traffic types, fresh bring-up each |
| `real-rekey.sh <variant> <run> [t] [dur] [at]` | long capture + forced `swanctl --rekey --child` |
| `real-tcp.sh <variant> <run>` | web/email/whatsapp captures |

Traffic: `testbed/traffic/live_gen.py serve|send` (per-run `--seed`).
Golden rules: `swanctl <cmd>` BEFORE `-u <uri>`; `STRONGSWAN_CONF` per
process; wait for pidfile release on restart; `rp_filter=0`.

## Synthetic generation

`.venv/bin/python capture/synth/synth_pcap.py` (360 pcaps, deterministic
per-(variant,run,traffic) seeds), `--ingest-real` folds `data/real`
labels + rebuilds `data/manifest.csv`. Validate with
`capture/validate_pcap.py` (gate rc=0) incl. `--self-test` (15/15).

## Key wire facts (verified, see DECISIONS D11–D14, D19)

- IKEv2 payloads: SA=33 KE=34 IDi=35 Nonce=40 Notify=41 SK=46; req 0x08,
  resp 0x20; exch 34/35/36; proposal next=3/0; ENCR 3/12/20, PRF 5/6,
  INTEG 2/12, DH 2/5/14/19/20.
- ESP CBC pads to block, GCM pads to 4; ICV16 (sha256) / ICV12 (sha1).
- AH tunnel: nh=4, len=5, ICV16.
- strongSwan encrypts the WHOLE CREATE_CHILD_SA (SK-only rekeys);
  post-INIT IKE floats to UDP 4500 on all variants; ESP-in-UDP only v18.

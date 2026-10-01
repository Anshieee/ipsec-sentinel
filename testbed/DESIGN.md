# Testbed Design — M1

Single source of truth: **`testbed/matrix.py`**. Everything under
`testbed/variants/`, `testbed/configs/`, `testbed/labels/` is generated:

```bash
.venv/bin/python testbed/gen_configs.py      # regenerate all configs + labels
.venv/bin/python testbed/validate_configs.py # verification gate (all phases)
```

Never hand-edit generated files — edit `matrix.py` (or this document) and
regenerate. The gate must stay green (currently **1437/1437 checks**).

---

## 1. Topology and addressing

Two gateways run strongSwan charon; client endpoints sit behind them; a
capture runs on the gw↔gw transit link (the point every IPsec packet
crosses).

```
 client-a ── LAN-A ── gw-a ══ transit (capture here) ══ gw-b ── LAN-B ── client-b
 10.1.0.10       10.1.0.1   10.30.0.10  10.30.0.0/24  10.2.0.1  10.2.0.10
 fd00:1::10        fd00:1::1  fd00:ff::1  fd00:ff::/64  fd00:2::1 fd00:2::10
```

| Network | IPv4 | IPv6 | Purpose |
|---|---|---|---|
| LAN-A | `10.1.0.0/24` (gw `10.1.0.1`, client `10.1.0.10`) | `fd00:1::/64` (`::1`, `::10`) | protected traffic behind gw-a |
| LAN-B | `10.2.0.0/24` (gw `10.2.0.1`, client `10.2.0.10`) | `fd00:2::/64` (`::1`, `::10`) | protected traffic behind gw-b |
| Transit | `10.30.0.0/24` (gw-a `10.30.0.10`, gw-b `10.30.0.20`) | `fd00:ff::/64` (`::1`, `::2`) | gw↔gw link: **IKE + ESP endpoints, capture point** |

**All variants use the transit-link addresses as IKE/ESP endpoints.**
This makes the visible outer addressing *identical across every variant*
(addresses carry zero variant information → no address-based label
leakage; per-run address randomisation is a separate M2 anti-leakage
rule), and it keeps capture simple: one tcpdump on the transit link sees
IKE (UDP 500/4500), ESP (proto 50) and AH (proto 51) for every variant.

Transport realisation (decision D3): the canonical testbed runs the whole
netns+veth topology inside one `NET_ADMIN` Docker container (host
`ip netns` needs root). The Docker-compose two-container layout in this
directory uses the same addressing and is the fallback path. Traffic
routes (see `scripts/entrypoint.sh`): each gw routes the *peer's* LAN
via the peer's transit address.

## 2. Variant matrix (18 variants, spec minimum 15)

Derived from `matrix.py`; regenerate the table with
`.venv/bin/python testbed/matrix.py`.

| id | mode | ip | proto | IKE | cipher | auth | DH | PFS | esn | replay | NAT-T | IKE/CHILD rekey (s) | one-line |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| v1 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | – | 32 | – | 14400/3600 | **baseline** |
| v2 | tunnel | 4 | esp | 2 | aes-256-cbc | hmac-sha256 | 20 | ✓ | – | 32 | – | 14400/3600 | AES-256 + DH20 |
| v3 | tunnel | 4 | esp | 2 | aes-128-gcm | aead | 14 | – | – | 32 | – | 14400/3600 | AEAD, PFS off |
| v4 | tunnel | 6 | esp | 2 | aes-256-gcm | aead | 20 | ✓ | – | 32 | – | 14400/3600 | IPv6 |
| v5 | transport | 4 | esp | 2 | aes-256-gcm | aead | 19 | ✓ | – | 32 | – | 14400/3600 | transport, ECP256 |
| v6 | transport | 6 | esp | 2 | aes-256-cbc | hmac-sha256 | 14 | – | – | 32 | – | 14400/3600 | transport + IPv6 |
| v7 | tunnel | 4 | **ah** | 2 | none | hmac-sha256 | 14 | ✓ | – | 32 | – | 14400/3600 | AH only (no encryption) |
| v8 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | **2** | ✓ | – | 32 | – | 14400/3600 | weak DH (1024-bit) |
| v9 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | **5** | ✓ | – | 32 | – | 14400/3600 | weak DH (1536-bit) |
| v10 | tunnel | 4 | esp | 2 | aes-128-cbc | **hmac-sha1** | 14 | ✓ | – | 32 | – | 14400/3600 | SHA1 integrity |
| v11 | tunnel | 4 | esp | 2 | **3des-cbc** | hmac-sha256 | 14 | ✓ | – | 32 | – | 14400/3600 | 3DES (168-bit) |
| v12 | tunnel | 4 | esp | **1** | aes-128-cbc | hmac-sha256 | 14 | ✓ | – | 32 | – | 14400/3600 | IKEv1 main mode |
| v13 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | – | 32 | – | **600/300** | short lifetimes |
| v14 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | – | 32 | – | **86400/43200** | long lifetimes |
| v15 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | – | **0** | – | 14400/3600 | replay off |
| v16 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | **on** | 32 | – | 14400/3600 | ESN on |
| v17 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | off | 32 | – | 14400/3600 | ESN off made explicit |
| v18 | tunnel | 4 | esp | 2 | aes-128-cbc | hmac-sha256 | 14 | ✓ | – | 32 | **yes** | 14400/3600 | NAT-T (ESP-in-UDP) |

Design principles:

1. **One-factor diffs.** v7–v18 each differ from the v1 baseline in
   exactly one parameter family (v12 changes IKE version, which includes
   `aggressive=no`; v17 differs only by an explicit `-noesn` token).
   v1–v6 are the spec's example baselines.
2. **IKE suite mirrors the CHILD suite** (so a label such as
   `encryption=3des-cbc` describes both phases without ambiguity), except
   v7 whose CHILD has no cipher — its IKE SA keeps the v1 suite.
3. **PFS is a DH token in the child proposal.** `pfs = yes` is a no-op in
   *both* config formats (verified in source and empirically), so PFS on
   = `esp_proposals`/`ah_proposals`/`esp=` contains a `modp*`/`ecp*`
   group; PFS off = no group token.
4. **ESN is a proposal token**: `-esn` (v16), `-noesn` (v17), and the
   verified default = no extended sequence numbers for all others.
5. **Replay** is `replay_window` (child in swanctl, conn in
   ipsec.conf): 32 everywhere except v15 (0 = disabled, verified in
   `ip xfrm state`: `replay-window 0`).

### Proposal strings (derived)

| id | IKE proposal | CHILD proposal |
|---|---|---|
| v1, v12–v15, v17, v18 | `aes128-sha256-modp2048` | `aes128-sha256-modp2048`¹ |
| v2 | `aes256-sha256-ecp384` | `aes256-sha256-ecp384` |
| v3 | `aes128gcm16-prfsha256-modp2048` | `aes128gcm16` |
| v4 | `aes256gcm16-prfsha384-ecp384` | `aes256gcm16-ecp384` |
| v5 | `aes256gcm16-prfsha384-ecp256` | `aes256gcm16-ecp256` |
| v6 | `aes256-sha256-modp2048` | `aes256-sha256` |
| v7 | `aes128-sha256-modp2048` | `sha256-modp2048` (AH) |
| v8 | `aes128-sha256-modp1024` | `aes128-sha256-modp1024` |
| v9 | `aes128-sha256-modp1536` | `aes128-sha256-modp1536` |
| v10 | `aes128-sha1-modp2048` | `aes128-sha1-modp2048` |
| v11 | `3des-sha256-modp2048` | `3des-sha256-modp2048` |
| v16 | `aes128-sha256-modp2048` | `aes128-sha256-modp2048-esn` |

¹ v17 uses `aes128-sha256-modp2048-noesn`.

## 3. Traffic selectors: why transport uses host addresses

strongSwan derives transport-mode selectors **from the IKE endpoints**
and rejects anything that is not host-to-host:

* `src/libcharon/config/child_cfg.c:284` — when proposing,
  `mode == MODE_TRANSPORT` replaces configured TS addresses with the
  endpoint hosts;
* `src/libcharon/sa/ikev2/tasks/child_create.c` `check_mode()` —
  transport requires `ts_list_is_host()` for both selector lists unless
  proxy mode is configured.

Empirical confirmation (two charons, strongSwan 5.9.1): transport mode
with subnet TS (`10.1.0.0/24`) fails with
`received TS_UNACCEPTABLE notify, no CHILD_SA built` → responder log
`no acceptable traffic selectors found`. With host TS equal to the
gateway-owned endpoints the CHILD SA installs and ESP flows on the wire.
Therefore:

| mode | local_ts / remote_ts | protected traffic |
|---|---|---|
| tunnel | client LAN subnets (`10.1.0.0/24` ↔ `10.2.0.0/24`, IPv6 `fd00:1::/64` ↔ `fd00:2::/64`) | client↔client flows, ESP carries an inner IP header |
| transport | transit **host** addresses (`10.30.0.10/32` ↔ `10.30.0.20/32`, `fd00:ff::1/128` ↔ `fd00:ff::2/128`) | gateway↔gateway flows over the transit link, ESP has no inner header |

A gateway-owned charon *cannot* protect client↔client flows in transport
mode: that would require the charon endpoints to be the client addresses,
which the gateways do not own. This supersedes the disputed claim in
`docs/review/testbed-review.md` (source evidence + probe above).

## 4. Config artefacts and naming contracts

```
testbed/variants/<id>/gw-a/swanctl.conf    primary format (loaded by charon)
testbed/variants/<id>/gw-b/swanctl.conf      (mirrored endpoints/ids/TS)
testbed/configs/<id>/gw-a/ipsec.conf         legacy fallback format
testbed/configs/<id>/gw-a/ipsec.secrets      (same PSK both gateways)
testbed/labels/variants.json                 per-variant ground truth rows
testbed/labels/example-label.json            complete per-pcap example
testbed/label_schema.json                    JSON Schema (draft-07)
```

* Connection name = variant id (`v1`…`v18`); **child name =
  `<variant>-child`** — required by `scripts/entrypoint.sh`
  (`swanctl --initiate --child ${VARIANT}-child`).
* Unique deterministic PSK per variant (`psk-` + SHA-256 of a project
  salt + variant id); `secrets{}` uses `id-1`/`id-2` (valid **only**
  inside `secrets{}` — inside `local{}`/`remote{}` the parser discards
  the whole connection).
* Every swanctl file carries both `connections{}` and `secrets{}`;
  `swanctl --load-conns` and `--load-creds` each ignore the other
  section (verified).

swanctl syntax facts this design relies on (all verified against
strongSwan 5.9.1 — see §6): `version = 1|2` (the token `ikev2` is
rejected); every option on its own line inside `{}` (inline comma
syntax invalid); child proposals key = `esp_proposals`/`ah_proposals`
(never `proposals`); unknown keys discard the entire connection
(rc ≠ 0), so the load gate catches them; `encap = yes` is a
connection-level key (legacy: `forceencaps=yes`).

## 5. Traffic types (spec M2 set — used by M2 generators)

| type | profile |
|---|---|
| `voip` | RTP-like UDP, 20 ms interval, 160 B payload |
| `video` | bursty UDP, 1200–1400 B packets, 2 s segments |
| `web` | short TCP request/response bursts |
| `email` | SMTP/IMAP-like TCP sessions with attachment transfers |
| `whatsapp` | small bidirectional TLS-like records + sparse large media blobs |
| `icmp` | ICMP echo, 64 / 512 / 1400 B payloads |

Counts: 18 variants × ≥3 runs × 6 types + plain negatives ≥ 300 pcaps.

## 6. Validation gates (what has actually been executed)

`testbed/validate_configs.py` — exit 0 only if every check passes:

| phase | checks | how |
|---|---|---|
| 1. matrix consistency | 117 | ≥15 variants, unique PSKs, TS shapes, PFS↔DH-token, naming contract |
| 2. files ↔ matrix | 1184 | every emitted token re-derived from `matrix.py` and matched (incl. encap/forceencaps/aggressive iff the right variant) |
| 3. **Gate A** — swanctl | 72 | `docker cp` each of the 36 files into the running `ss-verify` charon → `swanctl --load-conns` **and** `--load-creds`; rc = 0 *and* `successfully loaded` *and* no `failed`/`discarded` in output |
| 4. **Gate B** — legacy | 36 | `starter --conftest --conf` per file; stdout must contain **no** `parsing error` (starter exits rc=0 even for unknown keywords — rc alone is never trusted) |
| 5. negative controls | 3 | a swanctl file with an unknown key MUST be rejected; a legacy file with an unknown keyword MUST print `parsing error` (and does so with rc=0, proving the trap) |
| 6. label schema | 25 | schema is valid draft-07; example + all 18 variant labels + a plain-negative label validate; deliberately invalid labels are rejected |

Current result: **1437/1437 passed** (`ALL CHECKS PASSED`, rc=0).

### Empirical establishment probes (two-charon lab, strongSwan 5.9.1)

Load-tested ≠ established. The following were additionally proven
end-to-end (IKE_SA + CHILD_SA installed + packets on the wire) during M1:

| mechanism | evidence |
|---|---|
| IKEv2 PSK between gateway endpoints | `ESTABLISHED, IKEv2` (vici) |
| tunnel + subnet TS | `INSTALLED, TUNNEL`; ESP length 136 with inner IP hidden |
| transport + subnet TS | ❌ rejected: `TS_UNACCEPT` / `no acceptable traffic selectors found` (⇒ §3) |
| transport + host TS | `INSTALLED, TRANSPORT`; tcpdump: `10.30… > 10.30…: ESP(...)`, no inner header (probe used an equivalent /24 transit subnet) |
| IKEv1 main mode | `initiating Main Mode IKE_SA` → `ESTABLISHED, IKEv1`; quick mode with KE (PFS) |
| NAT-T (`encap=yes`) | tcpdump: `…4500 > …4500: UDP-encap: ESP(...)` |
| AH-only child | `INSTALLED, …, AH:HMAC_SHA2_256_128`; tcpdump: `AH(spi=…): IP 10.1.0.10 > 10.2.0.10: ICMP …` — **inner header in clear** (AH never encrypts) |
| ESN on | negotiated `ESP:…/EXT_SEQ`; `ip xfrm state` shows `esn` flag — **only when `replay_window ≠ 0`** (kernel_netlink_ipsec.c sets `XFRM_STATE_ESN` inside `replay_window != 0 && (esn \|\| window > 32)`) |
| replay off | `ip xfrm state`: `replay-window 0` |
| 3DES + SHA1 + modp1024 | `IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024` established (covers v8/v10/v11 algorithms) |
| IKEv2 PFS timing | initial CHILD_SA (IKE_AUTH) never carries KE even with PFS on — PFS DH happens at CREATE_CHILD_SA rekey (IKEv1 does KE in first quick mode). M2 rekey captures must reflect this. |

## 7. Known gaps / handover to M2

* **IPv6 transport (v6)** and IPv6 in general are load-tested only;
  establishment happens in M2 (same code path as the proven IPv4 case).
* `ip xfrm state` prints `replay-window 0` for ESN states (kernel
  stores the window in the ESN bitmap attr) — cosmetic; the `esn` flag
  is the check that matters.
* **Variant switching on a live daemon:** replacing a connection with
  `swanctl --load-conns` does *not* update children referenced by an
  already-established IKE_SA (responder kept matching against the old
  child proposal in the probe). Switching variants requires terminating
  the IKE_SA (or restarting charon) — encoded in `switch-variant.sh`.
* Legacy `ipsec.conf` files are parse-gated (Gate B); runtime behaviour
  of the legacy path (e.g. `aggressive=no`, AH without `esp=`) is only
  exercised if the fallback path is needed.
* Real netns bring-up (`netns-up.sh`), capture loop, traffic generators
  and the 300-pcap campaign are M2 work items.
* `docker-compose.yml` remains a convenience/fallback lab; the M2
  canonical testbed is the NET_ADMIN netns container (D3).

## 8. Files in this directory

| file | role |
|---|---|
| `matrix.py` | **single source of truth** — variants, topology, derivations |
| `gen_configs.py` | generator for configs + labels |
| `validate_configs.py` | M1 verification gate (6 phases, negative controls) |
| `label_schema.json` | ground-truth label JSON Schema (draft-07) |
| `DESIGN.md` | this document |
| `docker-compose.yml`, `Dockerfile.strongswan`, `scripts/` | fallback lab (entrypoint loads `${VARIANT}-child`) |
| `variants/`, `configs/`, `labels/` | generated — do not edit |

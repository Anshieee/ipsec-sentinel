#!/usr/bin/env python3
"""Synthetic IPsec pcap generator (M2 spec line 55).

Builds byte-realistic IKEv2 / IKEv1 / ESP / AH exchanges with Scapy, using
``testbed/matrix.py`` as the single source of truth for variant parameters.

Wire formats were verified against real strongSwan 5.9.1 captures
(data/real/...) and the strongSwan 5.9.1 sources (see module docstring in
git history for the full empirical record):
  - IKEv2 hdr [spi_i(8) spi_r(8) np ver=0x20 exch flags msgid len];
    req flags=0x08, resp flags=0x20; exch 34/35/36.
    Payload types: SA=33, KE=34, IDi=35, Nonce=40, Notify=41, SK=46.
  - Proposal/transform encoding with next=3 non-last, 0 last; true
    transform IDs (ENCR 3/12/20, PRF 5/6, INTEG 2/12, DH 2/5/14/19/20).
  - ESP CBC: IV16 (AES) / IV8 (3DES), pad to block, padlen+nh trailer,
    ICV16 (sha256) / ICV12 (sha1). GCM: IV8, pad to 4, tag16.
  - AH: nh len=5 spi seq icv16 + inner packet.
  - NAT-T (v18): INIT on UDP 500, rest on UDP 4500 + NON-ESP marker,
    ESP-in-UDP without marker.

Deterministic ESP/AH keys: SHA256("synth-ipsec-v1"|variant|run|traffic|
spi|usage), so the validator can decrypt synthetic ESP and verify layout /
padding / ICV. IKE SK uses a per-pcap random key (presence + length only).
Declared in docs/dataset-datasheet.md.

Anti-leakage (spec line 56): per-(variant,run,traffic) seeds; SPIs,
cookies, addresses within subnets, non-IKE ports, MACs, start times all
randomized with identical distributions across variants; jitter +-10..30%.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac as hmac_mod
import ipaddress
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testbed"))
import matrix  # noqa: E402  (D8 single source of truth)

from scapy.all import Ether, IP, IPv6, UDP, TCP, ICMP, Raw, wrpcap, conf  # noqa: E402

conf.verbose = 0

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

# --------------------------------------------------------------------------
# Constants (empirically verified)
# --------------------------------------------------------------------------
# IKEv2 payload types
P_SA, P_KE, P_IDI, P_NONCE, P_NOTIFY, P_SK = 33, 34, 35, 40, 41, 46
# IKEv2 exchanges
X_INIT, X_AUTH, X_REKEY = 34, 35, 36
# IKEv2 proposal protocol IDs
PROTO_IKE, PROTO_AH, PROTO_ESP = 1, 2, 3

ENCR_ID = {"aes-128-cbc": (12, 128), "aes-256-cbc": (12, 256),
           "aes-128-gcm": (20, 128), "aes-256-gcm": (20, 256),
           "3des-cbc": (3, None)}
INTEG_ID = {"hmac-sha256": 12, "hmac-sha1": 2}
PRF_ID = {"hmac-sha256": 5, "hmac-sha1": 2,
          "aes-128-gcm": 5, "aes-256-gcm": 6}
DH_PUB_LEN = {2: 128, 5: 192, 14: 256, 19: 64, 20: 96}
BLOCK_LEN = {"aes-128-cbc": 16, "aes-256-cbc": 16, "3des-cbc": 8}
IV_LEN = {"aes-128-cbc": 16, "aes-256-cbc": 16, "3des-cbc": 8}
ENC_KEY_LEN = {"aes-128-cbc": 16, "aes-256-cbc": 32,
               "aes-128-gcm": 16, "aes-256-gcm": 32, "3des-cbc": 24}
ICV_LEN = {"hmac-sha256": 16, "hmac-sha1": 12}
IKEV1_ENCR = {"aes-128-cbc": 7, "aes-256-cbc": 7, "3des-cbc": 5}
IKEV1_HASH = {"hmac-sha256": 4, "hmac-sha1": 2}

# IKEv1 vendor-ID bodies copied from the real v12 capture (identical for the
# single IKEv1 variant; np byte set at build time).
VIDS = [bytes.fromhex("09002689dfd6b712"),
        bytes.fromhex("afcad71368a1f1c96b8696fc77570100"),
        bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d380000000"),
        bytes.fromhex("4a131c81070358455c5728f20e95452f"),
        bytes.fromhex("90cb80913ebb696e086381b5ec427b1f")]

MAX_OUTER = 1500
# NOTE: traffic order comes from matrix.TRAFFIC_TYPES (no local copy).


# --------------------------------------------------------------------------
# RNG / keys / addressing
# --------------------------------------------------------------------------
def _seed(*parts: str) -> int:
    d = hashlib.sha256("|".join(parts).encode()).digest()
    return int.from_bytes(d[:8], "big")


def derive_esp_keys(variant: str, run: str, traffic: str, spi_hex: str):
    """Deterministic ESP/AH key material (validator recomputes this)."""
    def k(usage: str, n: int) -> bytes:
        msg = f"synth-ipsec-v1|{variant}|{run}|{traffic}|{spi_hex}|{usage}".encode()
        return hashlib.sha256(msg).digest()[:n]
    return {"enc": lambda n: k("enc", n), "mac": k("mac", 32),
            "salt": k("salt", 4)}


def derive_ike_keys(variant: str, run: str, traffic: str):
    """Deterministic IKE SK key material (validator decrypts AUTH/rekey).

    Real IKE keys come from the DH exchange and are unknowable; synthetic
    ones are derived so the validator can verify SK inner structure.
    One key per pcap (documented simplification).
    """
    def k(usage: str, n: int) -> bytes:
        msg = f"synth-ipsec-v1|{variant}|{run}|{traffic}|ike|{usage}".encode()
        return hashlib.sha256(msg).digest()[:n]
    return {"enc": lambda n: k("ike-enc", n), "mac": k("ike-mac", 32),
            "salt": k("ike-salt", 4)}


def _rand_host(rng: random.Random, net: str, exclude=()) -> str:
    n = ipaddress.ip_network(net)
    while True:
        if n.version == 4:
            h = rng.randint(2, 254)
            ip = str(n.network_address + h)
        else:
            iid = rng.randint(0x10, 0xFFFE)
            ip = str(n.network_address + iid)
        if ip not in exclude:
            return ip


def _rand_mac(rng: random.Random) -> str:
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(rng.randint(0, 255) for _ in range(5))


class NetCtx:
    """Per-run topology, SHARED across variants (spec: randomized per run).

    Sharing means no address/MAC value can identify a variant, even to a
    corpus-memorizing classifier with improper (non-run-grouped) splits.
    SPIs, IKE cookies, ports and start times stay per-pcap (fresh SA per
    pcap, like the real runner's fresh bring-up per traffic type)."""

    def __init__(self, run: str, fam: int):
        self.variant_id = run
        rng = random.Random(_seed("synth", "net", run, str(fam)))
        if fam == 4:
            self.fam = 4
            self.oa = _rand_host(rng, matrix.TOPOLOGY["nets"]["transit4"])
            self.ob = _rand_host(rng, matrix.TOPOLOGY["nets"]["transit4"], (self.oa,))
            self.ia = _rand_host(rng, matrix.TOPOLOGY["nets"]["lan_a4"])
            self.ib = _rand_host(rng, matrix.TOPOLOGY["nets"]["lan_b4"])
        else:
            self.fam = 6
            self.oa = _rand_host(rng, matrix.TOPOLOGY["nets"]["transit6"])
            self.ob = _rand_host(rng, matrix.TOPOLOGY["nets"]["transit6"], (self.oa,))
            self.ia = _rand_host(rng, matrix.TOPOLOGY["nets"]["lan_a6"])
            self.ib = _rand_host(rng, matrix.TOPOLOGY["nets"]["lan_b6"])
        self.mac_a, self.mac_b = _rand_mac(rng), _rand_mac(rng)


def _eth(fam: int, mac_s: str, mac_d: str):
    return Ether(src=mac_s, dst=mac_d,
                 type=0x0800 if fam == 4 else 0x86DD)


def _outer(fam: int, src: str, dst: str, proto: int):
    if fam == 4:
        return IP(src=src, dst=dst, proto=proto, ttl=64)
    return IPv6(src=src, dst=dst, nh=proto, hlim=64)


# --------------------------------------------------------------------------
# IKEv2 builders (return raw bytes)
# --------------------------------------------------------------------------
def _gen(next_t: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_t, 0, 4 + len(body)) + body


def _tv(t: int, v: int) -> bytes:
    return struct.pack("!HH", 0x8000 | t, v)


def _v2_transforms(enc: str, auth: str, dh: int | None, proto: int) -> bytes:
    tf: list[tuple[int, int, bytes]] = []
    if proto == PROTO_AH:
        tf.append((3, INTEG_ID[auth], b""))
    else:
        eid, eklen = ENCR_ID[enc]
        tf.append((1, eid, _tv(14, eklen) if eklen else b""))
        if not matrix.CIPHERS[enc]["aead"]:
            tf.append((3, INTEG_ID[auth], b""))
        if proto == PROTO_IKE:
            prf = PRF_ID[enc] if matrix.CIPHERS[enc]["aead"] else PRF_ID[auth]
            tf.append((2, prf, b""))
    if dh is not None:
        tf.append((4, dh, b""))
    out = b""
    for i, (tt, tid, ab) in enumerate(tf):
        last = i == len(tf) - 1
        body = struct.pack("!BBH", tt, 0, tid) + ab
        out += struct.pack("!BBH", 0 if last else 3, 0, 8 + len(ab)) + body
    return out, len(tf)


def _v2_proposal(proto: int, enc: str, auth: str,
                 dh: int | None) -> bytes:
    tfb, ntr = _v2_transforms(enc, auth, dh, proto=proto)
    fixed = struct.pack("!BBBB", 1, proto, 0, ntr)
    plen = 8 + len(tfb)
    return struct.pack("!BBH", 0, 0, plen) + fixed + tfb


def _v2_sa(next_t: int, proto: int, enc: str, auth: str,
           dh: int | None) -> bytes:
    prop = _v2_proposal(proto, enc, auth, dh)
    return _gen(next_t, prop)


def _v2_ke(next_t: int, dh: int, pub: bytes) -> bytes:
    return _gen(next_t, struct.pack("!HH", dh, 0) + pub)


def _v2_nonce(next_t: int, nonce: bytes) -> bytes:
    return _gen(next_t, nonce)


def _ike_hdr(spi_i: bytes, spi_r: bytes, np: int, exch: int, flags: int,
             msgid: int, payloads: bytes) -> bytes:
    return (spi_i + spi_r
            + struct.pack("!BBBBII", np, 0x20, exch, flags, msgid,
                          28 + len(payloads)) + payloads)


def _ike_suite(v: dict) -> tuple[str, str]:
    """(enc, auth) for the IKE SA (AH child keeps v1 baseline)."""
    if v["cipher"] == "none":
        return matrix.DEFAULT_IKE_CIPHER, matrix.DEFAULT_IKE_AUTH
    return v["cipher"], v["auth"]


def _sk_encrypt(enc: str, keys, inner: bytes,
                rng: random.Random, auth: str = "hmac-sha256") -> bytes:
    """Build an SK payload body (IV + cipher + ICV) with real crypto.

    IKEv2 SK has NO padlen/nh trailer (unlike ESP): pad with zeros to the
    block; the validator walks inner payloads by their Length fields and
    skips trailing pad. GCM needs no padding.
    """
    klen = ENC_KEY_LEN[enc]
    ekey = keys["enc"](klen) if callable(keys["enc"]) else keys["enc"]
    if matrix.CIPHERS[enc]["aead"]:
        iv = rng.randbytes(8)
        ct = AESGCM(ekey).encrypt(keys["salt"] + iv, inner, b"")
        return iv + ct  # tag appended by AESGCM
    blk = BLOCK_LEN[enc]
    iv = rng.randbytes(IV_LEN[enc])
    padn = (-len(inner)) % blk
    if enc == "3des-cbc":
        cipher = Cipher(TripleDES(ekey), modes.CBC(iv))
    else:
        cipher = Cipher(algorithms.AES(ekey), modes.CBC(iv))
    encor = cipher.encryptor()
    ct = encor.update(inner + bytes(padn)) + encor.finalize()
    tag = hmac_mod.new(keys["mac"], iv + ct, hashlib.sha256).digest()[:ICV_LEN[auth]]
    return iv + ct + tag


def _notify(next_t: int, ntype: int, data: bytes = b"",
            proto: int = 0, spi_size: int = 0) -> bytes:
    body = struct.pack("!BBH", proto, spi_size, ntype) + data
    return _gen(next_t, body)


def _auth_inner(v: dict, rng: random.Random, fam: int, resp: bool) -> bytes:
    """Plausible IKE_AUTH cleartext: IDi/AUTH/SA/TSi/TSr + Notify filler."""
    enc, _ = _ike_suite(v)
    idi = _gen(39, bytes([4 if fam == 4 else 5, 0, 0, 0])
               + rng.randbytes(4 if fam == 4 else 16))
    auth = _gen(33, struct.pack("!H", 2) + rng.randbytes(32))
    proto = PROTO_AH if v["ipsec_protocol"] == "ah" else PROTO_ESP
    cdh = v["dh_group"] if v["pfs"] else None
    cenc = v["cipher"] if proto == PROTO_ESP else enc
    sa = _gen(44, _v2_proposal(proto, cenc, v["auth"], cdh))
    tsi = _gen(45, b"\x01" + rng.randbytes(15))
    tsr = _gen(41, b"\x01" + rng.randbytes(15))
    blob = idi + auth + sa + tsi + tsr
    # bulk to realistic AUTH sizes with well-formed Notify payloads
    target = rng.randint(190, 260) if not resp else rng.randint(150, 210)
    while len(blob) < target:
        blob += _notify(41, 16430, rng.randbytes(rng.randint(8, 40)))
    return _rechain(bytearray(blob))


def _rechain(blob: bytearray) -> bytes:
    """Rewrite generic next-pointers along a payload chain in place."""
    offs, off = [], 0
    while off + 4 <= len(blob):
        ln = struct.unpack("!H", blob[off + 2:off + 4])[0]
        if ln < 8 or off + ln > len(blob):
            break
        offs.append(off)
        off += ln
    for i, off in enumerate(offs):
        nxt = blob[offs[i + 1]] if i + 1 < len(offs) else 0
        # next type of payload i = type of payload i+1: stored at its own
        # header? No: generic header's first byte IS the next-payload type
        # of the PREVIOUS; each payload header carries the NEXT type.
        # We encoded next slots already; just terminate the last one.
        if i == len(offs) - 1:
            blob[off] = 0
    return bytes(blob)


def _rekey_inner(v: dict, enc: str, rng: random.Random) -> bytes:
    """CREATE_CHILD_SA cleartext (encrypted as one SK blob, like real
    strongSwan): N(REKEY_SA) + SA(child) + Nonce + [KE iff PFS] + TSi + TSr.
    """
    proto = PROTO_AH if v["ipsec_protocol"] == "ah" else PROTO_ESP
    cdh = v["dh_group"] if v["pfs"] else None
    cenc = v["cipher"] if proto == PROTO_ESP else enc
    parts = [_notify(P_SA, 16384, rng.randbytes(4), proto=proto, spi_size=4),
             _v2_sa(P_NONCE, proto, cenc, v["auth"], cdh)]
    if cdh is not None:
        parts.append(_v2_nonce(34, rng.randbytes(32)))
        parts.append(_v2_ke(44, cdh, rng.randbytes(DH_PUB_LEN[cdh])))
    else:
        parts.append(_v2_nonce(44, rng.randbytes(32)))
    parts.append(_gen(45, b"\x01" + rng.randbytes(15)))
    parts.append(_gen(0, b"\x01" + rng.randbytes(15)))
    return _rechain(bytearray(b"".join(parts)))


def build_ikev2(v: dict, rng: random.Random, ike_keys=None):
    """Return list of (t, dir, ike_bytes). SK-only rekeys like strongSwan.
    ike_keys: derived deterministic keys (validator decrypts AUTH/rekey)."""
    enc, auth = _ike_suite(v)
    spi_i, spi_r = rng.randbytes(8), rng.randbytes(8)
    dh = v["dh_group"]
    msgs = []
    # SA_INIT
    sa = _v2_sa(P_KE, PROTO_IKE, enc, auth, dh)
    ke = _v2_ke(P_NONCE, dh, rng.randbytes(DH_PUB_LEN[dh]))
    no = _v2_nonce(0, rng.randbytes(32))
    msgs.append((0.0, 0, _ike_hdr(spi_i, b"\x00" * 8, P_SA, X_INIT, 0x08, 0,
                                  sa + ke + no)))
    sa_r = _v2_sa(P_KE, PROTO_IKE, enc, auth, dh)
    ke_r = _v2_ke(P_NONCE, dh, rng.randbytes(DH_PUB_LEN[dh]))
    no_r = _v2_nonce(0, rng.randbytes(32))
    msgs.append((rng.uniform(0.02, 0.05), 1,
                 _ike_hdr(spi_i, spi_r, P_SA, X_INIT, 0x20, 0,
                          sa_r + ke_r + no_r)))
    # AUTH (SK wraps IDi/AUTH/SA/TSi/TSr)
    inner = _auth_inner(v, rng, v["ip_version"], False)
    sk = _gen(0, _sk_encrypt(enc, ike_keys, inner, rng, auth))
    # SK generic next = first inner type (IDi=35)
    sk = struct.pack("!BBH", 35, 0, len(sk)) + sk[4:]
    msgs.append((rng.uniform(0.08, 0.20), 0,
                 _ike_hdr(spi_i, spi_r, P_SK, X_AUTH, 0x08, 1, sk)))
    inner_r = _auth_inner(v, rng, v["ip_version"], True)
    skr = _gen(0, _sk_encrypt(enc, ike_keys, inner_r, rng, auth))
    skr = struct.pack("!BBH", 35, 0, len(skr)) + skr[4:]
    msgs.append((msgs[-1][0] + rng.uniform(0.02, 0.05), 1,
                 _ike_hdr(spi_i, spi_r, P_SK, X_AUTH, 0x20, 1, skr)))
    # CREATE_CHILD_SA rekey: SK-ONLY (strongSwan encrypts the whole
    # exchange); inner = N(REKEY_SA) + SA + Nonce + [KE] + TSi + TSr.
    rk_t = rng.uniform(2.5, 4.5)
    rk_inner = _rekey_inner(v, enc, rng)
    rk = _gen(0, _sk_encrypt(enc, ike_keys, rk_inner, rng, auth))
    rk = struct.pack("!BBH", P_NOTIFY, 0, len(rk)) + rk[4:]
    msgs.append((rk_t, 0, _ike_hdr(spi_i, spi_r, P_SK, X_REKEY, 0x08, 2, rk)))
    rk_inner_r = _rekey_inner(v, enc, rng)
    rk_r = _gen(0, _sk_encrypt(enc, ike_keys, rk_inner_r, rng, auth))
    rk_r = struct.pack("!BBH", P_NOTIFY, 0, len(rk_r)) + rk_r[4:]
    msgs.append((rk_t + rng.uniform(0.02, 0.05), 1,
                 _ike_hdr(spi_i, spi_r, P_SK, X_REKEY, 0x20, 2, rk_r)))
    return msgs


# --------------------------------------------------------------------------
# IKEv1 builders (v12 only)
# --------------------------------------------------------------------------
def _v1_transform(enc: str, auth: str, dh: int, ike_rekey_s: int) -> bytes:
    attrs = b""
    attrs += _tv(1, IKEV1_ENCR[enc])
    if enc != "3des-cbc":
        attrs += _tv(14, matrix.CIPHERS[enc]["len"])
    attrs += _tv(2, IKEV1_HASH[auth])
    attrs += _tv(4, dh)
    attrs += _tv(3, 1)
    attrs += _tv(11, 1)
    attrs += _tv(12, int(ike_rekey_s * 1.1))
    body = struct.pack("!BBH", 1, 1, 0) + attrs
    return struct.pack("!BBH", 0, 0, 4 + len(body)) + body


def _v1_sa(next_t: int, enc: str, auth: str, dh: int,
           ike_rekey_s: int) -> bytes:
    tf = _v1_transform(enc, auth, dh, ike_rekey_s)
    prop = (struct.pack("!BBHBBBB", 0, 0, 8 + len(tf), 1, 1, 0, 1) + tf)
    body = struct.pack("!II", 1, 1) + prop
    return struct.pack("!BBH", next_t, 0, 4 + len(body)) + body


def _v1_vid(next_t: int, data: bytes) -> bytes:
    return struct.pack("!BBH", next_t, 0, 4 + len(data)) + data


def _v1_hdr(spi_i: bytes, spi_r: bytes, np: int, exch: int, flags: int,
            payloads: bytes) -> bytes:
    return (spi_i + spi_r
            + struct.pack("!BBBBII", np, 0x10, exch, flags, 0,
                          28 + len(payloads)) + payloads)


def _v1_encrypt(enc: str, key: bytes, inner: bytes,
                rng: random.Random) -> bytes:
    iv = rng.randbytes(16)
    padn = (-len(inner)) % 16
    if enc == "3des-cbc":
        cipher = Cipher(TripleDES(key), modes.CBC(iv))
    else:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = cipher.encryptor()
    return iv + e.update(inner + bytes(padn)) + e.finalize()


def build_ikev1(v: dict, rng: random.Random):
    enc, auth, dh = v["cipher"], v["auth"], v["dh_group"]
    spi_i, spi_r = rng.randbytes(8), rng.randbytes(8)
    klen = ENC_KEY_LEN[enc]
    ekey = rng.randbytes(klen)
    msgs = []
    # MM1: SA + 5 VIDs
    sa = _v1_sa(13, enc, auth, dh, v["ike_rekey_s"])
    pay = sa
    for i, vd in enumerate(VIDS):
        pay += _v1_vid(13 if i < 4 else 0, vd)
    msgs.append((0.0, 0, _v1_hdr(spi_i, b"\x00" * 8, 1, 2, 0, pay)))
    # MM2: SA + first 4 VIDs
    sa_r = _v1_sa(13, enc, auth, dh, v["ike_rekey_s"])
    pay = sa_r
    for i, vd in enumerate(VIDS[:4]):
        pay += _v1_vid(13 if i < 3 else 0, vd)
    msgs.append((rng.uniform(0.02, 0.05), 1,
                 _v1_hdr(spi_i, spi_r, 1, 2, 0, pay)))
    # MM3/MM4: KE + Nonce + 2x NAT-D(type 20)
    for direction, t in ((0, rng.uniform(0.08, 0.15)),):
        ke = _gen(10, rng.randbytes(DH_PUB_LEN[dh]))
        no = _gen(20, rng.randbytes(32))
        nd1 = _gen(20, rng.randbytes(32))
        nd2 = _gen(0, rng.randbytes(32))
        msgs.append((t, direction,
                     _v1_hdr(spi_i, spi_r, 4, 2, 0, ke + no + nd1 + nd2)))
    ke = _gen(10, rng.randbytes(DH_PUB_LEN[dh]))
    no = _gen(20, rng.randbytes(32))
    nd1 = _gen(20, rng.randbytes(32))
    nd2 = _gen(0, rng.randbytes(32))
    msgs.append((msgs[-1][0] + rng.uniform(0.02, 0.05), 1,
                 _v1_hdr(spi_i, spi_r, 4, 2, 0, ke + no + nd1 + nd2)))
    # MM5/MM6: encrypted ID + HASH
    for direction in (0, 1):
        idi = _gen(8, bytes([1 if v["ip_version"] == 4 else 5, 0, 0, 0])
                   + rng.randbytes(4 if v["ip_version"] == 4 else 16))
        hsh = _gen(0, rng.randbytes(32))
        ct = _v1_encrypt(enc, ekey, idi + hsh, rng)
        t = msgs[-1][0] + rng.uniform(0.05, 0.12) if direction == 0 else \
            msgs[-1][0] + rng.uniform(0.02, 0.05)
        msgs.append((t, direction, _v1_hdr(spi_i, spi_r, 5, 2, 0x1, ct)))
    # QM1/QM2 (exch 32): HASH + SA + [KE iff PFS] + Nonce ; QM3: HASH
    for qm, direction in ((1, 0), (2, 1), (3, 0)):
        if qm < 3:
            hsh = struct.pack("!BBH", 1, 0, 36) + rng.randbytes(32)
            csa = _v1_sa(4 if v["pfs"] else 10, enc, auth, dh,
                         v["child_rekey_s"])
            parts = hsh + csa
            if v["pfs"]:
                parts += _gen(10, rng.randbytes(DH_PUB_LEN[dh]))
            parts += _gen(0, rng.randbytes(32))
        else:
            parts = _gen(0, rng.randbytes(32))
        ct = _v1_encrypt(enc, ekey, parts, rng)
        t = msgs[-1][0] + (rng.uniform(0.3, 0.6) if qm == 1
                           else rng.uniform(0.02, 0.05))
        msgs.append((t, direction, _v1_hdr(spi_i, spi_r, 8, 32, 0x1, ct)))
    return msgs


# --------------------------------------------------------------------------
# ESP / AH
# --------------------------------------------------------------------------
def esp_bytes(v: dict, keys, spi: int, seq: int, inner: bytes,
              rng: random.Random) -> bytes:
    enc, auth = v["cipher"], v["auth"]
    aead = matrix.CIPHERS[enc]["aead"]
    spi_b = struct.pack("!I", spi)
    seq_b = struct.pack("!I", seq)
    if v["mode"] == "tunnel":
        data = inner
        nh = 4 if v["ip_version"] == 4 else 41
    else:
        nh, data = inner[0], inner[1:]
    if aead:
        align = 4
        padn = (-(len(data) + 2)) % align
        pt = data + bytes(range(1, padn + 1)) + bytes([padn, nh])
        iv = rng.randbytes(8)
        ct = AESGCM(keys["enc"](ENC_KEY_LEN[enc])).encrypt(
            keys["salt"] + iv, pt, spi_b + seq_b)
        return spi_b + seq_b + iv + ct
    blk = BLOCK_LEN[enc]
    iv = rng.randbytes(IV_LEN[enc])
    padn = (-(len(data) + 2)) % blk
    pt = data + bytes(range(1, padn + 1)) + bytes([padn, nh])
    key = keys["enc"](ENC_KEY_LEN[enc])
    if enc == "3des-cbc":
        cipher = Cipher(TripleDES(key), modes.CBC(iv))
    else:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = cipher.encryptor()
    ct = e.update(pt) + e.finalize()
    icv = hmac_mod.new(keys["mac"], spi_b + seq_b + iv + ct,
                       hashlib.sha256).digest()[:ICV_LEN[auth]]
    return spi_b + seq_b + iv + ct + icv


# --------------------------------------------------------------------------
# AH
def ah_bytes(v: dict, keys, spi: int, seq: int, inner: bytes) -> bytes:
    nh = 4 if v["ip_version"] == 4 else 41
    hdr = struct.pack("!BBHII", nh, 5, 0, spi, seq)
    icv = hmac_mod.new(keys["mac"], struct.pack("!II", spi, seq) + inner,
                       hashlib.sha256).digest()[:16]
    return hdr + icv + inner


# --------------------------------------------------------------------------
# Traffic profiles -> (t, dir, proto_tag, l4_bytes)
# --------------------------------------------------------------------------
def _tcp_seg(rng, sport, dport, seq, ack, flags, data=b""):
    return bytes(TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags,
                     window=64240) / Raw(load=data))


def _udp_seg(rng, sport, dport, data: bytes):
    return bytes(UDP(sport=sport, dport=dport) / Raw(load=data))


def _icmp_msg(rng, ident, seq, data: bytes, reply=False, v6=False):
    if v6:
        return bytes(ICMP(type=129 if reply else 128, id=ident, seq=seq)
                     / Raw(load=data))
    return bytes(ICMP(type=0 if reply else 8, id=ident, seq=seq)
                 / Raw(load=data))


def gen_traffic(traffic: str, rng: random.Random, fam: int,
                chunk: int) -> list[tuple[float, int, int, bytes]]:
    """Return [(t_offset, dir(0=a->b,1=b->a), proto, l4_bytes)]."""
    out: list[tuple[float, int, int, bytes]] = []
    J = rng.uniform(0.10, 0.30)
    T0 = 0.35

    def jit(base: float) -> float:
        return base * (1.0 + rng.uniform(-J, J))

    if traffic == "voip":
        sport = rng.randint(1024, 65535)
        t = T0
        while t < T0 + 8.0:
            out.append((t, 0, 17, _udp_seg(rng, sport, 5004,
                                           rng.randbytes(160))))
            t += jit(0.020)
    elif traffic == "video":
        sport = rng.randint(1024, 65535)
        t = T0
        while t < T0 + 8.0:
            burst = t
            while burst < t + 1.0 and burst < T0 + 8.0:
                n = min(rng.randint(1200, 1400), chunk - 8)
                out.append((burst, 0, 17, _udp_seg(rng, sport, 5006,
                                                  rng.randbytes(n))))
                burst += jit(0.010)
            t += 2.0
    elif traffic == "web":
        t = T0
        while t < T0 + 8.0:
            port = rng.choice([80, 443])
            sport = rng.randint(1024, 65535)
            s0, t0 = rng.randint(0, 2**31), rng.randint(0, 2**31)
            out.append((t, 0, 6, _tcp_seg(rng, sport, port, s0, 0, "S")))
            out.append((t + 0.01, 1, 6,
                        _tcp_seg(rng, port, sport, t0, s0 + 1, "SA")))
            seq = s0 + 1
            tack = t0 + 1
            out.append((t + 0.02, 0, 6,
                        _tcp_seg(rng, sport, port, seq, tack, "A")))
            t += 0.03
            for _ in range(rng.randint(2, 5)):
                if port == 80:
                    req = (f"GET /i{rng.randint(0,99)} HTTP/1.1\r\n"
                           f"Host: t\r\n\r\n").encode()
                else:
                    blob = rng.randbytes(rng.randint(200, 400))
                    req = bytes([0x16, 0x03, 0x01]) + \
                        len(blob).to_bytes(2, "big") + blob
                out.append((t, 0, 6, _tcp_seg(rng, sport, port, seq, tack,
                                             "PA", req)))
                seq += len(req)
                resp = rng.randbytes(rng.randint(2048, 16384))
                off = 0
                t += 0.02
                while off < len(resp):
                    seg = resp[off:off + chunk]
                    out.append((t, 1, 6, _tcp_seg(rng, port, sport, tack,
                                                 seq, "PA", seg)))
                    tack += len(seg)
                    off += len(seg)
                    t += 0.005
                out.append((t, 0, 6, _tcp_seg(rng, sport, port, seq, tack,
                                             "A")))
                t += jit(0.05)
            out.append((t, 0, 6, _tcp_seg(rng, sport, port, seq, tack,
                                         "FA")))
            out.append((t + 0.01, 1, 6,
                        _tcp_seg(rng, port, sport, tack, seq + 1, "FA")))
            t += rng.uniform(0.5, 2.0)
    elif traffic == "email":
        t = T0
        n = 0
        while t < T0 + 8.0:
            port, sport = 25, rng.randint(1024, 65535)
            s0, t0 = rng.randint(0, 2**31), rng.randint(0, 2**31)
            out.append((t, 0, 6, _tcp_seg(rng, sport, port, s0, 0, "S")))
            t += 0.01
            out.append((t, 1, 6, _tcp_seg(rng, port, sport, t0, s0 + 1,
                                         "SA", b"220 mail\r\n")))
            t += 0.01
            seq, tack = s0 + 1, t0 + 1 + 10
            out.append((t, 0, 6, _tcp_seg(rng, sport, port, seq, tack, "A")))
            t += 0.02
            for cmd, rep in ((b"EHLO t\r\n", b"250 ok\r\n"),
                             (b"MAIL FROM:<a>\r\n", b"250 ok\r\n"),
                             (b"RCPT TO:<b>\r\n", b"250 ok\r\n"),
                             (b"DATA\r\n", b"354 end\r\n")):
                out.append((t, 0, 6, _tcp_seg(rng, sport, port, seq, tack,
                                             "PA", cmd)))
                seq += len(cmd)
                t += 0.02
                out.append((t, 1, 6, _tcp_seg(rng, port, sport, tack, seq,
                                             "PA", rep)))
                tack += len(rep)
                t += 0.02
            body = b"Subject: h\r\n\r\n" + rng.randbytes(rng.randint(200, 2000))
            if n % 3 == 2:
                body += b"\r\n" + rng.randbytes(rng.randint(65536, 262144))
            body += b"\r\n.\r\n"
            off = 0
            while off < len(body):
                seg = body[off:off + chunk]
                out.append((t, 0, 6, _tcp_seg(rng, sport, port, seq, tack,
                                             "PA", seg)))
                seq += len(seg)
                off += len(seg)
                t += 0.005
            out.append((t, 1, 6, _tcp_seg(rng, port, sport, tack, seq,
                                         "PA", b"250 queued\r\n")))
            tack += 12
            out.append((t + 0.02, 0, 6,
                        _tcp_seg(rng, sport, port, seq, tack, "FA",
                                 b"QUIT\r\n")))
            n += 1
            t += rng.uniform(1.0, 3.0)
    elif traffic == "whatsapp":
        sport = rng.randint(1024, 65535)
        s0, t0 = rng.randint(0, 2**31), rng.randint(0, 2**31)
        out.append((T0, 0, 6, _tcp_seg(rng, sport, 5222, s0, 0, "S")))
        out.append((T0 + 0.01, 1, 6,
                    _tcp_seg(rng, 5222, sport, t0, s0 + 1, "SA")))
        seq, tack = s0 + 1, t0 + 1
        out.append((T0 + 0.02, 0, 6,
                    _tcp_seg(rng, sport, 5222, seq, tack, "A")))
        t = T0 + 0.05
        last_blob = t
        while t < T0 + 8.0:
            rec = _tls_records(rng.randbytes(rng.randint(30, 300)))
            off = 0
            while off < len(rec):
                seg = rec[off:off + chunk]
                out.append((t, 0, 6, _tcp_seg(rng, sport, 5222, seq, tack,
                                             "PA", seg)))
                seq += len(seg)
                off += len(seg)
            if rng.random() < 0.5:
                rep = _tls_records(rng.randbytes(rng.randint(20, 120)))
                out.append((t + 0.01, 1, 6,
                            _tcp_seg(rng, 5222, sport, tack, seq, "PA",
                                     rep[:chunk])))
                tack += len(rep[:chunk])
            if t - last_blob > rng.uniform(5.0, 8.0):
                blob = _tls_records(rng.randbytes(rng.randint(100000,
                                                              400000)))
                off = 0
                while off < len(blob):
                    seg = blob[off:off + chunk]
                    out.append((t, 0, 6,
                                _tcp_seg(rng, sport, 5222, seq, tack,
                                         "PA", seg)))
                    seq += len(seg)
                    off += len(seg)
                    t += 0.002
                last_blob = t
            t += rng.uniform(0.1, 1.0)
    elif traffic == "icmp":
        sizes = [64, 512, 1400 if fam == 4 else 1340]
        t = T0
        i = 0
        while t < T0 + 8.0:
            sz = sizes[i % 3]
            ident = rng.randint(0, 65535)
            data = rng.randbytes(sz - 8)
            proto = 1 if fam == 4 else 58
            out.append((t, 0, proto, _icmp_msg(rng, ident, i, data,
                                              v6=(fam == 6))))
            out.append((t + 0.005, 1, proto,
                        _icmp_msg(rng, ident, i, data, reply=True,
                                  v6=(fam == 6))))
            i += 1
            t += jit(1.0)
    else:
        raise ValueError(traffic)
    return out


def _tls_records(payload: bytes) -> bytes:
    out = b""
    for i in range(0, len(payload), 16000):
        c = payload[i:i + 16000]
        out += bytes([0x17, 0x03, 0x03]) + len(c).to_bytes(2, "big") + c
    return out


def chunk_cap(v: dict) -> int:
    """Max L4 payload keeping outer ESP <= 1500 B."""
    fam = v["ip_version"]
    outer_ip = 40 if fam == 6 else 20
    inner_ip = 40 if fam == 6 else 20
    if v["ipsec_protocol"] == "ah":
        inner_cap = MAX_OUTER - outer_ip - 28
    else:
        enc = v["cipher"]
        aead = matrix.CIPHERS[enc]["aead"]
        iv = 8 if aead else IV_LEN[enc]
        cipher_cap = MAX_OUTER - outer_ip - 8 - iv - 16
        inner_cap = cipher_cap - 2  # trailer minimum
        inner_cap -= inner_cap % (4 if aead else BLOCK_LEN[enc])
    return max(512, inner_cap - inner_ip - 20)


# --------------------------------------------------------------------------
# Pcap assembly
# --------------------------------------------------------------------------
def _inner_bytes(net: NetCtx, v: dict, direction: int, proto: int,
                 l4: bytes) -> bytes:
    s, d = (net.ia, net.ib) if direction == 0 else (net.ib, net.ia)
    fixed = _fix_l4_cksum(net.fam, s, d, proto, l4)
    if net.fam == 4:
        pkt = IP(src=s, dst=d, proto=proto, ttl=63) / Raw(load=fixed)
    else:
        pkt = IPv6(src=s, dst=d, nh=proto, hlim=63) / Raw(load=fixed)
    return bytes(pkt)


def _l4_dummy(net: NetCtx, direction: int, proto: int, l4: bytes) -> bytes:
    """Recompute L4 checksum against the outer (transport) endpoints."""
    s, d = (net.oa, net.ob) if direction == 0 else (net.ob, net.oa)
    return _fix_l4_cksum(net.fam, s, d, proto, l4)


def _fix_l4_cksum(fam: int, s: str, d: str, proto: int, l4: bytes) -> bytes:
    if fam == 4:
        if proto == 1:  # ICMP: checksum over message only
            return _cksum_set(l4, 2)
        ps = ipaddress.IPv4Address(s).packed + ipaddress.IPv4Address(d).packed
        ps += struct.pack("!BBH", 0, proto, len(l4))
    else:
        if proto == 58:
            ps = ipaddress.IPv6Address(s).packed + ipaddress.IPv6Address(d).packed
            ps += struct.pack("!II", len(l4), proto)
            return _cksum_set_v6(l4, ps, 2)
        ps = ipaddress.IPv6Address(s).packed + ipaddress.IPv6Address(d).packed
        ps += struct.pack("!II", len(l4), proto)
    # UDP(6,7)/TCP(16,17): zero checksum field then compute
    off = 6 if proto == 17 else 16
    return _cksum_set_pseudo(l4, ps, off)


def _cksum_set(data: bytes, off: int) -> bytes:
    b = bytearray(data)
    b[off:off + 2] = b"\x00\x00"
    c = _ones_complement(bytes(b))
    b[off:off + 2] = struct.pack("!H", c)
    return bytes(b)


def _cksum_set_v6(data: bytes, pseudo: bytes, off: int) -> bytes:
    b = bytearray(data)
    b[off:off + 2] = b"\x00\x00"
    c = _ones_complement(pseudo + bytes(b))
    b[off:off + 2] = struct.pack("!H", c)
    return bytes(b)


def _cksum_set_pseudo(data: bytes, pseudo: bytes, off: int) -> bytes:
    return _cksum_set_v6(data, pseudo, off)


def _ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_pcap(variant_id: str, traffic: str, run: str):
    """Build packets + stats for one synthetic pcap. Returns (pkts, info)."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package required")
    v = matrix.BY_ID[variant_id]
    net = NetCtx(run, v["ip_version"])
    # Isolated RNG streams (determinism hygiene, MAJOR-5): IKE edits must
    # never reshuffle traffic timing/counts, and vice versa.
    rng_ike = random.Random(_seed("synth", variant_id, run, traffic, "ike"))
    rng = random.Random(_seed("synth", variant_id, run, traffic, "data"))
    fam = v["ip_version"]
    nat = v["nat_t"]
    pkts = []
    n_ike = n_esp = 0

    def emit_ike(t, direction, ike: bytes, encap4500: bool):
        nonlocal n_ike
        s, d = (net.oa, net.ob) if direction == 0 else (net.ob, net.oa)
        ms, md = (net.mac_a, net.mac_b) if direction == 0 else \
            (net.mac_b, net.mac_a)
        if encap4500:
            pay = b"\x00" * 4 + ike
            p = _eth(fam, ms, md) / _outer(fam, s, d, 17) / \
                UDP(sport=4500, dport=4500) / Raw(load=pay)
        else:
            p = _eth(fam, ms, md) / _outer(fam, s, d, 17) / \
                UDP(sport=500, dport=500) / Raw(load=ike)
        p.time = base + t
        pkts.append(p)
        n_ike += 1

    base = 1700000000 + rng.randint(0, 200_000_000)
    # IKE phase
    if v["ike_version"] == 2:
        ike_keys = derive_ike_keys(variant_id, run, traffic)
        msgs = build_ikev2(v, rng_ike, ike_keys)
        for i, (t, direction, ike) in enumerate(msgs):
            emit_ike(t, direction, ike, encap4500=nat and i >= 2)
    else:
        for t, direction, ike in build_ikev1(v, rng_ike):
            emit_ike(t, direction, ike, encap4500=False)

    # Data phase
    spi = [rng.randint(1, 0xFFFFFFFF), rng.randint(1, 0xFFFFFFFF)]
    while spi[0] == spi[1]:
        spi[1] = rng.randint(1, 0xFFFFFFFF)
    seq = [1, 1]
    keys = [derive_esp_keys(variant_id, run, traffic, f"{s:08x}")
            for s in spi]
    is_ah = v["ipsec_protocol"] == "ah"
    for t, direction, proto, l4 in gen_traffic(traffic, rng, fam,
                                              chunk_cap(v)):
        if v["mode"] == "tunnel":
            protected = _inner_bytes(net, v, direction, proto, l4)
        else:
            protected = bytes([proto]) + _l4_dummy(net, direction, proto, l4)
        if is_ah:
            sec = ah_bytes(v, keys[direction], spi[direction],
                           seq[direction], protected)
            oproto, estr = 51, sec
        else:
            sec = esp_bytes(v, keys[direction], spi[direction],
                            seq[direction], protected, rng)
            oproto, estr = 50, sec
        seq[direction] += 1
        s, d = (net.oa, net.ob) if direction == 0 else (net.ob, net.oa)
        ms, md = (net.mac_a, net.mac_b) if direction == 0 else \
            (net.mac_b, net.mac_a)
        if nat and not is_ah:
            p = _eth(fam, ms, md) / _outer(fam, s, d, 17) / \
                UDP(sport=4500, dport=4500) / Raw(load=estr)
        else:
            p = _eth(fam, ms, md) / _outer(fam, s, d, oproto) / Raw(load=estr)
        p.time = base + t
        pkts.append(p)
        n_esp += 1
    pkts.sort(key=lambda p: float(p.time))
    dur = float(pkts[-1].time) - float(pkts[0].time)
    return pkts, {"ike": n_ike, "esp": n_esp, "duration": dur,
                  "base": base}


def build_plain(traffic: str, fam: int, run: str):
    """Plain negative: same traffic profile, no IPsec, TTL 63."""
    rng = random.Random(_seed("synth", "plain", str(fam), run, traffic))
    net = NetCtx(run, fam)
    # Plain = unencrypted gateway-to-gateway traffic on the transit link
    # (same wire addresses as transport-mode ESP): addresses must not
    # distinguish plain from IPsec variants (anti-leakage).
    oa, ob, ma, mb = net.oa, net.ob, net.mac_a, net.mac_b
    pkts = []
    base = 1700000000 + rng.randint(0, 200_000_000)
    for t, direction, proto, l4 in gen_traffic(traffic, rng, fam, 1400):
        s, d = (oa, ob) if direction == 0 else (ob, oa)
        ms, md = (ma, mb) if direction == 0 else (mb, ma)
        fixed = _fix_l4_cksum(fam, s, d, proto, l4)
        if fam == 4:
            inner = IP(src=s, dst=d, proto=proto, ttl=63) / Raw(load=fixed)
        else:
            inner = IPv6(src=s, dst=d, nh=proto, hlim=63) / Raw(load=fixed)
        p = _eth(fam, ms, md) / inner
        p.time = base + t
        pkts.append(p)
    pkts.sort(key=lambda p: float(p.time))
    dur = float(pkts[-1].time) - float(pkts[0].time)
    return pkts, {"ike": 0, "esp": 0, "duration": dur, "base": base}


# --------------------------------------------------------------------------
# Labels / manifest / ingest
# --------------------------------------------------------------------------
def label_for(variant_id: str, traffic: str, run: str, fam: int,
              duration: float, count: int) -> dict:
    if variant_id == "plain":
        lab = {"variant": "plain", "ipsec_protocol": "none",
               "ike_version": "none", "mode": "none", "encryption": "none",
               "key_length_bits": 0, "auth": "none", "aead": False,
               "dh_group": 0, "pfs": False, "esn": False, "replay_window": 0,
               "nat_t": False, "ike_rekey_s": 0, "child_rekey_s": 0}
    else:
        lab = matrix.label_row(matrix.BY_ID[variant_id])
    lab.update({"ip_version": fam, "traffic_type": traffic,
                "source": "synthetic", "run_id": run,
                "duration_s": round(duration, 3), "packet_count": count})
    return lab


def write_one(variant_id: str, traffic: str, run: str,
              fam: int | None = None):
    if variant_id == "plain":
        assert fam in (4, 6)
        pkts, info = build_plain(traffic, fam, run)
        sub = f"plain/v{fam}/{run}"
    else:
        v = matrix.BY_ID[variant_id]
        fam = v["ip_version"]
        pkts, info = build_pcap(variant_id, traffic, run)
        sub = f"{variant_id}/{run}"
    pcap_rel = f"data/pcaps/synth/{sub}/{traffic}.pcap"
    lab_rel = f"data/labels/synth/{sub}/{traffic}.json"
    (ROOT / pcap_rel).parent.mkdir(parents=True, exist_ok=True)
    (ROOT / lab_rel).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(ROOT / pcap_rel), pkts)
    lab = label_for(variant_id, traffic, run, fam, info["duration"],
                    len(pkts))
    with open(ROOT / lab_rel, "w") as f:
        json.dump(lab, f, indent=2)
    return {"file": pcap_rel, "variant": variant_id, "traffic": traffic,
            "ip_version": fam, "packets": len(pkts), "esp_packets": info["esp"],
            "ike_packets": info["ike"], "source": "synthetic", "valid": False}


def count_pcap(path: Path):
    """Fast dpkt-free count via scapy PcapReader (no full dissect)."""
    from scapy.all import PcapReader, IP, IPv6, UDP
    n = esp = ike = 0
    with PcapReader(str(path)) as rd:
        for p in rd:
            n += 1
            ip = p.getlayer(IP) or p.getlayer(IPv6)
            if ip is None:
                continue
            pr = ip.proto if isinstance(ip, IP) else ip.nh
            if pr == 50:
                esp += 1
            elif pr == 17 and UDP in p:
                u = p[UDP]
                if u.sport in (500, 4500) or u.dport in (500, 4500):
                    try:
                        pay = bytes(u.payload)
                    except Exception:
                        pay = b""
                    if u.dport == 500 or u.sport == 500 or \
                            pay[:4] == b"\x00" * 4:
                        ike += 1
                    else:
                        esp += 1
    return n, esp, ike


def rebuild_manifest() -> list[dict]:
    rows = []
    for lab_path in sorted((ROOT / "data" / "labels").rglob("*.json")):
        lab = json.loads(lab_path.read_text())
        rel = lab_path.relative_to(ROOT / "data" / "labels")
        parts = rel.parts
        if parts[0] == "synth":
            pcap_rel = str(Path("data/pcaps/synth", *parts[1:]).with_suffix(".pcap"))
        elif parts[0] == "real":
            pcap_rel = str(Path("data/real", *parts[1:]).with_suffix(".pcap"))
        else:
            continue
        p = ROOT / pcap_rel
        if not p.exists():
            continue
        n, esp, ike = count_pcap(p)
        rows.append({"file": pcap_rel, "variant": lab["variant"],
                     "traffic": lab["traffic_type"],
                     "ip_version": lab["ip_version"], "packets": n,
                     "esp_packets": esp, "ike_packets": ike,
                     "source": lab["source"], "valid": False})
    rows.sort(key=lambda r: r["file"])
    with open(ROOT / "data" / "manifest.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "variant", "traffic",
                                          "ip_version", "packets",
                                          "esp_packets", "ike_packets",
                                          "source", "valid"])
        w.writeheader()
        w.writerows(rows)
    return rows


def ingest_real() -> int:
    """Fold data/real pcaps into labels + manifest (host-side)."""
    from scapy.all import PcapReader
    n = 0
    for pcap in sorted((ROOT / "data" / "real").rglob("*.pcap")):
        rel = pcap.relative_to(ROOT / "data" / "real")
        variant_id, run, traffic = rel.parts[0], rel.parts[1], rel.stem
        v = matrix.BY_ID[variant_id]
        with PcapReader(str(pcap)) as rd:
            pkts = list(rd)
        dur = float(pkts[-1].time) - float(pkts[0].time) if len(pkts) > 1 else 0.0
        lab = matrix.label_row(v)
        lab.update({"ip_version": v["ip_version"], "traffic_type": traffic,
                    "source": "real", "run_id": run,
                    "duration_s": round(dur, 3), "packet_count": len(pkts)})
        lab_path = ROOT / "data" / "labels" / "real" / variant_id / run / \
            f"{traffic}.json"
        lab_path.parent.mkdir(parents=True, exist_ok=True)
        lab_path.write_text(json.dumps(lab, indent=2))
        n += 1
    rebuild_manifest()
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--variant", default=None)
    ap.add_argument("--run", default=None)
    ap.add_argument("--traffic", default=None)
    ap.add_argument("--family", type=int, default=None)
    ap.add_argument("--ingest-real", action="store_true")
    ap.add_argument("--manifest-only", action="store_true")
    args = ap.parse_args()

    if args.ingest_real:
        n = ingest_real()
        print(f"ingested {n} real pcaps")
        return 0
    if args.manifest_only:
        rows = rebuild_manifest()
        print(f"manifest: {len(rows)} rows")
        return 0

    variants = ([args.variant] if args.variant else
                [v["id"] for v in matrix.VARIANTS])
    runs = ([args.run] if args.run else ["r1", "r2", "r3"])
    traffics = ([args.traffic] if args.traffic else list(matrix.TRAFFIC_TYPES))
    total = 0
    for vid in variants:
        for run in runs:
            for tr in traffics:
                if vid == "plain":
                    for fam in ([args.family] if args.family else (4, 6)):
                        write_one(vid, tr, run, fam)
                        total += 1
                else:
                    write_one(vid, tr, run)
                    total += 1
    if not args.variant and not args.run and not args.traffic:
        for fam in (4, 6):
            for run in runs:
                for tr in traffics:
                    write_one("plain", tr, run, fam)
                    total += 1
    rebuild_manifest()
    print(f"generated {total} synthetic pcaps")
    return 0


if __name__ == "__main__":
    sys.exit(main())

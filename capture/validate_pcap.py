#!/usr/bin/env python3
"""Pcap validator (M2 spec line 58) — trustworthy gate, not a linter.

Checks per manifest row: file parses (scapy + dpkt + tcpdump triple
count); label exists and validates against testbed/label_schema.json;
row/label/pcap fields agree; IKE_SA_INIT/IKE_AUTH presence; SA proposal
transform IDs match the label; KE lengths match the DH group; rekey
present (synthetic only: real captures contain no rekey); ESP SPI
consistency + structure (synthetic: full decrypt — padding, padlen,
next-header, ICV/GCM-tag, tunnel/transport layout; real: block alignment
+ header structure, keys unknown); AH presence/structure (v7); negatives
contain no IPsec; packet counts match.

IKE parsing is an independent byte-level parser (not scapy's ISAKMP
layer). Exit code = number of invalid rows (0 = gate green).

Usage:
    validate_pcap.py [--manifest data/manifest.csv]
    validate_pcap.py --self-test   # negative controls must all fail
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac as hmac_mod
import ipaddress
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "testbed"))
sys.path.insert(0, str(ROOT / "capture" / "synth"))
import matrix  # noqa: E402
from synth_pcap import (derive_esp_keys, ENC_KEY_LEN, ICV_LEN, DH_PUB_LEN,  # noqa: E402
                        BLOCK_LEN, IV_LEN)

import jsonschema  # noqa: E402

SCHEMA = json.loads((ROOT / "testbed" / "label_schema.json").read_text())
_VALIDATOR = jsonschema.Draft7Validator(SCHEMA)

# --------------------------------------------------------------------------
# Independent byte-level IKE parser
# --------------------------------------------------------------------------
P_SA, P_KE, P_IDI, P_NONCE, P_NOTIFY, P_SK = 33, 34, 35, 40, 41, 46


class IKEError(Exception):
    pass


def parse_ike(data: bytes) -> dict:
    """Parse one IKE message (marker already stripped)."""
    if len(data) < 28:
        raise IKEError("short header")
    spi_i, spi_r = data[:8], data[8:16]
    np0, ver, exch, flags = data[16], data[17], data[18], data[19]
    msgid = struct.unpack("!I", data[20:24])[0]
    ln = struct.unpack("!I", data[24:28])[0]
    if ln != len(data):
        raise IKEError(f"length field {ln} != actual {len(data)}")
    payloads = []
    if ver == 0x10 and flags & 0x1:
        return {"spi_i": spi_i, "spi_r": spi_r, "np": np0, "ver": ver,
                "exch": exch, "flags": flags, "msgid": msgid, "len": ln,
                "payloads": payloads, "encrypted": True}
    np_, off = np0, 28
    while np_ != 0:
        if off + 4 > ln:
            raise IKEError("payload overrun")
        pn, _, pl = data[off], data[off + 1], struct.unpack("!H", data[off + 2:off + 4])[0]
        if pl < 4 or off + pl > ln:
            raise IKEError(f"bad payload len {pl}")
        payloads.append({"type": np_, "next": pn, "len": pl,
                         "body": data[off + 4:off + pl]})
        if np_ == P_SK:
            break  # next refers to encrypted inner payloads
        np_, off = pn, off + pl
    return {"spi_i": spi_i, "spi_r": spi_r, "np": np0, "ver": ver,
            "exch": exch, "flags": flags, "msgid": msgid, "len": ln,
            "payloads": payloads}


def parse_proposal(sa_body: bytes) -> dict:
    """Parse an SA payload body (after generic header) -> proposal dict."""
    if len(sa_body) < 8:
        raise IKEError("short proposal")
    nxt, _, plen = sa_body[0], sa_body[1], struct.unpack("!H", sa_body[2:4])[0]
    pnum, proto, spisz, ntr = sa_body[4], sa_body[5], sa_body[6], sa_body[7]
    off, tf = 8 + spisz, []
    for _ in range(ntr):
        if off + 8 > len(sa_body):
            raise IKEError("short transform")
        tn, _, tlen = sa_body[off], sa_body[off + 1], struct.unpack("!H", sa_body[off + 2:off + 4])[0]
        tt, _, tid = sa_body[off + 4], sa_body[off + 5], struct.unpack("!H", sa_body[off + 6:off + 8])[0]
        attrs = []
        ao = off + 8
        while ao + 4 <= off + tlen:
            at = struct.unpack("!H", sa_body[ao:ao + 2])[0]
            if at & 0x8000:
                attrs.append((at & 0x7FFF, struct.unpack("!H", sa_body[ao + 2:ao + 4])[0]))
                ao += 4
            else:
                al = struct.unpack("!H", sa_body[ao + 2:ao + 4])[0]
                attrs.append((at, sa_body[ao + 4:ao + 4 + al].hex()))
                ao += 4 + al
        tf.append({"type": tt, "id": tid, "attrs": attrs, "next": tn})
        off += tlen
    return {"proto": proto, "ntr": ntr, "transforms": tf}


def expected_init_transforms(lab: dict):
    """Expected [(type, id, keylen|None)] for the IKE SA proposal.

    Uses the IKE-suite label keys (ike_encryption/ike_auth/ike_dh_group):
    the INIT proposal describes the IKE SA, never the child suite
    (they differ for v19/v20 and v7/AH).
    """
    enc = lab.get("ike_encryption", lab["encryption"])
    if enc == "none":  # AH: IKE keeps baseline suite
        enc, auth = "aes-128-cbc", "hmac-sha256"
        dh = lab.get("ike_dh_group", lab["dh_group"])
    else:
        auth = lab.get("ike_auth", lab["auth"])
        dh = lab.get("ike_dh_group", lab["dh_group"])
    aead = enc in ("aes-128-gcm", "aes-256-gcm")
    exp = []
    eid = {"aes-128-cbc": 12, "aes-256-cbc": 12, "aes-128-gcm": 20,
           "aes-256-gcm": 20, "3des-cbc": 3}[enc]
    eklen = {"aes-128-cbc": 128, "aes-256-cbc": 256, "aes-128-gcm": 128,
             "aes-256-gcm": 256, "3des-cbc": None}[enc]
    exp.append((1, eid, eklen))
    if not aead:
        exp.append((3, {"hmac-sha256": 12, "hmac-sha1": 2}[auth], None))
        exp.append((2, {"hmac-sha256": 5, "hmac-sha1": 2}[auth], None))
    else:
        exp.append((2, {"aes-128-gcm": 5, "aes-256-gcm": 6}[enc], None))
    exp.append((4, dh, None))
    return exp


def expected_child_transforms(lab: dict):
    if lab["ipsec_protocol"] == "ah":
        exp = [(3, {"hmac-sha256": 12, "hmac-sha1": 2}[lab["auth"]], None)]
    else:
        enc = lab["encryption"]
        aead = enc in ("aes-128-gcm", "aes-256-gcm")
        eid = {"aes-128-cbc": 12, "aes-256-cbc": 12, "aes-128-gcm": 20,
               "aes-256-gcm": 20, "3des-cbc": 3}[enc]
        eklen = {"aes-128-cbc": 128, "aes-256-cbc": 256, "aes-128-gcm": 128,
                 "aes-256-gcm": 256, "3des-cbc": None}[enc]
        exp = [(1, eid, eklen)]
        if not aead:
            exp.append((3, {"hmac-sha256": 12, "hmac-sha1": 2}[lab["auth"]], None))
    if lab["pfs"]:
        exp.append((4, lab["dh_group"], None))
    return exp


def check_transforms(parsed: list, expected: list, where: str, errs: list):
    if len(parsed) != len(expected):
        errs.append(f"{where}: {len(parsed)} transforms, expected {len(expected)}")
        return
    for i, (p, e) in enumerate(zip(parsed, expected)):
        if (p["type"], p["id"]) != (e[0], e[1]):
            errs.append(f"{where} t{i}: type/id {(p['type'], p['id'])} != {(e[0], e[1])}")
        kl = dict(p["attrs"]).get(14)
        if kl != e[2]:
            errs.append(f"{where} t{i}: keylen {kl} != {e[2]}")

# --------------------------------------------------------------------------
# Packet access (scapy for structure, dpkt/tcpdump for independent counts)
# --------------------------------------------------------------------------
def load_packets(path: Path):
    from scapy.all import PcapReader, IP, IPv6, UDP
    pkts = []
    with PcapReader(str(path)) as rd:
        for p in rd:
            pkts.append(p)
    return pkts


def split_packets(pkts):
    """Return (ike list, esp list, ah list) using scapy layers + marker rule."""
    from scapy.all import IP, IPv6, UDP
    ike, esp, ah = [], [], []
    for p in pkts:
        ip = p.getlayer(IP) or p.getlayer(IPv6)
        if ip is None:
            continue
        pr = ip.proto if ip.__class__.__name__ == "IP" else ip.nh
        if pr == 50:
            esp.append(p)
        elif pr == 51:
            ah.append(p)
        elif pr == 17 and UDP in p:
            u = p[UDP]
            if u.sport in (500, 4500) or u.dport in (500, 4500):
                try:
                    pay = bytes(u.payload)
                except Exception:
                    pay = b""
                if u.dport == 500 or u.sport == 500 or pay[:4] == b"\x00" * 4:
                    ike.append((p, pay[4:] if pay[:4] == b"\x00" * 4 else pay))
                else:
                    esp.append(p)
    return ike, esp, ah


def dpkt_counts(path: Path):
    import dpkt
    n = esp = ike = ah = 0
    with open(path, "rb") as f:
        for _, buf in dpkt.pcap.Reader(f):
            n += 1
            if len(buf) < 14:
                continue
            et = struct.unpack("!H", buf[12:14])[0]
            if et == 0x0800:
                if len(buf) < 34:
                    continue
                pr, pay = buf[23], buf[34:]
            elif et == 0x86DD:
                if len(buf) < 54:
                    continue
                pr, pay = buf[20], buf[54:]
            else:
                continue
            if pr == 50:
                esp += 1
            elif pr == 51:
                ah += 1
            elif pr == 17 and len(pay) >= 8:
                sp, dp = struct.unpack("!HH", pay[:4])
                if sp in (500, 4500) or dp in (500, 4500):
                    udp = pay[8:]
                    if dp == 500 or sp == 500 or udp[:4] == b"\x00" * 4:
                        ike += 1
                    else:
                        esp += 1
    return n, esp, ike


def tcpdump_count(path: Path):
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return None
    try:
        r = subprocess.run([tcpdump, "-nn", "-r", str(path)],
                           capture_output=True, text=True, timeout=120)
        return len([l for l in r.stdout.splitlines() if l.strip()])
    except Exception:
        return None


SUBNETS4 = {"lan_a": "10.1.0.0/24", "lan_b": "10.2.0.0/24",
            "transit": "10.30.0.0/24"}
SUBNETS6 = {"lan_a": "fd00:1::/64", "lan_b": "fd00:2::/64",
            "transit": "fd00:ff::/64"}


def in_net(ip: str, net: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(net)


# --------------------------------------------------------------------------
# ESP / AH verification
# --------------------------------------------------------------------------
def _esp_raw(p):
    """ESP bytes, stripping UDP header for NAT-T encapsulation."""
    from scapy.all import IP, IPv6, UDP
    ip = p.getlayer(IP) or p.getlayer(IPv6)
    if UDP in p:
        return bytes(p[UDP].payload)
    return bytes(ip.payload)


def _check_icmp_type(fam: int, l4: bytes, errs: list, where: str):
    if len(l4) < 1:
        errs.append(f"{where} ICMP short")
        return
    t = l4[0]
    ok = (t in (8, 0)) if fam == 4 else (t in (128, 129))
    if not ok:
        errs.append(f"{where} ICMP type {t} wrong for IPv{fam}")


def check_esp_synthetic(lab: dict, esp_list, errs: list, stats: dict):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from scapy.all import IP, IPv6
    enc, auth = lab["encryption"], lab["auth"]
    aead = enc in ("aes-128-gcm", "aes-256-gcm")
    fam = lab["ip_version"]
    ivlen = 8 if aead else (8 if enc == "3des-cbc" else 16)
    icvlen = 16  # tag16 for GCM
    if not aead:
        icvlen = {"hmac-sha256": 16, "hmac-sha1": 12}[auth]
        blk = 8 if enc == "3des-cbc" else 16
    spis: dict[int, list] = {}
    for p in esp_list:
        raw = _esp_raw(p)
        if len(raw) < 8 + ivlen + icvlen + 1:
            errs.append("ESP short packet")
            continue
        spi, seq = struct.unpack("!II", raw[:8])
        iv, rest = raw[8:8 + ivlen], raw[8 + ivlen:]
        body, icv = rest[:-icvlen], rest[-icvlen:]
        keys = derive_esp_keys(lab["variant"], lab["run_id"],
                               lab["traffic_type"], f"{spi:08x}")
        ekey = keys["enc"](ENC_KEY_LEN[enc])
        try:
            if aead:
                pt = AESGCM(ekey).decrypt(keys["salt"] + iv, rest, raw[:8])
            else:
                body, icv = rest[:-icvlen], rest[-icvlen:]
                exp = hmac_mod.new(keys["mac"], raw[:8] + iv + body,
                                   hashlib.sha256).digest()[:icvlen]
                if exp != icv:
                    errs.append(f"ESP ICV mismatch spi={spi:#x} seq={seq}")
                    continue
                if len(body) % blk:
                    errs.append("ESP cipher not block-aligned")
                    continue
                if enc == "3des-cbc":
                    c = Cipher(TripleDES(ekey), modes.CBC(iv))
                else:
                    c = Cipher(algorithms.AES(ekey), modes.CBC(iv))
                d = c.decryptor()
                pt = d.update(body) + d.finalize()
        except Exception as e:
            errs.append(f"ESP decrypt fail spi={spi:#x} seq={seq}: {e}")
            continue
        padn, nh = pt[-2], pt[-1]
        if padn > len(pt) - 2:
            errs.append("ESP bad padlen")
            continue
        if list(pt[-2 - padn:-2]) != list(range(1, padn + 1)) and padn:
            errs.append("ESP bad pad bytes")
            continue
        inner = pt[:len(pt) - padn - 2]
        if lab["mode"] == "tunnel":
            if not inner or (inner[0] >> 4) != fam:
                errs.append(f"ESP tunnel inner version (nh={nh})")
                continue
            if fam == 4:
                s = ".".join(map(str, inner[12:16]))
                d = ".".join(map(str, inner[16:20]))
                if not (in_net(s, SUBNETS4["lan_a"]) and in_net(d, SUBNETS4["lan_b"])) \
                   and not (in_net(s, SUBNETS4["lan_b"]) and in_net(d, SUBNETS4["lan_a"])):
                    errs.append(f"ESP tunnel addrs {s}->{d}")
                if nh != 4:
                    errs.append(f"ESP tunnel nh={nh} != 4")
                ihl = (inner[0] & 0xF) * 4
                if inner[9] in (1,) and len(inner) >= ihl + 1:
                    _check_icmp_type(4, inner[ihl:], errs, "ESP tunnel")
            else:
                if nh != 41:
                    errs.append(f"ESP tunnel nh={nh} != 41")
                if len(inner) >= 41 and inner[6] == 58:
                    _check_icmp_type(6, inner[40:], errs, "ESP tunnel")
        else:
            if nh not in (6, 17, 1, 58):
                errs.append(f"ESP transport nh={nh}")
            elif nh == 17 and (len(inner) < 8 or
                               struct.unpack("!H", inner[4:6])[0] != len(inner)):
                errs.append("ESP transport UDP len")
            elif nh == 6 and (len(inner) < 20 or (inner[12] >> 4) != 5):
                errs.append("ESP transport TCP hlen")
            elif nh in (1, 58):
                _check_icmp_type(fam, inner, errs, "ESP transport")
        spis.setdefault(spi, []).append(seq)
    stats["spis"] = len(spis)
    if not 1 <= len(spis) <= 2:
        errs.append(f"ESP SPI count {len(spis)} not in 1..2")
    for spi, seqs in spis.items():
        if seqs[0] != 1:
            errs.append(f"SPI {spi:#x} first seq {seqs[0]} != 1")
        if any(b - a != 1 for a, b in zip(seqs, seqs[1:])):
            errs.append(f"SPI {spi:#x} seq not strictly increasing")


def check_esp_real(lab: dict, esp_list, errs: list, stats: dict):
    from scapy.all import IP, IPv6
    enc, auth = lab["encryption"], lab["auth"]
    aead = enc in ("aes-128-gcm", "aes-256-gcm")
    ivlen = 8 if aead else (8 if enc == "3des-cbc" else 16)
    icvlen = 16 if aead else {"hmac-sha256": 16, "hmac-sha1": 12}[auth]
    align = 4 if aead else (8 if enc == "3des-cbc" else 16)
    # reassemble outer-IP fragments (real captures may fragment + lose tail)
    frag_groups: dict[tuple, list] = {}
    whole = []
    for p in esp_list:
        ip = p.getlayer(IP) or p.getlayer(IPv6)
        frag = ip.frag if ip.__class__.__name__ == "IP" else 0
        mf = bool(ip.flags.MF) if ip.__class__.__name__ == "IP" else False
        if frag == 0 and not mf:
            whole.append(p)
            continue
        key = (ip.src, ip.dst, ip.id if ip.__class__.__name__ == "IP" else 0)
        from scapy.all import UDP as _UDP
        edata = bytes(p[_UDP].payload) if _UDP in p else bytes(ip.payload)
        frag_groups.setdefault(key, []).append((frag * 8, mf, edata))
    incomplete = 0
    for key, frags in frag_groups.items():
        frags.sort()
        if not frags[-1][1]:
            total = frags[-1][0] + len(frags[-1][2])
            covered = [False] * total
            for off, _, data in frags:
                for i in range(off, min(off + len(data), total)):
                    covered[i] = True
            if not all(covered):
                incomplete += 1
                continue
            raw = bytearray(total)
            for off, _, data in frags:
                raw[off:off + len(data)] = data[:max(0, total - off)]
            if (len(raw) - 8 - ivlen - icvlen) % align:
                errs.append("reassembled ESP cipher misaligned")
        else:
            incomplete += 1  # tail fragment lost in capture
    if incomplete:
        stats["frag_loss"] = incomplete
    spis: dict[int, list] = {}
    for p in whole:
        raw = _esp_raw(p)
        if len(raw) < 8 + ivlen + icvlen + 1:
            errs.append("ESP short packet")
            continue
        spi, seq = struct.unpack("!II", raw[:8])
        if (len(raw) - 8 - ivlen - icvlen) % align:
            errs.append(f"ESP cipher misaligned spi={spi:#x}")
        spis.setdefault(spi, []).append(seq)
    # first fragments carry a full ESP header: include their seqs
    for key, frags in frag_groups.items():
        frags.sort()
        if frags[0][0] == 0 and len(frags[0][2]) >= 8:
            spi, seq = struct.unpack("!II", frags[0][2][:8])
            spis.setdefault(spi, []).append(seq)
    stats["spis"] = len(spis)
    if not 1 <= len(spis) <= 2:
        errs.append(f"ESP SPI count {len(spis)} not in 1..2")
    for spi, seqs in spis.items():
        # real captures may reorder neighbors: require the contiguous set
        if set(seqs) != set(range(1, max(seqs) + 1)):
            errs.append(f"SPI {spi:#x} seq not contiguous")


def check_ah(lab: dict, ah_list, errs: list, stats: dict, decrypt: bool):
    from scapy.all import IP, IPv6
    for p in ah_list:
        ip = p.getlayer(IP) or p.getlayer(IPv6)
        raw = bytes(ip.payload)
        if len(raw) < 28:
            errs.append("AH short")
            continue
        nh, ln = raw[0], raw[1]
        spi, seq = struct.unpack("!II", raw[4:12])
        if ln != 5:
            errs.append(f"AH len field {ln} != 5")
        exp_nh = 4 if lab["ip_version"] == 4 else 41
        if lab["mode"] == "tunnel" and nh != exp_nh:
            errs.append(f"AH nh={nh} != {exp_nh}")
        if decrypt:
            inner = raw[28:]
            exp = hmac_mod.new(
                derive_esp_keys(lab["variant"], lab["run_id"],
                                lab["traffic_type"], f"{spi:08x}")["mac"],
                struct.pack("!II", spi, seq) + inner,
                hashlib.sha256).digest()[:16]
            if exp != raw[12:28]:
                errs.append(f"AH ICV mismatch seq={seq}")
            elif not inner or (inner[0] >> 4) != lab["ip_version"]:
                errs.append("AH inner version")
    stats["ah"] = len(ah_list)

# --------------------------------------------------------------------------
# IKE checks
# --------------------------------------------------------------------------
def decrypt_ike_sk(enc: str, auth: str, ike_keys, sk_body: bytes) -> bytes:
    """Decrypt an SK payload body (after generic header) with the
    deterministic synthetic IKE keys. Returns plaintext incl. zero pad."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    klen = {"aes-128-cbc": 16, "aes-256-cbc": 32, "aes-128-gcm": 16,
            "aes-256-gcm": 32, "3des-cbc": 24}[enc]
    ekey = ike_keys["enc"](klen)
    aead = enc in ("aes-128-gcm", "aes-256-gcm")
    if aead:
        iv, ct = sk_body[:8], sk_body[8:]
        return AESGCM(ekey).decrypt(ike_keys["salt"] + iv, ct, b"")
    ivlen = 8 if enc == "3des-cbc" else 16
    icvlen = {"hmac-sha256": 16, "hmac-sha1": 12}[auth]
    iv, rest = sk_body[:ivlen], sk_body[ivlen:]
    body, icv = rest[:-icvlen], rest[-icvlen:]
    exp = hmac_mod.new(ike_keys["mac"], iv + body,
                       hashlib.sha256).digest()[:icvlen]
    if exp != icv:
        raise IKEError("SK ICV mismatch")
    blk = 8 if enc == "3des-cbc" else 16
    if len(body) % blk:
        raise IKEError("SK cipher not block-aligned")
    if enc == "3des-cbc":
        c = Cipher(TripleDES(ekey), modes.CBC(iv))
    else:
        c = Cipher(algorithms.AES(ekey), modes.CBC(iv))
    d = c.decryptor()
    return d.update(body) + d.finalize()


def walk_inner(inner: bytes, first_type: int) -> list:
    """Walk clear payloads inside decrypted SK; tolerate trailing pad."""
    out, off, cur = [], 0, first_type
    while off + 4 <= len(inner):
        if inner[off:off + 4] == b"\x00" * 4:
            break  # zero pad region
        pn, pl = inner[off], struct.unpack("!H", inner[off + 2:off + 4])[0]
        if pl < 8 or off + pl > len(inner):
            break  # pad / malformed tail: stop, don't fail
        out.append({"type": cur, "next": pn, "len": pl,
                    "body": inner[off + 4:off + pl]})
        cur, off = pn, off + pl
    return out


def check_ikev2(lab: dict, ike_list, errs: list, stats: dict,
                need_rekey: bool):
    msgs = []
    for _, raw in ike_list:
        try:
            msgs.append(parse_ike(raw))
        except IKEError as e:
            errs.append(f"IKE parse: {e}")
    by_exch: dict[int, list] = {}
    for m in msgs:
        by_exch.setdefault(m["exch"], []).append(m)
    stats["exchanges"] = sorted(by_exch)
    init = [m for m in by_exch.get(34, [])
            if m["msgid"] == 0 and m["ver"] == 0x20]
    reqs = [m for m in init if m["flags"] == 0x08]
    resps = [m for m in init if m["flags"] == 0x20]
    if not reqs or not resps:
        errs.append("IKE_SA_INIT req/resp pair missing")
        return
    if reqs[0]["spi_r"] != b"\x00" * 8:
        errs.append("INIT req responder SPI nonzero")
    sa = next((p for p in reqs[0]["payloads"] if p["type"] == P_SA), None)
    if sa is None:
        errs.append("INIT req missing SA")
        return
    try:
        prop = parse_proposal(sa["body"])
    except IKEError as e:
        errs.append(f"INIT SA parse: {e}")
        return
    if prop["proto"] != 1:
        errs.append("INIT proposal proto != IKE")
    check_transforms(prop["transforms"], expected_init_transforms(lab),
                     "INIT", errs)
    ke = next((p for p in reqs[0]["payloads"] if p["type"] == P_KE), None)
    if ke is None:
        errs.append("INIT req missing KE")
    else:
        ike_dh = lab.get("ike_dh_group", lab["dh_group"])
        dh = struct.unpack("!H", ke["body"][:2])[0]
        if dh != ike_dh:
            errs.append(f"INIT KE group {dh} != {ike_dh}")
        if len(ke["body"]) - 4 != DH_PUB_LEN[ike_dh]:
            errs.append("INIT KE wrong length")
    if not any(p["type"] == P_NONCE for p in reqs[0]["payloads"]):
        errs.append("INIT req missing Nonce")
    auth = [m for m in by_exch.get(35, []) if m["msgid"] == 1]
    areq = [m for m in auth if m["flags"] == 0x08]
    aresp = [m for m in auth if m["flags"] == 0x20]
    if not areq or not aresp:
        errs.append("IKE_AUTH req/resp pair missing")
    else:
        for m, w in ((areq[0], "AUTH req"), (aresp[0], "AUTH resp")):
            if m["np"] != P_SK:
                errs.append(f"{w} first payload != SK")
            sk = next((p for p in m["payloads"] if p["type"] == P_SK), None)
            if sk is None:
                errs.append(f"{w} missing SK")
            elif not 150 <= sk["len"] <= 600:
                errs.append(f"{w} SK len {sk['len']} unrealistic")
            elif need_rekey:
                _check_auth_sk(lab, m, errs)
    if need_rekey:
        rk = [m for m in by_exch.get(36, []) if m["msgid"] == 2]
        rreq = [m for m in rk if m["flags"] == 0x08]
        rresp = [m for m in rk if m["flags"] == 0x20]
        if not rreq or not rresp:
            errs.append("CREATE_CHILD_SA rekey pair missing")
    else:
        # real rows: rekey msgid is whatever the session used; pair up
        # req/resp by msgid. strongSwan encrypts the whole CREATE_CHILD_SA
        # (message.c: all payloads encr=TRUE), so real rekeys are SK-only:
        # verify content only when a clear SA is present, else note.
        by_id: dict[int, list] = {}
        for m in by_exch.get(36, []):
            by_id.setdefault(m["msgid"], []).append(m)
        rreq = [m for v in by_id.values() for m in v
                if m["flags"] == 0x08]
        rresp = [m for v in by_id.values() for m in v
                 if m["flags"] == 0x20]
        if not rreq or not rresp:
            stats["note"] = "no rekey on the wire (real row)"
            rreq, rresp = [], []
    if rreq and rresp:
        if not need_rekey:
            stats["rekey"] = "present but opaque (SK-only real rekey; " \
                "PFS not wire-visible)"
        else:
            _check_rekey_sk(lab, rreq[0], rresp[0], errs, stats)
    elif not need_rekey:
        stats["note"] = "no rekey on the wire (real row)"


def _ike_suite_algs(lab: dict):
    """Decryption suite for IKE AUTH/rekey SK blobs: the IKE SA suite
    (ike_* label keys), never the child suite."""
    enc = lab.get("ike_encryption", lab["encryption"])
    if enc == "none":
        enc = "aes-128-cbc"
    auth = lab.get("ike_auth", lab["auth"])
    if enc.endswith("gcm"):
        auth = "aead"
    elif auth in ("aead", "none"):
        auth = "hmac-sha256"
    return enc, auth


def _check_rekey_sk(lab: dict, req, resp, errs: list, stats: dict):
    """Decrypt synthetic rekey SK pair; verify N+SA+No+[KE]+TSi+TSr."""
    enc, auth = _ike_suite_algs(lab)
    from synth_pcap import derive_ike_keys
    keys = derive_ike_keys(lab["variant"], lab["run_id"], lab["traffic_type"])
    for m, w in ((req, "rekey req"), (resp, "rekey resp")):
        sk = next((p for p in m["payloads"] if p["type"] == P_SK), None)
        if sk is None:
            errs.append(f"{w} missing SK")
            continue
        try:
            inner = decrypt_ike_sk(enc, auth, keys, sk["body"])
        except IKEError as e:
            errs.append(f"{w} SK decrypt: {e}")
            continue
        chain = walk_inner(inner, sk["next"])
        types = [p["type"] for p in chain]
        if 33 not in types or 40 not in types:
            errs.append(f"{w} SK inner missing SA/Nonce: {types}")
            continue
        sa = next(p for p in chain if p["type"] == 33)
        try:
            cprop = parse_proposal(sa["body"])
        except IKEError as e:
            errs.append(f"{w} inner SA parse: {e}")
            continue
        exp_proto = 2 if lab["ipsec_protocol"] == "ah" else 3
        if cprop["proto"] != exp_proto:
            errs.append(f"{w} inner child proto mismatch")
        check_transforms(cprop["transforms"],
                         expected_child_transforms(lab), f"{w} inner", errs)
        ke = next((p for p in chain if p["type"] == 34), None)
        if lab["pfs"]:
            if ke is None:
                errs.append(f"{w} inner missing PFS KE")
            else:
                dh = struct.unpack("!H", ke["body"][:2])[0]
                if dh != lab["dh_group"] or \
                        len(ke["body"]) - 4 != DH_PUB_LEN[dh]:
                    errs.append(f"{w} inner KE group/len mismatch")
        elif ke is not None:
            errs.append(f"{w} inner KE present but pfs=false")
    stats["rekey"] = "SK decrypted, inner SA/KE verified"


def _check_auth_sk(lab: dict, msg, errs: list):
    """Decrypt synthetic IKE_AUTH SK; verify IDi/AUTH/SA/TSi/TSr chain."""
    enc, auth = _ike_suite_algs(lab)
    from synth_pcap import derive_ike_keys
    keys = derive_ike_keys(lab["variant"], lab["run_id"], lab["traffic_type"])
    sk = next((p for p in msg["payloads"] if p["type"] == P_SK), None)
    if sk is None:
        return False
    try:
        inner = decrypt_ike_sk(enc, auth, keys, sk["body"])
    except IKEError as e:
        errs.append(f"AUTH SK decrypt: {e}")
        return False
    chain = walk_inner(inner, sk["next"])
    types = [p["type"] for p in chain]
    if not types or types[0] != 35:
        errs.append("AUTH SK inner must start with IDi")
        return False
    for t in (39, 33, 44, 45):
        if t not in types:
            errs.append(f"AUTH SK inner missing payload {t}")
            return False
    sa = next(p for p in chain if p["type"] == 33)
    try:
        cprop = parse_proposal(sa["body"])
    except IKEError as e:
        errs.append(f"AUTH inner SA parse: {e}")
        return False
    exp_proto = 2 if lab["ipsec_protocol"] == "ah" else 3
    if cprop["proto"] != exp_proto:
        errs.append("AUTH inner child proto mismatch")
    check_transforms(cprop["transforms"], expected_child_transforms(lab),
                     "AUTH inner", errs)
    return True


def check_ikev1(lab: dict, ike_list, errs: list, stats: dict,
                need_rekey: bool):
    msgs = []
    for _, raw in ike_list:
        try:
            msgs.append(parse_ike(raw))
        except IKEError as e:
            errs.append(f"IKEv1 parse: {e}")
    mm = [m for m in msgs if m["exch"] == 2 and m["ver"] == 0x10]
    qm = [m for m in msgs if m["exch"] == 32 and m["ver"] == 0x10]
    stats["mm"], stats["qm"] = len(mm), len(qm)
    if len(mm) < 6:
        errs.append(f"MM messages {len(mm)} < 6")
    mm1 = next((m for m in mm if m["np"] == 1 and m["spi_r"] == b"\x00" * 8),
               None)
    if mm1 is None:
        errs.append("MM1 (SA) missing")
    else:
        sa = next((p for p in mm1["payloads"] if p["type"] == 1), None)
        if sa is None or len(sa["body"]) < 8:
            errs.append("MM1 SA body short")
        else:
            prop_off = 8  # DOI(4) + Situation(4)
            try:
                prop = parse_proposal(sa["body"][prop_off:])
            except IKEError as e:
                errs.append(f"MM1 proposal: {e}")
                prop = None
            if prop is not None:
                exp_enc = {"aes-128-cbc": 7, "aes-256-cbc": 7,
                           "3des-cbc": 5}[lab["encryption"]]
                exp_h = {"hmac-sha256": 4, "hmac-sha1": 2}[lab["auth"]]
                want = {1: exp_enc, 14: lab["key_length_bits"]
                        if lab["encryption"] != "3des-cbc" else None,
                        2: exp_h, 4: lab["dh_group"], 3: 1}
                got = dict(prop["transforms"][0]["attrs"]) if prop["transforms"] else {}
                for k, wval in want.items():
                    if wval is None:
                        continue
                    if got.get(k) != wval:
                        errs.append(f"MM1 attr {k}={got.get(k)} != {wval}")
    ke_ok = any(p["type"] == 4 and p["len"] == 4 + DH_PUB_LEN[lab["dh_group"]]
                for m in mm for p in m["payloads"])
    if not ke_ok:
        errs.append("MM KE length mismatch")
    if not any(m["flags"] == 0x1 for m in mm):
        errs.append("MM5/MM6 encrypted flag missing")
    if not qm:
        errs.append("Quick Mode missing")
    if need_rekey and len(qm) < 2:
        errs.append(f"QM exchanges {len(qm)} < 2 (rekey)")


# --------------------------------------------------------------------------
# Row validation + manifest loop
# --------------------------------------------------------------------------
def label_path_for(pcap_rel: str) -> Path:
    parts = Path(pcap_rel).parts
    if parts[1] == "pcaps":
        return ROOT / "data" / "labels" / Path(*parts[2:]).with_suffix(".json")
    return ROOT / "data" / "labels" / "real" / \
        Path(*parts[2:]).with_suffix(".json")


def validate_row(row: dict) -> dict:
    errs: list[str] = []
    stats: dict = {}
    try:
        return _validate_row_inner(row, errs, stats)
    except Exception as e:  # validator must never crash on a bad row
        errs.append(f"validator exception: {type(e).__name__}: {e}")
        return {"file": row["file"], "valid": False, "errors": errs,
                "stats": stats}


def _validate_row_inner(row: dict, errs: list, stats: dict) -> dict:
    p = ROOT / row["file"]
    if not p.exists():
        return {"file": row["file"], "valid": False,
                "errors": ["missing file"], "stats": stats}
    try:
        pkts = load_packets(p)
    except Exception as e:
        return {"file": row["file"], "valid": False,
                "errors": [f"parse: {e}"], "stats": stats}
    ike, esp, ah = split_packets(pkts)
    n_dpkt = dpkt_counts(p)
    if (len(pkts), len(esp), len(ike)) != n_dpkt:
        errs.append(f"scapy/dpkt count mismatch {len(pkts), len(esp), len(ike)} vs {n_dpkt}")
    td = tcpdump_count(p)
    if td is not None and td != len(pkts):
        errs.append(f"tcpdump count {td} != {len(pkts)}")
    if row["packets"] != len(pkts) or row["esp_packets"] != len(esp) or \
            row["ike_packets"] != len(ike):
        errs.append("manifest counts != pcap")
    lab = None
    try:
        lab = json.loads(label_path_for(row["file"]).read_text())
    except Exception as e:
        errs.append(f"label: {e}")
    if lab is not None:
        for req in ("variant", "traffic_type", "ip_version", "source"):
            key = {"variant": "variant", "traffic_type": "traffic",
                   "ip_version": "ip_version", "source": "source"}[req]
            if lab.get(req) != row[key]:
                errs.append(f"label {req} != manifest")
        for e in _VALIDATOR.iter_errors(lab):
            errs.append(f"schema: {'/'.join(map(str, e.path))}: {e.message}")
            break
        if lab.get("packet_count") != len(pkts):
            errs.append("label packet_count != pcap")
        if pkts:
            dur = float(pkts[-1].time) - float(pkts[0].time)
            if abs(dur - lab.get("duration_s", -1)) > 0.01:
                errs.append("label duration != pcap")
        if lab.get("variant") == "plain":
            if esp or ah or ike:
                errs.append("negative contains IPsec")
        else:
            synth = lab.get("source") == "synthetic"
            if lab.get("ike_version") == "ikev2":
                check_ikev2(lab, ike, errs, stats, need_rekey=synth)
            elif lab.get("ike_version") == "ikev1":
                check_ikev1(lab, ike, errs, stats, need_rekey=synth)
            if lab.get("ipsec_protocol") == "esp":
                if not esp:
                    errs.append("no ESP packets")
                elif synth:
                    check_esp_synthetic(lab, esp, errs, stats)
                else:
                    check_esp_real(lab, esp, errs, stats)
            elif lab.get("ipsec_protocol") == "ah":
                if not ah:
                    errs.append("no AH packets")
                else:
                    check_ah(lab, ah, errs, stats, decrypt=synth)
            if not synth:
                stats["note"] = "real: rekey + decrypt checks skipped (no keys)"
    return {"file": row["file"], "valid": not errs, "errors": errs,
            "stats": stats}


def run_manifest(manifest: Path):
    rows = list(csv.DictReader(manifest.open()))
    out_rows, results = [], []
    bad = 0
    for i, row in enumerate(rows):
        row["packets"] = int(row["packets"])
        row["esp_packets"] = int(row["esp_packets"])
        row["ike_packets"] = int(row["ike_packets"])
        row["ip_version"] = int(row["ip_version"])
        res = validate_row(row)
        results.append(res)
        row["valid"] = str(res["valid"])
        out_rows.append(row)
        if not res["valid"]:
            bad += 1
            print(f"INVALID {row['file']}: {res['errors'][:3]}")
        elif (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(rows)} ok")
    with manifest.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "variant", "traffic",
                                          "ip_version", "packets",
                                          "esp_packets", "ike_packets",
                                          "source", "valid"])
        w.writeheader()
        w.writerows(out_rows)
    (ROOT / "data" / "validation.json").write_text(json.dumps(
        {"rows": len(rows), "invalid": bad,
         "results": {r["file"]: {"valid": r["valid"], "errors": r["errors"],
                                 "stats": r["stats"]} for r in results}},
        indent=1))
    print(f"{len(rows) - bad}/{len(rows)} valid")
    return bad


# --------------------------------------------------------------------------
# Self-test: positive control + mutation negatives (D7/D10)
# --------------------------------------------------------------------------
def _selftest_row(pcap: Path, lab: dict, tmp: Path) -> dict:
    from scapy.all import PcapReader, IP, IPv6, UDP
    n = esp = ike = 0
    with PcapReader(str(pcap)) as rd:
        for pkt in rd:
            n += 1
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue
            pr = ip.proto if ip.__class__.__name__ == "IP" else ip.nh
            if pr == 50:
                esp += 1
            elif pr == 17 and UDP in pkt:
                u = pkt[UDP]
                try:
                    pay = bytes(u.payload)
                except Exception:
                    pay = b""
                if u.dport == 500 or u.sport == 500 or pay[:4] == b"\x00" * 4:
                    ike += 1
                else:
                    esp += 1
    return {"file": str(pcap.relative_to(ROOT)), "variant": lab["variant"],
            "traffic": lab["traffic_type"], "ip_version": lab["ip_version"],
            "packets": n, "esp_packets": esp, "ike_packets": ike,
            "source": lab["source"]}


def self_test() -> int:
    """Generate small corpus in data/.selftest (cleaned up), mutate, check."""
    from scapy.all import rdpcap, wrpcap, IP, IPv6, UDP
    import synth_pcap
    work = ROOT / "data" / ".selftest"
    shutil.rmtree(work, ignore_errors=True)
    (work / "pcaps").mkdir(parents=True)
    (work / "labels").mkdir(parents=True)
    fails = []

    def gen(vid, tr, run, fam=None):
        if vid == "plain":
            pkts, info = synth_pcap.build_plain(tr, fam, run)
            sub = f"plain/v{fam}/{run}"
            lab = synth_pcap.label_for(vid, tr, run, fam, info["duration"],
                                       len(pkts))
        else:
            pkts, info = synth_pcap.build_pcap(vid, tr, run)
            v = matrix.BY_ID[vid]
            sub = f"{vid}/{run}"
            lab = synth_pcap.label_for(vid, tr, run, v["ip_version"],
                                       info["duration"], len(pkts))
        pp = work / "pcaps" / sub / f"{tr}.pcap"
        lp = work / "labels" / sub / f"{tr}.json"
        pp.parent.mkdir(parents=True, exist_ok=True)
        lp.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(pp), pkts)
        lp.write_text(json.dumps(lab))
        # repo-relative mirror so label_path_for() resolves
        rp = ROOT / "data" / "pcaps" / "synth" / sub / f"{tr}.pcap"
        rl = ROOT / "data" / "labels" / "synth" / sub / f"{tr}.json"
        rp.parent.mkdir(parents=True, exist_ok=True)
        rl.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(pp, rp)
        shutil.copy(lp, rl)
        row = _selftest_row(rp, lab, work)
        return rp, rl, row, lab

    def check(name, row, expect_valid):
        res = validate_row(row)
        ok = res["valid"] == expect_valid
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: "
              f"valid={res['valid']} (want {expect_valid}) "
              f"{'' if ok else res['errors'][:2]}")
        if not ok:
            fails.append(name)

    def repayload(pkt, raw: bytes):
        """Rebuild Ether/IP packet with replaced IP payload (keeps time)."""
        from scapy.all import Ether, IP, IPv6, Raw
        eth = pkt[Ether]
        if IP in pkt:
            ip = pkt[IP]
            newp = Ether(src=eth.src, dst=eth.dst, type=eth.type) / \
                IP(src=ip.src, dst=ip.dst, proto=ip.proto, ttl=ip.ttl,
                   id=ip.id) / Raw(load=raw)
        else:
            ip = pkt[IPv6]
            newp = Ether(src=eth.src, dst=eth.dst, type=eth.type) / \
                IPv6(src=ip.src, dst=ip.dst, nh=ip.nh, hlim=ip.hlim) / \
                Raw(load=raw)
        newp.time = pkt.time
        return newp

    def mutate_drop_ike(rp, keep_exch):
        """Drop IKE packets whose exchange not in keep set."""
        pkts = rdpcap(str(rp))
        keep = []
        for p in pkts:
            if UDP in p and (p[UDP].sport in (500, 4500) or
                             p[UDP].dport in (500, 4500)):
                b = bytes(p[UDP].payload)
                if b[:4] == b"\x00" * 4:
                    b = b[4:]
                if len(b) >= 28 and b[18] in keep_exch:
                    keep.append(p)
            else:
                keep.append(p)
        return keep

    # positive controls
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    rp7, rl7, row7, lab7 = gen("v7", "voip", "st1")
    rpp, rlp, rowp, labp = gen("plain", "icmp", "st1", 4)
    check("positive v1", dict(row1), True)
    check("positive v7", dict(row7), True)
    check("positive plain", dict(rowp), True)

    # 1. missing INIT
    wrpcap(str(rp1), mutate_drop_ike(rp1, {35, 36}))
    check("no INIT", dict(row1), False)
    # restore
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 2. missing AUTH
    wrpcap(str(rp1), mutate_drop_ike(rp1, {34, 36}))
    check("no AUTH", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 3. missing rekey
    wrpcap(str(rp1), mutate_drop_ike(rp1, {34, 35}))
    check("no rekey", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 4. label dh mismatch
    lab1["dh_group"] = 20
    rl1.write_text(json.dumps(lab1))
    check("label dh mismatch", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 5. label encryption mismatch
    lab1["encryption"] = "aes-256-cbc"
    lab1["key_length_bits"] = 256
    rl1.write_text(json.dumps(lab1))
    check("label enc mismatch", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 6. mode flip tunnel->transport
    lab1["mode"] = "transport"
    rl1.write_text(json.dumps(lab1))
    check("mode flip", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 7. tampered ESP ciphertext
    pkts = rdpcap(str(rp1))
    out = []
    done = False
    for p in pkts:
        if not done and IP in p and p[IP].proto == 50:
            raw = bytearray(bytes(p[IP].payload))
            raw[30] ^= 0xFF
            out.append(repayload(p, bytes(raw)))
            done = True
        else:
            out.append(p)
    wrpcap(str(rp1), out)
    check("ESP tamper", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 8. SPI changed on one packet
    pkts = rdpcap(str(rp1))
    out = []
    done = False
    for p in pkts:
        if not done and IP in p and p[IP].proto == 50:
            raw = bytearray(bytes(p[IP].payload))
            raw[:4] = b"\xde\xad\xbe\xef"
            out.append(repayload(p, bytes(raw)))
            done = True
        else:
            out.append(p)
    wrpcap(str(rp1), out)
    check("SPI flip", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 9. ESP injected into plain
    pkts = rdpcap(str(rpp))
    esp_pkt = [p for p in rdpcap(str(rp1))
               if IP in p and p[IP].proto == 50][0]
    wrpcap(str(rpp), list(pkts) + [esp_pkt])
    rowp2 = _selftest_row(rpp, labp, work)
    check("plain+ESP", rowp2, False)
    # 10. manifest count+1
    bad = dict(row1)
    bad["packets"] += 1
    check("count mismatch", bad, False)
    # 11. label schema violation
    del lab1["dh_group"]
    rl1.write_text(json.dumps(lab1))
    check("label schema", dict(row1), False)
    rp1, rl1, row1, lab1 = gen("v1", "voip", "st1")
    # 12. AH ICV tamper
    pkts = rdpcap(str(rp7))
    out = []
    done = False
    for p in pkts:
        if not done and IP in p and p[IP].proto == 51:
            raw = bytearray(bytes(p[IP].payload))
            raw[12] ^= 0xFF
            out.append(repayload(p, bytes(raw)))
            done = True
        else:
            out.append(p)
    wrpcap(str(rp7), out)
    check("AH tamper", dict(row7), False)

    # cleanup mirrors
    for sub in ("v1/st1", "v7/st1", "plain/v4/st1"):
        shutil.rmtree(ROOT / "data" / "pcaps" / "synth" / sub,
                      ignore_errors=True)
        shutil.rmtree(ROOT / "data" / "labels" / "synth" / sub,
                      ignore_errors=True)
    shutil.rmtree(work, ignore_errors=True)
    print(f"self-test: {len(fails)} failures: {fails}")
    return len(fails)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="data/manifest.csv")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return 0 if self_test() == 0 else 1
    bad = run_manifest(ROOT / args.manifest)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())



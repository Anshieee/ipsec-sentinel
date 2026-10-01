"""Feature extraction from packet bytes ONLY (M3 guardrail 1).

``extract(pcap_path)`` reads the pcap and nothing else: it never opens
label JSONs, never parses filenames/run ids, never touches the manifest.
Labels are used only as targets in training/evaluation code.

To enforce this, endpoint values (IPs, MACs, ports, SPIs, cookies,
absolute epochs) are NEVER stored as features — only counts, ratios,
and distribution statistics derived from them. A test suite
(`engine/tests/test_no_labels.py`) hides `data/labels` and asserts
byte-identical features and predictions.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "capture"))
from validate_pcap import parse_ike, IKEError  # noqa: E402  (tested parser)

FEAT_VERSION = 5  # bump when the feature schema changes (invalidates cache)

EXCHANGES = {34: "init", 35: "auth", 36: "rekey", 37: "info", 2: "mm",
             4: "qm_aggr", 32: "qm"}


def _ip_layer(p):
    from scapy.all import IP, IPv6
    return p.getlayer(IP) or p.getlayer(IPv6)


def extract(pcap_path: str | Path) -> dict:
    from scapy.all import PcapReader, IP, UDP, TCP
    feats: dict = {}
    sizes, iats = [], []
    n_ike = n_esp = n_ah = n_4500m = n_esp_udp = n_500 = 0
    ah_nh = -1
    ike_msgs = []
    spi_set, seq_gaps = set(), 0
    last_seq: dict[int, int] = {}
    flows: dict[tuple, int] = {}
    sports, dports = set(), set()
    esp_lens, mods16, mods8, mods4 = [], [0] * 16, [0] * 8, [0] * 4
    ipvers = set()
    protos = set()
    tcp_flags = set()
    t0 = t_prev = None
    n = 0
    with PcapReader(str(pcap_path)) as rd:
        for p in rd:
            n += 1
            t = float(p.time)
            if t0 is None:
                t0 = t
            else:
                iats.append(t - t_prev)
            t_prev = t
            sizes.append(len(p))
            ip = _ip_layer(p)
            if ip is None:
                continue
            fam = 4 if ip.__class__.__name__ == "IP" else 6
            ipvers.add(fam)
            pr = ip.proto if fam == 4 else ip.nh
            protos.add(pr)
            flows[(ip.src, ip.dst)] = flows.get((ip.src, ip.dst), 0) + 1
            if UDP in p:
                u = p[UDP]
                sports.add(u.sport)
                dports.add(u.dport)
            if TCP in p:
                t_ = p[TCP]
                sports.add(t_.sport)
                dports.add(t_.dport)
                tcp_flags.add(int(t_.flags))
            if pr == 50:
                n_esp += 1
                raw = bytes(ip.payload)
                if len(raw) >= 8:
                    spi, seq = struct.unpack("!II", raw[:8])
                    spi_set.add(spi)
                    if spi in last_seq and seq != last_seq[spi] + 1:
                        seq_gaps += 1
                    last_seq[spi] = seq
                esp_lens.append(len(raw))
                mods16[len(raw) % 16] += 1
                mods8[len(raw) % 8] += 1
                mods4[len(raw) % 4] += 1
            elif pr == 51:
                n_ah += 1
                try:
                    raw = bytes(ip.payload)
                    if raw and ah_nh == -1:
                        ah_nh = raw[0]
                except Exception:
                    pass
            elif pr == 17 and UDP in p:
                u = p[UDP]
                pay = bytes(u.payload)
                if u.sport in (500, 4500) or u.dport in (500, 4500):
                    if u.dport == 500 or u.sport == 500 or \
                            pay[:4] == b"\x00" * 4:
                        n_ike += 1
                        if u.sport == 500 or u.dport == 500:
                            n_500 += 1
                        else:
                            n_4500m += 1
                        body = pay[4:] if pay[:4] == b"\x00" * 4 else pay
                        try:
                            ike_msgs.append(parse_ike(body))
                        except IKEError:
                            pass
                    else:
                        n_esp += 1
                        n_esp_udp += 1
                        if len(pay) >= 8:
                            spi, seq = struct.unpack("!II", pay[:8])
                            spi_set.add(spi)
                            if spi in last_seq and seq != last_seq[spi] + 1:
                                seq_gaps += 1
                            last_seq[spi] = seq
                        esp_lens.append(len(pay))
                        mods16[len(pay) % 16] += 1
                        mods8[len(pay) % 8] += 1
                        mods4[len(pay) % 4] += 1
    feats["n_packets"] = n
    feats["duration"] = (t_prev - t0) if n > 1 else 0.0
    feats["n_ike"] = n_ike
    feats["n_esp"] = n_esp
    feats["n_ah"] = n_ah
    feats["n_udp500"] = n_500
    feats["n_udp4500_marked"] = n_4500m
    feats["n_esp_in_udp"] = n_esp_udp
    feats["has_ike"] = int(n_ike > 0)
    feats["has_esp"] = int(n_esp > 0)
    feats["has_ah"] = int(n_ah > 0)
    feats["n_spis"] = len(spi_set)
    feats["seq_gaps"] = seq_gaps
    feats["n_flows"] = len(flows)
    if flows:
        top = max(flows.values())
        feats["flow_dom_ratio"] = top / n
    else:
        feats["flow_dom_ratio"] = 0.0
    feats["n_sports"] = len(sports)
    feats["n_dports"] = len(dports)
    feats["ip_version"] = next(iter(ipvers)) if len(ipvers) == 1 else 0
    feats["has_tcp"] = int(6 in protos)
    feats["has_udp"] = int(17 in protos)
    feats["has_icmp"] = int(1 in protos or 58 in protos)
    feats["tcp_flag_or"] = 0
    for f in tcp_flags:
        feats["tcp_flag_or"] |= f
    for stat, vals in (("pktlen", sizes), ("iat", iats), ("esplen", esp_lens)):
        if vals:
            s = sorted(vals)
            feats[f"{stat}_mean"] = sum(vals) / len(vals)
            feats[f"{stat}_std"] = (sum((v - sum(vals) / len(vals)) ** 2
                                        for v in vals) / len(vals)) ** 0.5
            feats[f"{stat}_min"] = s[0]
            feats[f"{stat}_max"] = s[-1]
            feats[f"{stat}_p50"] = s[len(s) // 2]
        else:
            for k in ("mean", "std", "min", "max", "p50"):
                feats[f"{stat}_{k}"] = 0.0
    for i, c in enumerate(mods16):
        feats[f"mod16_{i}"] = c
    for i, c in enumerate(mods8):
        feats[f"mod8_{i}"] = c
    for i, c in enumerate(mods4):
        feats[f"mod4_{i}"] = c
    # IKE-derived (cleartext only)
    feats["ike_exchanges"] = ",".join(sorted(
        {EXCHANGES.get(m["exch"], str(m["exch"])) for m in ike_msgs}))
    feats["ike_n"] = len(ike_msgs)
    prop = ke_len = ke_group = None
    rekey = rk_req = rk_resp = 0
    for m in ike_msgs:
        if m["exch"] == 36:
            rekey = 1
            sk = next((p for p in m["payloads"] if p["type"] == 46), None)
            if m["flags"] == 0x08 and sk is not None:
                rk_req = sk["len"]
            if m["flags"] == 0x20 and sk is not None:
                rk_resp = sk["len"]
        if m["exch"] == 34 and m["ver"] == 0x20:
            sa = next((p for p in m["payloads"] if p["type"] == 33), None)
            if sa and len(sa["body"]) >= 8:
                try:
                    from validate_pcap import parse_proposal
                    pr = parse_proposal(sa["body"])
                    prop = pr
                except IKEError:
                    pass
            ke = next((p for p in m["payloads"] if p["type"] == 34), None)
            if ke and len(ke["body"]) >= 4:
                ke_group = struct.unpack("!H", ke["body"][:2])[0]
                ke_len = len(ke["body"]) - 4
    for k in ("ike_proto", "ike_ntr", "ike_dh", "ike_encr", "ike_integ",
              "ike_prf"):
        feats[k] = -1
    for i in range(4):
        for k in ("type", "id", "keylen"):
            feats[f"ike_t{i}_{k}"] = -1
    if prop:
        tf = prop["transforms"]
        feats["ike_proto"] = prop["proto"]
        feats["ike_ntr"] = prop["ntr"]
        for i, t in enumerate(tf[:4]):
            feats[f"ike_t{i}_type"] = t["type"]
            feats[f"ike_t{i}_id"] = t["id"]
            feats[f"ike_t{i}_keylen"] = dict(t["attrs"]).get(14, -1)
        feats["ike_dh"] = next((t["id"] for t in tf if t["type"] == 4), -1)
        feats["ike_encr"] = next((t["id"] for t in tf if t["type"] == 1), -1)
        feats["ike_integ"] = next((t["id"] for t in tf if t["type"] == 3), -1)
        feats["ike_prf"] = next((t["id"] for t in tf if t["type"] == 2), -1)
    feats["ike_ke_group"] = ke_group if ke_group is not None else -1
    feats["ike_ke_len"] = ke_len if ke_len is not None else -1
    feats["has_rekey"] = rekey
    feats["rk_sk_req_len"] = rk_req
    feats["rk_sk_resp_len"] = rk_resp
    feats["ah_nh"] = ah_nh
    # AH next-header (tunnel v4 -> 4 / v6 -> 41 determines mode for AH)
    # IKEv1 MM proposal (cleartext)
    v1 = [m for m in ike_msgs if m["ver"] == 0x10 and m["exch"] == 2]
    feats["ikev1_mm"] = len(v1)
    feats["ikev1_qm"] = sum(1 for m in ike_msgs if m["ver"] == 0x10
                            and m["exch"] == 32)
    for k in ("ike1_encr_id", "ike1_keylen", "ike1_hash", "ike1_group"):
        feats[k] = -1
    feats["ikev1_attrs"] = ""
    if v1:
        sa = next((p for p in v1[0]["payloads"] if p["type"] == 1), None)
        if sa and len(sa["body"]) >= 8:
            try:
                from validate_pcap import parse_proposal
                pr = parse_proposal(sa["body"][8:])
                if pr["transforms"]:
                    attrs = dict(pr["transforms"][0]["attrs"])
                    feats["ikev1_attrs"] = ",".join(
                        f"{a}={v}" for a, v in
                        pr["transforms"][0]["attrs"])
                    feats["ike1_encr_id"] = attrs.get(1, -1)
                    feats["ike1_keylen"] = attrs.get(14, -1)
                    feats["ike1_hash"] = attrs.get(2, -1)
                    feats["ike1_group"] = attrs.get(4, -1)
            except IKEError:
                pass
    return feats

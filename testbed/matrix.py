"""Single source of truth for the M1 IPsec variant matrix.

Every generated artifact (swanctl configs, legacy ipsec.conf files, label
rows) is DERIVED from this module.  Do not hand-edit files under
testbed/variants/ or testbed/configs/; regenerate them instead:

    .venv/bin/python testbed/gen_configs.py
    .venv/bin/python testbed/validate_configs.py

Design principles
-----------------
1. One-factor diffs: every variant after v1 differs from the v1 baseline in
   exactly one parameter family (cipher / integrity / DH / mode / ipver /
   ike version / lifetime / replay / esn / encap).  v2-v6 are the spec's
   example baselines.
2. The IKE suite mirrors the CHILD (ESP/AH) suite so a label such as
   enc=3des describes BOTH phases, except the AH variant (v7) whose CHILD
   has no cipher - its IKE SA keeps the v1 baseline suite.
3. Endpoints: all variants use the gw<->gw transit-link addresses as
   IKE/ESP endpoints.  Tunnel mode protects the client LAN subnets;
   transport mode protects host traffic between the gateways themselves
   (transport mode requires host-to-host selectors owned by the charon
   endpoints - verified empirically, see DESIGN.md "Transport mode").
4. PFS is expressed ONLY as a DH group token inside the ESP/AH proposal
   (`pfs = yes` is a no-op in both config formats).  ESN is expressed as
   the `-esn`/`-noesn` proposal token (v16 explicit on, v17 explicit off,
   all others implicit default = noesn).
"""

from __future__ import annotations

import hashlib

# --------------------------------------------------------------------------
# Topology / addressing (IPv4 + IPv6).  The canonical testbed is the
# netns-inside-a-NET_ADMIN-container topology (decision D3); the Docker
# compose file reuses the same addressing.
# --------------------------------------------------------------------------
TOPOLOGY = {
    "gw_a": {
        "lan4": "10.1.0.1",
        "lan6": "fd00:1::1",
        "transit4": "10.30.0.10",
        "transit6": "fd00:ff::1",
    },
    "gw_b": {
        "lan4": "10.2.0.1",
        "lan6": "fd00:2::1",
        "transit4": "10.30.0.20",
        "transit6": "fd00:ff::2",
    },
    "client_a": {"lan4": "10.1.0.10", "lan6": "fd00:1::10"},
    "client_b": {"lan4": "10.2.0.10", "lan6": "fd00:2::10"},
    "nets": {
        "lan_a4": "10.1.0.0/24",
        "lan_b4": "10.2.0.0/24",
        "lan_a6": "fd00:1::/64",
        "lan_b6": "fd00:2::/64",
        "transit4": "10.30.0.0/24",
        "transit6": "fd00:ff::/64",
    },
    "capture_point": "transit link gw-a <-> gw-b (tcpdump, BPF: udp 500/4500, proto 50/51)",
}

# IKE/ESP endpoints for EVERY variant (transit-link addresses).
ENDPOINTS = {
    ("gw-a", 4): (TOPOLOGY["gw_a"]["transit4"], TOPOLOGY["gw_b"]["transit4"]),
    ("gw-b", 4): (TOPOLOGY["gw_b"]["transit4"], TOPOLOGY["gw_a"]["transit4"]),
    ("gw-a", 6): (TOPOLOGY["gw_a"]["transit6"], TOPOLOGY["gw_b"]["transit6"]),
    ("gw-b", 6): (TOPOLOGY["gw_b"]["transit6"], TOPOLOGY["gw_a"]["transit6"]),
}

DH_TOKENS = {2: "modp1024", 5: "modp1536", 14: "modp2048", 19: "ecp256", 20: "ecp384"}

# Per-cipher proposal tokens: ike enc token, (AEAD) prf token, key length.
CIPHERS = {
    "aes-128-cbc": {"ike": "aes128", "len": 128, "aead": False},
    "aes-256-cbc": {"ike": "aes256", "len": 256, "aead": False},
    "aes-128-gcm": {"ike": "aes128gcm16", "prf": "prfsha256", "len": 128, "aead": True},
    "aes-256-gcm": {"ike": "aes256gcm16", "prf": "prfsha384", "len": 256, "aead": True},
    "3des-cbc": {"ike": "3des", "len": 168, "aead": False},
    "none": {"ike": None, "len": 0, "aead": False},  # AH child: no cipher
}

# Child integrity token (also the IKE integrity token for non-AEAD ciphers).
AUTH_TOKENS = {"hmac-sha256": "sha256", "hmac-sha1": "sha1"}

# IKE suite used where the CHILD has no cipher (AH variant v7): the v1 baseline.
DEFAULT_IKE_CIPHER = "aes-128-cbc"
DEFAULT_IKE_AUTH = "hmac-sha256"

BASELINE = {"ike_rekey_s": 14400, "child_rekey_s": 3600, "replay_window": 32}


def _v(id, *, mode, ip_version, proto="esp", ike_version=2, cipher, auth,
       dh_group, pfs, esn=False, replay_window=32, nat_t=False,
       ike_rekey_s=14400, child_rekey_s=3600, description=""):
    """Build one validated variant record."""
    assert cipher in CIPHERS, cipher
    if proto == "ah":
        assert cipher == "none"
        assert auth == "hmac-sha256" or auth == "hmac-sha1"
    else:
        assert auth in AUTH_TOKENS or CIPHERS[cipher]["aead"]
    if CIPHERS[cipher]["aead"]:
        assert auth == "aead"
    else:
        assert auth in AUTH_TOKENS
    if pfs:
        assert dh_group in DH_TOKENS
    return {
        "id": id,
        "mode": mode,                # tunnel | transport
        "ip_version": ip_version,    # 4 | 6 (IKE + protected traffic)
        "ipsec_protocol": proto,     # esp | ah
        "ike_version": ike_version,  # 1 | 2
        "cipher": cipher,            # label: encryption
        "auth": auth,                # label: auth algorithm
        "dh_group": dh_group,        # label: IKE DH group; ESP DH group iff pfs
        "pfs": pfs,                  # label: PFS (DH token present in child proposal)
        "esn": esn,                  # label: extended sequence numbers
        "replay_window": replay_window,  # label; 0 = replay protection off
        "nat_t": nat_t,              # label: ESP-in-UDP (encap)
        "ike_rekey_s": ike_rekey_s,      # label: IKE SA rekey interval
        "child_rekey_s": child_rekey_s,  # label: CHILD SA rekey interval
        "description": description,
    }


# --------------------------------------------------------------------------
# The 18-variant matrix (spec minimum: 15).
# v1-v6: spec example baselines; v7: AH; v8-v18: weak/unusual coverage.
# --------------------------------------------------------------------------
VARIANTS = [
    _v("v1", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True,
       description="baseline: tunnel/IPv4/AES-128-CBC+HMAC-SHA256/DH14/PFS on"),
    _v("v2", mode="tunnel", ip_version=4, cipher="aes-256-cbc",
       auth="hmac-sha256", dh_group=20, pfs=True,
       description="baseline: tunnel/IPv4/AES-256-CBC+HMAC-SHA256/DH20/PFS on"),
    _v("v3", mode="tunnel", ip_version=4, cipher="aes-128-gcm",
       auth="aead", dh_group=14, pfs=False,
       description="baseline: tunnel/IPv4/AES-128-GCM/DH14/PFS off"),
    _v("v4", mode="tunnel", ip_version=6, cipher="aes-256-gcm",
       auth="aead", dh_group=20, pfs=True,
       description="baseline: tunnel/IPv6/AES-256-GCM/DH20/PFS on"),
    _v("v5", mode="transport", ip_version=4, cipher="aes-256-gcm",
       auth="aead", dh_group=19, pfs=True,
       description="baseline: transport/IPv4/AES-256-GCM/DH19/PFS on"),
    _v("v6", mode="transport", ip_version=6, cipher="aes-256-cbc",
       auth="hmac-sha256", dh_group=14, pfs=False,
       description="baseline: transport/IPv6/AES-256-CBC+HMAC-SHA256/DH14/PFS off"),
    _v("v7", mode="tunnel", ip_version=4, proto="ah", cipher="none",
       auth="hmac-sha256", dh_group=14, pfs=True,
       description="AH variant: AH-HMAC-SHA256/DH14/PFS on (no encryption)"),
    _v("v8", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=2, pfs=True,
       description="weak: DH2/modp1024 (1024-bit MODP)"),
    _v("v9", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=5, pfs=True,
       description="weak: DH5/modp1536 (1536-bit MODP)"),
    _v("v10", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha1", dh_group=14, pfs=True,
       description="weak: HMAC-SHA1 integrity"),
    _v("v11", mode="tunnel", ip_version=4, cipher="3des-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True,
       description="weak: 3DES-CBC cipher (168-bit)"),
    _v("v12", mode="tunnel", ip_version=4, ike_version=1, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True,
       description="unusual: IKEv1 main mode (aggressive=no)"),
    _v("v13", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True,
       ike_rekey_s=600, child_rekey_s=300,
       description="unusual: short lifetimes (IKE 600s / CHILD 300s)"),
    _v("v14", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True,
       ike_rekey_s=86400, child_rekey_s=43200,
       description="unusual: long lifetimes (IKE 86400s / CHILD 43200s)"),
    _v("v15", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True, replay_window=0,
       description="weak: replay protection off (replay_window=0)"),
    _v("v16", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True, esn=True,
       description="unusual: ESN on (extended sequence numbers)"),
    _v("v17", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True, esn=False,
       description="unusual: ESN off made explicit (-noesn token)"),
    _v("v18", mode="tunnel", ip_version=4, cipher="aes-128-cbc",
       auth="hmac-sha256", dh_group=14, pfs=True, nat_t=True,
       description="unusual: NAT-T (ESP-in-UDP, encap=yes / forceencaps=yes)"),
]

VARIANT_IDS = [v["id"] for v in VARIANTS]
BY_ID = {v["id"]: v for v in VARIANTS}

# Traffic types (spec M2): generators emit these for every variant x run.
TRAFFIC_TYPES = ["voip", "video", "web", "email", "whatsapp", "icmp"]
TRAFFIC_PROFILES = {
    "voip": "RTP-like UDP, 20 ms interval, 160 B payload",
    "video": "bursty UDP, 1200-1400 B packets, 2 s segments",
    "web": "short TCP request/response bursts",
    "email": "SMTP/IMAP-like TCP sessions with attachment transfers",
    "whatsapp": "small bidirectional TLS-like records + sparse large media blobs",
    "icmp": "ICMP echo, 64 / 512 / 1400 B payloads",
}


# --------------------------------------------------------------------------
# Derivations (proposals, selectors, secrets, labels)
# --------------------------------------------------------------------------
def _integ_token(auth: str) -> str:
    if auth == "aead":
        return ""
    return AUTH_TOKENS[auth]


def ike_proposal(v: dict) -> str:
    """IKE SA proposal string (e.g. aes128-sha256-modp2048)."""
    cipher = v["cipher"]
    auth = v["auth"]
    if cipher == "none":  # AH child: IKE SA keeps the v1 baseline suite
        cipher, auth = DEFAULT_IKE_CIPHER, DEFAULT_IKE_AUTH
    c = CIPHERS[cipher]
    if c["aead"]:
        parts = [c["ike"], c["prf"], DH_TOKENS[v["dh_group"]]]
    else:
        parts = [c["ike"], _integ_token(auth), DH_TOKENS[v["dh_group"]]]
    return "-".join(parts)


def child_proposal_key(v: dict) -> str:
    """swanctl proposal key for the CHILD SA (ah_proposals vs esp_proposals)."""
    return "ah_proposals" if v["ipsec_protocol"] == "ah" else "esp_proposals"


def child_proposal(v: dict) -> str:
    """ESP (or AH) proposal string, including PFS DH and ESN tokens."""
    if v["ipsec_protocol"] == "ah":
        parts = [_integ_token(v["auth"])]
        if v["pfs"]:
            parts.append(DH_TOKENS[v["dh_group"]])
    else:
        c = CIPHERS[v["cipher"]]
        parts = [c["ike"]]
        if not c["aead"]:
            parts.append(_integ_token(v["auth"]))
        if v["pfs"]:
            parts.append(DH_TOKENS[v["dh_group"]])
    # ESN: explicit only where it is the variant's labelled feature
    # (v16 on, v17 off); all other variants rely on the verified default
    # (noesn).  Encoding this here keeps configs and labels in sync.
    esn_suffix = v.get("_esn_suffix", None)
    if esn_suffix is None:
        esn_suffix = "esn" if v["id"] == "v16" else ("noesn" if v["id"] == "v17" else None)
    if esn_suffix:
        parts.append(esn_suffix)
    return "-".join(parts)


def traffic_selectors(v: dict, gw: str) -> tuple[str, str]:
    """(local_ts, remote_ts) for one gateway.

    tunnel:    client LAN subnets (gateway-to-gateway outer, inner = client net)
    transport: transit-link HOST addresses (strongSwan derives transport TS
               from the IKE endpoints; subnet TS is rejected TS_UNACCEPT -
               verified empirically, see DESIGN.md)
    """
    ip = v["ip_version"]
    if v["mode"] == "tunnel":
        if gw == "gw-a":
            local = TOPOLOGY["nets"]["lan_a6" if ip == 6 else "lan_a4"]
            remote = TOPOLOGY["nets"]["lan_b6" if ip == 6 else "lan_b4"]
        else:
            local = TOPOLOGY["nets"]["lan_b6" if ip == 6 else "lan_b4"]
            remote = TOPOLOGY["nets"]["lan_a6" if ip == 6 else "lan_a4"]
        return local, remote
    # transport: host selectors on the transit link
    local, remote = ENDPOINTS[(gw, ip)]
    prefix = "/128" if ip == 6 else "/32"
    return local + prefix, remote + prefix


def endpoints(v: dict, gw: str) -> tuple[str, str]:
    """(local_addrs, remote_addrs) for one gateway."""
    return ENDPOINTS[(gw, v["ip_version"])]


def psk_for(variant_id: str) -> str:
    """Deterministic unique PSK per variant (never appears on the wire)."""
    digest = hashlib.sha256(f"sih-ipsec-psk-v1:{variant_id}".encode()).hexdigest()
    return f"psk-{digest[:16]}"


def conn_name(v: dict) -> str:
    return v["id"]


def child_name(v: dict) -> str:
    """MUST match the entrypoint contract ${VARIANT}-child."""
    return f"{v['id']}-child"


def label_row(v: dict) -> dict:
    """Per-variant ground-truth fields (merged with per-pcap fields later)."""
    return {
        "variant": v["id"],
        "ipsec_protocol": v["ipsec_protocol"],
        "ike_version": f"ikev{v['ike_version']}",
        "mode": v["mode"],
        "ip_version": v["ip_version"],
        "encryption": v["cipher"],
        "key_length_bits": CIPHERS[v["cipher"]]["len"],
        "auth": v["auth"],
        "aead": CIPHERS[v["cipher"]]["aead"],
        "dh_group": v["dh_group"],
        "pfs": v["pfs"],
        "esn": v["esn"],
        "replay_window": v["replay_window"],
        "nat_t": v["nat_t"],
        "ike_rekey_s": v["ike_rekey_s"],
        "child_rekey_s": v["child_rekey_s"],
    }


def legacy_lifetime(v: dict, which: str) -> str:
    """ipsec.conf ikelifetime/keylife strings (spec uses e.g. '4h')."""
    seconds = v["ike_rekey_s"] if which == "ike" else v["child_rekey_s"]
    if seconds % 3600 == 0 and seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


if __name__ == "__main__":
    # quick self-check: print the matrix table
    hdr = ("id", "mode", "ip", "proto", "ike", "cipher", "auth", "dh", "pfs",
           "esn", "replay", "natt", "ike_rt", "child_rt")
    print("\t".join(hdr))
    for v in VARIANTS:
        row = label_row(v)
        print("\t".join(str(x) for x in (
            row["variant"], row["mode"], row["ip_version"], row["ipsec_protocol"],
            row["ike_version"], row["encryption"], row["auth"], row["dh_group"],
            row["pfs"], row["esn"], row["replay_window"], row["nat_t"],
            row["ike_rekey_s"], row["child_rekey_s"])))
    print()
    for v in VARIANTS:
        print(v["id"], "ike=", ike_proposal(v), " child=", child_proposal(v))

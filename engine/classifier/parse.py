"""Deterministic wire parsers (M3 guardrail 2, `source: parsed`).

Every value here is read off bytes the peer actually sent in the clear
(IKE_SA_INIT proposals, KE lengths, headers, ESP/AH presence, NAT-T
markers, AH next-header). Anything not visible returns None and is left
to the ML models (`source: model`) or `unknown`.
"""
from __future__ import annotations

DH_LEN = {128: 2, 192: 5, 256: 14, 64: 19, 96: 20}
ENCR = {(12, 128): "aes-128-cbc", (12, 256): "aes-256-cbc",
        (20, 128): "aes-128-gcm", (20, 256): "aes-256-gcm",
        (3, None): "3des-cbc", (3, 168): "3des-cbc"}
INTEG = {12: "hmac-sha256", 2: "hmac-sha1"}
IKEV1_ENCR = {(7, 128): "aes-128-cbc", (7, 256): "aes-256-cbc",
              (5, None): "3des-cbc", (5, 168): "3des-cbc"}
IKEV1_HASH = {4: "hmac-sha256", 2: "hmac-sha1"}
PRF = {5: "hmac-sha256", 6: "hmac-sha384", 2: "hmac-sha1"}


def _out(value, confidence=1.0):
    return {"value": value, "source": "parsed", "confidence": confidence}


def parse_fields(f: dict) -> dict:
    """Parsed subset; model/unknown filled in by predict.py."""
    out: dict = {}
    # ike_version
    if f.get("ikev1_mm", 0) > 0:
        out["ike_version"] = _out("ikev1")
    elif f.get("ike_n", 0) > 0:
        out["ike_version"] = _out("ikev2")
    else:
        out["ike_version"] = _out("none")
    # ipsec_proto
    if f.get("has_esp"):
        out["ipsec_proto"] = _out("esp")
    elif f.get("has_ah"):
        out["ipsec_proto"] = _out("ah")
    else:
        out["ipsec_proto"] = _out("none")
    # ip_version
    out["ip_version"] = _out(f["ip_version"]) if f.get("ip_version") in (4, 6) \
        else {"value": "unknown", "source": "parsed", "confidence": 0.0}
    # nat_t: ESP-in-UDP is definitive
    out["nat_t"] = _out(bool(f.get("n_esp_in_udp", 0)))
    # Plain negatives: no IPsec on the wire -> definitional values.
    if out["ipsec_proto"]["value"] == "none":
        out["mode"] = {"value": "none", "source": "parsed", "confidence": 1.0,
                       "detail": {"header_parse": "none",
                                  "reason": "no ESP/AH on the wire"}}
        out["enc_alg"] = _out("none")
        out["enc_key_len"] = _out(0)
        out["auth_alg"] = _out("none")
        out["dh_group"] = _out(0)
        out["prf"] = _out("none")
        out["pfs"] = _out(False)
        return out
    # cipher / integrity / dh from the clear proposal.
    # AH never encrypts (RFC 4302): enc=none is definitional, auth comes
    # from the CHILD proposal (rekey, else the mirroring IKE proposal).
    if out["ipsec_proto"]["value"] == "ah":
        out["enc_alg"] = _out("none")
        out["enc_key_len"] = _out(0)
        rk_integ = f.get("rk_child_integ", -1)
        integ = rk_integ if rk_integ != -1 else f.get("ike_integ", -1)
        out["auth_alg"] = _out(INTEG.get(integ, "unknown")) if integ != -1 \
            else {"value": "unknown", "source": "parsed", "confidence": 0.0}
        dh = f.get("ike_dh", -1)
        out["dh_group"] = _out(dh) if dh != -1 else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        out["prf"] = _out(PRF.get(f.get("ike_prf", -1), "unknown")) \
            if f.get("ike_prf", -1) != -1 else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
    elif f.get("ike_encr", -1) != -1:
        keylen = f.get("ike_t0_keylen", None)
        enc = ENCR.get((f["ike_encr"], keylen), ENCR.get((f["ike_encr"], None)))
        out["enc_alg"] = _out(enc) if enc else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        if enc is not None:
            out["enc_key_len"] = _out(
                {"aes-128-cbc": 128, "aes-256-cbc": 256,
                 "aes-128-gcm": 128, "aes-256-gcm": 256,
                 "3des-cbc": 168}[enc])
        else:
            out["enc_key_len"] = {"value": "unknown", "source": "parsed",
                                  "confidence": 0.0}
        if f.get("ike_integ", -1) != -1:
            out["auth_alg"] = _out(INTEG.get(f["ike_integ"], "unknown"))
        elif enc and "gcm" in enc:
            out["auth_alg"] = _out("aead")
        else:
            out["auth_alg"] = {"value": "unknown", "source": "parsed",
                               "confidence": 0.0}
        dh = f.get("ike_dh", -1)
        out["dh_group"] = _out(dh) if dh != -1 else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        # KE cross-check (length must match the DH group)
        if dh != -1 and f.get("ike_ke_len", -1) != -1:
            want = {2: 128, 5: 192, 14: 256, 19: 64, 20: 96}.get(dh)
            if want != f["ike_ke_len"]:
                out["dh_group"] = {"value": dh, "source": "parsed",
                                   "confidence": 0.5}
        out["prf"] = _out(PRF.get(f.get("ike_prf", -1), "unknown")) \
            if f.get("ike_prf", -1) != -1 else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
    elif out["ike_version"]["value"] == "ikev1" and \
            f.get("ike1_encr_id", -1) != -1:
        keylen = f.get("ike1_keylen", None)
        enc = IKEV1_ENCR.get((f["ike1_encr_id"], keylen),
                             IKEV1_ENCR.get((f["ike1_encr_id"], None)))
        out["enc_alg"] = _out(enc) if enc else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        out["enc_key_len"] = _out(keylen) if keylen in (128, 256, 168) else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        out["auth_alg"] = _out(IKEV1_HASH.get(f.get("ike1_hash", -1),
                                              "unknown")) \
            if f.get("ike1_hash", -1) != -1 else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        dh = f.get("ike1_group", -1)
        out["dh_group"] = _out(dh) if dh != -1 else \
            {"value": "unknown", "source": "parsed", "confidence": 0.0}
        out["prf"] = {"value": "unknown", "source": "parsed",
                      "confidence": 0.0}  # IKEv1 has no PRF transform
    else:
        for k in ("enc_alg", "enc_key_len", "auth_alg", "dh_group", "prf"):
            out[k] = None
    # pfs: never visible in the clear (rekeys are SK-only blobs on every
    # stack we emit; only their LENGTH hints at KE presence) -> model,
    # except plain negatives which are definitionally PFS-free.
    if out["ipsec_proto"]["value"] == "none":
        out["pfs"] = _out(False)
    else:
        out["pfs"] = None
    # mode: AH next-header is definitive; ESP mode is never on the wire
    # in the clear (TS payloads are encrypted) -> model (size overhead).
    # detail.header_parse records the structural verdict (or n/a + reason);
    # predict.py adds the size-model signal and decided_by.
    if out["ipsec_proto"]["value"] == "ah":
        nh = f.get("ah_nh", -1)
        if nh in (4, 41):
            out["mode"] = {"value": "tunnel", "source": "parsed",
                           "confidence": 1.0,
                           "detail": {"header_parse": "tunnel",
                                      "reason": f"AH nh={nh} (IP-in-IP)"}}
        elif nh in (6, 17, 1, 58):
            out["mode"] = {"value": "transport", "source": "parsed",
                           "confidence": 1.0,
                           "detail": {"header_parse": "transport",
                                      "reason": f"AH nh={nh} (transport L4)"}}
        else:
            out["mode"] = None
    else:
        out["mode"] = None
    return out

"""Deterministic wire parsers (M3 guardrail 2, `source: parsed`).

Protocol boundary (v1.1): the IKE SA and the CHILD SA are DIFFERENT
objects. A proposal in IKE_SA_INIT describes the IKE SA and NEVER the
installed ESP suite; IKE_AUTH / CREATE_CHILD_SA negotiate CHILD SAs and
are encrypted on the wire, so child crypto is almost never parseable.

Every value here is read off bytes the peer actually sent in the clear,
with packet evidence. Anything not visible is returned as None (left to
the ML models as INFERRED) or as an explicit UNKNOWN / NOT_OBSERVED /
NOT_APPLICABLE field object — absence of evidence is never a confident
value. The responder's IKE_SA_INIT message carries the SELECTED suite;
the initiator's message is only the OFFERED set.
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

# Status vocabulary for every fact.
OBSERVED = "OBSERVED"        # read from packet bytes, with evidence
INFERRED = "INFERRED"        # model/candidate set; never overwrites observed
UNKNOWN = "UNKNOWN"          # evidence expected but inconclusive
NOT_OBSERVED = "NOT_OBSERVED"  # evidence absent (e.g. no handshake captured)
NOT_APPLICABLE = "NOT_APPLICABLE"  # concept does not apply (e.g. plain)


def _F(value, status, source="parsed", confidence=1.0, evidence=None):
    return {"value": value, "status": status, "source": source,
            "confidence": confidence, "evidence": evidence}


def _unk(status=NOT_OBSERVED):
    return _F("unknown", status, source="none", confidence=0.0,
              evidence=None)


def _ike_suite_from_init(f):
    """Parse the IKE_SA_INIT (selected = responder) proposal into an
    ike_sa field set. Returns None when no proposal is on the wire."""
    if f.get("ike_encr", -1) == -1:
        return None
    ev = {"exchange": "ike-sa-init", "role": "responder-selected"}
    if f.get("ike_init_resp_idx", -1) != -1:
        ev["packet"] = f["ike_init_resp_idx"]
    elif f.get("ike_init_req_idx", -1) != -1:
        ev["packet"] = f["ike_init_req_idx"]
        ev["role"] = "initiator-offered-only"
    keylen = f.get("ike_t0_keylen", None)
    enc = ENCR.get((f["ike_encr"], keylen),
                   ENCR.get((f["ike_encr"], None)))
    out = {}
    out["enc_alg"] = _F(enc, OBSERVED, evidence=dict(ev)) if enc else \
        _unk(UNKNOWN)
    if enc is not None:
        out["enc_key_len"] = _F(
            {"aes-128-cbc": 128, "aes-256-cbc": 256,
             "aes-128-gcm": 128, "aes-256-gcm": 256,
             "3des-cbc": 168}[enc], OBSERVED, evidence=dict(ev))
    else:
        out["enc_key_len"] = _unk(UNKNOWN)
    if f.get("ike_integ", -1) != -1:
        out["auth_alg"] = _F(INTEG.get(f["ike_integ"], "unknown"), OBSERVED,
                             evidence=dict(ev))
    elif enc and "gcm" in enc:
        out["auth_alg"] = _F("aead", OBSERVED, evidence=dict(ev))
    else:
        out["auth_alg"] = _unk(UNKNOWN)
    dh = f.get("ike_dh", -1)
    out["dh_group"] = _F(dh, OBSERVED, evidence=dict(ev)) if dh != -1 \
        else _unk(UNKNOWN)
    # KE cross-check (length must match the DH group)
    if dh != -1 and f.get("ike_ke_len", -1) != -1:
        want = {2: 128, 5: 192, 14: 256, 19: 64, 20: 96}.get(dh)
        if want != f["ike_ke_len"]:
            out["dh_group"] = _F(dh, OBSERVED, confidence=0.5,
                                 evidence={**ev, "note": "ke-length-mismatch"})
    out["prf"] = _F(PRF.get(f.get("ike_prf", -1), "unknown"), OBSERVED,
                    evidence=dict(ev)) \
        if f.get("ike_prf", -1) != -1 else _unk(UNKNOWN)
    return out


def _ike_suite_from_mm(f):
    """IKEv1 main-mode proposal (cleartext) -> ike_sa field set."""
    if f.get("ike1_encr_id", -1) == -1:
        return None
    ev = {"exchange": "ikev1-main-mode", "role": "responder-selected"}
    if f.get("ikev1_mm_idx", -1) != -1:
        ev["packet"] = f["ikev1_mm_idx"]
    out = {}
    keylen = f.get("ike1_keylen", None)
    enc = IKEV1_ENCR.get((f["ike1_encr_id"], keylen),
                         IKEV1_ENCR.get((f["ike1_encr_id"], None)))
    out["enc_alg"] = _F(enc, OBSERVED, evidence=dict(ev)) if enc else \
        _unk(UNKNOWN)
    out["enc_key_len"] = _F(keylen, OBSERVED, evidence=dict(ev)) \
        if keylen in (128, 256, 168) else _unk(UNKNOWN)
    out["auth_alg"] = _F(IKEV1_HASH.get(f.get("ike1_hash", -1), "unknown"),
                         OBSERVED, evidence=dict(ev)) \
        if f.get("ike1_hash", -1) != -1 else _unk(UNKNOWN)
    dh = f.get("ike1_group", -1)
    out["dh_group"] = _F(dh, OBSERVED, evidence=dict(ev)) if dh != -1 \
        else _unk(UNKNOWN)
    out["prf"] = _F("unknown", NOT_APPLICABLE, source="none",
                    confidence=0.0,
                    evidence={"note": "ikev1-has-no-prf-transform"})
    return out


def parse_fields(f: dict) -> dict:
    """Split parse: ike_sa (OBSERVED from handshake) + child_sa.

    Child crypto (enc/auth/keylen) is NEVER filled from IKE_SA_INIT here:
    with encrypted AUTH/rekey exchanges it stays None (model INFERRED
    downstream) or explicit UNKNOWN. Returns {"ike_sa", "child_sa",
    "ip_version", "nat_t", "traffic_type"}; predict.py derives the flat
    backward-compatible fields from these objects.
    """
    n_packets = f.get("n_packets", 0)
    has_l3 = f.get("n_ip", n_packets) > 0
    has_esp = bool(f.get("has_esp"))
    has_ah = bool(f.get("has_ah"))
    has_ipsec = has_esp or has_ah
    # No IP-layer packets at all (empty or non-IP garbage): nothing was
    # observed; every content fact is NOT_OBSERVED.
    empty = (n_packets == 0) or (not has_l3)

    # ---------------- IKE SA ----------------
    ike: dict = {}
    if f.get("ikev1_mm", 0) > 0:
        ev = {"exchange": "ikev1-main-mode"}
        if f.get("ikev1_mm_idx", -1) != -1:
            ev["packet"] = f["ikev1_mm_idx"]
        ike["version"] = _F("ikev1", OBSERVED, evidence=ev)
        suite = _ike_suite_from_mm(f) or {}
        for k in ("enc_alg", "enc_key_len", "auth_alg", "dh_group", "prf"):
            ike[k] = suite.get(k, _unk(UNKNOWN))
    elif f.get("ike_n", 0) > 0:
        ev = {"exchange": "ike-sa-init", "role": "responder-selected"}
        if f.get("ike_init_resp_idx", -1) != -1:
            ev["packet"] = f["ike_init_resp_idx"]
        elif f.get("ike_init_req_idx", -1) != -1:
            ev["packet"] = f["ike_init_req_idx"]
            ev["role"] = "initiator-offered-only"
        ike["version"] = _F("ikev2", OBSERVED, evidence=ev)
        suite = _ike_suite_from_init(f) or {}
        for k in ("enc_alg", "enc_key_len", "auth_alg", "dh_group", "prf"):
            ike[k] = suite.get(k, _unk(UNKNOWN))
    elif has_ipsec:
        # Handshake absent: "not observed", never a certain no-IKE.
        for k in ("version", "enc_alg", "enc_key_len", "auth_alg",
                  "dh_group", "prf"):
            ike[k] = _unk(NOT_OBSERVED)
    else:
        # No IPsec traffic at all: no IKE SA exists to describe.
        na = NOT_APPLICABLE
        ike["version"] = _F("none", na, source="none", confidence=1.0,
                            evidence={"note": "no-ipsec-traffic"})
        for k in ("enc_alg", "auth_alg", "prf"):
            ike[k] = _F("none", na, source="none", confidence=1.0,
                        evidence={"note": "no-ipsec-traffic"})
        ike["enc_key_len"] = _F(0, na, source="none", confidence=1.0,
                                evidence={"note": "no-ipsec-traffic"})
        ike["dh_group"] = _F(0, na, source="none", confidence=1.0,
                             evidence={"note": "no-ipsec-traffic"})

    # ---------------- CHILD SA ----------------
    child: dict = {}
    if has_esp:
        child["proto"] = _F("esp", OBSERVED,
                            evidence={"note": "ip-proto-50-observed"})
        # ESP mode: inner header encrypted -> never on the wire (model).
        child["mode"] = None
        # ESP suite: CHILD proposals travel encrypted -> never parsed here.
        child["enc_alg"] = None
        child["enc_key_len"] = None
        child["auth_alg"] = None
    elif has_ah:
        child["proto"] = _F("ah", OBSERVED,
                            evidence={"note": "ip-proto-51-observed"})
        # AH never encrypts (RFC 4302): enc=none is definitional.
        child["enc_alg"] = _F("none", OBSERVED,
                              evidence={"note": "rfc4302-ah-no-encryption"})
        child["enc_key_len"] = _F(0, OBSERVED,
                                  evidence={"note": "rfc4302-ah-no-encryption"})
        # AH integrity comes from the CHILD proposal, which is encrypted
        # on the wire (IKEv1 QM / IKEv2 rekey): never mirrored from IKE.
        child["auth_alg"] = None
        nh = f.get("ah_nh", -1)
        if nh in (4, 41):
            child["mode"] = _F("tunnel", OBSERVED, evidence={
                "header_parse": "tunnel",
                "reason": f"AH nh={nh} (IP-in-IP)"})
        elif nh in (6, 17, 1, 58):
            child["mode"] = _F("transport", OBSERVED, evidence={
                "header_parse": "transport",
                "reason": f"AH nh={nh} (transport L4)"})
        else:
            child["mode"] = None
    elif empty:
        child["proto"] = _unk(NOT_OBSERVED)
        child["mode"] = None
        child["enc_alg"] = None
        child["enc_key_len"] = None
        child["auth_alg"] = None
    else:
        na = NOT_APPLICABLE
        child["proto"] = _F("none", OBSERVED, evidence={
            "note": "packets-observed-no-esp-ah"})
        child["mode"] = _F("none", na, source="none", confidence=1.0,
                           evidence={"note": "no-ipsec-traffic"})
        child["enc_alg"] = _F("none", na, source="none", confidence=1.0,
                              evidence={"note": "no-ipsec-traffic"})
        child["enc_key_len"] = _F(0, na, source="none", confidence=1.0,
                                  evidence={"note": "no-ipsec-traffic"})
        child["auth_alg"] = _F("none", na, source="none", confidence=1.0,
                               evidence={"note": "no-ipsec-traffic"})
    # PFS: never visible in the clear (rekeys are SK-only blobs on every
    # stack we emit; only their LENGTH hints at KE presence) -> model,
    # except plain negatives which are definitionally PFS-free.
    if not has_ipsec and not empty:
        child["pfs"] = _F(False, NOT_APPLICABLE, source="none",
                          confidence=1.0,
                          evidence={"note": "no-ipsec-traffic"})
    elif empty:
        child["pfs"] = _unk(NOT_OBSERVED)
    else:
        child["pfs"] = None
    # Replay window and SA lifetimes are kernel-side state, never on the
    # wire in short captures: NOT_OBSERVED (labels may still score them).
    if empty:
        child["replay"] = _unk(NOT_OBSERVED)
        child["lifetime"] = _unk(NOT_OBSERVED)
    elif not has_ipsec:
        child["replay"] = _F("unknown", NOT_APPLICABLE, source="none",
                             confidence=0.0,
                             evidence={"note": "no-ipsec-traffic"})
        child["lifetime"] = _F("unknown", NOT_APPLICABLE, source="none",
                               confidence=0.0,
                               evidence={"note": "no-ipsec-traffic"})
    else:
        child["replay"] = _F("unknown", NOT_OBSERVED, source="none",
                             confidence=0.0, evidence={
                                 "note": "replay-state-not-on-wire"})
        child["lifetime"] = _F("unknown", NOT_OBSERVED, source="none",
                               confidence=0.0, evidence={
                                   "note": "rekey-intervals-not-on-wire"})

    # ---------------- session-level ----------------
    if f.get("ip_version") in (4, 6) and has_l3:
        ipver = _F(f["ip_version"], OBSERVED,
                   evidence={"note": "single-family-capture"})
    elif not has_l3:
        ipver = _unk(NOT_OBSERVED)
    else:
        ipver = _F("unknown", UNKNOWN, source="none", confidence=0.0,
                   evidence={"note": "mixed-or-missing-families"})
    if f.get("n_esp_in_udp", 0) > 0:
        nat = _F(True, OBSERVED,
                 evidence={"note": "esp-in-udp-4500-observed"})
    elif has_l3:
        nat = _F(False, OBSERVED,
                 evidence={"note": "no-esp-in-udp-observed"})
    else:
        nat = _F(False, NOT_OBSERVED, source="none", confidence=0.0,
                 evidence=None)
    return {"ike_sa": ike, "child_sa": child, "ip_version": ipver,
            "nat_t": nat, "traffic_type": None}

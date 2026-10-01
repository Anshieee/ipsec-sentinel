"""Security assessment from classified fields (docs/security-rubric.md).

Input: {field: {value, source, confidence}} as produced by
classifier/predict.py. Unknown values score conservatively (0 for that
criterion) and raise an uncertainty finding. Pure function of the
classification — no pcap/label access.
"""
from __future__ import annotations

CIPHER_SCORE = {"aes-256-gcm": 25, "aes-128-gcm": 24, "aes-256-cbc": 22,
                "aes-128-cbc": 20, "3des-cbc": 5, "none": 5}
DH_SCORE = {20: 20, 19: 18, 14: 15, 5: 7, 2: 2, 0: 0}
INTEG_SCORE = {"aead": 15, "hmac-sha256": 13, "hmac-sha1": 5, "none": 0}
IKE_SCORE = {"ikev2": 10, "ikev1": 4, "none": 0}
MODE_SCORE = {"tunnel": 5, "transport": 2, "none": 0}


def _lifetime_score(child_rekey_s) -> tuple[int, bool]:
    """Return (score, known). Unknown lifetimes score 0 (conservative)."""
    if child_rekey_s in (None, "unknown"):
        return 0, False
    try:
        s = int(child_rekey_s)
    except (TypeError, ValueError):
        return 0, False
    if s <= 0:
        return 0, False
    if s <= 3600:
        return 10, True
    if s <= 43200:
        return 4, True
    return 2, True


def assess(classification: dict, lifetimes: dict | None = None) -> dict:
    """lifetimes: optional {ike_rekey_s, child_rekey_s, replay_window}
    (label data; captures are 8 s so lifetimes are never observed)."""
    lifetimes = lifetimes or {}
    v = {k: (classification.get(k) or {}).get("value", "unknown")
         for k in ("enc_alg", "auth_alg", "dh_group", "pfs", "ike_version",
                   "mode", "variant")}
    # accept label-style keys too (tests/oracles pass labels directly)
    if v["enc_alg"] == "unknown" and isinstance(
            (classification.get("encryption") or {}).get("value"), str):
        v["enc_alg"] = classification["encryption"]["value"]
    if v["auth_alg"] == "unknown" and isinstance(
            (classification.get("auth") or {}).get("value"), str):
        v["auth_alg"] = classification["auth"]["value"]

    findings = []
    unk = [k for k in ("enc_alg", "auth_alg", "dh_group", "pfs",
                       "ike_version", "mode") if v.get(k) == "unknown"]
    for k in unk:
        findings.append({"id": f"unknown-{k}", "severity": "medium",
                         "likelihood": 2, "impact": 3,
                         "text": f"{k} unknown: assuming weak.",
                         "solution": "Recapture with IKE handshake visible."})
    enc = v["enc_alg"]
    cipher = CIPHER_SCORE.get(enc, 0) if enc != "unknown" else 0
    if enc == "3des-cbc":
        findings.append({"id": "weak-cipher", "severity": "critical",
                         "likelihood": 3, "impact": 5,
                         "text": "3DES-CBC is broken (SWEET32).",
                         "solution": "Migrate to AES-GCM (RFC 8221)."})
    if enc == "none" and v.get("variant") != "plain":
        findings.append({"id": "no-conf", "severity": "high",
                         "likelihood": 3, "impact": 5,
                         "text": "AH provides no confidentiality.",
                         "solution": "Use ESP with AES-GCM for secrecy."})
    dh = v["dh_group"]
    dh_s = DH_SCORE.get(dh, 0) if dh != "unknown" else 0
    if dh in (2, 5):
        findings.append({"id": "weak-dh", "severity": "critical",
                         "likelihood": 3, "impact": 5,
                         "text": f"DH group {dh} is weak (Logjam).",
                         "solution": "Use ECP_256+ or MODP-2048+ (RFC 8247)."})
    auth = v["auth_alg"]
    integ = INTEG_SCORE.get(auth, 0) if auth != "unknown" else 0
    if auth == "hmac-sha1":
        findings.append({"id": "weak-integ", "severity": "medium",
                         "likelihood": 2, "impact": 4,
                         "text": "HMAC-SHA1 integrity is weak.",
                         "solution": "Use HMAC-SHA2-256 or AEAD."})
    pfs = v["pfs"]
    pfs_s = 10 if pfs is True else 0
    if pfs is False:
        findings.append({"id": "no-pfs", "severity": "high",
                         "likelihood": 2, "impact": 5,
                         "text": "No PFS: key compromise decrypts history.",
                         "solution": "Enable PFS with a strong DH group."})
    life, life_known = _lifetime_score(lifetimes.get("child_rekey_s"))
    if not life_known:
        findings.append({"id": "unknown-lifetime", "severity": "medium",
                         "likelihood": 2, "impact": 3,
                         "text": "SA lifetime unknown: assuming weak.",
                         "solution": "Provide rekey intervals for scoring."})
    elif lifetimes.get("child_rekey_s", 0) > 3600:
        findings.append({"id": "long-sa", "severity": "low",
                         "likelihood": 2, "impact": 3,
                         "text": "Long-lived CHILD SA widens exposure.",
                         "solution": "Shorten CHILD rekey (<=1 h)."})
    rw = lifetimes.get("replay_window", "unknown")
    replay = 5 if rw == 32 else 0
    if rw == "unknown":
        findings.append({"id": "unknown-replay", "severity": "medium",
                         "likelihood": 2, "impact": 3,
                         "text": "Replay state unknown: assuming weak.",
                         "solution": "Enable anti-replay (window 32+)."})
    elif rw == 0:
        findings.append({"id": "no-replay", "severity": "medium",
                         "likelihood": 3, "impact": 3,
                         "text": "Replay protection disabled.",
                         "solution": "Enable anti-replay (window 32+)."})
    ike = v["ike_version"]
    ike_s = IKE_SCORE.get(ike, 0) if ike != "unknown" else 0
    if ike == "ikev1":
        findings.append({"id": "ikev1", "severity": "medium",
                         "likelihood": 2, "impact": 3,
                         "text": "IKEv1 negotiates weakly vs IKEv2.",
                         "solution": "Migrate to IKEv2."})
    mode = v["mode"]
    mode_s = MODE_SCORE.get(mode, 0) if mode != "unknown" else 0
    if mode == "transport":
        findings.append({"id": "transport", "severity": "low",
                         "likelihood": 2, "impact": 2,
                         "text": "Transport exposes host identities.",
                         "solution": "Prefer tunnel mode to hide topology."})
    score = cipher + dh_s + integ + pfs_s + life + replay + ike_s + mode_s
    risk = 100 - score
    bucket = "low" if risk < 25 else "medium" if risk < 50 else \
        "high" if risk < 75 else "critical"
    threats = [{"id": f["id"], "likelihood": f["likelihood"],
                "impact": f["impact"],
                "risk": f["likelihood"] * f["impact"]} for f in findings]
    return {"security_score": score, "risk_score": risk,
            "risk_level": bucket, "findings": findings,
            "threat_matrix": threats,
            "breakdown": {"cipher": cipher, "dh": dh_s, "integrity": integ,
                          "pfs": pfs_s, "lifetime": life, "replay": replay,
                          "ike": ike_s, "mode": mode_s}}

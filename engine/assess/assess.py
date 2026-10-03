"""Security assessment from classified SA objects (v1.1 controls).

Input: {"ike_sa", "child_sa", "detection", ...} as produced by
classifier/predict.py, plus optional label lifetimes
{child_rekey_s, replay_window} (oracle/eval path — short captures never
observe lifetimes on the wire). Pure function of the classification.

Every control returns PASS | FAIL | UNKNOWN | NOT_APPLICABLE with rule
id, rule version, evidence and explanation. Weak ESP never inherits a
strong IKE score: each SA is scored from its own evidence. UNKNOWN never
earns credit and never counts as FAIL. Reported separately:

  posture_score  0-100 over controls actually evaluated (PASS/FAIL only)
  coverage       weighted share of applicable controls with evidence (0-1)
  score_status   PUBLISHED if coverage >= 0.5 else WITHHELD

When WITHHELD there is no headline risk level (security_score/risk None),
but every confirmed FAIL is still listed. Every UNKNOWN names the
measurement that would resolve it.
"""
from __future__ import annotations

RULE_VERSION = "1.2.0"

CIPHER_POINTS = {"aes-256-gcm": 25, "aes-128-gcm": 24, "aes-256-cbc": 22,
                 "aes-128-cbc": 20, "3des-cbc": 5, "none": 5}
IKE_CIPHER_POINTS = {"aes-256-gcm": 5, "aes-128-gcm": 5,
                     "aes-256-cbc": 4, "aes-128-cbc": 4,
                     "3des-cbc": 1, "des-cbc": 0}
DH_POINTS = {20: 20, 19: 18, 14: 15, 5: 7, 2: 2, 1: 0, 0: 0}
INTEG_POINTS = {"aead": 15, "hmac-sha256": 13, "hmac-sha1": 5, "none": 0}
IKE_INTEG_POINTS = {"aead": 3, "hmac-sha256": 3, "hmac-sha384": 3,
                    "hmac-sha1": 1, "hmac-md5": 0, "md5": 0}
IKE_POINTS = {"ikev2": 10, "ikev1": 4}
# IKE-SA suite controls (v1.2): scored from ike_sa only. Weights keep the
# historical total at 100 for the data plane and add 8 for the IKE SA
# (cipher 5: handshake secrecy; integrity 3: AUTH/PRF forgery).
WEIGHTS = {"cipher": 25, "dh": 20, "integrity": 15, "pfs": 10,
           "lifetime": 10, "replay": 5, "ike": 10, "mode": 5,
           "ike_cipher": 5, "ike_integrity": 3}
W_TOTAL = sum(WEIGHTS.values())  # 108

PASS, FAIL, LIKELY, UNKNOWN, NOT_APPLICABLE = "PASS", "FAIL", "LIKELY", \
    "UNKNOWN", "NOT_APPLICABLE"

# LIKELY = FAIL resting on INFERRED evidence: severity capped one level
# below the OBSERVED (CONFIRMED) equivalent.
LIKELY_CAP = {"critical": "high", "high": "medium", "medium": "low",
              "low": "low"}
NOT_OBSERVED = "NOT_OBSERVED"  # field-level status (never a control status)


def _ctl(id, title, weight, status, points, evidence, explanation,
         resolve_by=None, remediation=None, source="none", confidence=0.0):
    return {"id": id, "rule_version": RULE_VERSION, "title": title,
            "status": status, "weight": weight, "points": points,
            "evidence": evidence, "explanation": explanation,
            "resolve_by": resolve_by, "remediation": remediation,
            "source": source, "confidence": confidence}


def _finding(id, severity, likelihood, impact, text, solution,
             verdict="CONFIRMED"):
    return {"id": id, "severity": severity, "likelihood": likelihood,
            "impact": impact, "text": text, "solution": solution,
            "verdict": verdict}


def _likely_finding(id, severity, likelihood, impact, text, solution):
    """FAIL on INFERRED evidence: LIKELY verdict, severity capped one
    level below the observed equivalent, text marked as inference."""
    return _finding(id, LIKELY_CAP[severity], likelihood, impact,
                    f"Likely: {text[0].lower() + text[1:]}", solution,
                    verdict="LIKELY")


def _src_of(field):
    """(source, confidence, factor) for a field object.

    OBSERVED (parsed/measured bytes) -> ("observed", 1.0, 1.0).
    INFERRED (model fill)            -> ("inferred", conf, conf).
    anything else                    -> ("none", 0.0, 0.0).
    Label/oracle inputs are passed explicitly as ("label", 1.0, 1.0):
    ground truth standing in as observed.
    """
    st = (field or {}).get("status", UNKNOWN)
    if st == "OBSERVED":
        return "observed", 1.0, 1.0
    if st == "INFERRED":
        try:
            c = float((field or {}).get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            c = 0.0
        c = min(max(c, 0.0), 1.0)
        return "inferred", c, c
    return "none", 0.0, 0.0


def _fail_or_likely(source):
    """FAIL rests on observed evidence; INFERRED evidence gives LIKELY."""
    return LIKELY if source == "inferred" else FAIL


def _factor_of(control):
    """Evidence weight of a control for posture/coverage math."""
    if control["source"] == "inferred":
        return control["confidence"]
    if control["source"] in ("observed", "label"):
        return 1.0
    return 0.0


def _lifetime_points(child_rekey_s):
    """(points, known). Lifetimes are label/oracle inputs; captures are
    short so lifetimes are never observed on the wire."""
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


def _na_controls(reason):
    specs = [("child-cipher", "Child cipher strength"),
             ("dh-strength", "DH group strength"),
             ("integrity", "Integrity algorithm"),
             ("pfs", "Perfect forward secrecy"),
             ("lifetime", "SA lifetime"),
             ("replay", "Replay protection"),
             ("ike-version", "IKE version"),
             ("ike-cipher", "IKE cipher strength"),
             ("ike-integrity", "IKE integrity strength"),
             ("mode-exposure", "Mode exposure")]
    wkey = {"child-cipher": "cipher", "dh-strength": "dh",
            "integrity": "integrity", "pfs": "pfs",
            "lifetime": "lifetime", "replay": "replay",
            "ike-version": "ike", "ike-cipher": "ike_cipher",
            "ike-integrity": "ike_integrity",
            "mode-exposure": "mode"}
    return [_ctl(cid, t, WEIGHTS[wkey[cid]],
                NOT_APPLICABLE, 0, {"note": reason},
                "Not applicable: no IPsec was detected in this capture.")
            for cid, t in specs]


def assess(classification: dict, lifetimes: dict | None = None) -> dict:
    """Assess from SA objects. lifetimes: optional label/oracle inputs
    {child_rekey_s, replay_window} (never observed in short captures)."""
    lifetimes = lifetimes or {}
    ike_sa = classification.get("ike_sa", {})
    child_sa = classification.get("child_sa", {})
    detection = classification.get("detection", {})
    detected = detection.get("ipsec_detected", True)

    def val(obj, key):
        f = (obj.get(key) or {})
        return f.get("value", "unknown"), f.get("status", UNKNOWN)

    if not detected:
        controls = _na_controls("no-ipsec-detected")
        return {"controls": controls, "posture_score": None,
                "coverage": 0.0, "score_status": "WITHHELD",
                "security_score": None, "risk_score": None,
                "risk_level": None, "findings": [], "threat_matrix": [],
                "breakdown": {k: 0 for k in WEIGHTS}}

    proto, proto_status = val(child_sa, "proto")
    controls, findings = [], []

    def ev(sa_name, key):
        f = ((ike_sa if sa_name == "ike_sa" else child_sa).get(key) or {})
        return {"field": f"{sa_name}.{key}",
                "status": f.get("status", UNKNOWN),
                "detail": f.get("evidence")}

    # ---- child cipher (scored on the CHILD SA alone) ----
    enc_f = child_sa.get("enc_alg") or {}
    enc, enc_status = enc_f.get("value", "unknown"), \
        enc_f.get("status", UNKNOWN)
    csrc, cconf, _ = _src_of(enc_f)
    if proto == "ah" and enc == "none":
        # AH has no cipher by design (RFC 4302): confirmed absence of
        # confidentiality is a FAIL scored at the old 5-point level.
        st = _fail_or_likely(csrc)
        controls.append(_ctl(
            "child-cipher", "Child cipher strength", 25, st, 5,
            ev("child_sa", "enc_alg"),
            "AH provides authentication only; there is no confidentiality.",
            remediation="Use ESP with AES-GCM where secrecy is required.",
            source=csrc, confidence=cconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "no-conf", "high", 3, 5,
            "AH provides no confidentiality.",
            "Use ESP with AES-GCM for secrecy."))
    elif enc_status in (UNKNOWN, NOT_OBSERVED) or enc == "unknown":
        controls.append(_ctl(
            "child-cipher", "Child cipher strength", 25, UNKNOWN, 0,
            ev("child_sa", "enc_alg"),
            "Child cipher not observed: IKE proposals describe the IKE SA "
            "only, and CHILD proposals travel encrypted.",
            resolve_by="Capture longer/more varied ESP traffic so the "
            "size-structure inference firms up, or score from ground-truth "
            "labels."))
    elif enc == "3des-cbc":
        st = _fail_or_likely(csrc)
        controls.append(_ctl(
            "child-cipher", "Child cipher strength", 25, st, 5,
            ev("child_sa", "enc_alg"),
            "3DES-CBC on the CHILD SA (SWEET32); the IKE suite "
            "does not change this verdict.",
            remediation="Migrate to AES-GCM (RFC 8221).",
            source=csrc, confidence=cconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "weak-cipher", "critical", 3, 5,
            "3DES-CBC is broken (SWEET32).",
            "Migrate to AES-GCM (RFC 8221)."))
    elif enc == "none" and proto == "esp":
        st = _fail_or_likely(csrc)
        controls.append(_ctl(
            "child-cipher", "Child cipher strength", 25, st, 0,
            ev("child_sa", "enc_alg"),
            "ESP child with no encryption: no confidentiality.",
            remediation="Use ESP with AES-GCM for secrecy.",
            source=csrc, confidence=cconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "no-conf", "high", 3, 5,
            "ESP child with no encryption.",
            "Use ESP with AES-GCM for secrecy."))
    else:
        controls.append(_ctl(
            "child-cipher", "Child cipher strength", 25, PASS,
            CIPHER_POINTS.get(enc, 0), ev("child_sa", "enc_alg"),
            f"Child cipher {enc} scored on its own SA evidence.",
            source=csrc, confidence=cconf))

    # ---- DH strength (child PFS-group scoped; IKE DH is IKE evidence) ----
    dh_f = classification.get("dh_group", {})
    dh, dh_status = dh_f.get("value", "unknown"), \
        dh_f.get("status", UNKNOWN)
    dsrc, dconf, _ = _src_of(dh_f)
    if dh_status in (UNKNOWN, NOT_OBSERVED) or dh == "unknown":
        controls.append(_ctl(
            "dh-strength", "DH group strength", 20, UNKNOWN, 0,
            {"field": "dh_group", "status": dh_status,
             "detail": dh_f.get("evidence")},
            "Negotiated DH group not observed: it appears only in the "
            "clear handshake, and the IKE group describes the IKE SA.",
            resolve_by="Capture IKE_SA_INIT (or the IKEv1 main-mode "
            "proposal) carrying the negotiated group."))
    elif dh in (1, 2, 5):
        st = _fail_or_likely(dsrc)
        controls.append(_ctl(
            "dh-strength", "DH group strength", 20, st, DH_POINTS.get(dh, 0),
            {"field": "dh_group", "status": dh_status},
            f"DH group {dh} is weak (Logjam).",
            remediation="Use ECP_256+ or MODP-2048+ (RFC 8247).",
            source=dsrc, confidence=dconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "weak-dh", "critical", 3, 5,
            f"DH group {dh} is weak (Logjam).",
            "Use ECP_256+ or MODP-2048+ (RFC 8247)."))
    else:
        controls.append(_ctl(
            "dh-strength", "DH group strength", 20, PASS, DH_POINTS.get(dh, 0),
            {"field": "dh_group", "status": dh_status},
            f"DH group {dh} meets the bar." if DH_POINTS.get(dh, 0) >= 15
            else f"DH group {dh} scored with reduced points.",
            source=dsrc, confidence=dconf))

    # ---- integrity (child SA) ----
    auth_f = child_sa.get("auth_alg") or {}
    auth, auth_status = auth_f.get("value", "unknown"), \
        auth_f.get("status", UNKNOWN)
    asrc, aconf, _ = _src_of(auth_f)
    if auth_status in (UNKNOWN, NOT_OBSERVED) or auth == "unknown":
        controls.append(_ctl(
            "integrity", "Integrity algorithm", 15, UNKNOWN, 0,
            ev("child_sa", "auth_alg"),
            "Child integrity not observed: it travels encrypted.",
            resolve_by="Capture longer/more varied ESP traffic, or score "
            "from ground-truth labels."))
    elif auth == "hmac-sha1":
        st = _fail_or_likely(asrc)
        controls.append(_ctl(
            "integrity", "Integrity algorithm", 15, st, 5,
            ev("child_sa", "auth_alg"), "HMAC-SHA1 integrity is weak.",
            remediation="Use HMAC-SHA2-256 or AEAD.",
            source=asrc, confidence=aconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "weak-integ", "medium", 2, 4,
            "HMAC-SHA1 integrity is weak.",
            "Use HMAC-SHA2-256 or AEAD."))
    elif auth == "none" and proto == "esp":
        st = _fail_or_likely(asrc)
        controls.append(_ctl(
            "integrity", "Integrity algorithm", 15, st, 0,
            ev("child_sa", "auth_alg"),
            "ESP child with no integrity.",
            remediation="Enable HMAC-SHA2-256 or use AEAD.",
            source=asrc, confidence=aconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "no-integ", "high", 3, 4, "ESP child with no integrity.",
            "Enable HMAC-SHA2-256 or use AEAD."))
    else:
        controls.append(_ctl(
            "integrity", "Integrity algorithm", 15, PASS,
            INTEG_POINTS.get(auth, 0), ev("child_sa", "auth_alg"),
            f"Child integrity {auth} scored on its own SA evidence.",
            source=asrc, confidence=aconf))

    # ---- PFS (states honestly whether observed or inferred) ----
    pfs_f = child_sa.get("pfs") or {}
    pfs, pfs_status = pfs_f.get("value", "unknown"), \
        pfs_f.get("status", UNKNOWN)
    psrc, pconf, _ = _src_of(pfs_f)
    if pfs_status in (UNKNOWN, NOT_OBSERVED) or pfs == "unknown":
        controls.append(_ctl(
            "pfs", "Perfect forward secrecy", 10, UNKNOWN, 0,
            ev("child_sa", "pfs"),
            "PFS state not observed: rekey content is encrypted; only "
            "rekey length hints at KE presence.",
            resolve_by="Capture a CREATE_CHILD_SA (or quick-mode) rekey "
            "exchange on the wire."))
    elif pfs is False:
        st = _fail_or_likely(psrc)
        controls.append(_ctl(
            "pfs", "Perfect forward secrecy", 10, st, 0,
            ev("child_sa", "pfs"),
            "No PFS: key compromise decrypts history.",
            remediation="Enable PFS with a strong DH group.",
            source=psrc, confidence=pconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "no-pfs", "high", 2, 5,
            "No PFS: key compromise decrypts history.",
            "Enable PFS with a strong DH group."))
    else:
        controls.append(_ctl(
            "pfs", "Perfect forward secrecy", 10, PASS, 10,
            ev("child_sa", "pfs"),
            "PFS rekey evidence observed." if psrc == "observed" else
            "PFS inferred from rekey length (model); rekey content is "
            "encrypted, so the group itself stays unconfirmed.",
            source=psrc, confidence=pconf))

    # ---- lifetime (label ground truth stands in as observed) ----
    life_raw = lifetimes.get("child_rekey_s")
    if life_raw is None:
        life_f = child_sa.get("lifetime") or {}
        life_v = life_f.get("value", "unknown")
        life_raw = None if life_v == "unknown" else life_v
        life_ev = ev("child_sa", "lifetime")
        lsrc, lconf, _ = _src_of(life_f)
    else:
        life_ev = {"field": "label.child_rekey_s", "status": "OBSERVED",
                   "detail": "oracle/label input (not wire-observable)"}
        lsrc, lconf = "label", 1.0
    pts, known = _lifetime_points(life_raw)
    if not known:
        controls.append(_ctl(
            "lifetime", "SA lifetime", 10, UNKNOWN, 0, life_ev,
            "SA lifetime not observed: rekey intervals are never visible "
            "in short captures.",
            resolve_by="Provide rekey intervals (configuration or "
            "long-duration capture with rekeys)."))
    elif life_raw is not None and int(life_raw) <= 3600:
        controls.append(_ctl(
            "lifetime", "SA lifetime", 10, PASS, pts, life_ev,
            f"CHILD rekey interval {life_raw}s within 1 h.",
            source=lsrc, confidence=lconf))
    else:
        st = _fail_or_likely(lsrc)
        controls.append(_ctl(
            "lifetime", "SA lifetime", 10, st, pts, life_ev,
            f"Long-lived CHILD SA ({life_raw}s) widens exposure.",
            remediation="Shorten CHILD rekey (<=1 h).",
            source=lsrc, confidence=lconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "long-sa", "low", 2, 3,
            "Long-lived CHILD SA widens exposure.",
            "Shorten CHILD rekey (<=1 h)."))

    # ---- replay (label ground truth stands in as observed) ----
    rw_raw = lifetimes.get("replay_window")
    if rw_raw is None:
        rw_f = child_sa.get("replay") or {}
        rw_v = rw_f.get("value", "unknown")
        rw_raw = None if rw_v == "unknown" else rw_v
        rw_ev = ev("child_sa", "replay")
        rsrc, rconf, _ = _src_of(rw_f)
    else:
        rw_ev = {"field": "label.replay_window", "status": "OBSERVED",
                 "detail": "oracle/label input (receiver enforcement is "
                           "never observable from packet sequence alone)"}
        rsrc, rconf = "label", 1.0
    if rw_raw is None or rw_raw == "unknown":
        controls.append(_ctl(
            "replay", "Replay protection", 5, UNKNOWN, 0, rw_ev,
            "Replay state not observed: sequence behavior does not prove "
            "receiver enforcement.",
            resolve_by="Read receiver configuration (anti-replay on, "
            "window size); packet captures cannot prove enforcement."))
    elif int(rw_raw) == 0:
        st = _fail_or_likely(rsrc)
        controls.append(_ctl(
            "replay", "Replay protection", 5, st, 0, rw_ev,
            "Replay protection disabled.",
            remediation="Enable anti-replay (window 32+).",
            source=rsrc, confidence=rconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "no-replay", "medium", 3, 3,
            "Replay protection disabled.",
            "Enable anti-replay (window 32+)."))
    else:
        # Any supported window at/above 32 is acceptable; larger windows
        # are a loss-tolerance choice, not a vulnerability.
        controls.append(_ctl(
            "replay", "Replay protection", 5, PASS, 5, rw_ev,
            f"Replay window {rw_raw} (>= 32) acceptable.",
            source=rsrc, confidence=rconf))

    # ---- IKE version (scored on the IKE SA alone) ----
    ike_f = ike_sa.get("version") or {}
    ike, ike_status = ike_f.get("value", "unknown"), \
        ike_f.get("status", UNKNOWN)
    isrc, iconf, _ = _src_of(ike_f)
    ike_dh_f = ike_sa.get("dh_group") or {}
    ike_dh = ike_dh_f.get("value", "unknown")
    ike_dh_status = ike_dh_f.get("status", UNKNOWN)
    weak_ike_dh = ike_dh_status == "OBSERVED" and ike_dh in (1, 2, 5)
    if ike_status in (UNKNOWN, NOT_OBSERVED) or ike == "unknown":
        controls.append(_ctl(
            "ike-version", "IKE version", 10, UNKNOWN, 0,
            ev("ike_sa", "version"),
            "IKE version not observed: no handshake in this capture.",
            resolve_by="Capture IKE_SA_INIT (UDP 500/4500) alongside ESP."))
    elif ike == "ikev1":
        pts = 2 if weak_ike_dh else IKE_POINTS["ikev1"]
        controls.append(_ctl(
            "ike-version", "IKE version", 10, FAIL, pts,
            ev("ike_sa", "version"),
            "IKEv1 negotiates weakly vs IKEv2." +
            (" Group observed on the IKE SA is also weak (Logjam)."
             if weak_ike_dh else ""),
            remediation="Migrate to IKEv2.",
            source=isrc, confidence=iconf))
        findings.append(_finding(
            "ikev1", "medium", 2, 3,
            "IKEv1 negotiates weakly vs IKEv2.",
            "Migrate to IKEv2."))
    elif weak_ike_dh:
        controls.append(_ctl(
            "ike-version", "IKE version", 10, FAIL, 2,
            ev("ike_sa", "version"),
            f"IKEv2, but the IKE SA group {ike_dh} is weak (Logjam). "
            "Scored on the IKE SA alone: it says nothing about the "
            "CHILD PFS group.",
            remediation="Use ECP_256+ or MODP-2048+ (RFC 8247).",
            source=isrc, confidence=iconf))
    else:
        controls.append(_ctl(
            "ike-version", "IKE version", 10, PASS,
            IKE_POINTS.get(ike, 0),
            ev("ike_sa", "version"), "IKEv2 in use.",
            source=isrc, confidence=iconf))
    if weak_ike_dh:
        # A weak group OBSERVED on the wire is a confirmed fact, even when
        # the child PFS group itself is unobserved (it stays UNKNOWN).
        findings.append(_finding(
            "weak-ike-dh", "critical", 3, 5,
            f"IKE SA DH group {ike_dh} is weak (Logjam).",
            "Use ECP_256+ or MODP-2048+ (RFC 8247)."))

    # ---- IKE cipher (v1.2; ike_sa evidence only, never the child) ----
    ienc_f = ike_sa.get("enc_alg") or {}
    ienc = ienc_f.get("value", "unknown")
    ienc_status = ienc_f.get("status", UNKNOWN)
    ikey_f = ike_sa.get("enc_key_len") or {}
    ikey = ikey_f.get("value", "unknown")
    esrc, econf, _ = _src_of(ienc_f)
    if ienc_status in (UNKNOWN, NOT_OBSERVED) or ienc == "unknown":
        if ienc_status == "OBSERVED":
            # Bytes seen but suite unidentified: cannot confirm strength.
            controls.append(_ctl(
                "ike-cipher", "IKE cipher strength", 5, UNKNOWN, 0,
                ev("ike_sa", "enc_alg"),
                f"IKE SA cipher {ienc!r} not recognized: strength "
                "unconfirmable from the transform id.",
                resolve_by="Identify the initiator/responder transform id "
                "against RFC 8221 / RFC 8247."))
        else:
            controls.append(_ctl(
                "ike-cipher", "IKE cipher strength", 5, UNKNOWN, 0,
                ev("ike_sa", "enc_alg"),
                "IKE SA cipher not observed: no handshake in this capture.",
                resolve_by="Capture IKE_SA_INIT (UDP 500/4500) alongside "
                "ESP."))
    elif ienc == "3des-cbc" or "des" in str(ienc).lower().replace("3des", "") \
            or (isinstance(ikey, int) and "cbc" in str(ienc) and ikey < 128):
        st = _fail_or_likely(esrc)
        controls.append(_ctl(
            "ike-cipher", "IKE cipher strength", 5, st,
            IKE_CIPHER_POINTS.get(ienc, 0),
            ev("ike_sa", "enc_alg"),
            f"IKE SA cipher {ienc} (key {ikey}) is weak: handshake "
            "confidentiality fails first (SWEET32 / short keys). Scored "
            "on the IKE SA alone.",
            remediation="Negotiate AES-GCM or AES-256-CBC for the IKE SA "
            "(RFC 8221).",
            source=esrc, confidence=econf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "weak-ike-cipher",
            "high" if ienc == "3des-cbc" else "critical", 3, 5,
            f"IKE SA cipher {ienc} is weak.",
            "Negotiate AES-GCM or AES-256-CBC for the IKE SA (RFC 8221)."))
    else:
        controls.append(_ctl(
            "ike-cipher", "IKE cipher strength", 5, PASS,
            IKE_CIPHER_POINTS.get(ienc, 4), ev("ike_sa", "enc_alg"),
            f"IKE SA cipher {ienc} acceptable (scored on the IKE SA).",
            source=esrc, confidence=econf))

    # ---- IKE integrity incl. PRF (v1.2; weakest link of auth/prf) ----
    iauth_f = ike_sa.get("auth_alg") or {}
    iauth = iauth_f.get("value", "unknown")
    iauth_status = iauth_f.get("status", UNKNOWN)
    iprf_f = ike_sa.get("prf") or {}
    iprf = iprf_f.get("value", "unknown")
    iprf_status = iprf_f.get("status", UNKNOWN)
    tsrc, tconf, _ = _src_of(
        iauth_f if iauth_status == "OBSERVED" else
        (iprf_f if iprf_status == "OBSERVED" else iauth_f))
    WEAK_IKE_INTEG = {"hmac-sha1", "hmac-sha1-96", "hmac-md5", "md5",
                      "xcbc"}
    weak_auth = iauth in WEAK_IKE_INTEG
    weak_prf = iprf in WEAK_IKE_INTEG
    if (iauth_status in (UNKNOWN, NOT_OBSERVED) or iauth == "unknown") \
            and (iprf_status in (UNKNOWN, NOT_OBSERVED)
                 or iprf == "unknown"):
        controls.append(_ctl(
            "ike-integrity", "IKE integrity strength", 3, UNKNOWN, 0,
            ev("ike_sa", "auth_alg"),
            "IKE SA integrity/PRF not observed: no handshake in capture.",
            resolve_by="Capture IKE_SA_INIT (UDP 500/4500) alongside ESP."))
    elif weak_auth or weak_prf:
        weak_val = iauth if weak_auth else iprf
        md5 = "md5" in str(weak_val)
        st = _fail_or_likely(tsrc)
        controls.append(_ctl(
            "ike-integrity", "IKE integrity strength", 3, st,
            IKE_INTEG_POINTS.get(weak_val, 1),
            ev("ike_sa", "auth_alg"),
            f"IKE SA integrity/PRF {weak_val} is weak: AUTH payloads and "
            "key derivation are only as strong as the weakest link.",
            remediation="Negotiate HMAC-SHA2-256+ (or AEAD) for integrity "
            "and PRF (RFC 8221/8247).",
            source=tsrc, confidence=tconf))
        findings.append((_likely_finding if st == LIKELY else _finding)(
            "weak-ike-integ", "high" if md5 else "medium", 3, 4,
            f"IKE SA integrity/PRF {weak_val} is weak.",
            "Negotiate HMAC-SHA2-256+ (or AEAD) for integrity and PRF."))
    else:
        shown = iauth if iauth != "unknown" else iprf
        controls.append(_ctl(
            "ike-integrity", "IKE integrity strength", 3, PASS,
            IKE_INTEG_POINTS.get(iauth, IKE_INTEG_POINTS.get(iprf, 3)),
            ev("ike_sa", "auth_alg"),
            f"IKE SA integrity/PRF {shown} acceptable (IKE SA scope).",
            source=tsrc, confidence=tconf))

    # ---- mode exposure: use-case dependent, never a blanket penalty ----
    mode_f = child_sa.get("mode") or {}
    mode = mode_f.get("value", "unknown")
    msrc, mconf, _ = _src_of(mode_f)
    if mode == "tunnel":
        controls.append(_ctl(
            "mode-exposure", "Mode exposure", 5, PASS, 5,
            ev("child_sa", "mode"), "Tunnel mode hides inner topology.",
            source=msrc, confidence=mconf))
    elif mode == "transport":
        controls.append(_ctl(
            "mode-exposure", "Mode exposure", 5, UNKNOWN, 0,
            ev("child_sa", "mode"),
            "Transport mode exposes host identities, but whether that is "
            "a finding depends on declared use (host-to-host transport "
            "is legitimate). No verdict without policy.",
            resolve_by="Declare policy: tunnel for site-to-site, "
            "transport only for host-to-host links."))
    else:
        controls.append(_ctl(
            "mode-exposure", "Mode exposure", 5, UNKNOWN, 0,
            ev("child_sa", "mode"), "Encapsulation mode not determined.",
            resolve_by="Capture more ESP for size-overhead inference "
            "(AH: read the next-header)."))

    # Confidence-weighted aggregation (v1.2): each control speaks with
    # its evidence weight f (OBSERVED/label 1.0, INFERRED its confidence,
    # UNKNOWN 0). posture = 100 * S(points*f) / S(weight*f) over f > 0;
    # coverage = S(weight*f) / S(weights of applicable controls).
    evaluated = [c for c in controls if _factor_of(c) > 0]
    applicable = [c for c in controls if c["status"] != NOT_APPLICABLE]
    num = sum(c["points"] * _factor_of(c) for c in evaluated)
    den = sum(c["weight"] * _factor_of(c) for c in evaluated)
    posture = round(100 * num / den) if den else None
    w_app = sum(c["weight"] for c in applicable)
    coverage = round(sum(c["weight"] * _factor_of(c) for c in evaluated)
                     / w_app, 4) if w_app else 0.0
    status = "PUBLISHED" if coverage >= 0.5 else "WITHHELD"

    if status == "PUBLISHED":
        security, risk = posture, 100 - posture
        bucket = "low" if risk < 25 else "medium" if risk < 50 else \
            "high" if risk < 75 else "critical"
    else:
        security, risk, bucket = None, None, None
    threats = [{"id": f["id"], "likelihood": f["likelihood"],
                "impact": f["impact"],
                "risk": f["likelihood"] * f["impact"]} for f in findings]
    pts_by = {c["id"]: c["points"] for c in controls}
    breakdown = {"cipher": pts_by["child-cipher"], "dh": pts_by["dh-strength"],
                 "integrity": pts_by["integrity"], "pfs": pts_by["pfs"],
                 "lifetime": pts_by["lifetime"], "replay": pts_by["replay"],
                 "ike": pts_by["ike-version"],
                 "ike_cipher": pts_by["ike-cipher"],
                 "ike_integrity": pts_by["ike-integrity"],
                 "mode": pts_by["mode-exposure"]}
    return {"controls": controls, "posture_score": posture,
            "coverage": round(coverage, 4), "score_status": status,
            "security_score": security, "risk_score": risk,
            "risk_level": bucket, "findings": findings,
            "threat_matrix": threats, "breakdown": breakdown,
            "rule_version": RULE_VERSION}

#!/usr/bin/env python
"""M1 validation gate. Verify, never assume - every check reads real output.

Phases:
  1. matrix self-consistency (count, PSK uniqueness, one-factor diffs)
  2. emitted files cross-checked against matrix.py derivations
  3. Gate A: every swanctl file loads into the ss-verify charon
     (`swanctl --load-conns` AND `--load-creds`, rc + output inspected)
  4. Gate B: every legacy ipsec.conf passes starter --conftest with
     ZERO "parsing error" in stdout (rc alone is NOT trusted: starter
     exits 0 even on unknown keywords)
  5. negative controls: deliberately broken configs MUST be rejected,
     otherwise the gates themselves are proven broken -> fail
  6. label_schema.json is a valid JSON Schema; example and all 18
     variant labels validate; deliberately invalid labels MUST fail

Usage:
  .venv/bin/python testbed/validate_configs.py
Exit code 0 only when every check passes.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import matrix as m  # noqa: E402
import gen_configs as g  # noqa: E402

TESTBED = Path(__file__).resolve().parent
VARIANTS_DIR = TESTBED / "variants"
CONFIGS_DIR = TESTBED / "configs"
LABELS_DIR = TESTBED / "labels"
SCHEMA_PATH = TESTBED / "label_schema.json"

SS_VERIFY = "ss-verify"
LEGACY_IMAGE = "testbed-strongswan"
LEGACY_STARTER = "/usr/lib/ipsec/starter"

results: list[tuple[bool, str]] = []


def check(cond: bool, msg: str) -> bool:
    results.append((bool(cond), msg))
    return bool(cond)


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout + proc.stderr)


# ---------------------------------------------------------------- phase 1
def phase_matrix() -> None:
    check(len(m.VARIANTS) >= 15, f"matrix has {len(m.VARIANTS)} variants (spec minimum 15)")
    psks = [m.psk_for(v["id"]) for v in m.VARIANTS]
    check(len(set(psks)) == len(psks), "PSK unique per variant")
    check(
        all(p.startswith("psk-") and len(p) == 20 for p in psks),
        "PSK format psk-<16 hex>",
    )
    for v in m.VARIANTS:
        vid = v["id"]
        child = m.child_name(v)
        check(child == f"{vid}-child", f"{vid}: child name '{child}' matches entrypoint contract")
        # TS shape
        for gw in ("gw-a", "gw-b"):
            lts, rts = m.traffic_selectors(v, gw)
            if v["mode"] == "transport":
                suffix = "/128" if v["ip_version"] == 6 else "/32"
                check(
                    lts.endswith(suffix) and rts.endswith(suffix),
                    f"{vid}/{gw}: transport TS are host selectors ({lts} <-> {rts})",
                )
                lo, ro = m.endpoints(v, gw)
                check(
                    lts == lo + suffix and rts == ro + suffix,
                    f"{vid}/{gw}: transport TS equal IKE endpoints",
                )
            else:
                check(
                    "/" in lts and not lts.endswith(("/32", "/128")),
                    f"{vid}/{gw}: tunnel TS are subnets ({lts} <-> {rts})",
                )
        # one-factor diff vs v1 for the simple weak variants: proposal present
        ike_p, child_p = m.ike_proposal(v), m.child_proposal(v)
        check("-" in ike_p, f"{vid}: ike proposal well-formed ({ike_p})")
        check(len(child_p) > 0, f"{vid}: child proposal non-empty ({child_p})")
        if v["pfs"]:
            check(
                m.DH_TOKENS[v["dh_group"]] in child_p,
                f"{vid}: PFS on -> DH token in child proposal",
            )
        else:
            check(
                m.DH_TOKENS[v["dh_group"]] not in child_p,
                f"{vid}: PFS off -> no DH token in child proposal",
            )
    # v17 (esn off explicit) vs v1: identical except the esn token
    v1, v17 = m.BY_ID["v1"], m.BY_ID["v17"]
    check(
        m.child_proposal(v17) == m.child_proposal(v1) + "-noesn",
        "v17 differs from v1 only by explicit -noesn token",
    )
    check(m.child_proposal(m.BY_ID["v16"]).endswith("-esn"), "v16 ends with -esn token")


# ---------------------------------------------------------------- phase 2
def phase_files() -> None:
    for v in m.VARIANTS:
        vid = v["id"]
        ike_p = m.ike_proposal(v)
        child_p = m.child_proposal(v)
        prop_key = m.child_proposal_key(v)
        for gw in ("gw-a", "gw-b"):
            sw = VARIANTS_DIR / vid / gw / "swanctl.conf"
            lg = CONFIGS_DIR / vid / gw / "ipsec.conf"
            check(sw.is_file(), f"{vid}/{gw}: swanctl.conf exists")
            check(lg.is_file(), f"{vid}/{gw}: legacy ipsec.conf exists")
            # legacy ipsec.secrets are deploy-time generated (MAJOR-2),
            # never committed: validate the generator output instead.
            want_sec = g.legacy_secrets(v)
            check(m.psk_for(vid) in want_sec,
                  f"{vid}: generated legacy secrets embed psk_for")
            if not sw.is_file():
                continue
            text = sw.read_text(encoding="utf-8")
            lo, ro = m.endpoints(v, gw)
            lts, rts = m.traffic_selectors(v, gw)
            need = [
                f"version = {v['ike_version']}",
                f"local_addrs = {lo}",
                f"remote_addrs = {ro}",
                f"proposals = {ike_p}",
                f"{m.child_name(v)} {{",
                f"local_ts = {lts}",
                f"remote_ts = {rts}",
                f"mode = {v['mode']}",
                f"{prop_key} = {child_p}",
                f"rekey_time = {v['ike_rekey_s']}",
                f"replay_window = {v['replay_window']}",
                "id-1 = \"gw-a\"",
                "id-2 = \"gw-b\"",
            ]
            # secret line: REDACTED placeholder (committed) or the real
            # deploy-time PSK (filled by gen_secrets.py) — both valid.
            sec_ok = (f'secret = "{m.psk_for(vid)}"' in text
                      or 'secret = "REDACTED-deploy-generated"' in text)
            check(sec_ok, f"{vid}/{gw}/swanctl: secret present or REDACTED")
            for token in need:
                check(token in text, f"{vid}/{gw}/swanctl: contains `{token}`")
            check(
                text.count("encap = yes") == (1 if v["nat_t"] else 0),
                f"{vid}/{gw}/swanctl: encap present iff nat_t",
            )
            # child-level rekey line (the child one) exists
            check(
                f"        rekey_time = {v['child_rekey_s']}" in text,
                f"{vid}/{gw}/swanctl: child rekey_time emitted",
            )
            # secrets identical across gateways: verify the generator
            # output (files themselves are deploy-time only, MAJOR-2).
            t2 = g.legacy_secrets(v)
            check(m.psk_for(vid) in t2 and "gw-a gw-b" in t2,
                  f"{vid}: generated legacy secrets sane")
            # legacy content
            lt = lg.read_text(encoding="utf-8")
            legacy_need = [
                f"conn {vid}",
                f"type={v['mode']}",
                f"keyexchange=ikev{v['ike_version']}",
                f"ike={ike_p}",
                f"left={lo}",
                f"right={ro}",
                f"ikelifetime={m.legacy_lifetime(v, 'ike')}",
                f"keylife={m.legacy_lifetime(v, 'child')}",
                f"replay_window={v['replay_window']}",
            ]
            if v["ipsec_protocol"] == "ah":
                legacy_need.append(f"ah={child_p}")
            else:
                legacy_need.append(f"esp={child_p}")
            if v["mode"] == "tunnel":
                lts_l, rts_l = m.traffic_selectors(v, gw)
                legacy_need += [f"leftsubnet={lts_l}", f"rightsubnet={rts_l}"]
            else:
                check(
                    "leftsubnet" not in lt,
                    f"{vid}/{gw}/legacy: transport omits leftsubnet (endpoint TS)",
                )
            for token in legacy_need:
                check(token in lt, f"{vid}/{gw}/ipsec.conf: contains `{token}`")
            active = [ln.strip() for ln in lt.splitlines() if not ln.strip().startswith("#")]
            check(
                active.count("forceencaps=yes") == (1 if v["nat_t"] else 0),
                f"{vid}/{gw}/legacy: forceencaps present iff nat_t",
            )
            check(
                (active.count("aggressive=no") == 1) == (v["ike_version"] == 1),
                f"{vid}/{gw}/legacy: aggressive=no iff IKEv1",
            )


# ---------------------------------------------------------------- phase 3
def phase_swanctl_gate() -> None:
    rc, out = _run(["docker", "inspect", "-f", "{{.State.Running}}", SS_VERIFY])
    if rc != 0 or out.strip() != "true":
        check(False, f"preflight: container {SS_VERIFY} running (start it first)")
        return
    for v in m.VARIANTS:
        for gw in ("gw-a", "gw-b"):
            src = VARIANTS_DIR / v["id"] / gw / "swanctl.conf"
            tag = f"{v['id']}/{gw}"
            if not src.is_file():
                check(False, f"Gate A {tag}: file missing, skipped")
                continue
            cp = subprocess.run(
                ["docker", "cp", str(src), f"{SS_VERIFY}:/tmp/m1-validate.conf"],
                capture_output=True, text=True,
            )
            if cp.returncode != 0:
                check(False, f"Gate A {tag}: docker cp failed: {cp.stderr.strip()}")
                continue
            rc1, out1 = _run(
                ["docker", "exec", SS_VERIFY,
                 "swanctl", "--load-conns", "-f", "/tmp/m1-validate.conf"]
            )
            ok1 = (
                rc1 == 0
                and "successfully loaded" in out1
                and "failed" not in out1
                and "discarded" not in out1
            )
            msg = f"Gate A {tag}: load-conns rc={rc1} :: {out1.strip().splitlines()[-1:] }"
            check(ok1, msg)
            print(("  ok   " if ok1 else "  FAIL ") + msg)
            rc2, out2 = _run(
                ["docker", "exec", SS_VERIFY,
                 "swanctl", "--load-creds", "-f", "/tmp/m1-validate.conf"]
            )
            ok2 = rc2 == 0 and "loaded ike secret" in out2
            msg = f"Gate A {tag}: load-creds rc={rc2} :: has_secret={'loaded ike secret' in out2}"
            check(ok2, msg)
            print(("  ok   " if ok2 else "  FAIL ") + msg)


# ---------------------------------------------------------------- phase 4
def phase_legacy_gate(mount_dir: Path) -> None:
    rc, out = _run(["docker", "image", "inspect", LEGACY_IMAGE], timeout=30)
    if rc != 0:
        check(False, f"preflight: image {LEGACY_IMAGE} missing (build testbed/Dockerfile.strongswan)")
        return
    for v in m.VARIANTS:
        for gw in ("gw-a", "gw-b"):
            rel = f"{v['id']}/{gw}/ipsec.conf"
            src = mount_dir / rel
            tag = f"{v['id']}/{gw}"
            if not src.is_file():
                check(False, f"Gate B {tag}: file missing")
                continue
            rc1, out1 = _run(
                ["docker", "run", "--rm", "--entrypoint", "sh",
                 "-v", f"{mount_dir}:/x:ro", LEGACY_IMAGE,
                 "-c", f"{LEGACY_STARTER} --conftest --conf /x/{rel}"],
                timeout=45,
            )
            has_parse_err = "parsing error" in out1 or "parsing errors" in out1
            has_fatal = "fatal" in out1.lower() and "0 fatal" not in out1
            ok = rc1 == 0 and not has_parse_err and not has_fatal
            last = out1.strip().splitlines()[-1:] or [""]
            msg = f"Gate B {tag}: conftest rc={rc1} parse_errors={has_parse_err} :: {last}"
            check(ok, msg)
            print(("  ok   " if ok else "  FAIL ") + msg)


# ---------------------------------------------------------------- phase 5
def phase_negative_controls(mount_dir: Path) -> None:
    del mount_dir  # negative controls live in temp dirs, never in the repo
    with tempfile.TemporaryDirectory(prefix="m1-negative-") as tmp:
        neg_root = Path(tmp)
        # 5a: broken swanctl (unknown key) MUST be rejected by load-conns
        bad_sw = neg_root / "negative-control-swanctl.conf"
        bad_sw.write_text(
            "connections {\n  bad {\n    version = 2\n    local_addrz = 10.0.0.1\n  }\n}\n",
            encoding="utf-8",
        )
        cp = subprocess.run(
            ["docker", "cp", str(bad_sw), f"{SS_VERIFY}:/tmp/m1-negative.conf"],
            capture_output=True, text=True,
        )
        if cp.returncode != 0:
            check(False, f"negative swanctl: docker cp failed: {cp.stderr.strip()}")
        else:
            rc1, out1 = _run(
                ["docker", "exec", SS_VERIFY,
                 "swanctl", "--load-conns", "-f", "/tmp/m1-negative.conf"]
            )
            accepted = rc1 == 0 and "successfully loaded" in out1 and "failed" not in out1
            ok = not accepted
            msg = f"negative swanctl (unknown key) rejected: {ok} (rc={rc1})"
            check(ok, msg)
            print(("  ok   " if ok else "  FAIL ") + msg)

        # 5b: broken legacy conf (unknown keyword) MUST produce "parsing error"
        #     - starter exits 0 here; only stdout proves the failure (rc trap!)
        neg_dir = neg_root / "legacy"
        neg_dir.mkdir()
        (neg_dir / "ipsec.conf").write_text(
            "config setup\n\nconn bad\n    keyexchange=ikev2\n    boguskeyword=42\n",
            encoding="utf-8",
        )
        rc1, out1 = _run(
            ["docker", "run", "--rm", "--entrypoint", "sh",
             "-v", f"{neg_dir}:/x:ro", LEGACY_IMAGE,
             "-c", f"{LEGACY_STARTER} --conftest --conf /x/ipsec.conf"],
            timeout=45,
        )
        ok1 = "parsing error" in out1
        msg = (
            f"negative legacy (unknown keyword) reports parsing error: {ok1} "
            f"(starter rc={rc1} - rc alone is untrusted)"
        )
        check(ok1, msg)
        print(("  ok   " if ok1 else "  FAIL ") + msg)
        msg = f"documented starter trap: unknown keyword exits rc=0 (rc={rc1})"
        check(rc1 == 0, msg)
        print(("  ok   " if rc1 == 0 else "  FAIL ") + msg)


# ---------------------------------------------------------------- phase 6
def phase_schema() -> None:
    try:
        import jsonschema
    except ImportError:
        check(False, "jsonschema package installed in .venv")
        return
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft7Validator.check_schema(schema)
        check(True, "label_schema.json is a valid draft-07 JSON Schema")
    except Exception as exc:  # noqa: BLE001
        check(False, f"label_schema.json invalid: {exc}")
        return
    validator = jsonschema.Draft7Validator(schema)

    def errors(obj) -> list[str]:
        return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in validator.iter_errors(obj)]

    # example label
    example = json.loads((LABELS_DIR / "example-label.json").read_text(encoding="utf-8"))
    errs = errors(example)
    check(not errs, f"example-label.json validates against schema {errs}")

    # every variant label (merged with per-pcap fields) validates
    variants = json.loads((LABELS_DIR / "variants.json").read_text(encoding="utf-8"))
    check(len(variants) == len(m.VARIANTS), "variants.json has one row per variant")
    for row in variants:
        full = dict(row)
        full.update(
            traffic_type="icmp", source="synthetic", run_id="r1",
            duration_s=1.0, packet_count=10,
        )
        errs = errors(full)
        check(not errs, f"label for {row['variant']} validates {errs}")

    # plain negative label
    plain = {
        "variant": "plain", "ipsec_protocol": "none", "ike_version": "none",
        "mode": "none", "encryption": "none", "key_length_bits": 0,
        "auth": "none", "aead": False, "dh_group": 0, "pfs": False,
        "esn": False, "replay_window": 0, "nat_t": False,
        "ike_rekey_s": 0, "child_rekey_s": 0, "ip_version": 4,
        "traffic_type": "icmp", "source": "synthetic", "run_id": "r1",
        "duration_s": 1.0, "packet_count": 10,
    }
    check(not errors(plain), "plain (non-IPsec) negative label validates")

    # negative controls: deliberately invalid labels MUST fail
    bad1 = dict(plain)
    bad1.update(variant="v1", encryption="none", ipsec_protocol="esp",
                ike_version="ikev2", mode="tunnel", key_length_bits=128,
                auth="hmac-sha256", dh_group=14, pfs=True)
    check(bool(errors(bad1)), "schema rejects inconsistent label (variant=v1, encryption=none)")
    bad2 = dict(plain)
    bad2["packet_count"] = 0
    check(bool(errors(bad2)), "schema rejects packet_count=0")
    bad3 = dict(plain)
    bad3["variant"] = "v99"
    check(bool(errors(bad3)), "schema rejects unknown variant id")


# ---------------------------------------------------------------- main
def phase_no_committed_secrets() -> None:
    """MAJOR-2: no PSK may appear in tracked testbed files."""
    import subprocess as sp
    r = sp.run(["git", "-C", str(TESTBED.parent), "grep", "-E",
                "psk-[0-9a-f]{16}", "HEAD", "--", "testbed/"],
               capture_output=True, text=True)
    hits = [l for l in r.stdout.splitlines() if l.strip()]
    check(not hits, f"no psk-* in tracked testbed/ files ({len(hits)} hits)")
    for h in hits[:5]:
        print(f"   LEAK {h[:120]}")


def main() -> int:
    phases = [
        ("phase 1: matrix self-consistency", phase_matrix),
        ("phase 2: emitted files vs matrix", phase_files),
        ("phase 2b: no committed secrets", phase_no_committed_secrets),
        ("phase 3: Gate A swanctl load into ss-verify", phase_swanctl_gate),
        ("phase 4: Gate B legacy conftest (stdout inspected)", lambda: phase_legacy_gate(CONFIGS_DIR)),
        ("phase 5: negative controls", lambda: phase_negative_controls(CONFIGS_DIR)),
        ("phase 6: label schema", phase_schema),
    ]
    for name, fn in phases:
        print(f"== {name}")
        before = len(results)
        fn()
        failed_here = [msg for ok, msg in results[before:] if not ok]
        print(f"   -> {len(results) - before - len(failed_here)}/{len(results) - before} passed")
        for msg in failed_here:
            print(f"   FAIL {msg}")

    failed = [msg for ok, msg in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print(f"{len(failed)} FAILURES (listed above)")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deploy-time secrets (independent review MAJOR-2).

All PSKs are deterministic test-only lab credentials derived from
``matrix.psk_for`` — never real secrets. They must NOT live in git:
- `testbed/gen_configs.py` writes REDACTED placeholders into committed
  outputs (`--redacted`); full-secret output is deploy-only.
- This script fills secrets at deploy time:
    gen_secrets.py <variant> | --all [--redact]
  `<variant>`/`--all` writes legacy `ipsec.secrets` files and patches the
  `secret = ...` lines of `swanctl.conf` from `matrix.psk_for`
  (idempotent). `--redact` replaces committed secrets with the
  placeholder (one-time hygiene).
- `testbed/scripts/netns-up.sh` runs this before `load-conns`.
- `testbed/validate_configs.py` validates the generator output and
  asserts no `psk-<hex>` appears in tracked `testbed/` files.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TESTBED = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTBED))
import matrix as m  # noqa: E402
import gen_configs as g  # noqa: E402

PLACEHOLDER = "REDACTED-deploy-generated"
SECRET_RE = re.compile(r'secret\s*=\s*"([^"]*)"')
PSK_RE = re.compile(r"psk-[0-9a-f]{16}")
LEGACY_RE = re.compile(r'PSK\s+"([^"]+)"')


def fill_variant(vid: str) -> list[str]:
    """Write secrets for one variant from matrix.psk_for. Idempotent."""
    v = m.BY_ID[vid]
    psk = m.psk_for(vid)
    changed = []
    for gw in ("gw-a", "gw-b"):
        sw = TESTBED / "variants" / vid / gw / "swanctl.conf"
        text = sw.read_text(encoding="utf-8")
        new, n = SECRET_RE.subn(f'secret = "{psk}"', text)
        if n == 0:
            raise RuntimeError(f"no secret line in {sw}")
        if new != text:
            sw.write_text(new, encoding="utf-8")
            changed.append(str(sw))
        lg = TESTBED / "configs" / vid / gw / "ipsec.secrets"
        lg.parent.mkdir(parents=True, exist_ok=True)
        want = g.legacy_secrets(v)
        if not lg.exists() or lg.read_text(encoding="utf-8") != want:
            lg.write_text(want, encoding="utf-8")
            changed.append(str(lg))
    return changed


def redact_tree() -> list[str]:
    """One-time hygiene: replace committed PSKs with the placeholder."""
    changed = []
    for sw in sorted((TESTBED / "variants").rglob("swanctl.conf")):
        text = sw.read_text(encoding="utf-8")
        new = SECRET_RE.sub(f'secret = "{PLACEHOLDER}"', text)
        if new != text:
            sw.write_text(new, encoding="utf-8")
            changed.append(str(sw))
    for lg in sorted((TESTBED / "configs").rglob("ipsec.secrets")):
        lg.unlink()
        changed.append(str(lg) + " (deleted)")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("variant", nargs="?", help="variant id or --all")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--redact", action="store_true")
    args = ap.parse_args()
    if args.redact:
        for c in redact_tree():
            print(c)
        return 0
    vids = m.VARIANT_IDS if args.all else [args.variant]
    if not vids or vids == [None]:
        ap.error("give a variant id or --all")
    for vid in vids:
        if vid not in m.BY_ID:
            ap.error(f"unknown variant {vid}")
        for c in fill_variant(vid):
            print(f"filled {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

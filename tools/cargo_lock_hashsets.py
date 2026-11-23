#!/usr/bin/env python3
"""Verify or write Hashset (BLAKE3 + SHA-256) entries for every crate in Cargo.lock.

    python3 tools/cargo_lock_hashsets.py            # verify fetched .crate files against Cargo.lock [metadata]
    python3 tools/cargo_lock_hashsets.py --write    # compute and write hashsets into Cargo.lock [metadata]

Uses `reference/blake3.py` (stdlib only, no `b3sum` required) after `cargo fetch --locked`.
"""

import base64
import glob
import hashlib
import os
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK = os.path.join(ROOT, "Cargo.lock")
sys.path.insert(0, os.path.join(ROOT, "reference"))
import blake3  # noqa: E402


def b32(raw):
    return base64.b32encode(raw).decode().rstrip("=").lower()


def crate_file(name, version):
    home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    hits = glob.glob(os.path.join(home, "registry", "cache", "*", f"{name}-{version}.crate"))
    if not hits:
        sys.exit(f"{name} {version}: no .crate file under {home}/registry/cache (run `cargo fetch --locked`)")
    return hits[0]


def main():
    lock_text = open(LOCK, "r", encoding="utf-8").read()
    lock = tomllib.loads(lock_text)
    want = {}
    for p in lock["package"]:
        source = p.get("source", "")
        if not source.startswith("registry+"):
            continue
        raw = open(crate_file(p["name"], p["version"]), "rb").read()
        sha256 = hashlib.sha256(raw).digest()
        if sha256.hex() != p["checksum"]:
            sys.exit(f"{p['name']} {p['version']}: .crate file does not match Cargo.lock checksum")
        b3 = blake3.hash(raw)
        want[f"hashset {p['name']} {p['version']} ({source})"] = f"blake3-{b32(b3)}.sha256-{b32(sha256)}"

    metadata = lock.get("metadata", {})
    if sys.argv[1:] == ["--write"]:
        kept = {k: v for k, v in metadata.items() if not k.startswith("hashset ")}
        packages = lock_text.split("\n[metadata]\n")[0].rstrip("\n") + "\n"
        lines = "".join(f'"{k}" = "{v}"\n' for k, v in sorted({**kept, **want}.items()))
        open(LOCK, "w", encoding="utf-8").write(packages + "\n[metadata]\n" + lines)
        print(f"wrote {len(want)} hashsets to Cargo.lock")
        return 0
    if sys.argv[1:]:
        sys.exit(__doc__)

    have = {k: v for k, v in metadata.items() if k.startswith("hashset ")}
    wrong = sorted(k for k in want.keys() | have.keys() if want.get(k) != have.get(k))
    for k in wrong:
        print("missing, stale or wrong:", k, file=sys.stderr)
    if wrong:
        return 1
    print(f"{len(want)} crates match their hashsets in Cargo.lock (BLAKE3 + SHA-256)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

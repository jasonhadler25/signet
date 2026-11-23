#!/usr/bin/env python3
"""Landing gate for BLINCS: checks every required gate against the exact HEAD commit.

    python3 tools/land.py                 # full gate (requires clean working tree)
    python3 tools/land.py --mutants       # also runs full release-mode cargo-mutants check
    python3 tools/land.py --skip-clean-check --skip-rust  # Python/vector checks only (CI helper)
"""

import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference"))
import blake3  # noqa: E402
import blincs  # noqa: E402

REF_SIG = os.path.join(ROOT, "test_vectors", "reference-signature-1.bin")
REF_SHA256 = "ac0808dbf5a435ab21d7426df178abb707f89f3a26a1b84cd13cda083f6f00e1"
REF_BLAKE3 = "f5de1861fe29352b6f290469517a749cc426cf22c48d246acc494cb75d10a4c8"


def run(label, cmd):
    print(f"==> {label}: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=ROOT)
    if res.returncode != 0:
        print(f"FAIL: {label} (exit {res.returncode})", file=sys.stderr)
        sys.exit(res.returncode)


def check_vectors_and_python():
    print("==> Checking reference-signature-1.bin digests (SHA-256 + BLAKE3)")
    raw = open(REF_SIG, "rb").read()
    assert len(raw) == 3988, f"unexpected length {len(raw)}"
    got_sha256 = hashlib.sha256(raw).hexdigest()
    got_blake3 = blake3.hash(raw).hex()
    assert got_sha256 == REF_SHA256, f"SHA-256 mismatch: {got_sha256}"
    assert got_blake3 == REF_BLAKE3, f"BLAKE3 mismatch: {got_blake3}"

    # Verify reference-signature-1.bin with pure Python reference.
    vk = blincs.VerifyingKey(bytes.fromhex("0ad9c13b8972b912a211f9fd2ba1eec80f172d89ea2869ab004a78588619f97c"))
    assert vk.verify(b"hello, BLINCS", raw), "Python reference rejected reference-signature-1.bin"

    # Verify python3 -O validation (no reliance on assert).
    run(
        "Python -O reference validation",
        [
            sys.executable,
            "-O",
            "-c",
            (
                "import sys; sys.path.insert(0, 'reference'); import blincs\n"
                "for fn, args in [(blincs.VerifyingKey,(b'x',)),(blincs.SigningKey,(b'x',)),"
                "(blincs.mix,(b'x',0,b'0'*32,b'')),(blincs.draw,(b'x',0))]:\n"
                "    try:\n        fn(*args)\n        raise SystemExit(1)\n"
                "    except ValueError:\n        pass\n"
                "ba = bytearray(bytes.fromhex('0ad9c13b8972b912a211f9fd2ba1eec80f172d89ea2869ab004a78588619f97c'))\n"
                "vk = blincs.VerifyingKey(ba)\n"
                "ba[0] ^= 0xff\n"
                "if vk.bytes[0] != 0x0a: raise SystemExit(1)\n"
            ),
        ],
    )


def main():
    args = set(sys.argv[1:])
    unknown = args - {"--mutants", "--skip-clean-check", "--skip-rust"}
    if unknown:
        print(f"unknown option(s): {sorted(unknown)}\n{__doc__}", file=sys.stderr)
        return 2

    if "--skip-clean-check" not in args:
        st = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=True)
        if st.stdout.strip():
            print("FAIL: working tree is not clean:\n" + st.stdout, file=sys.stderr)
            return 1
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        print(f"Landing gate on exact commit: {sha}")

    run("BLAKE3 official test vectors (Python)", [sys.executable, "reference/blake3.py"])
    run("Parameter optimizer self-check", [sys.executable, "tools/optimize.py", "--check"])
    check_vectors_and_python()

    if "--skip-rust" not in args:
        run("cargo fetch", ["cargo", "fetch", "--locked"])
        run("Cargo.lock hashsets (BLAKE3 + SHA-256)", [sys.executable, "tools/cargo_lock_hashsets.py"])
        run("rustfmt", ["cargo", "fmt", "--", "--check"])
        run("clippy", ["cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings"])
        run("nextest", ["cargo", "nextest", "run", "--locked"])
        run("doctests", ["cargo", "test", "--doc", "--locked"])
        run("planted-fault controls", [sys.executable, "tools/controls.py"])

    if "--mutants" in args:
        run("release-mode mutation check", [sys.executable, "tools/mutants/check.py"])

    print("\nALL GATES PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

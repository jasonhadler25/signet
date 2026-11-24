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
REF_SHA256 = "7fbc1537b5b516c823542c425f48129fe78d974a1806ae24fe0c8dc382a7436c"
REF_BLAKE3 = "ab80843efd3f5860ccc87f578b8831a79eaf3bb595ac516954823f2ed6886b23"
EDGE_VEC = os.path.join(ROOT, "test_vectors", "edge-vectors.json")
EDGE_SHA256 = "4be3ee44ca7318bdd15a492e77dd1b749ee8d957124701fe070615a52d4a3437"
EDGE_BLAKE3 = "ffddb6318d2d4a33974fb3d9062f3ec98c796bb58e1a59c9c8f9ab63232f1efe"


def run(label, cmd):
    print(f"==> {label}: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=ROOT)
    if res.returncode != 0:
        print(f"FAIL: {label} (exit {res.returncode})", file=sys.stderr)
        sys.exit(res.returncode)


def check_vectors_and_python():
    print("==> Checking reference-signature-1.bin digests (SHA-256 + BLAKE3)")
    raw = open(REF_SIG, "rb").read()
    assert len(raw) == 5616, f"unexpected length {len(raw)}"
    got_sha256 = hashlib.sha256(raw).hexdigest()
    got_blake3 = blake3.hash(raw).hex()
    assert got_sha256 == REF_SHA256, f"SHA-256 mismatch: {got_sha256}"
    assert got_blake3 == REF_BLAKE3, f"BLAKE3 mismatch: {got_blake3}"

    # Verify reference-signature-1.bin and edge-vectors.json with pure Python reference.
    vk = blincs.VerifyingKey(bytes.fromhex("0ad9c13b8972b912a211f9fd2ba1eec863399e14d2f6c8c3309f9d7e61a53c46"))
    assert vk.verify(b"hello, BLINCS", raw), "Python reference rejected reference-signature-1.bin"

    print("==> Checking edge-vectors.json digests (SHA-256 + BLAKE3) and Python verification")
    import json

    edge_raw = open(EDGE_VEC, "rb").read()
    assert hashlib.sha256(edge_raw).hexdigest() == EDGE_SHA256, "edge-vectors.json SHA-256 mismatch"
    assert blake3.hash(edge_raw).hex() == EDGE_BLAKE3, "edge-vectors.json BLAKE3 mismatch"
    edge_msgs = {
        "empty": b"",
        "one-byte-zero": b"\x00",
        "chunk-1024": bytes((i * 31) & 0xFF for i in range(1024)),
        "pipeline-16385-high-leaf": bytes((i * 37 + 5) & 0xFF for i in range(16385)),
    }
    for entry in json.loads(edge_raw.decode("utf-8")):
        sig = bytes.fromhex(entry["sig_hex"])
        assert hashlib.sha256(sig).hexdigest() == entry["sig_sha256"]
        assert blake3.hash(sig).hex() == entry["sig_blake3"]
        assert vk.verify(edge_msgs[entry["name"]], sig), f"Python reference rejected edge vector {entry['name']}"

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
                "ba = bytearray(bytes.fromhex('0ad9c13b8972b912a211f9fd2ba1eec863399e14d2f6c8c3309f9d7e61a53c46'))\n"
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
    run("Shipped-code safety counts", [sys.executable, "tools/counts.py"])
    run("Static + dynamic domain separation", [sys.executable, "tools/domain_sep.py"])
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

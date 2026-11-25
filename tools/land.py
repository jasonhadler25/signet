#!/usr/bin/env python3
"""Landing gate for BLINCS: checks every required gate against the exact HEAD commit.

    python3 tools/land.py                 # full gate (requires clean working tree)
    python3 tools/land.py --mutants       # also runs full release-mode cargo-mutants check
    python3 tools/land.py --skip-clean-check --skip-rust  # Python/vector checks only (CI helper)
"""

import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference"))
import blake3  # noqa: E402
import blincs  # noqa: E402

REF_IMP = os.path.join(ROOT, "test_vectors", "reference-imprint-1.bin")
REF_SHA256 = "965c4bf2ccc1b670f17f26d1ecaeda126f6de57839c8cf964ef2f6ffac749bb0"
REF_BLAKE3 = "9f88101241de2493b0c2e3584e2cef5c8463d64e606040086f2d602e4bed8351"
EDGE_VEC = os.path.join(ROOT, "test_vectors", "edge-vectors.json")
EDGE_SHA256 = "f5d6ab2ee23c650231e8098fc28e5684b0d1522196e9e6b5929ba6b1128c301e"
EDGE_BLAKE3 = "57d7af23421b796c128f9c012a41cc22951d6db6e220bcaffea8c319a429aa52"
REF_SIGNET_ID = "db09192c50a65494941887b9c57895ab1d8c239fbfb22e021f3b8dcc8d5b3da2"


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def run(label, cmd):
    print(f"==> {label}: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=ROOT)
    if res.returncode != 0:
        fail(f"{label} (exit {res.returncode})")


def check_vectors_and_python():
    print("==> Checking reference-imprint-1.bin digests (SHA-256 + BLAKE3)")
    raw = open(REF_IMP, "rb").read()
    if len(raw) != 5888:
        fail(f"unexpected length {len(raw)}")
    got_sha256 = hashlib.sha256(raw).hexdigest()
    got_blake3 = blake3.hash(raw).hex()
    if got_sha256 != REF_SHA256:
        fail(f"SHA-256 mismatch: {got_sha256}")
    if got_blake3 != REF_BLAKE3:
        fail(f"BLAKE3 mismatch: {got_blake3}")

    sid = blincs.SignetId(bytes.fromhex(REF_SIGNET_ID))
    if not sid.verify(b"hello, BLINCS", raw):
        fail("Python reference rejected reference-imprint-1.bin")

    print("==> Checking edge-vectors.json digests (SHA-256 + BLAKE3) and Python verification")
    edge_raw = open(EDGE_VEC, "rb").read()
    if hashlib.sha256(edge_raw).hexdigest() != EDGE_SHA256:
        fail("edge-vectors.json SHA-256 mismatch")
    if blake3.hash(edge_raw).hex() != EDGE_BLAKE3:
        fail("edge-vectors.json BLAKE3 mismatch")
    edge_msgs = {
        "empty": b"",
        "one-byte-zero": b"\x00",
        "chunk-1024": bytes((i * 31) & 0xFF for i in range(1024)),
        "stream-16385-high-leaf": bytes((i * 37 + 5) & 0xFF for i in range(16385)),
    }
    for entry in json.loads(edge_raw.decode("utf-8")):
        imp = bytes.fromhex(entry["imprint_hex"])
        if hashlib.sha256(imp).hexdigest() != entry["imprint_sha256"]:
            fail(f"edge vector SHA-256 mismatch: {entry['name']}")
        if blake3.hash(imp).hex() != entry["imprint_blake3"]:
            fail(f"edge vector BLAKE3 mismatch: {entry['name']}")
        if not sid.verify(edge_msgs[entry["name"]], imp):
            fail(f"Python reference rejected edge vector {entry['name']}")

    run(
        "Python -O reference validation",
        [
            sys.executable,
            "-O",
            "-c",
            (
                "import sys; sys.path.insert(0, 'reference'); import blincs\n"
                "for fn, args in [(blincs.SignetId,(b'x',)),(blincs.Signet,(b'x',)),"
                "(blincs.mix_pool,([b'0'*33],b'0'*32,b'')),(blincs.expand_pool,(b'x',)),(blincs.draw,(b'x',0))]:\n"
                "    try:\n        fn(*args)\n        raise SystemExit(1)\n"
                "    except ValueError:\n        pass\n"
                f"ba = bytearray(bytes.fromhex('{REF_SIGNET_ID}'))\n"
                "sid = blincs.SignetId(ba)\n"
                "ba[0] ^= 0xff\n"
                "if sid.bytes[0] != 0xdb: raise SystemExit(1)\n"
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
            fail("working tree is not clean:\n" + st.stdout)
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

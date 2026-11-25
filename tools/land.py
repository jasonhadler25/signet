#!/usr/bin/env python3
"""Exact-commit landing gate for Signet (BLINCS-128-7x5).

Runs every check required before pushing a commit:
  - clean working tree (unless --skip-clean-check)
  - Python BLAKE3 official 35-vector check
  - constrained-device parameter optimizer self-check
  - shipped-code safety counts (0 unsafe, 0 debug_assert!, 0 truncation allows, 0 Drop)
  - static & dynamic domain separation + SPEC.md table check
  - checked-in reference & edge test vectors (SHA-256 + BLAKE3 + Python + Node 24 TypeScript)
  - cargo fetch --locked + Cargo.lock BLAKE3 & SHA-256 hashsets
  - cargo fmt -- --check
  - cargo clippy --all-targets --locked -- -D warnings
  - RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
  - cargo nextest run --locked + cargo test --doc --locked
  - cargo package --locked (verifies unpacked .crate archive compiles cleanly)
  - 17 planted-fault controls in a disposable copy (tools/controls.py)
  - optional: release-mode mutation testing (--mutants)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference"))
import blake3  # noqa: E402
import blincs  # noqa: E402

REF_IMP = os.path.join(ROOT, "test_vectors", "reference-imprint-1.bin")
REF_CTX = b"BLINCS-128-7x5 reference vector v1"
REF_SHA256 = "056e4c91aab74cf3ae9dedc3b0799e25f0eb19d25070e285f3b114c601ffe993"
REF_BLAKE3 = "1f90309febb00685d497c84edfae3bf9563206e15215f143a1eab51bcc5332bf"
EDGE_VEC = os.path.join(ROOT, "test_vectors", "edge-vectors.json")
EDGE_SHA256 = "4ef1f28a65247ee8a17981a6faa6d3dda99b68126ae721cd40572b0379e48299"
EDGE_BLAKE3 = "0616c04735308daff990d1051a8992da5052d4f9d1fc63c18acba7a67df68483"
REF_SIGNET_ID = "b58abfb655db7c92808f12c3a8ffd2d04841cf61994321648cf193638876c492"

EDGE_MSGS = {
    "empty": b"",
    "one-byte-zero": b"\x00",
    "chunk-1024": bytes((i * 31) & 0xFF for i in range(1024)),
    "stream-16385-high-leaf": bytes((i * 37 + 5) & 0xFF for i in range(16385)),
}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def run(label, cmd, extra_env=None):
    print(f"==> {label}: {' '.join(cmd)}")
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    res = subprocess.run(cmd, cwd=ROOT, env=env)
    if res.returncode != 0:
        fail(f"{label} (exit {res.returncode})")


def check_vectors_and_references():
    print("==> Checking reference-imprint-1.bin digests (SHA-256 + BLAKE3)")
    raw = open(REF_IMP, "rb").read()
    if len(raw) != 7392:
        fail(f"unexpected length {len(raw)}")
    got_sha256 = hashlib.sha256(raw).hexdigest()
    got_blake3 = blake3.hash(raw).hex()
    if got_sha256 != REF_SHA256:
        fail(f"SHA-256 mismatch: {got_sha256}")
    if got_blake3 != REF_BLAKE3:
        fail(f"BLAKE3 mismatch: {got_blake3}")

    sid = blincs.SignetId(bytes.fromhex(REF_SIGNET_ID))
    if not sid.verify(REF_CTX, b"hello, BLINCS", raw):
        fail("Python reference rejected reference-imprint-1.bin")
    if sid.verify(b"", b"hello, BLINCS", raw):
        fail("Python reference accepted wrong context on reference-imprint-1.bin")

    print("==> Checking edge-vectors.json digests (SHA-256 + BLAKE3) and Python verification")
    edge_raw = open(EDGE_VEC, "rb").read()
    if hashlib.sha256(edge_raw).hexdigest() != EDGE_SHA256:
        fail("edge-vectors.json SHA-256 mismatch")
    if blake3.hash(edge_raw).hex() != EDGE_BLAKE3:
        fail("edge-vectors.json BLAKE3 mismatch")
    edge_entries = json.loads(edge_raw.decode("utf-8"))
    for entry in edge_entries:
        ctx = bytes.fromhex(entry["ctx_hex"])
        imp = bytes.fromhex(entry["imprint_hex"])
        if hashlib.sha256(imp).hexdigest() != entry["imprint_sha256"]:
            fail(f"edge vector SHA-256 mismatch: {entry['name']}")
        if blake3.hash(imp).hex() != entry["imprint_blake3"]:
            fail(f"edge vector BLAKE3 mismatch: {entry['name']}")
        if not sid.verify(ctx, EDGE_MSGS[entry["name"]], imp):
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
                "(blincs.frame_context,(b'0'*256,)),"
                "(blincs.mix_pool,([b'0'*33],b'0'*32,b'')),(blincs.expand_pool,(b'x',)),(blincs.draw,(b'x',0))]:\n"
                "    try:\n        fn(*args)\n        raise SystemExit(1)\n"
                "    except ValueError:\n        pass\n"
                f"ba = bytearray(bytes.fromhex('{REF_SIGNET_ID}'))\n"
                "sid = blincs.SignetId(ba)\n"
                "ba[0] ^= 0xff\n"
                "if sid.bytes[0] != 0xb5: raise SystemExit(1)\n"
            ),
        ],
    )

    node = shutil.which("node")
    if not node:
        fail("node not found in PATH (required to verify reference/blincs.ts)")
    print("==> Checking Node TypeScript reference (reference/blincs.ts) against all 5 vectors + RNG mix")
    ts_path = os.path.join(ROOT, "reference", "blincs.ts")
    with tempfile.TemporaryDirectory(prefix="signet-ts-") as td:
        msg1 = os.path.join(td, "msg1.bin")
        open(msg1, "wb").write(b"hello, BLINCS")
        r = subprocess.run([node, ts_path, "--verify", REF_SIGNET_ID, REF_CTX.hex(), REF_IMP, msg1], text=True, capture_output=True)
        if r.returncode != 0 or r.stdout.strip() != "true":
            fail(f"blincs.ts rejected reference-imprint-1.bin: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
        rb = subprocess.run([node, ts_path, "--verify", REF_SIGNET_ID, "", REF_IMP, msg1], text=True, capture_output=True)
        if rb.returncode != 1 or rb.stdout.strip() != "false":
            fail(f"blincs.ts did not reject wrong context: rc={rb.returncode} out={rb.stdout!r}")
        for entry in edge_entries:
            sp = os.path.join(td, f"{entry['name']}.sig")
            mp = os.path.join(td, f"{entry['name']}.msg")
            open(sp, "wb").write(bytes.fromhex(entry["imprint_hex"]))
            open(mp, "wb").write(EDGE_MSGS[entry["name"]])
            re_ts = subprocess.run([node, ts_path, "--verify", REF_SIGNET_ID, entry["ctx_hex"], sp, mp], text=True, capture_output=True)
            if re_ts.returncode != 0 or re_ts.stdout.strip() != "true":
                fail(f"blincs.ts rejected edge vector {entry['name']}: rc={re_ts.returncode} out={re_ts.stdout!r} err={re_ts.stderr!r}")
        mix = subprocess.run([node, ts_path, "--mix", "01" * 32 + ",aabb", "02" * 32, "clock-reading", "0"], text=True, capture_output=True)
        expected_lines = [
            "a927779e28c7d4d6e9b90fce92b7d968 fe3349e18bfbb00aa7c01e353a77116c60a815f9c4c2d2c0975b378013860ceb "
            "c8957425119b74d75e27985c4a1dbc9854fa0ad485361642b13fb927e17770c2 a10872041d434e01fd6c8761bfc3f25e84a697c255c1dbd26959cec5c5ad1cc6",
            "2654e875d07988376ff03a027fc5168c708341b72c01a97e29f143bc9429caea",
        ]
        if mix.returncode != 0 or mix.stdout.strip().splitlines() != expected_lines:
            fail(f"blincs.ts --mix mismatch: rc={mix.returncode} out={mix.stdout!r} err={mix.stderr!r}")


def main():
    if not __debug__:
        fail("tools/land.py must not be run with python -O")

    args = set(sys.argv[1:])
    unknown = args - {"--mutants", "--skip-clean-check", "--skip-rust"}
    if unknown:
        print(f"unknown option(s): {sorted(unknown)}\n{__doc__}", file=sys.stderr)
        return 2

    skipped = []
    if "--skip-clean-check" not in args:
        st = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=True)
        if st.stdout.strip():
            fail("working tree is not clean:\n" + st.stdout)
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        print(f"Landing gate on exact commit: {sha}")
    else:
        skipped.append("clean-working-tree")

    run("BLAKE3 official test vectors (Python)", [sys.executable, "reference/blake3.py"])
    run("Parameter optimizer self-check", [sys.executable, "tools/optimize.py", "--check"])
    run("Shipped-code safety counts", [sys.executable, "tools/counts.py"])
    run("Static + dynamic domain separation", [sys.executable, "tools/domain_sep.py"])
    check_vectors_and_references()

    if "--skip-rust" not in args:
        run("cargo fetch", ["cargo", "fetch", "--locked"])
        run("Cargo.lock hashsets (BLAKE3 + SHA-256)", [sys.executable, "tools/cargo_lock_hashsets.py"])
        run("rustfmt", ["cargo", "fmt", "--", "--check"])
        run("clippy", ["cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings"])
        run("rustdoc", ["cargo", "doc", "--no-deps", "--locked"], extra_env={"RUSTDOCFLAGS": "-D warnings"})
        run("nextest", ["cargo", "nextest", "run", "--locked"])
        run("doctests", ["cargo", "test", "--doc", "--locked"])
        pkg_cmd = ["cargo", "package", "--locked"]
        if "--skip-clean-check" in args:
            pkg_cmd.append("--allow-dirty")
        run("cargo package (unpacked .crate build verification)", pkg_cmd)
        run("planted-fault controls", [sys.executable, "tools/controls.py"])
    else:
        skipped.append("rust-gates")

    if "--mutants" in args:
        run("mutation tests", [sys.executable, "tools/mutants/check.py"])
    else:
        skipped.append("mutants (pass --mutants)")

    if skipped:
        print(f"\nGATES PASSED (skipped: {', '.join(skipped)}).")
    else:
        print("\nALL GATES PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

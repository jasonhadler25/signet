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
REF_SHA256 = "5d1b63aa041a6cd3f44b9e5a2c2ed27d4ab6b4d166d3a28a8d019a611472ced6"
REF_BLAKE3 = "e9e433283ad714c487275b7dcc747fb5e93c7f43d98353d24dd98d2e4794b231"
EDGE_VEC = os.path.join(ROOT, "test_vectors", "edge-vectors.json")
EDGE_SHA256 = "ef06e6fe467be56bae91434c2042f73bc7b994ae116a4de68f463de12fc747e1"
EDGE_BLAKE3 = "981210f93509158996974e12f521a002e62b24ace355cbd720ff0ee7db8e6bb2"
REF_SIGNET_ID = "98a5b8314b854e78f72cbadc9f5ed67c15bc2ad253cd98be1d5951595f217512"

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
    if len(raw) != 6432:
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
    # Also verify live Python reference SIGNER regenerates reference-imprint-1.bin byte-for-byte.
    py_signer = blincs.Signet(bytes(range(32)))
    if py_signer.id.bytes != bytes.fromhex(REF_SIGNET_ID):
        fail("Python reference signer derived wrong SignetId")
    regen = py_signer.imprint(REF_CTX, b"hello, BLINCS", bytes([7] * 32))
    if regen != raw:
        fail("Python reference signer output differed from test_vectors/reference-imprint-1.bin")

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
                "(blincs.mix_pool,(b'0'*33,b'0'*32,0,b'')),(blincs.expand_pool,(b'x',)),(blincs.draw,(b'x',0))]:\n"
                "    try:\n        fn(*args)\n        raise SystemExit(1)\n"
                "    except ValueError:\n        pass\n"
                f"ba = bytearray(bytes.fromhex('{REF_SIGNET_ID}'))\n"
                "sid = blincs.SignetId(ba)\n"
                "ba[0] ^= 0xff\n"
                "if sid.bytes[0] != 0x98: raise SystemExit(1)\n"
            ),
        ],
    )

    node = shutil.which("node")
    if not node:
        fail("node not found in PATH (required to verify reference/blincs.ts)")
    print("==> Checking Node TypeScript reference (reference/blincs.ts) against all 5 vectors + RNG mix")
    ts_path = os.path.join(ROOT, "reference", "blincs.ts")
    # Single in-process Node run over all 5 positive vectors, negative cases, and RNG mix/draw:
    ts_check_script = f"""
import {{ readFileSync }} from "node:fs";
import {{ verify, mixPool, expandPool, draw }} from {json.dumps(ts_path)};
const hex = (s) => Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();
const vk = hex({json.dumps(REF_SIGNET_ID)});
const refCtx = hex({json.dumps(REF_CTX.hex())});
const refMsg = enc.encode("hello, BLINCS");
const refSig = new Uint8Array(readFileSync({json.dumps(REF_IMP)}));
if (!verify(vk, refCtx, refMsg, refSig)) throw new Error("rejected reference-imprint-1.bin");
if (verify(vk, new Uint8Array(0), refMsg, refSig)) throw new Error("accepted wrong context");
const tampered = Uint8Array.from(refSig); tampered[4096] ^= 1;
if (verify(vk, refCtx, refMsg, tampered)) throw new Error("accepted tampered sig");
const wrongId = Uint8Array.from(vk); wrongId[0] ^= 1;
if (verify(wrongId, refCtx, refMsg, refSig)) throw new Error("accepted wrong SignetId");
if (verify(vk, refCtx, refMsg, refSig.slice(0, -1))) throw new Error("accepted truncated sig");
const edges = JSON.parse(readFileSync({json.dumps(EDGE_VEC)}, "utf8"));
const edgeMsgs = {{
  "empty": new Uint8Array(0),
  "one-byte-zero": new Uint8Array([0]),
  "chunk-1024": Uint8Array.from({{ length: 1024 }}, (_, i) => (i * 31) & 0xff),
  "stream-16385-high-leaf": Uint8Array.from({{ length: 16385 }}, (_, i) => (i * 37 + 5) & 0xff),
}};
for (const e of edges) {{
  if (!verify(vk, hex(e.ctx_hex), edgeMsgs[e.name], hex(e.imprint_hex))) {{
    throw new Error("rejected edge vector " + e.name);
  }}
}}
const [ns, rk, kk] = expandPool(mixPool(hex("01".repeat(32)), hex("02".repeat(32)), 4242, enc.encode("clock-reading")));
const got = [ns, rk, kk, draw(rk, 0n)].map(toHex);
const want = [
  "97b8baab73eac1d7054392950f031281019b65b801470471fe558ab838bb18d8",
  "0c098f138cdb2414e1d302cc2239c6083666a0a0df0a09b5e016f3425ebcb663",
  "6c6e05e84a6afff9374640a0f0db963b696a501e88f175967efd5b8c8a74b8e7",
  "7a6fcaeaa30742062cee1f2be0ac3aafb1ec114b1f14c44a87899e34cfd43d26",
];
if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error("mixPool/draw mismatch: " + got.join(" "));
"""
    r_inproc = subprocess.run([node, "--input-type=module", "-e", ts_check_script], text=True, capture_output=True)
    if r_inproc.returncode != 0:
        fail(f"blincs.ts verification failed: rc={r_inproc.returncode} out={r_inproc.stdout!r} err={r_inproc.stderr!r}")
    # Plus one real CLI smoke test (positive + negative):
    with tempfile.TemporaryDirectory(prefix="signet-ts-") as td:
        msg1 = os.path.join(td, "msg1.bin")
        open(msg1, "wb").write(b"hello, BLINCS")
        r = subprocess.run([node, ts_path, "--verify", REF_SIGNET_ID, REF_CTX.hex(), REF_IMP, msg1], text=True, capture_output=True)
        if r.returncode != 0 or r.stdout.strip() != "true":
            fail(f"blincs.ts CLI rejected reference-imprint-1.bin: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
        rb = subprocess.run([node, ts_path, "--verify", REF_SIGNET_ID, "", REF_IMP, msg1], text=True, capture_output=True)
        if rb.returncode != 1 or rb.stdout.strip() != "false":
            fail(f"blincs.ts CLI did not reject wrong context: rc={rb.returncode} out={rb.stdout!r}")


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
        run("rustfmt", ["cargo", "fmt", "--all", "--", "--check"])
        run("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"])
        run("rustdoc", ["cargo", "doc", "--workspace", "--no-deps", "--locked"], extra_env={"RUSTDOCFLAGS": "-D warnings"})
        run("nextest", ["cargo", "nextest", "run", "--workspace", "--locked"])
        run("doctests", ["cargo", "test", "--workspace", "--doc", "--locked"])
        pkg_allow = ["--allow-dirty"] if "--skip-clean-check" in args else []
        run("cargo package signet", ["cargo", "package", "-p", "signet", "--locked", *pkg_allow])
        run("cargo package signet-verify", ["cargo", "package", "-p", "signet-verify", "--locked", *pkg_allow])
        run(
            "freestanding wasm32-unknown-unknown build (signet-verify)",
            ["cargo", "build", "--manifest-path", "wasm-test/Cargo.toml", "--target", "wasm32-unknown-unknown", "--release", "--locked"],
        )
        run("freestanding wasm32-unknown-unknown execution (Node 24)", ["node", "wasm-test/run_wasm.mjs"])
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

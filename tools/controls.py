#!/usr/bin/env python3
"""Planted-fault positive controls for Signet (BLINCS-128-7x5).

Runs all mutations inside a disposable temporary copy (sharing target/ for speed),
so the main repository checkout is never modified even if interrupted.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONTROLS = [
    (
        "WOTS+ checksum nibbles computed in digits()",
        "src/one_time.rs",
        "    out[MSG_CHAINS] = u8::try_from(csum & 0x0f).unwrap();",
        "    out[MSG_CHAINS] = 0;",
        "wots_digits_and_checksum_boundaries",
    ),
    (
        "FORS 35-bit leaf_addr masking in LeafAddr::from_digest_word()",
        "src/params.rs",
        "        Self(word & ((1u64 << HYPER_BITS) - 1))",
        "        Self(word)",
        "parse_digest_extracts_all_fors_indices_and_35bit_leaf_addr",
    ),
    (
        "FORS root compression binds all 20 tree roots (fors_root)",
        "src/few_time.rs",
        "    for t in 0..FORS_TREES {\n        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);\n    }",
        "    for t in 0..FORS_TREES - 1 {\n        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);\n    }",
        "every_signature_region_is_checked",
    ),
    (
        "Hypertree final top-root equality check (verify_short)",
        "src/lib.rs",
        "        if ct_eq_n(&node, self.root()) { Ok(()) } else { Err(InvalidImprint) }",
        "        let _ = node;\n        Ok(())",
        "every_signature_region_is_checked",
    ),
    (
        "verify_short rejects mismatched serialized salt against short",
        "src/lib.rs",
        "        if !ct_eq_n(imprint.salt(), short[..N].try_into().unwrap()) {\n            return Err(InvalidImprint);\n        }",
        "        let _ = imprint.salt();",
        "verify_short_rejects_mismatched_salt_against_short",
    ),
    (
        "Per-signature salt keyed into content hash (derive_msg_key)",
        "src/content.rs",
        "    buf[..N].copy_from_slice(salt);",
        "    buf[..N].copy_from_slice(&[0u8; N]);",
        "reference_vector_and_intermediate_kats_match_python_byte_for_byte",
    ),
    (
        "Application Context framed into content hash (derive_msg_key)",
        "src/content.rs",
        "    let ctx_bytes = ctx.as_bytes();\n    let mut buf = [0u8; N + 1 + MAX_CONTEXT_LEN];",
        "    let ctx_bytes: &[u8] = b\"\";\n    let _ = ctx;\n    let mut buf = [0u8; N + 1 + MAX_CONTEXT_LEN];",
        "context_validation_framing_and_error_contracts",
    ),
    (
        "Streaming content_from_reader feeds chunks into Hasher",
        "src/content.rs",
        "        hasher.update(&buf[..filled]);",
        "        let _ = filled;",
        "streaming_boundaries_and_fragmented_readers_match_slices",
    ),
    (
        "Streaming content_from_reader zeroes read buffer before each read",
        "src/content.rs",
        "    buf[filled..].fill(0);",
        "    let _ = filled;",
        "reader_never_sees_previous_callers_bytes",
    ),
    (
        "Randomness::initialize rejects non-directory paths",
        "src/randomness.rs",
        "        if !meta.file_type().is_dir() {",
        "        if false {",
        "hostile_directory_and_unexpected_files_are_rejected_without_deletion",
    ),
    (
        "Randomness::initialize rejects unexpected filenames/symlinks in directory",
        "src/randomness.rs",
        "            if !is_seed_filename(&name) || !entry.file_type()?.is_file() {",
        "            if false {",
        "hostile_directory_and_unexpected_files_are_rejected_without_deletion",
    ),
    (
        "Randomness::initialize rejects seed files exceeding 32 bytes",
        "src/randomness.rs",
        "    if filled > SEED_FILE_MAX_LEN {",
        "    if false {",
        "hostile_directory_and_unexpected_files_are_rejected_without_deletion",
    ),
    (
        "Randomness::create refuses to overwrite existing directory",
        "src/randomness.rs",
        "        builder.create(dir)?;",
        "        fs::create_dir_all(dir)?;",
        "randomness_seed_directory_lifecycle_concurrency_and_self_healing",
    ),
    (
        "SignetId::from_bytes initializes blake3-servil-core",
        "src/lib.rs",
        "    pub fn from_bytes(bytes: &[u8; SIGNET_ID_LEN]) -> Self {\n        ensure_init();",
        "    pub fn from_bytes(bytes: &[u8; SIGNET_ID_LEN]) -> Self {",
        "verify_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "Signet::from_seed initializes blake3-servil-core",
        "src/lib.rs",
        "    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {\n        ensure_init();",
        "    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {",
        "signing_key_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "Randomness::draw panics instead of wrapping at u64::MAX",
        "src/randomness.rs",
        '        self.count.try_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(1)).expect("randomness draw counter exhausted")',
        "        self.count.fetch_add(1, Ordering::Relaxed)",
        "randomness_draw_panics_on_counter_exhaustion",
    ),
    (
        "Randomness::initialize initializes blake3-servil-core",
        "src/randomness.rs",
        "    pub fn initialize(dir: impl AsRef<Path>) -> io::Result<Self> {\n        ensure_init();",
        "    pub fn initialize(dir: impl AsRef<Path>) -> io::Result<Self> {",
        "initialize_alone_initializes_blake3_in_fresh_process",
    ),
]


def run_nextest(workdir, target_dir, test_filter=None):
    cmd = ["cargo", "nextest", "run", "--locked", "--no-fail-fast", "--color", "never"]
    if test_filter is not None:
        cmd += ["-E", f"test(/{test_filter}$/)"]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = target_dir
    return subprocess.run(cmd, cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)


def main():
    tmp_root = tempfile.mkdtemp(prefix="signet-controls-")
    work = os.path.join(tmp_root, "work")
    target_dir = os.path.join(tmp_root, "target")
    try:
        shutil.copytree(
            ROOT,
            work,
            ignore=shutil.ignore_patterns(".git", "target", "bench", "audits", "__pycache__"),
        )
        print("Baseline: checking unmutated tests pass in disposable copy...")
        base = run_nextest(work, target_dir)
        if base.returncode != 0:
            print(base.stdout, file=sys.stderr)
            print("FAIL: baseline tests did not pass", file=sys.stderr)
            return 1

        missed = []
        for i, (name, rel, old, new, flt) in enumerate(CONTROLS, 1):
            path = os.path.join(work, rel)
            orig = open(path).read()
            count = orig.count(old)
            if count != 1:
                print(f"ERROR [{i}/{len(CONTROLS)}] {name}: expected 1 match in {rel}, found {count}", file=sys.stderr)
                return 2
            try:
                open(path, "w").write(orig.replace(old, new, 1))
                res = run_nextest(work, target_dir, flt)
            finally:
                open(path, "w").write(orig)

            if res.returncode == 0:
                print(f"MISSED [{i}/{len(CONTROLS)}] {name} ({flt} still passed!)")
                missed.append(name)
            elif "1 test run: 0 passed, 1 failed" not in res.stdout or flt not in res.stdout:
                print(f"ERROR [{i}/{len(CONTROLS)}] {name}: nonzero exit without running/failing {flt}:\n{res.stdout}", file=sys.stderr)
                return 2
            else:
                print(f"CAUGHT [{i}/{len(CONTROLS)}] {name}")

        if missed:
            print(f"\nFAIL: {len(missed)} planted fault(s) escaped: {missed}", file=sys.stderr)
            return 1
        print(f"\nPASS: all {len(CONTROLS)} planted faults caught by their targeted tests (disposable copy).")
        return 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

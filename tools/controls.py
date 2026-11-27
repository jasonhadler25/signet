#!/usr/bin/env python3
"""Planted-fault positive controls for Signet (BLINCS-128-A2).

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
        "S-WOTS+Z Sperner unranker selects exact constant-sum digits in sperner_unrank()",
        "src/coding.rs",
        "        *slot = u8::try_from(chosen).unwrap();\n        rem_s -= chosen;",
        "        *slot = 0;\n        rem_s -= chosen;",
        "hex_and_sperner_unranking_and_fast_select_parser_are_exact",
    ),
    (
        "U-PORS 33-bit leaf_addr masking in LeafAddr::from_word()",
        "src/params.rs",
        "        Self(word & ((1u64 << HYPER_BITS) - 1))",
        "        Self(word)",
        "hex_and_sperner_unranking_and_fast_select_parser_are_exact",
    ),
    (
        "U-PORS canonical trailing zero-padding enforced in upors_verify()",
        "src/few_time.rs",
        "    if !constant_time_eq(pad, &zeros[..pad.len()]) {\n        return None;\n    }",
        "    let _ = (pad, zeros);",
        "every_signature_region_and_canonical_padding_are_checked",
    ),
    (
        "S-WOTS+Z leading zero-byte check enforced in verify_wots_msg()",
        "src/one_time.rs",
        "    if h[0] != 0 {\n        return None;\n    }",
        "    let _ = h[0];",
        "every_signature_region_and_canonical_padding_are_checked",
    ),
    (
        "Hypertree final top-root equality check (verify_short)",
        "src/lib.rs",
        "        if ct_eq_n(&node, self.root()) { Ok(()) } else { Err(InvalidImprint) }",
        "        let _ = node;\n        Ok(())",
        "every_signature_region_and_canonical_padding_are_checked",
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
        "    let ctx_len = ctx.write_framed(&mut buf[N..]);",
        "    let _ = ctx;\n    let ctx_len = Context::EMPTY.write_framed(&mut buf[N..]);",
        "context_validation_framing_and_error_contracts",
    ),
    (
        "Streaming Sink::update feeds bytes into Hasher",
        "src/content.rs",
        "                self.hasher.update(bytes);",
        "                let _ = bytes;",
        "streaming_imprint_with_and_verify_with_match_slices",
    ),
    (
        "Streaming Sink::write feeds bytes into Hasher",
        "src/content.rs",
        "        self.hasher.update(buf);",
        "        let _ = buf;",
        "streaming_imprint_with_and_verify_with_match_slices",
    ),
    (
        "Streaming Sink detects u64::MAX overflow and poisons verification",
        "src/lib.rs",
        "        let Some(short) = content_with(&self.content_key, imprint.salt(), ctx, produce).map_err(VerifyError::Source)? else {\n            return Err(VerifyError::Invalid);\n        };",
        "        let Some(short) = content_with(&self.content_key, imprint.salt(), ctx, produce).map_err(VerifyError::Source)? else {\n            return Ok(());\n        };",
        "streaming_imprint_with_and_verify_with_match_slices",
    ),
    (
        "Randomness::initialize rejects non-regular files (directories/symlinks)",
        "src/randomness.rs",
        "    if !meta.file_type().is_file() {",
        "    if false {",
        "hostile_state_path_and_bad_files_are_rejected_without_clobbering",
    ),
    (
        "Randomness::initialize rejects non-private file permissions (mode & 0o077 != 0)",
        "src/randomness.rs",
        "        if meta.permissions().mode() & 0o077 != 0 {",
        "        if false {",
        "hostile_state_path_and_bad_files_are_rejected_without_clobbering",
    ),
    (
        "Randomness::initialize rejects state files not exactly 32 bytes",
        "src/randomness.rs",
        "    if filled != SEED_FILE_LEN {",
        "    if false {",
        "hostile_state_path_and_bad_files_are_rejected_without_clobbering",
    ),
    (
        "Randomness::create refuses to overwrite existing state file",
        "src/randomness.rs",
        "        let link_res = fs::hard_link(&tmp, path);",
        "        let link_res = fs::rename(&tmp, path);",
        "randomness_state_file_lifecycle_and_concurrency",
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
        "    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {\n        ensure_init();",
        "    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {",
        "initialize_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "signet-verify top-root constant-time equality check",
        "crates/signet-verify/src/lib.rs",
        "        if constant_time_eq::constant_time_eq_16(&node, &root) { Ok(()) } else { Err(InvalidImprint) }",
        "        let _ = (node, root);\n        Ok(())",
        "reference_and_edge_vectors_verify_oneshot_and_streamed",
    ),
]


def run_nextest(workdir, target_dir, test_filter=None):
    cmd = ["cargo", "nextest", "run", "--workspace", "--locked", "--no-fail-fast", "--color", "never"]
    if test_filter is not None:
        cmd += ["-E", f"test(/{test_filter}$/)"]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = target_dir
    return subprocess.run(cmd, cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)


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

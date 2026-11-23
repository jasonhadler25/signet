#!/usr/bin/env python3
"""Planted-fault controls for BLINCS: each security check must fail a test when removed.

    python3 tools/controls.py

First confirms the unmutated test suite passes under cargo-nextest. Then, for each
control below, removes or disables that protection with one exact edit, runs its
targeted test under cargo-nextest, and requires that test to fail. Restores every
file unconditionally. Exits 0 only if every planted fault is caught.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (description, rel_path, old_text, new_text, nextest_filter)
CONTROLS = [
    (
        "PORS+FP threshold zero-bits check (parse_pick)",
        "src/few_time.rs",
        "    if g[0] & ((1u8 << THRESHOLD_BITS) - 1) != 0 {\n        return None;\n    }\n",
        "",
        "parse_pick_checks_threshold_distinctness_and_merged_limit",
    ),
    (
        "PORS+FP duplicate-leaf check (parse_pick)",
        "src/few_time.rs",
        "    for j in 0..OPENED - 1 {\n        if indices[j] == indices[j + 1] {\n            return None;\n        }\n    }\n",
        "",
        "parse_pick_checks_threshold_distinctness_and_merged_limit",
    ),
    (
        "PORS+FP merged-set size limit <= 103 (parse_pick)",
        "src/few_time.rs",
        "    if merged_len > AUTH_NODES {\n        return None;\n    }\n",
        "",
        "parse_pick_checks_threshold_distinctness_and_merged_limit",
    ),
    (
        "PORS+FP trailing unused auth-slot zero padding (few_time_verify)",
        "src/few_time.rs",
        "    if auth[N * picked.merged_len..].iter().any(|&b| b != 0) {\n        return None;\n    }\n",
        "",
        "every_signature_region_and_unused_padding_is_checked",
    ),
    (
        "WOTS+C low 8 zero-bits check (parse_digits)",
        "src/one_time.rs",
        "    if digest[0] != 0 {\n        return None;\n    }\n",
        "",
        "parse_digits_checks_zero_bits_and_exact_sum",
    ),
    (
        "WOTS+C exact digit sum == 372 check (parse_digits)",
        "src/one_time.rs",
        "    (sum == DIGIT_SUM).then_some(out)",
        "    let _ = sum;\n    Some(out)",
        "parse_digits_checks_zero_bits_and_exact_sum",
    ),
    (
        "Hypertree final top-root equality check (verify_short)",
        "src/lib.rs",
        "            node == self.root()",
        "            let _ = node;\n            true",
        "every_signature_region_and_unused_padding_is_checked",
    ),
    (
        "Per-signature salt keyed into content hash (content_from_slice)",
        "src/content.rs",
        "    let msg_key = keyed(content_key, salt);\n    let message_hash = *TreeHasher::new(Mode::Keyed(&msg_key)).hash(message).as_bytes();",
        "    let message_hash = *TreeHasher::new(Mode::Keyed(content_key)).hash(message).as_bytes();",
        "reference_vector_matches_python_byte_for_byte",
    ),
    (
        "State file magic and exact-48-byte check (read_exact_or_reject)",
        "src/randomness.rs",
        '    if filled != STATE_LEN || &buf[..8] != MAGIC {\n        return Err(io::Error::new(ErrorKind::InvalidData, "not a BLINCS randomness state file"));\n    }',
        "    let _ = filled;",
        "randomness_create_and_initialize_lifecycle_and_rejection",
    ),
    (
        "State file counter overflow check (Randomness::initialize)",
        "src/randomness.rs",
        '        let new_count = old_count.checked_add(1).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "randomness state counter exhausted"))?;',
        "        let new_count = old_count.wrapping_add(1);",
        "randomness_create_and_initialize_lifecycle_and_rejection",
    ),
    (
        "Explicit create refuses to overwrite existing file (Randomness::create)",
        "src/randomness.rs",
        "        opts.write(true).create_new(true);",
        "        opts.write(true).create(true);",
        "randomness_create_and_initialize_lifecycle_and_rejection",
    ),
    (
        "VerifyingKey::from_bytes initializes blake3-servil-core",
        "src/lib.rs",
        "    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {\n        blake3_servil_core::initialize();",
        "    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {",
        "verify_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "SigningKey::from_seed initializes blake3-servil-core",
        "src/lib.rs",
        "    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {\n        blake3_servil_core::initialize();",
        "    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {",
        "signing_key_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "Randomness::draw panics instead of wrapping at u64::MAX",
        "src/randomness.rs",
        "let n = self.count.try_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(1)).expect(\"randomness draw counter exhausted\");",
        "let n = self.count.fetch_add(1, Ordering::Relaxed);",
        "randomness_draw_panics_on_counter_exhaustion",
    ),
    (
        "Randomness::initialize initializes blake3-servil-core",
        "src/randomness.rs",
        "    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {\n        blake3_servil_core::initialize();",
        "    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {",
        "initialize_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "Streaming content_from_reader feeds read bytes into keyed hasher",
        "src/content.rs",
        "            Ok(n) => {\n                hasher.update(&buf[..n]);\n            }\n",
        "            Ok(_n) => {}\n",
        "streaming_boundaries_and_fragmented_readers_match_slices",
    ),
]


def run_nextest(test_filter=None):
    cmd = ["cargo", "nextest", "run", "--locked", "--no-fail-fast"]
    if test_filter is not None:
        cmd += ["-E", f"test(/{test_filter}$/)"]
    return subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def main():
    print("Baseline: checking unmutated tests pass...")
    base = run_nextest()
    if base.returncode != 0:
        print(base.stdout, file=sys.stderr)
        print("FAIL: baseline tests did not pass", file=sys.stderr)
        return 1

    missed = []
    for i, (name, rel, old, new, flt) in enumerate(CONTROLS, 1):
        path = os.path.join(ROOT, rel)
        orig = open(path).read()
        count = orig.count(old)
        if count != 1:
            print(f"ERROR [{i}/{len(CONTROLS)}] {name}: expected 1 match in {rel}, found {count}", file=sys.stderr)
            return 2
        try:
            open(path, "w").write(orig.replace(old, new, 1))
            res = run_nextest(flt)
        finally:
            open(path, "w").write(orig)

        if res.returncode == 0:
            print(f"MISSED [{i}/{len(CONTROLS)}] {name} ({flt} still passed!)")
            missed.append(name)
        else:
            print(f"CAUGHT [{i}/{len(CONTROLS)}] {name}")

    if missed:
        print(f"\nFAIL: {len(missed)} planted fault(s) escaped: {missed}", file=sys.stderr)
        return 1
    print(f"\nPASS: all {len(CONTROLS)} planted faults caught by their targeted tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

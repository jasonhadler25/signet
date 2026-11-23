#!/usr/bin/env python3
"""Planted-fault positive controls for BLINCS.

Each control injects one deliberate bug into src/, runs the targeted test via
cargo-nextest, restores the file immediately, and checks that the test fails.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONTROLS = [
    (
        "WOTS+ checksum nibbles computed in digits()",
        "src/one_time.rs",
        "    out[MSG_CHAINS] = (csum & 0x0f) as u8;",
        "    out[MSG_CHAINS] = 0;",
        "wots_digits_and_checksum_boundaries",
    ),
    (
        "FORS 33-bit leaf_addr masking in parse_digest()",
        "src/few_time.rs",
        "    let leaf_addr = u64::from_le_bytes(digest[20..28].try_into().unwrap()) & ((1u64 << HYPER_BITS) - 1);",
        "    let leaf_addr = u64::from_le_bytes(digest[20..28].try_into().unwrap());",
        "parse_digest_extracts_all_fors_indices_and_33bit_leaf_addr",
    ),
    (
        "FORS root binds all 16 tree roots (fors_verify)",
        "src/few_time.rs",
        "        public.hash_many(&ws.b48.part(0..FORS_TREES), &mut ws.out[..FORS_TREES]);",
        "        public.hash_many(&ws.b48.part(0..FORS_TREES - 1), &mut ws.out[..FORS_TREES - 1]);",
        "every_signature_region_is_checked",
    ),
    (
        "Hypertree final top-root equality check (verify_short)",
        "src/lib.rs",
        "            ct_eq_n(&node, self.root())",
        "            true",
        "every_signature_region_is_checked",
    ),
    (
        "Top-tree cache keyed BLAKE3 MAC check (from_seed_with_cache)",
        "src/lib.rs",
        "        if !ct_eq_32(&stored_mac, &expected_mac) {",
        "        if false {",
        "top_tree_cache_save_load_and_tamper_rejection",
    ),
    (
        "Top-tree cache magic and exact-length check (from_seed_with_cache)",
        "src/lib.rs",
        "        if raw.len() != TOP_CACHE_LEN || &raw[..16] != TOP_CACHE_MAGIC {",
        "        if raw.len() != TOP_CACHE_LEN {",
        "top_tree_cache_save_load_and_tamper_rejection",
    ),
    (
        "Per-signature salt keyed into content hash (content_from_slice)",
        "src/content.rs",
        "    let msg_key = keyed(content_key, salt);\n    let message_hash = if message.len() >= MT_SLICE_THRESHOLD {",
        "    let msg_key = *content_key;\n    let message_hash = if message.len() >= MT_SLICE_THRESHOLD {",
        "reference_vector_matches_python_byte_for_byte",
    ),
    (
        "Streaming content_from_reader Pipeline path commits room bytes",
        "src/content.rs",
        "        if room_filled > 0 {\n            pipe.commit(&mut msg, &mut room, room_filled);\n        }",
        "        let _ = room_filled;",
        "streaming_boundaries_and_fragmented_readers_match_slices",
    ),
    (
        "Streaming content_from_reader aborts Pipeline cleanly on mid-stream I/O error",
        "src/content.rs",
        "                    pipe.abort(msg);\n                    while pipe.next_event().is_none() {\n                        block_on(pipe.ready());\n                    }\n                    return Err(e);",
        "                    return Err(e);",
        "streaming_boundaries_and_fragmented_readers_match_slices",
    ),
    (
        "State file magic and exact-48-byte check (read_exact_or_reject)",
        "src/randomness.rs",
        "    if filled != STATE_LEN || &buf[..8] != MAGIC {",
        "    if filled != STATE_LEN {",
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
        "VerifyingKey::from_bytes initializes blake3-servil",
        "src/lib.rs",
        "    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {\n        ensure_init();",
        "    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {",
        "verify_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "SigningKey::from_seed initializes blake3-servil",
        "src/lib.rs",
        "    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {\n        ensure_init();",
        "    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {",
        "signing_key_alone_initializes_blake3_in_fresh_process",
    ),
    (
        "Randomness::draw panics instead of wrapping at u64::MAX",
        "src/randomness.rs",
        '        let n = self.count.try_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(1)).expect("randomness draw counter exhausted");',
        "        let n = self.count.fetch_add(1, Ordering::Relaxed);",
        "randomness_draw_panics_on_counter_exhaustion",
    ),
    (
        "Randomness::initialize initializes blake3-servil",
        "src/randomness.rs",
        "    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {\n        ensure_init();",
        "    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {",
        "initialize_alone_initializes_blake3_in_fresh_process",
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

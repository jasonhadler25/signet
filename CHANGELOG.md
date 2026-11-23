# Changelog

## 0.1.0 (unreleased draft)

- Specified BLINCS (`SPEC.md`) and recorded all design rationales (`DESIGN.md`): SPHINCS+ hypertree (`h=36, d=4`), WOTS+C (24 chains of 32, 8 zero bits, digit sum 372), PORS+FP ($2^{15}$ leaves, 11 opened, at most 103 merged authentication nodes, 6 threshold bits), 256 KiB two-pass salted content hashing, startup-only 48-byte signer randomness state without `fsync`.
- Implemented independent pure-Python reference (`reference/blake3.py` passing all 35 official BLAKE3 vectors, `reference/blincs.py`) and checked in `test_vectors/reference-signature-1.bin`.
- Implemented `#![forbid(unsafe_code)]` Rust crate on `blake3-servil-core = "=0.10.0"` (10 crates total in `Cargo.lock`, zero dev-dependencies), matching the Python reference byte for byte.
- Optimized verification with `TreeHasher::on_this_core()` and per-level few-time batching (57.3 µs → 33.3 µs on Apple M6) and signing with cached top tree and `GRIND = 2048` (16.2 ms on Apple M6; 3.5 GB/s two-pass content verification at 16 MiB).
- Added Servil Software Factory quality gates: `cargo-nextest` sentinel, 16 planted-fault controls (`tools/controls.py`), release-mode `cargo-mutants` check (`tools/mutants/check.py`, 606 caught, 6 known equivalent survivors, 0 timeouts), standalone `clocks` benchmark (`bench/`), SHA-pinned CI, and exact-commit `tools/land.py`.
- Completed Round 1 formal contract review with `openai/gpt-6.2-astra-pro` (`audits/2026-11-23-gpt-6.2-astra-pro-round1.md`), fixed `ChunkLease` zero-on-drop and re-entrant reader isolation, fixed the `SPEC.md` merged-set pseudocode, hardened `reference/blincs.py` under `python3 -O`, and adopted the four-license regime (MIT, Apache-2.0, TGPPL-1.0, BOSL-1.0).
- Added reproducible parameter optimizer (`tools/optimize.py`, standard-library Python, exact integer DP) formalizing the unknown-thresholds "minimax" and joint-survival models in `DESIGN.md`, plus PORS+FP grinding-sweep analysis (`m = 95..120`).
- Added `BENCHMARKS.md` reproducing Project 11's SLH-DSA-B Criterion benchmarks on Apple M6 alongside BLINCS, `clocks` wall/cycle tables, and `blake3-servil` multithreading measurements.
- Clarified half-open height loop notation (`0..15`, heights 0 through 14) in `SPEC.md`.

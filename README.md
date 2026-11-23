# BLINCS

Stateless hash-based signatures built on BLAKE3.

- **Specification:** [`SPEC.md`](SPEC.md)
- **Reference implementation (pure Python):** [`reference/blincs.py`](reference/blincs.py) and [`reference/blake3.py`](reference/blake3.py)
- **Rust implementation:** [`src/`](src/) (`#![forbid(unsafe_code)]`, single runtime dependency `blake3-servil-core = "=0.10.0"`)

## Summary

- **Sizes:** 32-byte verifying key, 32-byte signing-key seed, 3,988-byte signature.
- **Construction:** SPHINCS+-style hypertree (`h = 36`, `d = 4`) with WOTS+C one-time signatures (24 chains of 32, 8 zero bits, digit sum 372) and PORS+FP few-time signatures ($2^{15}$ leaves, 11 opened, at most 103 merged authentication nodes, 6 threshold bits).
- **Content hashing:** 256 KiB chunks, each read twice under a per-signature salt, with no pre-hash entry point. Passing the message or stream directly to BLINCS relies on second-preimage resistance rather than collision resistance.
- **Target budget:** at least 128 bits of security up to $2^{33}$ signatures under the SPHINCS+ / PORS+FP cover-probability model.

## Running the tests

Tests run under `cargo-nextest` so every test gets its own process:

```sh
cargo nextest run --locked
cargo test --doc --locked
python3 reference/blake3.py
```

## Status and authorship

Pre-1.0 draft under active development; formats, context strings, and APIs may change before 1.0. Written primarily by an AI assistant at the direction of this repository's owner. No independent human security audit has been performed.

Dual-licensed under MIT or Apache-2.0.

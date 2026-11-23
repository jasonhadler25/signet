# BLINCS

Stateless hash-based signatures built on [BLAKE3](https://github.com/servil-software-factory/BLAKE3).

- **32-byte verifying key** — short enough to embed directly in a name or URL.
- **32-byte signing-key seed** — caller-supplied; stateless across machines and backups.
- **3,988-byte fixed-size signature** — fits inside a 4 KiB page for any message length (0 bytes to multi-gigabyte streams).
- **Salted two-pass streaming content hash** — messages are hashed directly in 256 KiB chunks with no pre-hash API. Pre-hashing makes users vulnerable to collision attacks; passing the message or stream to BLINCS relies on second-preimage resistance and hashes at BLAKE3 speed.
- **Design target:** at least 128 bits of classical security up to $2^{33}$ signatures per signing key (8,589,934,592: 10 signatures a second for 27 years) under the SPHINCS+ / PORS+FP cover-probability model, pending independent cryptographic review.

## Documents

- [`SPEC.md`](SPEC.md) — normative byte-level specification
- [`DESIGN.md`](DESIGN.md) — rationale for every design choice (including the minimax parameter strategy, crash-only lifecycle, and no-`fsync` analysis)
- [`QUALITY.md`](QUALITY.md) — verification layers, planted-fault controls, mutation testing, and known gaps
- [`SECURITY.md`](SECURITY.md) — operational boundaries, threat model, and vulnerability reporting
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — repository layout and landing gates

## Measured speed (single core, Apple M6)

Measured with `bench/` (`bench-hashes`'s `clocks` crate, single thread, quiet machine, 0% E-cores):

| Operation | Wall time | Core cycles | Throughput |
|---|---:|---:|---:|
| `SigningKey::from_seed` (loads & caches 16 KiB top tree) | 4.43 ms | 19.8M cyc | 226 / s |
| `SigningKey::sign` (64 B) | 16.22 ms | 72.5M cyc | 61.7 / s |
| `VerifyingKey::verify` (64 B) | 33.3 µs | 152k cyc | 30,000 / s |
| `VerifyingKey::verify_reader` (64 B) | 34.8 µs | 160k cyc | 28,700 / s |
| `SigningKey::sign` (16 MiB) | 20.96 ms | 92.7M cyc | 800 MB/s |
| `VerifyingKey::verify` (16 MiB, two-pass salted) | 4.77 ms | 20.6M cyc | 3,516 MB/s |
| `Randomness::initialize` (48 B state update, no `fsync`) | 23.1 µs | 105k cyc | — |

## Quick start

```rust
use blincs::{Randomness, SigningKey, VerifyingKey};

// Provision once in a private directory owned by the signer:
Randomness::create("/path/to/private/blincs.state")?;
// Load once at process startup; subsequent draws touch memory only:
let rng = Randomness::initialize("/path/to/private/blincs.state")?;

// Caller supplies a 32-byte cryptographically random seed:
let signing_key = SigningKey::from_seed(&seed);
let verifying_key = VerifyingKey::from_bytes(signing_key.verifying_key().as_bytes());

let signature = signing_key.sign(&rng, b"hello, BLINCS");
assert!(verifying_key.verify(b"hello, BLINCS", &signature));
```

For large files or streams, use `SigningKey::sign_reader` and `VerifyingKey::verify_reader`.

## Trusted base and testing

The library enforces `#![forbid(unsafe_code)]`, has **one** runtime dependency (`blake3-servil-core = "=0.10.0"`, 10 crates total in `Cargo.lock`, all SHA-256 checksummed), and zero dev-dependencies. An independent pure-Python implementation (`reference/blincs.py` + `reference/blake3.py`) cross-checks the Rust implementation byte for byte.

Tests run under `cargo-nextest` (one process per test):

```sh
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo nextest run --locked
cargo test --doc --locked
python3 reference/blake3.py
python3 tools/controls.py
python3 tools/mutants/check.py
```

## Status and authorship

Pre-1.0 draft (`0.1.0`): formats, context strings, and APIs may change before 1.0. Written primarily by an AI assistant at the direction of this repository's owner. Round 1 automated cross-family review is archived in [`audits/`](audits/); **no independent human cryptographic review or security audit has been performed**.

## Contributing and licenses

[`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to work on this repository.

Copyright (c) the BLINCS contributors. You may use BLINCS under the terms of any of these four Free and Open Source Software licences, at your choice:

* MIT license ([LICENSE-MIT](LICENSE-MIT))
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* Transitive Grace Period Public Licence 1.0 ([LICENSE-TGPPL](LICENSE-TGPPL)):
  *Licensed under the Transitive Grace Period Public Licence version 1.0*
* Bootstrap Open Source Licence v1.0 ([LICENSE-BOSL.txt](LICENSE-BOSL.txt)):
  *Licensed under the Bootstrap Open Source Licence version 1.0*

# BLINCS

Stateless hash-based signatures built on [BLAKE3](https://github.com/servil-software-factory/BLAKE3).

- **32-byte verifying key** — short enough to embed directly in a name or URL.
- **32-byte signing-key seed** — caller-supplied; stateless across machines and backups, with no key cache file on disk (`5.43 ms` cold key derivation builds the 128 KiB top tree across CPU cores).
- **5,616-byte fixed-size signature** (`7,488 B` Base64 — clears default Apache `8,190 B` and nginx `8,192 B` HTTP headers with 702 B to spare) for any message length from 0 bytes to multi-gigabyte streams.
- **Zero counter grinding & textbook FIPS 205 building blocks** — pure nibble `WOTS+` (`w = 16`, 35 chains) + `FORS` (`16` trees of `1,024` leaves) on a `12 + 3×7` hypertree: deterministic signing latency (no grinding tails), no disk cache API, ~40% simpler spec and code, and textbook FIPS 205 security proofs.
- **Salted single-pass multi-core content hash** — messages are hashed directly with keyed BLAKE3 under a fresh per-signature salt with no pre-hash API. Pre-hashing makes users vulnerable to collision attacks; passing the message or stream to BLINCS relies on second-preimage resistance and runs at full multi-core BLAKE3 speed (**28.6 GB/s** slice / **27.7 GB/s** streaming on Apple M6 via `blake3-servil`).
- **Design target:** **133.2 bits** of classical security up to **$2^{32}$ signatures** per signing key (4,294,967,296: 10 signatures a second for 13.6 years; degrading gracefully to `126.8` bits at $2^{33}$ and `119.3` bits at $2^{34}$), pending independent cryptographic review.

## Credits and thanks

BLINCS stands on the shoulders of a great deal of open cryptographic research and engineering.

### Thanks to Project 11

Special thanks to the [Project 11](https://research.projecteleven.com/) research team for open hash-based signature research, benchmarks, tools, and direct feedback that shaped BLINCS:

- **Conor Deegan** — direct review of [`SPEC.md`](SPEC.md) (clarifying the `0..15` merged-set height loop and prompting the explicit `m = 103` vs. `m = 112` grinding-time analysis in [`DESIGN.md`](DESIGN.md)), encouraging us to combine **irregular hypertrees** with **stateless upper-layer caching**, to optimize for **signing time** rather than minimum bytes alone, and to explore independent-hash parallelism; co-author of [SLH-DSA-B / PQC Suite B](https://github.com/PQC-Suite-B/signatures) (with **julienif**, building on RustCrypto's `slh-dsa`), [THINCS](https://github.com/conor-deegan/THINCS), [CUTS](https://eprint.iacr.org/2026/2455), and [*A review of SHRINCS*](https://research.projecteleven.com/articles/a-review-of-shrincs) (with **Alex Pruden**).
- **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** — the [SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter) and [companion guide](https://research.projecteleven.com/articles/sphincs-parameter-explorer-companion-guide) (Alessandro Baiocchi), [SPHINCS-G hardware-wallet and MPC benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks) (Alessandro Baiocchi & Matteo Vicari), and [*Raising SPHINCS-like lifetime budgets on constrained hardware*](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets) (Alessandro Baiocchi, Matteo Vena, & Matteo Vicari), whose work on taller cached top trees and partial upper-tree caching directly inspired our irregular-hypertree evaluation in [`DESIGN.md`](DESIGN.md).
- **Jamie Judd, Louis Tajan, Conor Deegan, and Furkan Akal** — [*CUTS: Chained Uniform-sum Tree Signatures*](https://eprint.iacr.org/2026/2455).

### Foundational work BLINCS builds on

- **BLAKE3 & implementation foundation:** **Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn** for BLAKE3 (building on **Daniel J. Bernstein**'s Salsa20/ChaCha lineage), and **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3), [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`), and its engineering practices and four-license regime.
- **Hash-based signature lineage:** **Ralph Merkle** (Merkle trees and hash-based signatures), **Leslie Lamport** and **Robert Winternitz** (one-time signatures), the **SPHINCS** authors (**Daniel J. Bernstein, Daira-Emma Hopwood, Andreas Hülsing, Tanja Lange, Ruben Niederhagen, Louiza Papachristodoulou, Michael Schneider, Peter Schwabe, and Zooko Wilcox-O'Hearn**, [ePrint 2014/795](https://eprint.iacr.org/2014/795)), and the **SPHINCS+ / SLH-DSA** team (**Daniel J. Bernstein, Andreas Hülsing, Stefan Kölbl, Ruben Niederhagen, Joost Rijneveld, Peter Schwabe**, [ePrint 2019/1086](https://eprint.iacr.org/2019/1086), and the NIST FIPS 205 submission team: Jean-Philippe Aumasson, Ward Beullens, Christoph Dobraunig, Maria Eichlseder, Scott Fluhrer, Stefan-Lukas Gazdag, Panos Kampanakis, Martin M. Lauridsen, Florian Mendel, Christian Rechberger, and Bas Westerbaan).
- **WOTS+C / SPHINCS+C:** **Mikhail Kudinov, Andreas Hülsing, Eyal Ronen, and Eylon Yogev** ([*SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost*](https://eprint.iacr.org/2022/778), IEEE S&P 2023) for checksum-free constant-sum Winternitz signatures.
- **PORS+FP & Octopus merging:** **Mehdi Abri and Jonathan Katz** ([*Shorter Hash-Based Signatures Using Forced Pruning*](https://eprint.iacr.org/2025/2069), CRYPTO 2026) for PORS+FP and its forced-pruning cover bound, building on **Jean-Philippe Aumasson and Guillaume Endignoux** ([*Improving Stateless Hash-Based Signatures*](https://eprint.iacr.org/2017/933), Gravity-SPHINCS PORS & Octopus).
- **Recent parameter, hypertree, and encoding research evaluated in [`DESIGN.md`](DESIGN.md):** **Mikhail Kudinov and Jonas Nick** ([*Hash-based Signature Schemes for Bitcoin*](https://eprint.iacr.org/2025/2203)), **Zhen Qin, Siwei Sun, and Fangyu Zheng** ([*Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths*](https://eprint.iacr.org/2025/2236), ASIACRYPT 2026), **Dmitry Khovratovich, Mikhail Kudinov, and Benedikt Wagner** ([*At the Top of the Hypercube*](https://eprint.iacr.org/2025/889), CRYPTO 2025), and **Chongxu Ren, Kaiyi Zhang, Haorui Cui, and Hongbo Yu** ([*Prepared Episodes for Short Online Hash Based Signatures*](https://eprint.iacr.org/2026/1708)).
- **Signer randomness & hedged-nonce literature:** **Boaz Barak and Shai Halevi** ([ePrint 2005/029](https://eprint.iacr.org/2005/029)), **Niels Ferguson, Bruce Schneier, and Tadayoshi Kohno** (*Cryptography Engineering*, Ch. 9 Fortuna seed files), **Yevgeniy Dodis, David Pointcheval, Sylvain Ruhault, Damien Vergnaud, and Daniel Wichs** ([ePrint 2013/338](https://eprint.iacr.org/2013/338)), **Thomas Ristenpart and Scott Yilek** (NDSS 2010), and **Mihir Bellare and Björn Tackmann** ([ePrint 2016/290](https://eprint.iacr.org/2016/290)).
- **Design principles:** **Daira-Emma Hopwood** (that hash-based signatures add strictly fewer cryptographic assumptions when a user already depends on a secure hash function) and **Ron Rivest** (the "minimax strategy" of performing well enough for many use cases).

## Documents

- [`SPEC.md`](SPEC.md) — normative byte-level specification
- [`DESIGN.md`](DESIGN.md) — rationale for every design choice, every candidate technique evaluated (including Project 11's ideas), and the calibrated tradeoff models (`tools/optimize.py`)
- [`BENCHMARKS.md`](BENCHMARKS.md) — Project 11 SLH-DSA-B reproduction, BLINCS comparison, `clocks` wall/cycle tables, and multithreading results
- [`QUALITY.md`](QUALITY.md) — verification layers, planted-fault controls, mutation testing, and known gaps
- [`SECURITY.md`](SECURITY.md) — operational boundaries, threat model, and vulnerability reporting
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — repository layout and landing gates
- [`docs/history/manifesto.md`](docs/history/manifesto.md) — original project strategy note (historical context)

## Measured speed (Apple M6, multithreaded by default)

Measured with `bench/` (`bench-hashes`'s `clocks` crate, quiet machine, `blake3-servil = "=0.10.0"`, verification 1 core / signing & large-message hashing multi-core by default):

| Operation | Wall time | Core cycles (main thread) | Throughput |
|---|---:|---:|---:|
| `SigningKey::from_seed` (128 KiB top-tree build, 12 cores, no disk cache) | **5.43 ms** | 19.3M cyc | **184 / s** |
| `SigningKey::sign` (64 B) | **729.7 µs** | 2.57M cyc | **1,370 / s** |
| `SigningKey::sign_reader` (64 B) | **730.1 µs** | 2.57M cyc | **1,370 / s** |
| `VerifyingKey::verify` (64 B, 1 core) | **25.3 µs** | 117k cyc | **39,500 / s** |
| `VerifyingKey::verify_reader` (64 B, 1 core) | **25.7 µs** | 118k cyc | **38,900 / s** |
| `SigningKey::sign` (16 MiB) | **1.29 ms** | 5.05M cyc | **12,987 MB/s** |
| `VerifyingKey::verify` (16 MiB) | **595.9 µs** | 2.58M cyc | **28,156 MB/s** |
| `SigningKey::sign_reader` (100 MiB, zero-copy `Pipeline`) | **4.46 ms** | 18.0M cyc | **23,521 MB/s** |
| `VerifyingKey::verify_reader` (100 MiB, zero-copy `Pipeline`) | **3.79 ms** | 15.3M cyc | **27,674 MB/s** |
| `Randomness::initialize` (48 B state update, no `fsync`) | 22.8 µs | 103k cyc | — |

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

The library enforces `#![forbid(unsafe_code)]`, has **one** runtime dependency (`blake3-servil = "=0.10.0"`, 10 crates total in `Cargo.lock`, all BLAKE3 + SHA-256 hashset-verified before building), and zero dev-dependencies. An independent pure-Python implementation (`reference/blincs.py` + `reference/blake3.py`) cross-checks the Rust implementation byte for byte.

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

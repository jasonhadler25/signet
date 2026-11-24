# BLINCS

> **Pre-1.0 — Experimental & Unsupported.** BLINCS (`0.1.0`) is under active development. Wire formats, context strings, and APIs may change incompatibly before 1.0, there is no commitment to bug fixes or security support yet, and **no independent human cryptographic audit has been performed**. Do not rely on it to protect anything of value yet.

**BLINCS** is a general-purpose, post-quantum digital signature library based on [BLAKE3](https://github.com/servil-software-factory/BLAKE3) and SPHINCS.

It gives you a **32-byte signet** (secret signing key), a **32-byte signet ID** (verifying key), and a **5.6 KiB imprint** (signature) that signs in under a millisecond, verifies in 25 microseconds, and streams gigabytes per second — all with zero `unsafe` Rust and a single dependency.

## Why BLINCS exists

If your software already relies on a secure hash function, hash-based signatures let you add post-quantum signing without adding a dependency on any new cryptographic assumption. No elliptic curves, no factoring, no lattices.

Existing hash-based schemes force an uncomfortable choice:

- **Stateful schemes (XMSS, LMS)** are compact and fast, but require keeping exact per-signature state. Restoring a backup, cloning a virtual machine, or running two signers out of sync can compromise the signing key immediately.
- **Standard stateless schemes (SLH-DSA)** avoid that fragility, but size their keys for $2^{64}$ signatures — a budget so extreme that every signature pays heavily in signing time or signature size.

BLINCS takes the practical middle ground: size each key for **4 billion signatures** ($2^{32}$ — ten signatures every second for thirteen years) and build strictly on **BLAKE3**. Choosing a realistic per-key limit makes stateless signatures both compact and fast.

## What happens past 4 billion signatures?

A BLINCS signing key does **not** suddenly break at 4 billion signatures.

Instead, every additional signature slowly wears down the key's security against brute-force attack. If an attacker collects billions of signatures made by the same key, forging a signature on a new message gradually gets easier:

| Signatures made by one key | Brute-force security | Brute-force cost (ASIC electricity) | Brute-force time (800 EH/s, Bitcoin scale) | What that means in practice |
|---:|---:|---:|---:|---|
| Up to **4.3 billion** ($2^{32}$) | **128-bit** | ~$1.6 × 10²⁰ | ~13 billion years | Full strength (comparable to AES-128 / Ed25519) |
| **34 billion** ($8\times$) | **111-bit** | ~$9.6 × 10¹⁴ | ~78,000 years | Still far beyond any practical attack |
| **69 billion** ($16\times$) | **100-bit** | ~$870 billion | ~71 years | Weakening, though still out of reach today |
| **More than 69 billion** | **< 100-bit** | falls rapidly | falls rapidly | Potentially forgeable by a well-funded attacker |

To keep full security, rotate to a new signing key before making $2^{32}$ signatures.

These numbers are the cost of a brute-force attack. There is no known reason to think that either quantum computers or super-intelligent AIs could generate forgeries any more efficiently than brute force; if they could, it would reduce the security level.

## Why adopt it

- **Resilient to copies and restarts.** Because your signing key is a 32-byte seed and requires no per-signature state synchronization, copying a key across servers or restoring a backup will not break it.
- **Short verifying keys.** At 32 bytes, a verifying key fits naturally anywhere a short identifier goes.
- **Fast on small messages and huge streams.** On a modern laptop, BLINCS signs in under a millisecond, verifies tens of thousands of signatures per second on a single core, and hashes large inputs across all CPU cores at tens of gigabytes per second.
- **No pre-hash footgun.** You pass bytes or a stream directly to BLINCS. Pre-hashing a message before signing exposes your users to collision attacks on the pre-hash; hashing the stream directly inside BLINCS avoids that exposure at full BLAKE3 speed.
- **Small enough to read and audit.** Zero `unsafe` Rust, one runtime dependency (`blake3-servil`), and a short pure-Python reference implementation that matches the Rust library byte for byte.

BLINCS is built for general-purpose signing wherever 5.6 KiB signatures fit and you want simple, durable, post-quantum security. If you need 64-byte signatures, unlimited signatures from a single key without rotation, or FIPS 205 wire interoperability, choose a different scheme.

*BLINCS is currently pre-1.0: formats and APIs may still change, and an independent human cryptographic audit has not yet been performed.*

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
| `Signet::from_seed` (128 KiB top-tree build, 12 cores, no disk cache) | **5.42 ms** | 19.0M cyc | **185 / s** |
| `Signet::imprint` (64 B) | **729.5 µs** | 2.56M cyc | **1,371 / s** |
| `Signet::imprint_reader` (64 B) | **729.1 µs** | 2.57M cyc | **1,372 / s** |
| `SignetId::verify` (64 B, 1 core) | **24.3 µs** | 114k cyc | **41,200 / s** |
| `SignetId::verify_reader` (64 B, 1 core) | **24.6 µs** | 115k cyc | **40,700 / s** |
| `Signet::imprint` (16 MiB) | **1.29 ms** | 5.06M cyc | **12,975 MB/s** |
| `SignetId::verify` (16 MiB) | **594.3 µs** | 2.63M cyc | **28,228 MB/s** |
| `Signet::imprint_reader` (100 MiB, zero-copy `Pipeline`) | **4.50 ms** | 18.4M cyc | **23,321 MB/s** |
| `SignetId::verify_reader` (100 MiB, zero-copy `Pipeline`) | **3.79 ms** | 15.8M cyc | **27,641 MB/s** |
| `Randomness::initialize` (48 B state update, no `fsync`) | 23.1 µs | 105k cyc | — |

## Quick start

Unlike a handwritten signature tied to one person, a cryptographic key is a transferable **bearer** authority — anyone holding the secret can exercise it, and the public half simply tells you *which* authority you mean. In this API we therefore call the secret a `Signet`, its 32-byte public half a `SignetId` (which names which signet you mean and verifies its imprints), and the 5,616-byte proof an `Imprint`. If you are used to standard terminology, they correspond directly to a signing key, verifying key, and signature (see [`DESIGN.md`](DESIGN.md) for the authorization rationale).

```rust
use blincs::{Randomness, Signet, SignetId};

// Provision once in a private directory owned by the signer:
Randomness::create("/path/to/private/blincs.state")?;
// Load once at process startup; subsequent draws touch memory only:
let rng = Randomness::initialize("/path/to/private/blincs.state")?;

// Caller supplies a 32-byte cryptographically random seed:
let signet = Signet::from_seed(&seed);
let id = SignetId::from_bytes(signet.id().as_bytes());

let imprint = signet.imprint(&rng, b"hello, BLINCS");
assert!(id.verify(b"hello, BLINCS", &imprint));
```

For large files or streams, use `Signet::imprint_reader` and `SignetId::verify_reader`.

## Dependencies and testing

The library enforces `#![forbid(unsafe_code)]`, has **one** runtime dependency (`blake3-servil = "=0.10.0"`, 10 crates total in `Cargo.lock`, all BLAKE3 + SHA-256 hashset-verified before building), and zero dev-dependencies. An independent pure-Python implementation (`reference/blincs.py` + `reference/blake3.py`) cross-checks the Rust implementation byte for byte. Signing randomness state (`Randomness`) currently targets Unix (`/dev/urandom` and `flock`).

Tests run under `cargo-nextest` (one process per test):

```sh
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo nextest run --locked
cargo test --doc --locked
python3 reference/blake3.py
python3 tools/counts.py
python3 tools/domain_sep.py
python3 tools/controls.py
python3 tools/mutants/check.py
```

## Status and authorship

**Pre-1.0 experimental / unsupported draft (`0.1.0`):** wire formats, context strings, and APIs may change incompatibly before 1.0, and there is no support commitment. Written primarily by an AI assistant at the direction of this repository's owner. Round 1–2 (`openai/gpt-6.2-astra-pro`) and recall-calibrated Round 3 (`anthropic/claude-opus-5.5`) automated cross-family reviews are archived in [`audits/`](audits/); **no independent human cryptographic review or security audit has been performed**.

## Contributing and licenses

[`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to work on this repository.

Copyright (c) the BLINCS contributors. You may use BLINCS under the terms of any of these four Free and Open Source Software licences, at your choice:

* MIT license ([LICENSE-MIT](LICENSE-MIT))
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* Transitive Grace Period Public Licence 1.0 ([LICENSE-TGPPL](LICENSE-TGPPL)):
  *Licensed under the Transitive Grace Period Public Licence version 1.0*
* Bootstrap Open Source Licence v1.0 ([LICENSE-BOSL.txt](LICENSE-BOSL.txt)):
  *Licensed under the Bootstrap Open Source Licence version 1.0*

# BLINCS

**BLINCS** is a post-quantum digital signature library for Rust, based on BLAKE3 and SPHINCS. It is hash-based: it relies only on BLAKE3 and this SPHINCS-family construction, with no elliptic curves or lattices. Each signet (signing key) is sized for a budget of **2³² signatures**. That budget buys **5,616-byte imprints** (signatures) and **32-byte signet IDs** (verifying keys). Running strictly on a single core (`blake3-servil-core`, zero background worker threads), signing takes **~2.54 ms** and verifying takes **~21.3 µs** on an Apple M6.

> **Pre-1.0: Experimental & Unsupported.**
>
> - **It may change.** `blincs 0.1.0` is under active development. Wire formats, context strings, and APIs may change incompatibly before 1.0. There is no commitment to bug fixes or security support.
> - **Who wrote it.** BLINCS was written primarily by an AI assistant at the direction of the repository owner.
> - **No independent human cryptographic audit has been performed.** Project 11 researchers gave informal feedback on an early draft of the specification. That feedback is not an audit. Neither are the automated AI-model reviews archived in [`audits/`](audits/).
> - **Its hash dependency is not upstream BLAKE3.** BLINCS depends on [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3), Servil Software Factory's single-threaded BLAKE3 implementation. It is a separate crate from upstream [`blake3`](https://github.com/BLAKE3-team/BLAKE3).
>
> Do not use BLINCS to protect anything of value yet.

## Comparison

| Scheme | Verifying key | Signature | Sign, 64 B msg (1 core) | Verify, 64 B msg (1 core) | Per-key budget | Relies on | Status |
|---|---:|---:|---:|---:|---|---|---|
| **Ed25519** | 32 B | 64 B | not measured here | not measured here | No comparable per-key budget | Elliptic-curve discrete log (**not** quantum-resistant: broken by Shor's algorithm) | RFC 8032, FIPS 186-5; mature |
| **ML-DSA-44** | 1,312 B | 2,420 B | not measured here | not measured here | No comparable per-key budget | Module lattices + hash | FIPS 204 (2024) |
| **SLH-DSA-128s** | 32 B | 7,856 B | 75.5–548 ms (warm) | 74–509 µs | 2⁶⁴ | Hash function | FIPS 205 (2024) |
| **SLH-DSA-128f** | 32 B | 17,088 B | 3.6–26.3 ms (warm) | 220–1,540 µs | 2⁶⁴ | Hash function | FIPS 205 (2024) |
| **BLINCS** | **32 B** | **5,616 B** | **2.54 ms** (warm); 23.1 ms cold | **21.3 µs** | **2³²** (degrades gradually past it) | BLAKE3 + this SPHINCS-family construction | No standard; pre-1.0; no human audit |

**How to read the timings:**

- All SLH-DSA and BLINCS numbers were measured **single-threaded (1 core vs. 1 core)** on the same Apple M6 (macOS arm64, Rust 1.100.0).
- **Warm** means the key is already loaded. **Cold** means load the key, then sign.
- SLH-DSA ranges span the SHA2, BLAKE3, and SHAKE variants of [PQC Suite B](https://github.com/PQC-Suite-B/signatures), which builds on RustCrypto's `slh-dsa`.
- Full methodology and cycle counts are in [`BENCHMARKS.md`](BENCHMARKS.md).

A BLINCS imprint is 7,488 bytes in Base64.

### When to choose BLINCS — and when not to

**BLINCS may fit when:**

- you want hash-based post-quantum signatures without curve or lattice assumptions;
- you want signatures smaller than SLH-DSA's (29% smaller than `128s`, 3× smaller than `128f`) and fast single-core signing and verification, with the same 32-byte verifying key;
- your volume fits 2³² signatures per signet;
- you control both signer and verifier;
- you are prototyping or experimenting while BLINCS is pre-1.0.

**Choose something else when:**

- **You need a standard or compliance standing.** Use ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) for hash-only assumptions. BLINCS is not FIPS 205 compatible.
- **Third-party tools must verify.** Stock Git, sigstore, minisign, COSE/JOSE, browsers, and HSMs have no BLINCS support. No OID or algorithm identifier exists.
- **You need the smallest post-quantum signatures and accept lattices.** ML-DSA-44 signatures are 2,420 B.
- **You do not need quantum resistance.** Ed25519 signatures are 64 B.
- **You cannot stay within 2³² signatures per signet.**
- **Your platform is not on the supported platforms list below.**
- **Anything valuable depends on it.**

## Quick Start

A cryptographic key is a transferable bearer authority, not a person's handwritten signature, so BLINCS names its pieces accordingly:

- a `Signet` is the signing key;
- a `SignetId` is the 32-byte verifying key that names a signet and checks its work;
- an `Imprint` is the 5,616-byte signature.

Whoever holds a signet's seed can sign as that signet, so guard the seed accordingly.

**Add the dependency.** BLINCS uses Rust 2024 edition:

```toml
[dependencies]
blincs = { git = "https://github.com/jasonhadler25/blincs" }
```

Formats can change between pre-1.0 commits. Add `rev = "…"` with a commit you have reviewed, and commit your `Cargo.lock`.

**Provision once per signer host**, as a setup step before any signer starts:

```rust
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use blincs::{Randomness, SEED_LEN};

fn main() -> io::Result<()> {
    // The 48-byte randomness state file. Refuses to overwrite an existing file.
    Randomness::create("blincs.state")?;

    // The 32-byte seed, from the OS CSPRNG, is the only signing secret.
    // Prefer a secrets manager; never derive it from a password.
    let mut seed = [0u8; SEED_LEN];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open("signet.seed")?.write_all(&seed)
}
```

**Sign, serialize, and verify** at every process start:

```rust
use std::fs::File;
use std::io::{self, Read};

use blincs::{Imprint, Randomness, SEED_LEN, SIGNET_ID_LEN, Signet, SignetId};

fn main() -> io::Result<()> {
    let rng = Randomness::initialize("blincs.state")?; // once per process
    let mut seed = [0u8; SEED_LEN];
    File::open("signet.seed")?.read_exact(&mut seed)?;
    let signet = Signet::from_seed(&seed); // ~20.5 ms: rebuilds the 128 KiB top tree in memory

    // Publish these 32 bytes through a channel your verifiers can authenticate.
    let id_bytes: [u8; SIGNET_ID_LEN] = *signet.id().as_bytes();

    // Sign and serialize: 5,616 raw bytes on the wire.
    let message = b"hello, BLINCS";
    let wire: Vec<u8> = signet.imprint(&rng, message).as_bytes().to_vec();

    // Verify from received bytes; `try_from` rejects wrong lengths.
    let id = SignetId::from_bytes(&id_bytes);
    let imprint = Imprint::try_from(wire.as_slice()).expect("imprint must be 5,616 bytes");
    assert!(id.verify(message, &imprint));
    assert!(!id.verify(b"tampered", &imprint));
    Ok(())
}
```

**Stream large inputs** directly. This continues inside the same `main`:

```rust
let file_imprint = signet.imprint_reader(&rng, File::open("artifact.bin")?)?;
assert!(id.verify_reader(File::open("artifact.bin")?, &file_imprint)?);
```

**Return types:**

- `verify` returns `bool`.
- `imprint_reader` and `verify_reader` return `io::Result`, because reads can fail.

## Operational model

### 1. The `Randomness` state file

The 48-byte file holds three things: a magic value, a startup count, and a 32-byte seed. Its only job is to keep per-imprint **content salts** fresh across restarts, even if boot-time OS randomness is weak or repeats. It holds no key index or one-time-key counter.

**The two calls:**

- **`Randomness::create`** provisions the file once per host, with mode `0600`. Do not race it against `initialize`.
- **`Randomness::initialize`** runs once per process.
  - Under `flock`, it mixes four inputs into an in-memory run key: the stored seed, an incremented count, 32 bytes from `/dev/urandom`, and the monotonic clock.
  - It writes a fresh seed back (~23 µs, no `fsync`).
  - Each imprint then draws from the run key, with no syscalls or disk writes.

**Losing, cloning, or resetting the file does not cause XMSS/LMS-style one-time-key reuse.**

- Signing secrets derive only from the seed.
- Signing positions come from the message digest.
- Each hypertree one-time key always signs the same deterministic root.
- Randomness is hedged: the salt is keyed by the signet, and the randomizer derives from the signet, the salt, and the message hash.

**If the file, `/dev/urandom`, and the clock all repeat together**, salts repeat. Signing secrets stay hidden. Content hashing degrades from salted (randomized target-collision) security to the 128-bit collision resistance of keyed BLAKE3.

**Recovery and placement:**

- **Lost or corrupted file (when no live signer is using it):** remove the damaged file and run `Randomness::create` again. Do not delete a file while running processes hold locks on it, and diagnose `AlreadyExists` or permission errors rather than deleting blindly. Signets and existing imprints are unaffected.
- **Placement:** use one file per host, in a private local directory. Processes on one host serialize through `flock`. Network filesystems are unsupported.
- **Forks and live VM snapshots:** after `fork()` (without `exec()`) or restoring a live VM snapshot, call `Randomness::initialize` again so cloned processes or images do not repeat `(run_key, count)`.

### 2. Per-signet signing budget

**Do not imprint more than 2³² things with one signet.**

A BLINCS signet does **not** suddenly break at 4.3 billion imprints. Instead, every additional imprint slowly wears down the modeled security against brute-force forgery.

**Estimated brute-force security for one modeled FORS leaf-cover event under the project's ideal-hash model:**

| Signatures made by one signet | Brute-force security | Brute-force cost (ASIC electricity) | Brute-force time (800 EH/s, Bitcoin scale) | What that means in practice |
|---:|---:|---:|---:|---|
| Up to **4.3 billion** (2³²) | **128-bit** | ~$1.6 × 10²⁰ | ~13 billion years | Full strength (comparable to AES-128) |
| **34 billion** (8×) | **111-bit** | ~$9.6 × 10¹⁴ | ~78,000 years | Still far beyond any practical attack |
| **69 billion** (16×) | **100-bit** | ~$870 billion | ~71 years | Weakening, though still out of reach today |
| **More than 69 billion** | **< 100-bit** | falls rapidly | falls rapidly | Potentially forgeable by a well-funded attacker |

These numbers are the cost of a brute-force attack for that single-key ideal-hash event (not a full multi-user or complete scheme proof; see [`SPEC.md`](SPEC.md#security-target-model-and-limits)). There is no known reason to think that either quantum computers or super-intelligent AIs could generate forgeries any more efficiently than brute force; if they could, it would reduce the security level.

The library does not count imprints across runs or across copies of a seed. When retiring a `Signet`, destroy its seed and stop signing, while keeping its `SignetId` in your accepted verifier set for as long as older imprints must still verify.

### 3. Startup, streaming, and authenticated IDs

**Startup and memory.** `Signet::from_seed` derives the 128 KiB top tree in memory from the 32-byte seed in **~20.5 ms** on 1 core. Nothing is cached on disk, so the seed is all you store. A cold load-and-sign takes ~23.1 ms. Signing allocates a transient local workspace (~446 KiB) that is freed when signing returns; verification uses only stack buffers (~2.5 KiB, plus a 16 KiB stack buffer for `verify_reader`) with zero heap allocation.

**Streaming.** `imprint`/`verify` take message bytes, and `imprint_reader`/`verify_reader` take a stream. Either way, BLINCS hashes every byte in a single salted keyed-BLAKE3 pass on the calling thread. The per-imprint salt is chosen before the message is read. On 1 Apple M6 core, 100 MiB hashes at ~6.0 GB/s signing and ~6.9 GB/s verifying (in-memory slice), or ~3.9–4.3 GB/s via `imprint_reader`/`verify_reader` using a local 16 KiB stack buffer.

**Authenticated IDs.** Verifiers need an **authenticated** `SignetId`. A valid imprint proves only that it matches a given 32-byte ID. Deliver IDs through a channel that ties them to the signer, such as pinned configuration or signed release metadata.

### 4. Platform, dependencies, and caller obligations

**Dependencies and code:**

- **Hash dependency:** the single runtime dependency is pinned exactly, `blake3-servil-core = "=0.11.0"` (**2 external crates** total in `Cargo.lock`, both BLAKE3 + SHA-256 hashset-verified). It runs strictly single-threaded with zero background worker threads, supplying single-core SIMD/SME2 batch hashing through its assembly kernels.
- **Rust code:** `blincs` itself is pure safe Rust (`#![forbid(unsafe_code)]`, zero `Drop` implementations, ~890 lines of shipped code). It requires `std` today.

**Supported platforms:**

- **Linux** (`x86_64`, `aarch64`)
- **macOS** (`x86_64`, `aarch64`)

If your platform is not on this list, this software is not expected to work for that use. (`Randomness` uses Unix `/dev/urandom`, `0600` file mode, and `flock`.)

**Other implementations:**

- an independent pure-Python reference, `reference/blincs.py`, which matches the Rust output byte for byte;
- an educational TypeScript reference verifier (`reference/blincs.ts`).

**Caller obligations:**

- Seeds need full entropy; `from_seed` performs no entropy check.
- Secret memory (the seed, derived keys, and transient signing workspaces) is **not** wiped on drop.
- Branches and memory indices depend only on public inputs or values published in the imprint. Hardware timing channels remain the platform's responsibility.
- The full list is in [`SECURITY.md`](SECURITY.md).

## Benchmarks

Apple M6 (macOS arm64, Rust 1.100.0, `blake3-servil-core = "=0.11.0"`, strictly single-threaded, `0% E-cores`). x86-64 results are not yet published.

| Operation (1 core) | Wall time | Throughput |
|---|---:|---:|
| Sign, 64 B (warm) | **2.54 ms** | **394 / s** |
| Verify, 64 B | **21.3 µs** | **46,900 / s** |
| Load key (`Signet::from_seed`, 128 KiB top tree) | 20.53 ms | 49 / s |
| Sign / verify, 100 MiB (slice) | 17.61 ms / 15.16 ms | 5,953 / 6,917 MB/s |
| Sign / verify, 100 MiB (`*_reader`, 16 KiB stack buf) | 27.00 ms / 24.45 ms | 3,884 / 4,288 MB/s |
| `Randomness::initialize` | 23.0 µs | — |

Signing has no counter-grinding retry loop. Full cycle counts, IPC, and the 1-core SLH-DSA-B reproduction are in [`BENCHMARKS.md`](BENCHMARKS.md).

## Documentation & References

- [`SPEC.md`](SPEC.md): normative byte-level specification and security estimates.
- [`DESIGN.md`](DESIGN.md): rationale and the alternatives evaluated.
- [`BENCHMARKS.md`](BENCHMARKS.md): methodology, cycle counts, and 1-core SLH-DSA-B comparison.
- [`QUALITY.md`](QUALITY.md): verification layers, mutation testing, and known gaps.
- [`SECURITY.md`](SECURITY.md): threat model, caller obligations, and private vulnerability reporting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): repository layout, the `cargo nextest` suite, and the Python cross-check gates.
- Standards: [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final) and [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final).

## Credits and thanks

**[Project 11](https://research.projecteleven.com/)**

- **Conor Deegan** gave feedback on an early `SPEC.md` draft, encouraged optimizing for signing time, and inspired BLINCS's constrained-device-first parameter search approach (targeting Good Enough UX on constrained signing hardware while minimizing desktop costs). With **julienif**, he co-authored [PQC Suite B](https://github.com/PQC-Suite-B/signatures), the SLH-DSA implementation and benchmark harness reproduced in `BENCHMARKS.md`. PQC Suite B builds on RustCrypto's `slh-dsa`.
- **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** built the [SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter). Their research on [taller cached top trees](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets) shaped BLINCS's layout.

**Foundations**

- **BLAKE3:** Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn.
- **Implementation and tooling:** Servil Software Factory, for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes).
- **Hash-based signatures:** Ralph Merkle, Leslie Lamport, and Robert Winternitz.
- **SPHINCS:** Bernstein, Hopwood, Hülsing, Lange, Niederhagen, Papachristodoulou, Schneider, Schwabe, and Wilcox-O'Hearn ([ePrint 2014/795](https://eprint.iacr.org/2014/795)).
- **SPHINCS+ / SLH-DSA:** Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld, and Schwabe ([ePrint 2019/1086](https://eprint.iacr.org/2019/1086)), together with the NIST FIPS 205 team.

**Signer randomness:** Barak and Halevi; Ferguson, Schneier, and Kohno; Dodis et al.; Ristenpart and Yilek; and Bellare and Tackmann.

**Design principles:**

- Daira-Emma Hopwood, for the case for hash-based signatures in systems that already rely on a secure hash.
- Ron Rivest, for the "minimax" goal of performing well enough for many use cases.

**Research evaluated for earlier drafts.** Earlier BLINCS drafts evaluated two compressed variants. **The current design uses neither;** it uses standard WOTS+ and FORS.

- WOTS+C, by Kudinov, Hülsing, Ronen, and Yogev ([ePrint 2022/778](https://eprint.iacr.org/2022/778)).
- PORS+FP, by Abri and Katz ([ePrint 2025/2069](https://eprint.iacr.org/2025/2069)), building on Aumasson and Endignoux ([ePrint 2017/933](https://eprint.iacr.org/2017/933)).

## Licensing

Copyright (c) the BLINCS contributors. Use BLINCS under **any one** of the following licenses, at your choice. MIT or Apache-2.0 alone suffices for most users.

- `MIT`: [LICENSE-MIT](LICENSE-MIT)
- `Apache-2.0`: [LICENSE-APACHE](LICENSE-APACHE)
- `TGPPL-1.0`: [LICENSE-TGPPL](LICENSE-TGPPL)
- `BOSL-1.0`: [LICENSE-BOSL.txt](LICENSE-BOSL.txt)

The Cargo SPDX expression is `MIT OR Apache-2.0 OR TGPPL-1.0`, with `BOSL-1.0` offered alongside.

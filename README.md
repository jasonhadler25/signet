# Signet (`BLINCS-48-X`)

**Signet** (`signet` crate) is a Rust implementation of **BLINCS** (specifically the **`BLINCS-48-X`** suite), a post-quantum digital signature algorithm based on BLAKE3 and SPHINCS. BLINCS is hash-based: it relies only on BLAKE3 and this SPHINCS-family construction, with no elliptic curves or lattices.

Each signet (signing key) is sized for a lifetime budget of **2⁴⁸ signatures** (281.5 trillion — one million signatures per second nonstop for 8.9 years), combining a `13+7×5` hypertree (`d = 6, h = 48`), zero-coding-table bit-packed constant-sum **`WOTS+C`** (`n = 21, w = 60, z = 2, S = 679`, `u24` LE counter), and a single height-11 chained **`U-PORS`** Octopus tree (`n = 3, w = 24, S = 42, C = 376, k = 9, m_max = 45`, `FEW_CODE` chained directly from `H_sel`) to produce **3,990-byte imprints** (**5,320 bytes** Base64 — **49.2% smaller** than `SLH-DSA-128s`), **32-byte signet IDs** (verifying keys), pure 32-byte keyed BLAKE3 everywhere (zero XOF mode), bounded length-framed application **contexts** (`0..=255 B`), and fail-closed verification (`Result<(), InvalidImprint>` / `Result<(), VerifyError>`). Running strictly on a single core (`blake3-servil-core = "=0.11.0"`, zero background worker threads), warm signing takes **~8.45 ms** (`from_seed` builds the `256 KiB` top tree in **~82.74 ms**) and verifying takes **~62.7 µs** (`7.44 IPC`, zero heap allocations) on an Apple M6. The standalone algorithm specification, exact-`BigInt` all-orbits certifier, Lean 4 formalization, and paper live in [`jasonhadler25/blincs`](https://github.com/jasonhadler25/blincs).

> **Pre-1.0: Experimental & Unsupported.**
>
> - **It may change.** `signet 0.1.0` (`BLINCS-48-X`) is under active development. Wire formats, context strings, and APIs may change incompatibly before 1.0. There is no commitment to bug fixes or security support.
> - **Who wrote it.** Signet and the BLINCS specification were written primarily by an AI assistant at the direction of the repository owner.
> - **No independent human cryptographic audit has been performed.** Project 11 researchers gave informal feedback on an early draft of the specification. That feedback is not an audit. Neither are the automated AI-model reviews archived in [`audits/`](audits/).
> - **Its hash dependency is not upstream BLAKE3.** Signet depends on [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3), Servil Software Factory's single-threaded BLAKE3 implementation. It is a separate crate from upstream [`blake3`](https://github.com/BLAKE3-team/BLAKE3).
>
> Do not use Signet / BLINCS to protect anything of value yet.

## Comparison

| Scheme | Verifying key | Signature | Sign, 64 B msg (1 core) | Verify, 64 B msg (1 core) | Per-key budget | Relies on | Status |
|---|---:|---:|---:|---:|---|---|---|
| **Ed25519** | 32 B | 64 B | not measured here | not measured here | No comparable per-key budget | Elliptic-curve discrete log (**not** quantum-resistant: broken by Shor's algorithm) | RFC 8032, FIPS 186-5; mature |
| **ML-DSA-44** | 1,312 B | 2,420 B | 0.15 ms (OpenSSL 4.1) | 31.0 µs (OpenSSL 4.1) | No comparable per-key budget | Module lattices + hash | FIPS 204 (2024) |
| **SLH-DSA-128s** | 32 B | 7,856 B | 52.4–274.5 ms (OpenSSL 4.1) / 121.7 ms (BLAKE3) | 50.0–278.0 µs / 126.6 µs | 2⁶⁴ | Hash function | FIPS 205 (2024) |
| **SLH-DSA-128f** | 32 B | 17,088 B | 5.81 ms (BLAKE3, 1c) | 353.7 µs (BLAKE3) | 2⁶⁴ | Hash function | FIPS 205 (2024) |
| **BLINCS-48-X (Signet)** | **32 B** | **3,990 B** | **8.45 ms** (warm); **82.74 ms** `from_seed` | **62.7 µs** | **2⁴⁸** (degrades gradually past it) | BLAKE3 + this SPHINCS-family construction | No standard; pre-1.0; no human audit |

**How to read the timings:**

- All SLH-DSA, ML-DSA, and Signet numbers were measured **single-threaded (1 core vs. 1 core)** on the same Apple M6 (macOS arm64, Rust 1.100.0).
- **Warm** means the `Signet` (and its `256 KiB` cached height-13 top tree) is already loaded. Because fixed tree construction dominates signing, total warm-sign `p99 / mean ≈ 1.042×` (with exact discrete geometric grinding mean `34,019` / `p99 = 75,533` compressions). Wire signatures are identical under a `16 KiB` depth-10 partial cache (`+1.08%` ideal fixed compressions) or `0 B` cache.
- OpenSSL 4.1.0 rows use ARMv8 SHA2/SHA3 hardware extensions (uncached); SLH-DSA-BLAKE3 rows reproduce [PQC Suite B](https://github.com/PQC-Suite-B/signatures) (`RAYON_NUM_THREADS=1`, uncached).
- Full methodology, cycle counts, IPC, and bare-metal QEMU Cortex-M33 emulation measurements are in [`BENCHMARKS.md`](BENCHMARKS.md).

A `BLINCS-48-X` imprint is **5,320 bytes** in Base64.

### When to choose Signet (`BLINCS-48-X`) — and when not to

**Signet may fit when:**

- you want stateless hash-based post-quantum signatures without curve or lattice assumptions;
- you want sub-4 KiB **3,990-byte** signatures (`49.2%` smaller than `SLH-DSA-128s`, `4.28×` smaller than `SLH-DSA-128f`), **~8.45 ms** single-core warm signing, **~62.7 µs** zero-allocation verification (`27.1 KiB` freestanding zero-import WASM), built-in application context separation, and a `2^{48}` per-key lifetime budget;
- your volume fits 2⁴⁸ signatures per signet;
- you control both signer and verifier;
- you are prototyping or experimenting while Signet / BLINCS is pre-1.0.

**Choose something else when:**

- **You need a standard or compliance standing.** Use ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) for hash-only assumptions. BLINCS is not FIPS 205 compatible.
- **Third-party tools must verify.** Stock Git, sigstore, minisign, COSE/JOSE, browsers, and HSMs have no BLINCS support. No OID or algorithm identifier exists.
- **You need the smallest post-quantum signatures and accept lattices.** ML-DSA-44 signatures are 2,420 B.
- **You do not need quantum resistance.** Ed25519 signatures are 64 B.
- **You cannot stay within 2⁴⁸ signatures per signet.**
- **Your platform is not on the supported platforms list below.**
- **Anything valuable depends on it.**

## Quick Start

A cryptographic key is a transferable bearer authority, not a person's handwritten signature, so Signet names its pieces accordingly:

- a `Signet` is the signing key;
- a `SignetId` is a publisher's self-certifying 32-byte identifier and its complete `BLINCS-48-X` verifying key;
- an `Imprint` is the 3,990-byte signature;
- a `Context` is a bounded (`0..=255` byte) protocol label that prevents imprints from one application from verifying in another.

Whoever holds a signet's seed can sign as that signet, so guard the seed accordingly. Receiving a `SignetId` does not authenticate the sender — obtain the expected `SignetId` from a pinned or authenticated channel.

**Add the dependency.** Signet uses Rust 2024 edition:

```toml
[dependencies]
signet = { git = "https://github.com/jasonhadler25/signet" }
```

Formats can change between pre-1.0 commits. Add `rev = "…"` with a commit you have reviewed, and commit your `Cargo.lock`.

**Provision once per signer host**, as a setup step before any signer starts:

```rust
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;

use signet::{Randomness, Signet};

fn main() -> io::Result<()> {
    // Private 32-byte state file (0600). Refuses to overwrite an existing path.
    Randomness::create("signet.salt")?;
    let rng = Randomness::initialize("signet.salt")?;

    // Generates a fresh 32-byte seed mixing local persisted randomness + OS getrandom(2).
    // Prefer a secrets manager; never derive a seed from a password.
    let publisher = Signet::generate(&rng)?;
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open("signet.seed")?;
    f.write_all(publisher.seed())?;
    f.sync_all()
}
```

**Sign, serialize, and verify (fail-closed)** at every process start:

```rust
use std::fs;
use std::io;

use signet::{Context, Imprint, InvalidImprint, Randomness, SEED_LEN, SIGNET_ID_LEN, Signet, SignetId, VerifyError};

const RELEASE_CTX: Context<'static> = Context::new(b"example.org release manifest v1");

fn main() -> Result<(), VerifyError> {
    let rng = Randomness::initialize("signet.salt")?; // once per process
    let raw_seed = fs::read("signet.seed")?;
    let seed: [u8; SEED_LEN] = raw_seed.try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "seed must be 32 bytes"))?;
    let publisher = Signet::from_seed(&seed); // ~83 ms: builds the cached 256 KiB height-13 top tree in memory

    // Publish these 32 bytes through a channel your verifiers can authenticate.
    let pinned_id_bytes: [u8; SIGNET_ID_LEN] = *publisher.id().as_bytes();

    // Sign and serialize: 3,990 raw bytes on the wire.
    let message = b"hello, BLINCS";
    let wire: Vec<u8> = publisher.imprint(&rng, RELEASE_CTX, message).as_bytes().to_vec();

    // Verify against the expected publisher's pinned SignetId and protocol Context.
    // Fails closed: `?` propagates Err(InvalidImprint) on wrong length or invalid imprint.
    let expected_publisher = SignetId::from_bytes(&pinned_id_bytes);
    let imprint = Imprint::try_from(wire.as_slice()).map_err(|_| InvalidImprint)?;
    expected_publisher.verify(RELEASE_CTX, message, &imprint)?;
    assert!(expected_publisher.verify(RELEASE_CTX, b"tampered", &imprint).is_err());
    assert!(expected_publisher.verify(Context::new(b"other-protocol"), message, &imprint).is_err());

    // A valid imprint made by a different signet must also be rejected.
    let other_publisher = Signet::generate(&rng)?;
    let other_imprint = other_publisher.imprint(&rng, RELEASE_CTX, message);
    assert!(expected_publisher.verify(RELEASE_CTX, message, &other_imprint).is_err());
    Ok(())
}
```

**Stream large inputs** directly (fails closed on both I/O errors and invalid imprints). This continues inside the same `main`:

```rust
let file_imprint = publisher.imprint_with(&rng, RELEASE_CTX, |sink| {
    std::io::copy(&mut fs::File::open("artifact.bin")?, sink)?;
    Ok::<(), std::io::Error>(())
})?;
expected_publisher.verify_with(RELEASE_CTX, &file_imprint, |sink| {
    std::io::copy(&mut fs::File::open("artifact.bin")?, sink)?;
    Ok::<(), std::io::Error>(())
})?;
```

**Standalone `#![no_std]` verification (`crates/signet-verify`):** verifiers that want zero `std`, zero heap allocator, zero coding lookup tables (packed 6-bit `WOTS+C` unpacking and 24-row arithmetic `U-PORS` unranking), and zero-copy signature views (`ImprintRef<'_>`) can depend on `signet-verify`, which provides both one-shot `SignetId::verify` and incremental `SignetId::verifier` (`update` / `finalize`) on pure-Rust BLAKE3 and is tested on host and freestanding `wasm32-unknown-unknown` (**27.1 KiB `.wasm`**, zero imports).

**Return types:**

- `verify` returns `Result<(), InvalidImprint>` (fail-closed).
- `verify_with` returns `Result<(), VerifyError<E>>` (`VerifyError::Source(E)` or `VerifyError::Invalid`, fail-closed on both; `E` defaults to `std::io::Error`).
- `imprint_with` returns `Result<Imprint, E>`, aborting without finalizing if the producer returns an error.

## Operational model

### 1. The lock-free `Randomness` state file

Signet stores startup randomness in a single private 32-byte regular file on a local filesystem (created once with `Randomness::create`, mode `0600`). Its only job is to keep per-imprint **content salts** fresh across restarts and hedge `Signet::generate`, even if boot-time OS randomness is weak or repeats. It holds no key index or one-time-key counter.

**How `Randomness::initialize` works (~92.1 µs, zero `flock`, zero `fsync`):**

- Verifies the path is a private (`0600`) regular non-symlink file and reads its exact 32 bytes (rejecting missing paths, directories, symlinks, group/world-accessible permissions, or wrong lengths without touching anything).
- Mixes the prior 32-byte state with 32 bytes from OS `getrandom(2)` / `getentropy`, the process ID, and the monotonic clock.
- Derives three independent, domain-separated outputs from that pool: `next_seed` (32 bytes written to a fresh `0600` sibling temp file and published atomically via POSIX `rename`, preserving forward secrecy on disk with no locks and no torn reads), `run_key` (in-memory imprint draws), and `keygen_key` (in-memory draws for `Signet::generate`).
- Each subsequent imprint draws from `run_key` in memory, with no syscalls or disk writes.

**Losing, cloning, or resetting the state file does not cause XMSS/LMS-style one-time-key reuse.**

- Signing secrets derive only from the signet's 32-byte seed.
- Signing positions come from the message digest.
- Each hypertree one-time key always signs the same deterministic root with the deterministic smallest valid `u24` counter.
- Randomness is hedged: the salt is keyed by the signet, and the randomizer derives from the signet, the salt, the message hash, and the context.

**If the state file, OS randomness, PID, and the clock all repeat together**, salts repeat. Signing secrets stay hidden. Content hashing degrades from salted (randomized target-collision) security to the 128-bit collision resistance of keyed BLAKE3.

**Forks and live VM snapshots:** in multithreaded POSIX processes, call `exec()` before initializing Signet rather than calling `Randomness::initialize` directly after `fork()`. After restoring a live VM snapshot, ensure genuinely fresh unshared OS entropy before initializing so cloned images do not repeat `(run_key, count)`.

### 2. Per-signet signing budget

**Do not imprint more than 2⁴⁸ things with one signet.**

A BLINCS signet does **not** suddenly break at 281.5 trillion imprints. Instead, every additional imprint slowly wears down the modeled security against brute-force forgery.

**Deterministic all-orbits exact-`BigInt` upper-envelope bounds for one modeled raw `U-PORS` cover event (accounting for Octopus sibling clustering across all `1,614,132` `Aut(T_11)`-orbits via `blincs/tools/upors_cert.rs`, zero Monte Carlo, alongside exact uncapped envelope bounds) under the project's single-key ideal-hash model:**

| Signatures made by one signet | Brute-force security *(uncapped / certified capped UB)* | Brute-force cost (ASIC electricity, 15 J/TH @ $0.08/kWh) | Brute-force time (800 EH/s, Bitcoin scale) | What that means in practice |
|---:|---:|---:|---:|---|
| Up to **281 trillion** (2⁴⁸) | **131.7-bit** *(128.0 / 131.7 b)* | ~$1.5 × 10²¹ | ~176 billion years | Full strength (>128-bit classical target) |
| **563 trillion** (2×, 2⁴⁹) | **125.4-bit** *(120.9 / 125.4 b)* | ~$1.8 × 10¹⁹ | ~2.2 billion years | Dips modestly below 128 bits; stay within 2⁴⁸ |
| **1.13 quadrillion** (4×, 2⁵⁰) | **117.9-bit** *(112.5 / 117.9 b)* | ~$1.0 × 10¹⁷ | ~11.9 million years | Still far beyond any practical classical attack |
| **2.25 quadrillion** (8×, 2⁵¹) | **109.0-bit** *(102.5 / 109.0 b)* | ~$2.2 × 10¹⁴ | ~25,500 years | Weakening, though still out of reach today |
| **5.29 quadrillion** (18.8×, 21.1 EB) | **96.0-bit** *(exact integer `q_96`)* | ~$2.6 × 10¹⁰ | ~3.1 years | Weakening rapidly; stay well clear |

These numbers are the cost of a classical brute-force attack for that single-key ideal-hash event (not a full multi-user or QROM proof; see [`jasonhadler25/blincs/paper/blincs.pdf`](https://github.com/jasonhadler25/blincs/blob/main/paper/blincs.pdf) §§4–5, §8.2, and Daniel J. Bernstein's SHARCS 2009 physical cost analysis of quantum hash collisions). There is no known reason to think that either quantum computers or super-intelligent AIs could generate forgeries any more efficiently than brute force; if they could, it would reduce the security level.

Signet does not count imprints across runs or across copies of a seed. When retiring a `Signet`, destroy its seed and stop signing, while keeping its `SignetId` in your accepted verifier set for as long as older imprints must still verify.

### 3. Startup, streaming, and authenticated IDs

**Startup and memory.** `Signet::from_seed` builds the `256 KiB` height-13 top Merkle heap (`16,383 × 16 B` nodes) in memory from the 32-byte seed in **~82.74 ms** on 1 Apple M6 core. Nothing is cached on disk, so the 32-byte seed is all you store. Warm signing allocates a transient local super-wave buffer (~1.5 MiB for all `19,584` lower-tree + `U-PORS` chains) that is freed on return; verification uses only stack buffers (~4 KiB for `verify`, plus the `Sink`'s BLAKE3 `Hasher` for `verify_with`) with zero heap allocation.

**Streaming.** `imprint`/`verify` take message bytes, and `imprint_with`/`verify_with` push bytes into a `Sink` (implementing both `Sink::update` and `std::io::Write`, so `std::io::copy` works in one line). Either way, Signet hashes every byte in a single salted keyed-BLAKE3 pass on the calling thread, choosing the per-imprint salt before the producer runs. On 1 Apple M6 core, 100 MiB hashes at **~4.48 GB/s** signing and **~6.95 GB/s** verifying (in-memory slice), or **~2.99–3.93 GB/s** via `imprint_with`/`verify_with`.

**Authenticated IDs.** Verifiers need an **authenticated** `SignetId`. Receiving a `SignetId` does not authenticate the sender; a valid imprint proves only that it matches a given 32-byte ID and `Context`. Deliver IDs through a channel that ties them to the signer, such as pinned configuration or signed release metadata.

### 4. Supported platforms, dependencies, and caller obligations

**Supported platforms:**

- **Host signer & verifier (`signet`):** Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`).
- **Standalone `#![no_std]` verifier (`crates/signet-verify`):** host targets above plus freestanding `wasm32-unknown-unknown` (tested with zero imports and zero allocator under Node 24).

If your platform is not on this list, this software is not expected to work for that use.

**Dependencies and code:**

- **Host `signet` runtime dependencies:** `blake3-servil-core = "=0.11.0"` (single-threaded SIMD/SME2 BLAKE3, zero background worker threads), `constant_time_eq = "=0.4.2"` (`no_std`), and `getrandom = "=0.4.3"` (OS `getrandom(2)` / `getentropy`), all BLAKE3 + SHA-256 hashset-verified in `Cargo.lock`.
- **Standalone `signet-verify` dependencies:** `blake3 = "=1.8.7"` (`default-features = false, features = ["pure"]`) and `constant_time_eq = "=0.4.2"` (`default-features = false`) — `#![no_std]`, zero `alloc`, zero coding lookup tables, `#![forbid(unsafe_code)]`.
- **Rust code:** both crates are `#![forbid(unsafe_code)]` with zero explicit `Drop` implementations.

**Other implementations of `BLINCS-48-X`:**

- standalone `#![no_std]` verifier crate `crates/signet-verify` (tested natively and on freestanding `wasm32-unknown-unknown`, `27.1 KiB`, 0 imports);
- an independent pure-Python reference, `reference/blincs.py`, which matches `signet` byte for byte (both signing and verification checked live in `tools/land.py`);
- an educational TypeScript reference verifier (`reference/blincs.ts`), verified live (positive and negative cases) under Node 24 in `tools/land.py` and CI.

**Caller obligations:**

- Use `Signet::generate(&rng)` for new signets; `from_seed` performs no entropy check.
- Use a protocol-specific `Context` for each distinct message purpose.
- Never disclose the per-imprint salt `e` or `K_msg` to a message submitter before `(ctx, M)` is committed (`SPEC.md §7`).
- Secret memory (the seed, derived keys, and transient signing workspaces) is **not** wiped on drop.
- Branches and memory indices in Signet's Rust code depend only on public inputs or values reconstructible from the message, context, and imprint. Hardware timing channels remain the platform's responsibility.
- The full list is in [`SECURITY.md`](SECURITY.md).

## Benchmarks

Apple M6 (macOS arm64, Rust 1.100.0, `blake3-servil-core = "=0.11.0"`, strictly single-threaded, `0–1% E-cores`). x86-64 results are not yet published.

| Operation (1 core) | Wall time | Throughput |
|---|---:|---:|
| Load key (`Signet::from_seed`, `256 KiB` height-13 top tree) | **82.74 ms** | **12 / s** |
| Sign, 64 B (warm, 19,584-chain super-wave + self-verify) | **8.45 ms** | **118 / s** |
| Verify, 64 B (zero heap alloc, `7.44 IPC`) | **62.7 µs** | **15,950 / s** |
| Sign / verify, 100 MiB (slice) | 23.41 ms / 15.08 ms | 4,479 / 6,951 MB/s |
| Sign / verify, 100 MiB (`imprint_with` / `verify_with`) | 35.04 ms / 26.72 ms | 2,992 / 3,925 MB/s |
| `Randomness::initialize` (lock-free atomic file) | 92.1 µs | — |

Full cycle counts, IPC, QEMU Cortex-M33 instruction/stack measurements, and the 1-core OpenSSL / SLH-DSA-B comparison are in [`BENCHMARKS.md`](BENCHMARKS.md).

## Documentation & References

- [`SPEC.md`](SPEC.md): normative byte-level specification for `BLINCS-48-X` and security estimates.
- [`DESIGN.md`](DESIGN.md): rationale, all-orbits rational-interval `U-PORS` bounds, `WOTS+C` + chained `U-PORS` design, and alternatives evaluated.
- [`BENCHMARKS.md`](BENCHMARKS.md): methodology, cycle counts, QEMU Cortex-M33 results, and 1-core OpenSSL / SLH-DSA-B comparison.
- [`QUALITY.md`](QUALITY.md): verification layers, mutation testing, and known gaps.
- [`SECURITY.md`](SECURITY.md): threat model, caller obligations, and private vulnerability reporting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): repository layout, the `cargo nextest` suite, and the reference cross-check gates.
- Standards: [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final) and [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final).

## Credits and thanks

**[Project 11](https://research.projecteleven.com/)**

- **Conor Deegan** gave feedback on an early `SPEC.md` draft, encouraged optimizing for signing time, and inspired BLINCS's constrained-device-first parameter search approach. With **julienif**, he co-authored [PQC Suite B](https://github.com/PQC-Suite-B/signatures), the SLH-DSA implementation and benchmark harness reproduced in `BENCHMARKS.md`. PQC Suite B builds on RustCrypto's `slh-dsa`.
- **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** built the [SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter) and explored taller cached top trees.

**Foundations**

- **BLAKE3:** Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn.
- **Implementation and tooling:** Servil Software Factory, for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes).
- **Hash-based signatures:** Ralph Merkle, Leslie Lamport, and Robert Winternitz.
- **SPHINCS:** Bernstein, Hopwood, Hülsing, Lange, Niederhagen, Papachristodoulou, Schneider, Schwabe, and Wilcox-O'Hearn ([ePrint 2014/795](https://eprint.iacr.org/2014/795)).
- **SPHINCS+ / SLH-DSA:** Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld, and Schwabe ([ePrint 2019/1086](https://eprint.iacr.org/2019/1086)), together with the NIST FIPS 205 team.
- **Constant-sum WOTS+C & Octopus multi-proofs:** Bos and Chaum (1992); Bleichenbacher and Maurer (ASIACRYPT 1996); Aumasson and Endignoux (Gravity-SPHINCS Octopus, [ePrint 2017/933](https://eprint.iacr.org/2017/933)); Kudinov, Hülsing, Ronen, and Yogev (`WOTS+C`, [ePrint 2022/778](https://eprint.iacr.org/2022/778)); Abri and Katz (`PORS+FP`, [ePrint 2025/2069](https://eprint.iacr.org/2025/2069)); Joag-Dev and Proschan (1983).

**Signer randomness:** Barak and Halevi; Ferguson, Schneier, and Kohno; Dodis et al.; Ristenpart and Yilek; and Bellare and Tackmann.

**Design principles:**

- Daira-Emma Hopwood, for the case for hash-based signatures in systems that already rely on a secure hash.
- Ron Rivest, for the "minimax" goal of performing well enough for many use cases.

## Licensing

Copyright (c) the Signet / BLINCS contributors. Use Signet under **any one** of the following licenses, at your choice. MIT or Apache-2.0 alone suffices for most users.

- `MIT`: [LICENSE-MIT](LICENSE-MIT)
- `Apache-2.0`: [LICENSE-APACHE](LICENSE-APACHE)
- `TGPPL-1.0`: [LICENSE-TGPPL](LICENSE-TGPPL)
- `BOSL-1.0`: [LICENSE-BOSL.txt](LICENSE-BOSL.txt)

The Cargo SPDX expression is `MIT OR Apache-2.0 OR TGPPL-1.0`, with `BOSL-1.0` offered alongside.

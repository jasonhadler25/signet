# Security

## Status

> **Pre-1.0 — Experimental & Unsupported.** Signet (`signet 0.1.0`, implementing `BLINCS-48-X`) is under active development. Its wire format, key-derivation contexts, and APIs may change incompatibly before 1.0, there is no support commitment, and **no independent human cryptographic audit has been performed**. Do not rely on Signet / BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** do not imprint more than $2^{48}$ things (281,474,976,710,656) with one signet. Signet does not enforce this limit across copies of a seed or across runs.
- **Application domain separation (`Context`):** always pass a distinct, protocol-specific `Context` (`<= 255` bytes) for each message purpose so imprints from one protocol cannot verify in another under the same `SignetId`.
- **Salt non-disclosure before commitment (`SPEC.md §7`):** signers MUST NOT disclose the per-imprint salt `e` or derived message key `K_msg` to a message submitter before `(ctx, M)` is committed.
- **Signet generation & seed entropy:** use `Signet::generate(&rng)` for new signets (mixing persisted local randomness with OS `getrandom(2)`). `Signet::from_seed` is for restoring persisted seeds and performs no entropy test; never pass passwords or low-entropy strings.
- **Supported platforms:** Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`) for the host `signet` crate, plus freestanding `wasm32-unknown-unknown` (and host targets) for the standalone `#![no_std]` `signet-verify` verifier crate. If your platform is not on this list, this software is not expected to work for that use.
- **State file placement:** provision a dedicated private 32-byte regular file (`0600` on Unix) inside a private directory on a local filesystem whose ancestor directories are writable only by the signing user or system administrator. `initialize` checks that the path is a private (`0600`) regular non-symlink file of exact length 32 bytes without touching invalid paths, derives independent `next_seed`, `run_key`, and `keygen_key` outputs (preserving forward secrecy on disk), and rotates `next_seed` atomically via a `0600` sibling temp file + POSIX `rename` with no locks.
- **Process forks and VM snapshots:** in multithreaded POSIX processes, call `exec()` before initializing Signet rather than calling `Randomness::initialize` directly after `fork()`. After restoring a live VM snapshot, ensure genuinely fresh unshared OS entropy before initializing so cloned images do not repeat `(run_key, count)`.
- **Memory retention:** `Signet` retains its 32-byte seed, derived keys, and `256 KiB` cached height-13 top Merkle heap; signing allocates a transient local super-wave buffer (~1.5 MiB) freed on return. Neither Signet nor `blake3-servil-core` wipes secret key memory on drop. Verification in `signet` uses local stack buffers with zero heap allocation, and standalone `crates/signet-verify` links with `#![no_std]`, zero allocator, and zero coding lookup tables.
- **Pass the original message or stream directly:** call `imprint`/`imprint_with` and `verify`/`verify_with` on the full message so the entire input is hashed in BLINCS's single salted BLAKE3 pass at full speed, resting on randomized target-collision resistance rather than unsalted collision resistance.

## Timing and secret independence

In Signet's Rust code, every branch and memory index during signing and verification depends only on public inputs or values reconstructible from the message, context, and imprint (`salt`, `randomizer`, `D_seed`, `ctr_ft`, `U-PORS` selections & Octopus topology, `leaf_addr`, `ctr_l`, and `WOTS+C` chain digits). Secret values (`seed`, `SecretKey`, `salt_key`, `randomizer_key`, `run_key`, `keygen_key`, `draw`, and unrevealed `U-PORS`/`WOTS+C` chain starts) are only copied or hashed by `blake3-servil-core`, whose assembly kernels are proved branch- and address-independent of keys and inputs. Hardware timing guarantees (Arm `DIT`, Intel `DOITM`, and mitigation of frequency/prefetcher channels such as Hertzbleed or GoFetch) remain the caller's or platform's responsibility; see [`QUALITY.md`](QUALITY.md).

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-imprint-1.bin` (`3,990` bytes, `ctx = b"BLINCS-48-X reference vector v1"`):
  - SHA-256: `5ddc2156d48938300f73abfa21fe514b69ed56ffbb44c61b2dc2d2bb6a4f9386`
  - BLAKE3:  `cefb8846c95ff890a8e7cb1a51a2d2c2032c3f0de9e57fef8fc3d7943723ac22`
- `test_vectors/edge-vectors.json` (4 boundary vectors: empty/empty-ctx, 1 B, 1,024 B, 16,385 B with max 255-byte context and high `leaf_addr`):
  - SHA-256: `89437ccbd170293b5ec20e621a7d528e12696837e681097bff2d24434f3e6a9e`
  - BLAKE3:  `524d43dea3d631e2baabc04e98f70c7362c6a1ac630d5331f9bd2eee44a88704`

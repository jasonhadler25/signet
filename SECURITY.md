# Security

## Status

> **Pre-1.0 — Experimental & Unsupported.** Signet (`signet 0.1.0`, implementing `BLINCS-128-7x5`) is under active development. Its wire format, key-derivation contexts, and APIs may change incompatibly before 1.0, there is no support commitment, and **no independent human cryptographic audit has been performed**. Do not rely on Signet / BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** do not imprint more than $2^{32}$ things (4,294,967,296) with one signet. Signet does not enforce this limit across copies of a seed or across runs.
- **Application domain separation (`Context`):** always pass a distinct, protocol-specific `Context` (`<= 255` bytes) for each message purpose so imprints from one protocol cannot verify in another under the same `SignetId`.
- **Signet generation & seed entropy:** use `Signet::generate(&rng)` for new signets (mixing persisted local randomness with OS `getrandom(2)`). `Signet::from_seed` is for restoring persisted seeds and performs no entropy test; never pass passwords or low-entropy strings.
- **Supported platforms:** Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`) for the host `signet` crate, plus freestanding `wasm32-unknown-unknown` (and host targets) for the standalone `#![no_std]` `signet-verify` verifier crate. If your platform is not on this list, this software is not expected to work for that use.
- **Seed directory placement:** provision a dedicated private directory (`0700` on Unix) on a local filesystem whose ancestor directories are writable only by the signing user or system administrator. `initialize` checks that the directory is private (`0700`) and rejects non-directories, symlinks, unexpected entries, or seed files whose length is not 32 bytes without touching them. New seed files are written completely inside `.stage/` and published atomically via no-replace `hard_link`. Filenames (`signet-r2-<32 hex>`) are pool-derived names domain-separated from `next_seed`, `run_key`, and `keygen_key` (not a MAC authenticating the file contents).
- **Process forks and VM snapshots:** in multithreaded POSIX processes, call `exec()` before initializing Signet rather than calling `Randomness::initialize` directly after `fork()`. After restoring a live VM snapshot, ensure genuinely fresh unshared OS entropy before initializing so cloned images do not repeat `(run_key, count)`.
- **Memory retention:** `Signet` retains its 32-byte seed, derived keys, and inline 1 KiB top tree; signing allocates a transient local `SignWorkspace` (~555 KiB for cross-tree FORS batching) freed on return. Neither Signet nor `blake3-servil-core` wipes secret key memory on drop. Verification in `signet` uses local stack buffers, and standalone `crates/signet-verify` links with `#![no_std]` and zero allocator. Streaming readers use a fresh local 16 KiB stack buffer, zeroing each lent slice before every `Read::read` call.
- **Pass the original message or stream directly:** call `imprint`/`imprint_reader` and `verify`/`verify_reader` on the full message so the entire input is hashed in BLINCS's single salted BLAKE3 pass at full speed, resting on randomized target-collision resistance rather than unsalted collision resistance.

## Timing and secret independence

In Signet's Rust code, every branch and memory index during signing and verification depends only on public inputs or values reconstructible from the message, context, and imprint (`salt`, `randomizer`, `D`, `fors_indices`, `leaf_addr`, and WOTS+ chain digits). Secret values (`seed`, `SecretKey`, `salt_key`, `randomizer_key`, `run_key`, `keygen_key`, `draw`, and unrevealed leaf secrets) are only copied or hashed by `blake3-servil-core`, whose assembly kernels are proved branch- and address-independent of keys and inputs. Hardware timing guarantees (Arm `DIT`, Intel `DOITM`, and mitigation of frequency/prefetcher channels such as Hertzbleed or GoFetch) remain the caller's or platform's responsibility; see [`QUALITY.md`](QUALITY.md).

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-imprint-1.bin` (`7,392` bytes, `ctx = b"BLINCS-128-7x5 reference vector v1"`):
  - SHA-256: `056e4c91aab74cf3ae9dedc3b0799e25f0eb19d25070e285f3b114c601ffe993`
  - BLAKE3:  `1f90309febb00685d497c84edfae3bf9563206e15215f143a1eab51bcc5332bf`
- `test_vectors/edge-vectors.json` (4 boundary vectors: empty/empty-ctx, 1 B, 1,024 B, 16,385 B with max 255-byte context and bit-34 `leaf_addr`):
  - SHA-256: `4ef1f28a65247ee8a17981a6faa6d3dda99b68126ae721cd40572b0379e48299`
  - BLAKE3:  `0616c04735308daff990d1051a8992da5052d4f9d1fc63c18acba7a67df68483`

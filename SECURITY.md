# Security

## Status

> **Pre-1.0 — Experimental & Unsupported.** BLINCS (`0.1.0`) is under active development. Its wire format, key-derivation contexts, and APIs may change incompatibly before 1.0, there is no support commitment, and **no independent human cryptographic audit has been performed**. Do not rely on BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** do not imprint more than $2^{32}$ things (4,294,967,296) with one signet. The library does not enforce this limit across copies of a seed or across runs.
- **Signet generation & seed entropy:** use `Signet::generate(&rng)` for new signets (mixing persisted local randomness with OS `getrandom(2)`). `Signet::from_seed` is for restoring persisted seeds and performs no entropy test; never pass passwords or low-entropy strings.
- **Supported platforms:** Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`). If your platform is not on this list, this software is not expected to work for that use.
- **Seed directory placement:** provision a dedicated private directory (`0700` on Unix) once with `Randomness::create`. Do not place unrelated files in that directory (`initialize` rejects unexpected entries, symlinks, or files `> 32` bytes without touching them). Filenames (`blincs-r2-<32 hex>`) derive from a domain-separated `file_id` and reveal zero bits of future salts or signets.
- **Process forks and VM snapshots:** after `fork()` (without `exec()`) or restoring a live VM snapshot, call `Randomness::initialize` again so cloned processes or images do not share the same `(run_key, count)` draw sequence.
- **Memory retention:** `Signet` retains its 32-byte seed, derived keys, and inline 1 KiB top tree; signing allocates a transient local `SignWorkspace` (~110 KiB) freed on return. Neither BLINCS nor `blake3-servil-core` wipes secret key memory on drop. Verification uses only local stack buffers (zero heap allocation). Streaming readers use a fresh local zero-initialized 16 KiB stack buffer, zeroing each slice before `Read::read`.
- **Pass the original message or stream directly:** call `imprint`/`imprint_reader` and `verify`/`verify_reader` on the full message so the entire input is hashed in BLINCS's single salted BLAKE3 pass at full speed, resting on randomized target-collision resistance rather than unsalted collision resistance.

## Timing and secret independence

In BLINCS's Rust code, every branch and memory index during signing and verification depends only on public inputs or values published in the signature (`salt`, `randomizer`, `D`, `fors_indices`, `leaf_addr`, and WOTS+ chain digits). Secret values (`seed`, `SecretKey`, `salt_key`, `randomizer_key`, `run_key`, `keygen_key`, `draw`, and unrevealed leaf secrets) are only copied or hashed by `blake3-servil-core`, whose assembly kernels are proved branch- and address-independent of keys and inputs. Hardware timing guarantees (Arm `DIT`, Intel `DOITM`, and mitigation of frequency/prefetcher channels such as Hertzbleed or GoFetch) remain the caller's or platform's responsibility; see [`QUALITY.md`](QUALITY.md).

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-imprint-1.bin` (7,392 bytes):
  - SHA-256: `ab9d2c8bf1e375e49ef57c3df2fe0c3700ffd5553d5085bd2f48abaac4e2386d`
  - BLAKE3:  `b72623d86ea8e954b39604329aeb2694c701f1e2043f6ca62285fbd770af9421`
- `test_vectors/edge-vectors.json` (4 boundary vectors: empty, 1 B, 1,024 B, 16,385 B with bit-34 `leaf_addr`):
  - SHA-256: `bd46fb9730fcaa11be294f6ed7e5d6ad931906cb89957681fe6315af4b1ca4e8`
  - BLAKE3:  `dc3ba2d0b4094aed404ec293994deded59294c970cf5de0d23eb6c21bdd124bf`

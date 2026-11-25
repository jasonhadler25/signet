# Security

## Status

> **Pre-1.0 — Experimental & Unsupported.** BLINCS (`0.1.0`) is under active development. Its wire format, key-derivation contexts, and APIs may change incompatibly before 1.0, there is no support commitment, and **no independent human cryptographic audit has been performed**. Do not rely on BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** at most $2^{32}$ signatures (4,294,967,296) per signing key. The library does not enforce this limit across copies of a seed or across runs.
- **Signing-seed entropy:** `Signet::from_seed` accepts a caller-supplied 32-byte seed and performs no entropy test. Generate seeds from a vetted cryptographic source; never pass passwords or low-entropy strings.
- **Supported platforms:** Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`). If your platform is not on this list, this software is not expected to work for that use (`Randomness` uses Unix `/dev/urandom`, `0600` mode, and POSIX advisory `flock`).
- **State file placement & error recovery:** keep the 48-byte randomness state file in a private local directory owned by the signer on a Unix filesystem that enforces advisory `flock` locks. Create it once with `Randomness::create` before starting signers. If the state file is lost or corrupted and no live signer holds locks on it, remove the damaged file and re-provision it with `Randomness::create`.
- **Process forks and VM snapshots:** after `fork()` (without `exec()`) or restoring a live VM snapshot, call `Randomness::initialize` again so cloned processes or images do not share the same `(run_key, count)` draw sequence.
- **Memory retention:** `Signet` retains its 32-byte seed and derived keys, and signing allocates a transient local `SignWorkspace` freed on return. Neither BLINCS nor `blake3-servil-core` wipes secret key memory on drop. Verification uses only local stack buffers (zero heap allocation). Streaming readers use a fresh local zero-initialized 16 KiB stack buffer, zeroing each slice before `Read::read`.
- **Pass the original message or stream directly:** call `imprint`/`imprint_reader` and `verify`/`verify_reader` on the full message so the entire input is hashed in BLINCS's single salted BLAKE3 pass at full speed, resting on randomized target-collision resistance rather than unsalted collision resistance.

## Timing and secret independence

In BLINCS's Rust code, every branch and memory index during signing and verification depends only on public inputs or values published in the signature (`salt`, `randomizer`, `D`, `fors_indices`, `leaf_addr`, and WOTS+ chain digits). Secret values (`seed`, `SecretKey`, `salt_key`, `randomizer_key`, `run_key`, `draw`, and unrevealed leaf secrets) are only copied or hashed by `blake3-servil-core`, whose assembly kernels are proved branch- and address-independent of keys and inputs. Hardware timing guarantees (Arm `DIT`, Intel `DOITM`, and mitigation of frequency/prefetcher channels such as Hertzbleed or GoFetch) remain the caller's or platform's responsibility; see [`QUALITY.md`](QUALITY.md).

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-imprint-1.bin` (5,616 bytes):
  - SHA-256: `f94f0a1f23135a4941ba79b11435cde6e3802894840f2ff306d2026d5e628784`
  - BLAKE3:  `53405a42fe874e64f69d9f0e52140c7016226eabf7a59f33e8d5bed61614b94b`
- `test_vectors/edge-vectors.json` (4 boundary vectors: empty, 1 B, 1,024 B, 16,385 B with bit-32 `leaf_addr`):
  - SHA-256: `51dcec9fe12f78d726ffd39ef3748e8c8ff469a0069ab1c8f44c2b7e773a9d71`
  - BLAKE3:  `a95d39c94d4d253ffdedd70924e84787705f9eb302ef1251cbaca0ffb730cf20`

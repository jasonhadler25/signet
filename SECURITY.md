# Security

## Status

> **Pre-1.0 — Experimental & Unsupported.** BLINCS (`0.1.0`) is under active development. Its wire format, key-derivation contexts, and APIs may change incompatibly before 1.0, there is no support commitment, and **no independent human cryptographic audit has been performed**. Do not rely on BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** at most $2^{32}$ signatures (4,294,967,296) per signing key. The library does not enforce this limit across copies of a seed or across runs.
- **Signing-seed entropy:** `Signet::from_seed` accepts a caller-supplied 32-byte seed and performs no entropy test. Generate seeds from a vetted cryptographic source; never pass passwords or low-entropy strings.
- **Platform scope (Unix imprinting):** `Randomness::create` and `Randomness::initialize` currently target Unix (`/dev/urandom`, `0600` mode, POSIX advisory `flock`). `SignetId` works on any target supporting `blake3-servil` and 64-bit atomics.
- **State file placement & error recovery:** keep the 48-byte randomness state file in a private local directory owned by the signer on a Unix filesystem that enforces advisory `flock` locks. Create it once with `Randomness::create` before starting signers. If `create` fails partway through or a host crashes mid-`initialize`, remove and re-provision the state file before resuming imprinting.
- **Process forks and VM snapshots:** do **not** call BLINCS in a `fork()` child without `exec()` (multithreaded fork children do not inherit background worker threads; the worker pool detects a PID change and aborts fail-stop rather than hanging). After restoring a live VM snapshot, call `Randomness::initialize` again so clones do not share the same `(run_key, count)` draw sequence.
- **Memory retention:** `Signet` retains its 32-byte seed and derived keys, parallel jobs copy `SecretKey`, and both worker threads and participating application threads keep thread-local scratch buffers that retain intermediate leaf secrets until thread exit. Neither BLINCS nor `blake3-servil` wipes secret key memory on drop. Streaming readers use a fresh local zero-initialized 16 KiB stack buffer ($< 16$ KiB) or a fresh per-call `Pipeline` ($\ge 16$ KiB, zeroing each newly acquired room slice before `Read::read`) with no shared cross-caller pool.
- **Pass the original message or stream directly:** call `imprint`/`imprint_reader` and `verify`/`verify_reader` on the full message so the entire input is hashed in BLINCS's single salted BLAKE3 pass at full speed, resting on randomized target-collision resistance rather than unsalted collision resistance.

## Timing and secret independence

In BLINCS's Rust code, every branch and memory index during signing and verification depends only on public inputs or values published in the signature (`salt`, `randomizer`, `D`, `fors_indices`, `leaf_addr`, and WOTS+ chain digits). Secret values (`seed`, `SecretKey`, `salt_key`, `randomizer_key`, `run_key`, `draw`, and unrevealed leaf secrets) are only copied or hashed by `blake3-servil`, whose assembly kernels are proved branch- and address-independent of keys and inputs. Hardware timing guarantees (Arm `DIT`, Intel `DOITM`, and mitigation of frequency/prefetcher channels such as Hertzbleed or GoFetch) remain the caller's or platform's responsibility; see [`QUALITY.md`](QUALITY.md).

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-imprint-1.bin` (5,616 bytes):
  - SHA-256: `f94f0a1f23135a4941ba79b11435cde6e3802894840f2ff306d2026d5e628784`
  - BLAKE3:  `53405a42fe874e64f69d9f0e52140c7016226eabf7a59f33e8d5bed61614b94b`
- `test_vectors/edge-vectors.json` (4 boundary vectors: empty, 1 B, 1,024 B, 16,385 B with bit-32 `leaf_addr`):
  - SHA-256: `51dcec9fe12f78d726ffd39ef3748e8c8ff469a0069ab1c8f44c2b7e773a9d71`
  - BLAKE3:  `a95d39c94d4d253ffdedd70924e84787705f9eb302ef1251cbaca0ffb730cf20`

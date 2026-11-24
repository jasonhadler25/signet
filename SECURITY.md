# Security

## Status

BLINCS is pre-1.0 (`0.1.0`). Its wire format, key-derivation contexts, and APIs may change before 1.0, and **no independent human cryptographic audit has been performed**. Do not rely on BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** at most $2^{32}$ signatures (4,294,967,296) per signing key. The library does not enforce this limit across copies of a seed or across runs.
- **Signing-key seed entropy:** `SigningKey::from_seed` accepts a caller-supplied 32-byte seed and performs no entropy test. Generate seeds from a vetted cryptographic source; never pass passwords or low-entropy strings.
- **Platform scope (Unix signing):** `Randomness::create` and `Randomness::initialize` currently target Unix (`/dev/urandom`, `0600` mode, POSIX advisory `flock`). `VerifyingKey` works on any target supporting `blake3-servil` and 64-bit atomics.
- **State file placement & error recovery:** keep the 48-byte randomness state file in a private local directory owned by the signer on a Unix filesystem that enforces advisory `flock` locks. Create it once with `Randomness::create` before starting signers. If `create` fails partway through or a host crashes mid-`initialize`, remove and re-provision the state file before resuming signing.
- **Process forks and VM snapshots:** do **not** call BLINCS in a `fork()` child without `exec()` (multithreaded fork children do not inherit background worker threads). After restoring a live VM snapshot, call `Randomness::initialize` again so clones do not share the same `(run_key, count)` draw sequence.
- **Memory retention:** `SigningKey` retains its 32-byte seed and derived keys, parallel jobs copy `SecretKey`, and both worker threads and participating application threads keep thread-local scratch buffers that retain intermediate leaf secrets until thread exit. Neither BLINCS nor `blake3-servil` wipes secret key memory on drop. Streaming readers use a fresh local zero-initialized 16 KiB stack buffer ($< 16$ KiB) or a fresh per-call `Pipeline` ($\ge 16$ KiB, zeroing each newly acquired room slice before `Read::read`) with no shared cross-caller pool.
- **No pre-hash API:** pass the message or stream directly to `sign`/`sign_reader` and `verify`/`verify_reader`. Pre-hashing before calling BLINCS exposes users to collision attacks on the pre-hash.

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-signature-1.bin` (5,616 bytes):
  - SHA-256: `7fbc1537b5b516c823542c425f48129fe78d974a1806ae24fe0c8dc382a7436c`
  - BLAKE3:  `ab80843efd3f5860ccc87f578b8831a79eaf3bb595ac516954823f2ed6886b23`

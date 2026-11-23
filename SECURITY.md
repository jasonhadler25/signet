# Security

## Status

BLINCS is pre-1.0 (`0.1.0`). Its wire format, key-derivation contexts, and APIs may change before 1.0, and **no independent human cryptographic audit has been performed**. Do not rely on BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** at most $2^{32}$ signatures (4,294,967,296) per signing key. The library does not enforce this limit across copies of a seed or across runs.
- **Signing-key seed entropy:** `SigningKey::from_seed` accepts a caller-supplied 32-byte seed and performs no entropy test. Generate seeds from a vetted cryptographic source; never pass passwords or low-entropy strings.
- **State file placement:** keep the 48-byte randomness state file in a private local directory owned by the signer on a filesystem that enforces advisory `flock` locks. Create it once with `Randomness::create` before starting signers.
- **Process forks and VM snapshots:** after `fork()` or restoring a live VM/process image, call `Randomness::initialize` again so clones do not share the same `(run_key, count)` draw sequence.
- **Memory retention:** `SigningKey` retains its 32-byte seed and derived keys, and each worker thread keeps reusable scratch buffers that retain intermediate leaf secrets until process exit. Neither BLINCS nor `blake3-servil` wipes secret key memory on drop. Streaming readers use a fresh local zero-initialized 16 KiB stack buffer ($\le 16$ KiB) or a fresh per-call `Pipeline` ($> 16$ KiB) with no shared cross-caller pool.
- **No pre-hash API:** pass the message or stream directly to `sign`/`sign_reader` and `verify`/`verify_reader`. Pre-hashing before calling BLINCS exposes users to collision attacks on the pre-hash.

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-signature-1.bin` (5,616 bytes):
  - SHA-256: `7fbc1537b5b516c823542c425f48129fe78d974a1806ae24fe0c8dc382a7436c`
  - BLAKE3:  `ab80843efd3f5860ccc87f578b8831a79eaf3bb595ac516954823f2ed6886b23`

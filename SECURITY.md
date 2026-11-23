# Security

## Status

BLINCS is pre-1.0 (`0.1.0`). Its wire format, key-derivation contexts, and APIs may change before 1.0, and **no independent human cryptographic audit has been performed**. Do not rely on BLINCS to protect high-value assets until independent review is complete.

## Reporting a vulnerability

Report suspected security vulnerabilities privately through GitHub's private vulnerability reporting for this repository, rather than opening a public issue. Include the exact git commit SHA, platform, and the smallest reproducing input or program.

## Security model and boundaries

Full mathematical and operational details are in [`SPEC.md`](SPEC.md) and [`DESIGN.md`](DESIGN.md). Key boundaries callers must uphold:

- **Per-key signing budget:** at most $2^{33}$ signatures (8,589,934,592) per signing key. The library does not enforce this limit across copies of a seed or across runs.
- **Signing-key seed entropy:** `SigningKey::from_seed` accepts a caller-supplied 32-byte seed and performs no entropy test. Generate seeds from a vetted cryptographic source; never pass passwords or low-entropy strings.
- **State file placement:** keep the 48-byte randomness state file in a private local directory owned by the signer on a filesystem that enforces advisory `flock` locks. Create it once with `Randomness::create` before starting signers.
- **Process forks and VM snapshots:** after `fork()` or restoring a live VM/process image, call `Randomness::initialize` again so clones do not share the same `(run_key, count)` draw sequence.
- **Memory retention:** `SigningKey` retains its 32-byte seed and derived keys, and each signing thread keeps a reusable workspace whose buffers retain intermediate few-time leaf secrets until the thread exits. Neither BLINCS nor `blake3-servil-core` wipes secret key memory on drop. Streaming readers use a fresh zero-initialized 64 KiB stack buffer per call with no shared cross-caller pool.
- **No pre-hash API:** pass the message or stream directly to `sign`/`sign_reader` and `verify`/`verify_reader`. Pre-hashing before calling BLINCS exposes users to collision attacks on the pre-hash.

## Verifying checked-in vectors

Where this repository records digests, it records both SHA-256 and BLAKE3:

- `test_vectors/reference-signature-1.bin` (3,988 bytes):
  - SHA-256: `ac0808dbf5a435ab21d7426df178abb707f89f3a26a1b84cd13cda083f6f00e1`
  - BLAKE3:  `f5de1861fe29352b6f290469517a749cc426cf22c48d246acc494cb75d10a4c8`

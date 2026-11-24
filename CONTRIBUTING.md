# Contributing to BLINCS

BLINCS is a stateless hash-based signature scheme on BLAKE3 implemented in Rust with an independent pure-Python reference, following Servil Software Factory engineering practices.

## Repository layout

```text
SPEC.md                 Normative byte-level specification
DESIGN.md               Rationale for every design decision (including minimax)
BENCHMARKS.md           SLH-DSA-B reproduction, BLINCS comparison, clocks & MT
QUALITY.md              Verification layers, reproduction commands, and known gaps
SECURITY.md             Threat model, operational boundaries, and reporting
src/
  lib.rs                Public API (SigningKey, VerifyingKey, Signature)
  params.rs             Constants, contexts, 16-byte tweaks, key helpers
  content.rs            Single-pass salted BLAKE3 content hashing (multi-core slices & zero-copy Pipeline streams)
  few_time.rs           FORS few-time signatures (16 trees x 1,024 leaves, zero grinding)
  one_time.rs           WOTS+ nibble one-time signatures (w = 16, 35 chains, zero grinding) and Merkle trees
  pool.rs               Crash-only parallel task runner and per-thread scratch workspaces (zero Drop impls)
  randomness.rs         48-byte state file (create, initialize) and in-memory draws
  test.rs               Unit tests, reference vector checks, negative tests
tests/
  integration.rs        Public API tests and live Python cross-verification
reference/
  blake3.py             From-spec pure-Python BLAKE3 (35 official test vectors)
  blincs.py             Independent pure-Python reference implementation
  blincs.ts             Educational blind spec-only TypeScript verifier (for reading, not production execution)
test_vectors/           Checked-in primary & edge-case reference signatures (SHA-256 + BLAKE3 recorded)
tools/
  require_nextest.rs    Sentinel test failing plain `cargo test`
  controls.py           16 planted-fault controls
  counts.py             Shipped-code safety counts (0 unsafe, 0 debug_assert!, 0 truncation allows, 0 Drop)
  domain_sep.py         Static & dynamic domain-separation and tweak-uniqueness check
  optimize.py           Reproducible parameter optimizer (unknown-thresholds model)
  mutants/              cargo-mutants runner and known-survivors list
  land.py               Exact-commit landing gate
bench/                  Standalone benchmark crate using bench-hashes' `clocks`
audits/                 Unedited cross-family review reports
```

## Engineering practices

- **Simplicity:** prefer one clear mechanism with the fewest runtime cases and fewest new concepts. Every piece earns its place.
- **Design by Contract:** document preconditions and fail stop on broken invariants; avoid defensive fallback modes that hide bugs.
- **Crash-only:** avoid shutdown hooks and per-call allocate-and-drop cycles for reusable buffers.
- **Zero `unsafe`:** the library crate enforces `#![forbid(unsafe_code)]`.
- **Terminology:** call the 32-byte verification key a **verifying key**, not a "public key".
- **Two hashes:** whenever recording or checking a file digest, record both SHA-256 and BLAKE3.
- **Measurement:** time changes with `bench/` (`clocks`: wall time, core cycles, clock speed, and background load together).

## Gates before landing a commit

Install [`cargo-nextest`](https://nexte.st) (and `cargo-mutants` for the mutation gate), then run:

```sh
python3 tools/land.py
python3 tools/mutants/check.py
```

`tools/land.py` checks a clean working tree, `cargo fmt -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo nextest run --locked`, `cargo test --doc --locked`, `reference/blake3.py`, `tools/optimize.py --check`, `tools/counts.py`, `tools/domain_sep.py`, `python3 -O` reference input validation, checked-in test vector SHA-256 and BLAKE3 digests (`reference-signature-1.bin` and `edge-vectors.json`), and all 16 planted-fault controls in `tools/controls.py`.

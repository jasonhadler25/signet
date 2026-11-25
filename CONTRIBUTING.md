# Contributing to BLINCS

BLINCS is a stateless hash-based signature scheme on BLAKE3 implemented in Rust with an independent pure-Python reference, following Servil Software Factory engineering practices.

## Repository layout

```text
SPEC.md                 Normative byte-level specification
DESIGN.md               Rationale for every design decision (including minimax)
BENCHMARKS.md           SLH-DSA-B 1-core reproduction, BLINCS comparison, and clocks wall/cycle tables
QUALITY.md              Verification layers, reproduction commands, and known gaps
SECURITY.md             Threat model, operational boundaries, and reporting
src/
  lib.rs                Public API (Signet, SignetId, Imprint)
  params.rs             Constants, contexts, 16-byte tweaks, key helpers
  content.rs            Single-pass salted BLAKE3 content hashing (single-threaded slices & 16 KiB stack streams)
  few_time.rs           Byte-aligned FORS few-time signatures (20 trees x 256 leaves, zero grinding)
  one_time.rs           WOTS+ nibble one-time signatures (w = 16, 35 chains, zero grinding), uniform height-5 trees, SignWorkspace
  randomness.rs         Lock-free content-addressed seed directory (create, initialize) and in-memory draws
  test.rs               Unit tests, reference vector checks, negative tests
tests/
  integration.rs        Public API tests and live Python cross-verification
reference/
  blake3.py             From-spec pure-Python BLAKE3 (35 official test vectors)
  blincs.py             Independent pure-Python reference implementation
  blincs.ts             Educational spec-only TypeScript verifier (for reading, not production execution)
test_vectors/           Checked-in primary & edge-case reference signatures (SHA-256 + BLAKE3 recorded)
tools/
  require_nextest.rs    Sentinel test failing plain `cargo test`
  controls.py           16 planted-fault controls
  counts.py             Shipped-code safety counts (0 unsafe, 0 debug_assert!, 0 truncation allows, 0 Drop)
  domain_sep.py         Static & dynamic domain-separation and tweak-uniqueness check
  optimize.py           Reproducible constrained-device-first parameter search (inspired by Conor Deegan, Project 11)
  mutants/              cargo-mutants runner and known-survivors list
  land.py               Exact-commit landing gate
bench/                  Standalone benchmark crate using bench-hashes' `clocks`
audits/                 Unedited cross-family review reports
```

## Engineering practices

- **Simplicity:** prefer one clear mechanism with the fewest runtime cases and fewest new concepts. Every piece earns its place.
- **Design by Contract:** document preconditions and fail stop on broken invariants; avoid defensive fallback modes that hide bugs.
- **Crash-only:** zero `Drop` implementations and no shutdown hooks; verification uses only stack buffers (zero heap allocation).
- **Zero `unsafe`:** the library crate enforces `#![forbid(unsafe_code)]`.
- **Terminology:** call the 32-byte secret bearer object a **signet** (`Signet`), its 32-byte self-certifying identifier a **signet ID** (`SignetId`) — never "public key" — and the 7,392-byte proof an **imprint** (`Imprint`).
- **Two hashes:** whenever recording or checking a file digest, record both SHA-256 and BLAKE3.
- **Measurement:** time changes with `bench/` (`clocks`: wall time, core cycles, clock speed, and background load together).

## Gates before landing a commit

Install [`cargo-nextest`](https://nexte.st) (and `cargo-mutants` for the mutation gate), then run:

```sh
python3 tools/land.py
python3 tools/mutants/check.py
```

`tools/land.py` checks a clean working tree, `cargo fmt -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo nextest run --locked`, `cargo test --doc --locked`, `reference/blake3.py`, `tools/optimize.py --check`, `tools/counts.py`, `tools/domain_sep.py`, `python3 -O` reference input validation, checked-in test vector SHA-256 and BLAKE3 digests (`reference-imprint-1.bin` and `edge-vectors.json`), and all 16 planted-fault controls in `tools/controls.py`.

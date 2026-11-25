# Contributing to Signet (`BLINCS-128-7x5`)

**Signet** (`signet` crate) is a Rust implementation of the **BLINCS** (`BLINCS-128-7x5`) stateless hash-based signature algorithm on BLAKE3, accompanied by independent Python and TypeScript references and following Servil Software Factory engineering practices.

## Repository layout

```text
SPEC.md                 Normative byte-level specification for BLINCS-128-7x5
DESIGN.md               Rationale for every design decision (including ST33 p99 <= 5s parameter search)
BENCHMARKS.md           SLH-DSA-B 1-core reproduction, Signet comparison, and clocks wall/cycle tables
QUALITY.md              Verification layers, reproduction commands, and known gaps
SECURITY.md             Threat model, operational boundaries, and reporting
src/
  lib.rs                Public API (Signet, SignetId, Imprint, Context, InvalidImprint, VerifyError)
  params.rs             Suite constants (BLINCS-128-7x5), contexts, 16-byte tweaks, key helpers
  content.rs            Single-pass salted BLAKE3 content hashing (framed Context, slices & 16 KiB stack streams)
  few_time.rs           Byte-aligned FORS few-time signatures (20 trees x 256 leaves, cross-tree batched, zero grinding)
  one_time.rs           WOTS+ nibble one-time signatures (w = 16, 35 chains, zero grinding), uniform height-5 trees, SignWorkspace
  randomness.rs         Lock-free content-addressed seed directory (create, initialize) and in-memory draws
  test.rs               Unit tests, intermediate KATs, reference/edge vector checks, fuzzing, negative tests
tests/
  integration.rs        Public API tests and live Python cross-verification
reference/
  blake3.py             From-spec pure-Python BLAKE3 (35 official test vectors)
  blincs.py             Independent pure-Python reference implementation (educational / vectors only)
  blincs.ts             Educational spec-only TypeScript verifier (live-verified under Node 24)
test_vectors/           Checked-in primary & edge-case reference imprints (SHA-256 + BLAKE3 recorded)
tools/
  require_nextest.rs    Sentinel test failing plain `cargo test`
  controls.py           17 planted-fault controls (executed inside a disposable copy)
  counts.py             Shipped-code safety counts (0 unsafe, 0 debug_assert!, 0 truncation allows, 0 Drop)
  domain_sep.py         Static SPEC-table & dynamic domain-separation / tweak-uniqueness check
  optimize.py           Reproducible constrained-device-first parameter search (inspired by Conor Deegan, Project 11)
  mutants/              cargo-mutants runner and known-survivors list
  land.py               Exact-commit landing gate
bench/                  Standalone benchmark crate using bench-hashes' `clocks`
audits/                 Unedited cross-family review reports
```

## Engineering practices

- **Simplicity:** prefer one clear mechanism with the fewest runtime cases and fewest new concepts. Every piece earns its place.
- **Design by Contract:** document preconditions and fail stop on broken invariants; avoid defensive fallback modes that hide bugs.
- **Crash-only:** zero explicit `Drop` implementations and no shutdown hooks; verification uses only stack buffers (zero heap allocation).
- **Zero `unsafe`:** the library crate enforces `#![forbid(unsafe_code)]`.
- **Terminology:** the algorithm is **BLINCS (`BLINCS-128-7x5`)**; this codebase/crate is **Signet (`signet`)**; call the 32-byte secret bearer object a **signet** (`Signet`), its 32-byte self-certifying identifier a **signet ID** (`SignetId`) — never "public key" — and the 7,392-byte proof an **imprint** (`Imprint`).
- **Two hashes:** whenever recording or checking a file digest, record both SHA-256 and BLAKE3.
- **Measurement:** time changes with `bench/` (`clocks`: wall time, core cycles, clock speed, and background load together).

## Gates before landing a commit

Install [`cargo-nextest`](https://nexte.st) (and `cargo-mutants` for the mutation gate), then run:

```sh
python3 tools/land.py
python3 tools/mutants/check.py
```

`tools/land.py` checks a clean working tree, `reference/blake3.py`, `tools/optimize.py --check`, `tools/counts.py`, `tools/domain_sep.py`, checked-in test vector SHA-256 and BLAKE3 digests + Python `-O` validation + live Node 24 `reference/blincs.ts` verification, `Cargo.lock` hashsets, `cargo fmt -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked`, `cargo nextest run --locked`, `cargo test --doc --locked`, `cargo package --locked`, and all 17 planted-fault controls in `tools/controls.py`.

# Contributing to Signet (`BLINCS-128-A2`)

**Signet** (`signet` crate) is a Rust implementation of the **BLINCS** (`BLINCS-128-A2`) stateless hash-based signature algorithm on BLAKE3, accompanied by standalone `#![no_std]` verifier crate `crates/signet-verify` and independent Python and TypeScript references, following Servil Software Factory engineering practices.

## Repository layout

```text
SPEC.md                 Normative byte-level specification for BLINCS-128-A2
DESIGN.md               Rationale for every design decision (`12+7+7+7` S-WOTS+Z + U-PORS Octopus)
BENCHMARKS.md           SLH-DSA-B 1-core reproduction, Signet comparison, and clocks wall/cycle tables
QUALITY.md              Verification layers, mutation testing, reproduction commands, and known gaps
SECURITY.md             Threat model, operational boundaries, and reporting
src/
  lib.rs                Public API (Signet, SignetId, Imprint, ImprintRef, Context, InvalidImprint, VerifyError)
  params.rs             Suite constants (BLINCS-128-A2), 11 contexts, 8 tweak kinds, LeafAddr, Layer, key helpers
  coding.rs             Closed-form U-PORS hexagon unranking (L_42(3, 24)) & cached Sperner unranking (L_468(24, 40))
  content.rs            Single-pass salted BLAKE3 content hashing (framed Context, slices & streaming Sink)
  few_time.rs           U-PORS Octopus few-time signatures (height-10 tree, k=10, m_max=44, FewSelect/FewCode, zero-alloc verify)
  one_time.rs           S-WOTS+Z (n=24, w=40, S=468, z=8), 128 KiB tiled top tree, 12,288-chain SIMD super-wave, zero-alloc verify
  randomness.rs         Lock-free atomic 32-byte state file (create, initialize) and in-memory draws
  test.rs               Unit tests, intermediate KATs, reference/edge vector checks, fuzzing, negative tests
crates/
  signet-verify/        Standalone #![no_std], zero-alloc, zero-ROM verifier (O(S) boxcar deconvolution + hexagon unranking)
wasm-test/              Freestanding wasm32-unknown-unknown verification harness (0 imports, Node 24)
tests/
  integration.rs        Public API tests and live Python cross-verification
reference/
  blake3.py             From-spec pure-Python BLAKE3 (35 official test vectors)
  blincs.py             Independent pure-Python reference implementation (educational / vectors only)
  blincs.ts             Educational spec-only TypeScript verifier (live-verified under Node 24)
test_vectors/           Checked-in primary & edge-case reference imprints (SHA-256 + BLAKE3 recorded)
tools/
  require_nextest.rs    Sentinel test failing plain `cargo test`
  cargo_lock_hashsets.py BLAKE3 + SHA-256 hashset verification over Cargo.lock
  controls.py           20 planted-fault controls (executed inside a disposable copy)
  counts.py             Shipped-code safety counts (0 unsafe, 0 debug_assert!, 0 truncation allows, 0 Drop)
  domain_sep.py         Static SPEC-table & dynamic domain-separation / tweak-uniqueness check
  optimize.py           Reproducible exact combinatorial & hypergeometric DP security checker
  mutants/              cargo-mutants runner and known-survivors list
  land.py               Exact-commit landing gate
bench/                  Standalone benchmark crate using bench-hashes' `clocks`
audits/                 Unedited cross-family review reports
```

## Engineering practices

- **Simplicity:** prefer one clear mechanism with the fewest runtime cases and fewest new concepts. Every piece earns its place.
- **Design by Contract:** document preconditions and fail stop on broken invariants; avoid defensive fallback modes that hide bugs.
- **Crash-only:** zero explicit `Drop` implementations and no shutdown hooks; verification uses only stack buffers (zero heap allocation).
- **Zero `unsafe`:** both `signet` and `signet-verify` enforce `#![forbid(unsafe_code)]`.
- **Terminology:** the algorithm is **BLINCS (`BLINCS-128-A2`)**; this codebase/crate is **Signet (`signet`)**; call the 32-byte secret bearer object a **signet** (`Signet`), its 32-byte self-certifying identifier a **signet ID** (`SignetId`) — never "public key" — and the 3,292-byte proof an **imprint** (`Imprint`).
- **Two hashes:** whenever recording or checking a file digest, record both SHA-256 and BLAKE3.
- **Measurement:** time changes with `bench/` (`clocks`: wall time, core cycles, clock speed, and background load together).

## Gates before landing a commit

Install [`cargo-nextest`](https://nexte.st) (and `cargo-mutants` for the mutation gate), then run:

```sh
python3 tools/land.py
python3 tools/mutants/check.py
```

`tools/land.py` checks a clean working tree, `reference/blake3.py`, `tools/optimize.py --check`, `tools/counts.py`, `tools/domain_sep.py`, checked-in test vector SHA-256 and BLAKE3 digests + Python `-O` validation + live Node 24 `reference/blincs.ts` verification, `Cargo.lock` hashsets, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, `cargo nextest run --workspace --locked`, `cargo test --workspace --doc --locked`, `cargo package --locked` for both `signet` and `signet-verify`, freestanding `wasm32-unknown-unknown` build & execution (`wasm-test/run_wasm.mjs`), and all 20 planted-fault controls in `tools/controls.py`.

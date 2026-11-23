# How BLINCS protects your results

BLINCS computes signatures matching [`SPEC.md`](SPEC.md) with zero `unsafe` Rust and one runtime dependency (`blake3-servil-core = "=0.10.0"`). When a check detects a broken contract, the process stops rather than returning a silently broken signature.

## What we check

| Layer | How we check it | What remains outside it |
|---|---|---|
| Byte-level specification conformance | An independent pure-Python implementation ([`reference/blincs.py`](reference/blincs.py)) with its own from-spec BLAKE3 ([`reference/blake3.py`](reference/blake3.py), verified against all 35 official BLAKE3 test vectors in three modes) cross-checks the Rust crate in both directions: Rust reproduces `test_vectors/reference-signature-1.bin` byte for byte, and Python verifies Rust signatures across empty, small, 64 KiB, and 512 KiB+ messages. | Shared misunderstandings present in both `SPEC.md` and the two implementations. |
| Memory safety & trusted base | `#![forbid(unsafe_code)]` across the entire crate. One runtime dependency (`blake3-servil-core = "=0.10.0"`, 10 crates total in `Cargo.lock`, all SHA-256 checksummed from crates.io) and zero dev-dependencies. | Safety and correctness of `blake3-servil-core` and its assembly kernels (separately checked by BLAKE3-Servil's own symbolic proofs and tests). |
| Verifier checks & planted-fault controls | Unit tests exercise every rejection predicate individually (threshold zero bits, duplicate leaves, merged set boundary `103` vs. `104`, trailing zero padding, WOTS+C zero byte, exact digit sum `371`/`372`/`373`, every signature region flipped bit-by-bit, wrong verifying key, wrong length). [`tools/controls.py`](tools/controls.py) removes 16 protections one by one and requires a failing test for every single one. | Predicates not listed in `tools/controls.py`. |
| Streaming I/O & buffer isolation | Tests verify slice-vs-reader equivalence across 12 length boundaries (`0` through `1 MiB + 19`) spanning the on-core stack fast path ($\le 64$ KiB), the zero-copy `Pipeline` streaming path ($> 64$ KiB), and the multi-core slice threshold ($\ge 512$ KiB), with fragmented reads, `EINTR` injection, mid-stream `Pipeline::abort` recovery, strict no-read-after-EOF checks, re-entrant `Read` callbacks, and no shared cross-caller buffer pool (zero `Drop` implementations). | Non-conforming `Read` implementations that report reading more bytes than the slice capacity. |
| Authenticated top-tree cache | `top_tree_cache_save_load_and_tamper_rejection` verifies atomic save/reload (`0600` mode, bare relative path), identical signatures, missing-file `NotFound`, and `InvalidData` rejection of wrong seeds, bad magic, flipped MAC/node bytes, truncation, and trailing bytes. | Filesystem-level silent corruption outside a cache reload. |
| Startup randomness state | Tests check explicit `create` (refuses overwrite, `0o600` on Unix, distinct OS seeds), `initialize` (rejects missing, short, oversized-with-valid-magic, wrong-magic, and counter-exhausted files without modifying a byte; serializes 8 concurrent threads under `flock`), monotonic clock progress, `mix` exact cross-check against Python, and draw counter exhaustion. | Filesystems without working advisory locks, untracked symlinks in untrusted directories, live process `fork()` or VM snapshot cloning (callers must re-run `initialize`). |
| Process isolation (`cargo-nextest`) | Every test runs in its own process via `cargo-nextest` (`.config/nextest.toml`). Plain `cargo test` fails immediately on the sentinel test `aaa_require_nextest`. Separate fresh-process tests verify each entry point initializes `blake3-servil-core`. | Doc examples run under `cargo test --doc` (rustdoc already isolates each example in its own process). |
| Mutation testing | [`tools/mutants/check.py`](tools/mutants/check.py) runs `cargo-mutants` in `[profile.mutants]` (release optimization, no debug assertions or overflow checks) across all of `src/`. Every viable mutant must be caught by a test or justified in [`tools/mutants/known.txt`](tools/mutants/known.txt); timeouts and stale known entries both fail the gate. Current score: 606 caught, 6 known equivalent/unobservable survivors, 0 timeouts. | Mutants equivalent to valid behavior or only observable across power loss (the 6 entries in `tools/mutants/known.txt`). |
| Self-check on signing | `SigningKey::sign` and `sign_reader` run `VerifyingKey::verify_short` over every finished signature before returning it (~33 µs, ~0.2% of signing time) and panic on mismatch. | External stream corruption before hashing; hardware faults that corrupt both signing and self-verification symmetrically. |
| Performance measurements | [`bench/`](bench/) measures wall time, core cycles, instructions, clock frequency, and background CPU load together via `bench-hashes`'s `clocks` crate, summarizing runs in exact integers. | Machines other than those explicitly reported; thermal or host interference on non-dedicated hardware. |
| Cross-family contract review | Round 1 formal contract and specification review by `openai/gpt-6.2-astra-pro` archived unedited in [`audits/2026-11-23-gpt-6.2-astra-pro-round1.md`](audits/2026-11-23-gpt-6.2-astra-pro-round1.md); every concrete code, test, and specification finding fixed and covered by regression tests. | Independent human cryptographic review and formal security proof of the full BLINCS instantiation (not yet performed). |

## Reproduction commands

```sh
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo nextest run --locked
cargo test --doc --locked
python3 reference/blake3.py
python3 tools/controls.py
python3 tools/mutants/check.py
python3 tools/land.py
```

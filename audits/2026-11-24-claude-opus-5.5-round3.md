# Independent Contract-Extraction Review — Round 3 (Anthropic Claude Opus 5.5)

- **Date:** 2026-11-24 UTC
- **Reviewer model:** `anthropic/claude-opus-5.5` (via OpenRouter, reasoning effort `high`, third independent model family distinct from the `google/gemini-4-neon` author and the `openai/gpt-6.2-astra-pro` Round 1–2 auditor)
- **Audited commit:** `e1d6c882f0e33c2cec6000448bf3b50c09f376b8` (`12 + 3×7`, 1,100 shipped Rust code lines, 7 modules, `#![forbid(unsafe_code)]`)
- **Methodology:**
  1. **Recall calibration (before auditing):** Ran the neutral contract-extraction brief on a copy of `e1d6c88` containing 3 planted defects (unmasked `LeafAddr::from_digest_word`, omitted serialized-salt check in `verify_short`, omitted `buf[filled..].fill(0)` in `fill_buf`), without stating that bugs were planted or asserting any property of the code. **Measured recall: 3/3 (100%)**, plus a bonus contract tightening on `Pos::new`.
  2. **Clean-tree contract-extraction audit:** Ran the same brief against exact commit `e1d6c88`.
  3. **Blind spec-only TypeScript test:** Provided *only* `SPEC.md` (zero Rust/Python code, zero test vectors) to `anthropic/claude-opus-5.5` to implement a zero-dependency TypeScript BLAKE3 + BLINCS verifier (`201` lines, executed on Node 24.22.3). All test vectors (`verify`, negative `verify`, `mix`, `draw`) passed byte-for-byte on the first run.
- **Note:** This is an automated AI review, not an independent human cryptographic audit. Each section below is archived verbatim.

---

## Part 1 — Clean-Tree Contract-Extraction Audit (`e1d6c88`, verbatim)

# BLINCS security, conformance, and contract review

**Commit:** `e1d6c882f0e33c2cec6000448bf3b50c09f376b8`
**Scope:** `Cargo.toml`, `SPEC.md`, and `src/{lib,params,one_time,few_time,content,randomness,pool}.rs` as supplied.
**Method:** Manual source review against `SPEC.md`. No code was executed. `blake3-servil` was treated as an opaque dependency.

## Summary

- **No Critical, High, or Medium findings.** Byte-level conformance with `SPEC.md` checks out for all tweaks, key derivations, digest parsing, WOTS+, FORS, hypertree addressing, and signature layout. No secret value steers a branch or memory index in BLINCS's own Rust code.
- **5 Low findings:**
  - liveness of the worker pool;
  - inconsistent panic/abort behaviour;
  - a missing `#[must_use]` on the verification verdict;
  - state-file hardening;
  - the OS entropy source.
- **14 Informational findings.** Most cover spec wording, platform scope, resources, packaging, and residual dependency risk.

---

## 1. Findings

### L-1 (Low): Worker death or a `fork()` child leaves the signing caller blocked forever

- **File / symbol:** `src/pool.rs`, `Pool::new` (worker closure) and `Pool::run`.
- **Violated contract:** The pool's liveness invariant, "each of `n_workers` live workers decrements `remaining_workers` exactly once per generation."
  - Only `wave.drain` is inside `catch_unwind`.
  - A panic anywhere else in a worker kills that thread silently. Examples: `ensure_init()` before the loop, or a `lock().unwrap()` on a poisoned mutex.
  - The dead worker never decrements, so `run` spins forever in `while guard.remaining_workers > 0 { done.wait(..) }`.
  - The `fork()` case is the same. The child inherits an initialized `POOL` with `n_workers > 0` but no threads.
- **Concrete triggers:**
  - `blake3_servil::initialize_multithreaded` panics inside a freshly spawned worker. The first keygen or sign hangs permanently.
  - A process forks without `exec` after any signing. The child's first `SigningKey::from_seed` or `sign` hangs. This case is documented as unsupported, but nothing detects it.
- **Impact:**
  - The hung caller keeps holding `dispatch`, so every later caller silently degrades to serial execution.
  - The hung request never completes. This is a denial of service, not a key compromise.
- **Fix:**
  - Wrap the whole worker body (including `ensure_init` and `WorkerScratch::new`) in `catch_unwind(..).unwrap_or_else(|_| abort())`, consistent with the crash-only design.
  - Alternatively, decrement through a drop guard.
  - Record `std::process::id()` in `Pool`. If it differs in `run`, fall back to `with_caller_scratch(|ws| wave.drain(true, ws))`.

### L-2 (Low): Panic semantics depend on contention, and the library can abort the host process

- **File / symbol:** `src/pool.rs`, `Pool::run` and the worker loop.
- **Violated contract:** Consistent fail-stop behaviour.
  - On the main path, a panic in any task (caller or worker) calls `std::process::abort()`.
  - On the fallback paths (`n_workers == 0`, or `dispatch.try_lock()` fails because another thread is signing), the same panic unwinds normally to the caller.
- **Concrete trigger:** An internal `assert!` fires inside a task. Examples: `Pos::new`, `build_fors_tree`, `advance_chains`, or an allocation-related panic. Whether the host survives depends on whether another thread happened to be signing at that moment.
- **Impact:**
  - Behaviour is not reproducible.
  - A library-initiated `abort()` kills a whole server, with no chance for `catch_unwind` or graceful shutdown.
- **Fix (either):**
  - Always abort, by wrapping the fallback drains the same way.
  - Preferably, catch the panic payload in workers, still decrement `remaining_workers`, store the payload in `PoolState`, and have the caller `resume_unwind` after the wave completes.

### L-3 (Low): The verification verdict is a bare `bool` without `#[must_use]`

- **File / symbol:** `src/lib.rs`, `VerifyingKey::verify` and `VerifyingKey::verify_reader`.
- **Violated contract:** A misuse-resistant API. The crate's `unused_must_use = "deny"` lint only protects its own code.
- **Concrete triggers** (both compile without warning):
  ```rust
  vk.verify_reader(file, &sig)?;   // `?` consumes the Result; the inner `false` is silently discarded
  vk.verify(msg, &sig);            // statement-position bool, no warning
  ```
  Either way, a forged signature is accepted.
- **Fix:**
  - Add `#[must_use = "signature verification result must be checked"]` to both methods. Consider adding it to `sign`, `sign_reader`, and `Signature::from_bytes` as well.
  - Optionally offer a `Result<(), VerifyError>` API.

### L-4 (Low): `Randomness::initialize` opens the path before validating it and never checks permissions or owner

- **File / symbol:** `src/randomness.rs`, `Randomness::initialize`.
- **Violated contract:** The spec's precondition: "state file in a private local directory owned by the signer."
  - The path is opened `O_RDWR`, following symlinks and without `O_NONBLOCK` or `O_NOCTTY`, before `is_file()` is checked.
  - The mode and owner are never inspected.
- **Concrete triggers:**
  1. The state file is group- or world-writable, for example provisioned by other tooling.
     - Another local user writes `count = u64::MAX`. Every later `initialize` returns "counter exhausted", a denial of service.
     - That user can also overwrite the seed. This does not by itself predict `run_key`, because fresh `/dev/urandom` output is mixed in.
  2. The path, or a symlink it follows, points at a device or tty. The device is opened read-write, with open-time side effects, before the type check rejects it.
- **Fix:**
  - Open with `custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)`, or at least `O_NONBLOCK | O_NOCTTY` if symlink-following is kept as documented.
  - After open, check `metadata.mode() & 0o077 == 0`. Optionally compare `metadata.uid()` with the effective uid.
  - Reject the file otherwise.

### L-5 (Low): `/dev/urandom` instead of `getrandom(2)` for seed creation and remixing

- **File / symbol:** `src/randomness.rs`, `read_os_randomness`, used by `Randomness::create` and `Randomness::initialize`.
- **Violated contract:** Fresh, full-entropy `os_bytes`. On Linux before 5.18, `/dev/urandom` returns output before the CRNG is seeded.
- **Concrete triggers:**
  - `Randomness::create` runs during early boot of a freshly cloned VM image or minimal container, which is a common provisioning pattern. The state file seed is then generated from an uninitialized pool.
  - `/dev` is absent in a chroot, or bind-mounted to an attacker-controlled regular file. The `File::open` call does not check for a character device.
- **Fix:**
  - Use the `getrandom` syscall: the `getrandom` crate, or `std::random` once stable. This blocks until the pool is seeded.
  - Otherwise, `fstat` the opened file and require a character device.

---

### Informational findings

| ID | File / symbol | Observation | Suggestion |
|---|---|---|---|
| I-1 | `SPEC.md`, FORS section | "The FORS root compresses all 16 tree roots (`height = 10`, `index = 0`)" reads as tweak fields `a=10, b=0`. The formula, and the code in `few_time.rs::fors_root`, use `tweak(FEW_ROOT, 0, leaf_addr, 0, 0, 0)`, i.e. `a = 0`. | Reword to "(each `root_t` is node `(t, 10, 0)`)" so independent implementers cannot diverge. |
| I-2 | `lib.rs` crate docs | The crate doc says "stateless post-quantum digital signatures". `SPEC.md` claims only a 128-bit *classical* target and explicitly gives no quantum proof. | Align the claims, e.g. "hash-based, intended for post-quantum use; see SPEC.md for the classical security target and limits". |
| I-3 | `lib.rs`, `finish_signature` | The top layer signs with `self.top_tree` (tree 0) without asserting that `coords[3].0 == 0`. This holds only because `LeafAddr` masks to 33 bits, and the self-check would catch a violation. `Pos::new` likewise does not enforce per-layer tree ranges. | Add `assert_eq!(top_tree_idx, 0)` as cheap defense in depth. |
| I-4 | `lib.rs`, `finish_signature` | A self-verification failure is `assert!`, i.e. a panic, even from `sign_reader`, which returns `io::Result`. This is fail-stop and correct, since the faulty signature is never released. | Consider a distinct error variant so services can alert and retry instead of unwinding. |
| I-5 | `content.rs`, `content_from_reader` error path | After `pipe.abort(msg)`, the loop waits for *any* event and discards it without checking that it is the abort acknowledgement. Non-blocking readers (`WouldBlock`) are treated as hard errors. Both fail closed. | Match the abort event explicitly and `panic!` otherwise. Document the blocking-reader requirement. |
| I-6 | `randomness.rs`, `initialize` | No `fsync`, by design and documented. After power loss, the next `initialize` reuses the same `(seed, new_count)`, and freshness rests entirely on `/dev/urandom` plus the clock. `read_monotonic_clock` uses `assert!`, which panics, rather than returning `io::Error`. | Return an error instead of asserting. Consider an optional `sync_data` mode. |
| I-7 | `randomness.rs`, `create` | Not atomic: it can leave a partial file. This fails closed, because `initialize` rejects any length other than 48. It is also unlocked. Both are documented. | Write to a temp file, `fsync`, then `link`/`renameat2(RENAME_NOREPLACE)`, and unlink on error. |
| I-8 | `randomness.rs`, platform scope | On non-Unix targets the code compiles. There, `create` fails at the `/dev/urandom` read, and `File::open(parent)` would fail on Windows. `initialize` likewise fails at runtime. | Gate `Randomness` with `#[cfg(unix)]`, or return a clear `Unsupported` error. |
| I-9 | `params.rs::ensure_init`, `VerifyingKey::from_bytes` | Verifier-only users get `blake3-servil`'s multithreaded runtime initialized. The spec's statement "no OS filesystem dependency" is true, but there is a threading dependency, which matters for wasm and no-thread targets. | Document this, or use a single-thread initialization path for verification. |
| I-10 | `pool.rs`, resources | Each thread that ever signs retains roughly 240 KiB of `WorkerScratch`, containing leaf secrets, for its lifetime. This is documented, but it grows linearly in thread-per-request servers. Other costs: about 16 KiB FORS `nodes` on worker and caller stacks plus a 16 KiB reader buffer, with workers on the default stack size; a fresh 32-room `Pipeline` allocation per streamed call; and fully serial execution for contended concurrent signers. | Set an explicit worker stack size. Document the peak memory and stack per signing thread. |
| I-11 | `lib.rs`, API | `SigningKey::seed()` exposes the raw seed. `SecretKey: Copy` spreads copies into wave closures, as documented. The doc example uses the constant seed `[0x42; 32]`, and there is no `generate()` helper. | Add `SigningKey::generate()` from OS randomness. Mark the example seed as "never do this". |
| I-12 | `Cargo.toml` | No `rust-version`, while the code uses recent std APIs: `File::lock` (1.89), `is_multiple_of` (1.87), `AtomicU64::try_update` (recent stabilization), and edition 2024. | Declare `rust-version`. |
| I-13 | `Cargo.toml` | `TGPPL-1.0` is not an SPDX identifier, so crates.io may reject the license expression. The BOSL option exists only in a comment. | Use `license-file` or a valid SPDX expression. |
| I-14 | `Cargo.toml`, dependency | The only dependency, `blake3-servil = "=0.10.0"`, is a non-reference BLAKE3 implementation with its own SIMD/SME2 kernels, threading, and pipeline. `#![forbid(unsafe_code)]` does not extend to it. All correctness and constant-time properties rest on it, and the exact pin blocks downstream semver patch fixes. | Keep vector tests against the reference `blake3` crate across every code path (see Residual limits). Use `~0.10.0` once trust is established. |

---

## 2. Type invariants and trait checks

| Type | Invariant | Construction / operations | Traits | Verdict |
|---|---|---|---|---|
| `SigningKey` | All fields deterministically derived from `seed` per the spec. `top_tree` is the 1-indexed heap of tree `(3, 0)`, with `top_tree[1] == vk.root`. | `from_seed` is the only constructor. Fields are private and never mutated. | No `Clone`, `Copy`, or `PartialEq` (good). `Debug` prints only the verifying key. Auto `Send + Sync`. No zeroization (documented). | Holds |
| `VerifyingKey` | `public_key = Derive(PUBLIC_HASH, bytes[..16])` and `content_key = Derive(CONTENT, bytes)`. | The sole constructor is `from_bytes`, also reached via `TryFrom`, which requires exactly 32 bytes. | `Copy`/`Eq` over all fields is equivalent to equality of `bytes`, since the other fields are pure functions of them. `Debug` prints public hex. | Holds |
| `Signature` | Any 5,616 bytes. The verifier consumes **every** byte: e, R, 16×11 FORS nodes, and 4 layers. There is no unbound padding, so no trivial malleability. | `from_bytes`; `TryFrom` requires an exact length. Accessors use offsets from `Layer`. | Derived `Eq` is not constant-time, but the data is public. `Debug` prints only the salt. | Holds |
| `Randomness` | `run_key` is secret. `count` is monotone, takes values `0..u64::MAX`, and never wraps (`try_update` with `checked_add`, then `expect`). | `initialize` only; `from_run_key_at` is `cfg(test)`. `draw` is `pub(crate)`. | Not `Clone` (prevents stream duplication; good). `Debug` is redacted. Auto `Send + Sync`. `Relaxed` ordering suffices for a read-modify-write uniqueness counter. | Holds |
| `SecretKey` | `K_sec = Derive(SECRET_VALUES, seed)`. | `derive` and `hasher` only. | `Copy`, which is documented. No `Debug` or `PartialEq`. `pub(crate)`. | Holds |
| `PublicKey` | `K_pub = Derive(PUBLIC_HASH, pk_seed)`. | `from_seed`, `hasher`, `keyed`. | `Copy`, `Eq`. | Holds |
| `LeafAddr` | Value is below `2^33`. | The sole constructor, `from_digest_word`, applies the mask. `split_layers` gives a top-tree index of 0 and all leaves below their layer's `leaves()`. | `Copy`, `Eq`. | Holds |
| `Layer` | A closed enum of 4 values. | Heights 7/7/7/12. Offsets 2848/3520/4192/4864. Lengths 672×3 + 752, totalling 5616. | `Copy`, `Eq`. | Holds |
| `Pos` | `tree < 2^48` and `leaf < layer.leaves()`, both asserted. Per-layer tree range is not enforced (I-3). | Every chunk builder also asserts `leaf + count <= leaves`. | `Copy`. | Holds (weak form) |
| `Pool` | At most one dispatched wave at a time. `active` is `Some` during a wave. Every live worker decrements once per generation. | Generation and `remaining_workers` are updated under a single mutex. `while` loops guard both condvars. | Effectively `Sync` via `Mutex`/`Condvar`/`Arc`. Lives in a `static OnceLock`. | Holds, except worker death and fork (L-1) |

### Pool handshake analysis

- **No lost wakeups.** Both predicates are checked and updated under the same mutex.
- **Spurious wakeups are handled.** Every wait sits inside a `while` loop.
- **No skipped generation or `remaining_workers` underflow.** The caller waits for every worker before releasing `dispatch`, so no worker can see two generations in one wave.
- **Partial spawn is handled.** `n_workers = spawned`.
- **Every slot is filled.** A worker decrements only after `drain` returns. The `slots` mutexes publish results.
- **Contention falls back to correct serial execution.**
- **No `RefCell` re-entrancy.** No path calls `parallel_collect` or `with_*` while the same thread-local is borrowed. In particular, the self-check runs outside `with_caller_scratch`.

---

## 3. Verified areas

### Byte-level conformance (`SPEC.md` vs `src/`)

- **Tweak layout:** `kind ‖ layer ‖ tree (6 bytes LE) ‖ leaf (u16 LE) ‖ a (u16 LE) ‖ b (u32 LE)`, with `tree < 2^48` asserted.
- **Tweak usage per kind:**

  | Kind | Code |
  |---|---|
  | `CHAIN_SECRET` | `(L, T, leaf, c, 0)` |
  | `CHAIN` | `(…, c, step)`, where the first hash uses `start` and later hashes use `start + k`. The fixed tweak prefix stays valid because the slot-to-chain mapping is stable. |
  | `ONE_TIME_KEY` | `(…, leaf, 0, 0)` followed by 560 bytes |
  | `NODE` | `(L, T, 0, level, index)` |
  | `FEW_*` | `tree = leaf_addr`, `leaf = t`, `a = height`, `b = i` or `index` |
  | `FEW_ROOT` | `(0, leaf_addr, 0, 0, 0)` |
  | `MESSAGE` | all-zero fields; the full 32-byte output is used |

- **Key derivation:**
  - All nine context strings match the spec exactly.
  - `pk_seed` is the first 16 bytes of the derived output.
  - `K_pub` is derived from `pk_seed`, and `K_content` from the full 32-byte `vk`.
  - `e = Keyed(K_salt, draw)[..16]`, `K_msg = Keyed(K_content, e)`, `R = Keyed(K_R, short)[..16]`, and `D` is computed over `tweak ‖ R ‖ root ‖ short`.
  - Each key is used with only one role, so domain separation holds.
- **Digest parsing:**
  - Four 5-byte LE groups yield `idx[4g + j] = bits[40g + 10j ..]`, equivalent to `u160_le >> 10t`.
  - `leaf_addr = u64_le(D[20..28]) & (2^33 − 1)`.
  - The FORS bits and hypertree bits do not overlap.
- **WOTS+ encoding:**
  - The low nibble comes first.
  - The checksum is `Σ(15 − d)`, at most 480 and computed in `u16`.
  - The three checksum nibbles are little-endian.
  - The signer advances chains `0 → d`; the verifier advances `d → 15`.
  - The chain-batching sort uses only public digits.
- **FORS:**
  - Packing is the secret followed by 10 siblings, bottom first, with a stride of 176 bytes.
  - `auth[level-1]` is captured before compression.
  - The verifier's left/right choice by `idx & 1`, followed by `idx >>= 1`, is equivalent to the spec's rule.
- **Hypertree:**
  - The heap uses 1-indexed children `2i, 2i+1`, and the auth path takes `cursor ^ 1`.
  - `split_layers` matches the spec's `leaf/tree/addr = tree` recursion. The top tree index is always 0.
  - The final root comparison covers all 16 bytes.
- **Signature layout:** The offsets in `Layer::sig_offset` and `Signature` accessors match the spec table exactly. The total length of 5,616 bytes is checked by a `const` assertion.

### Verification soundness

- Every signature byte is bound by a hash, including both `e` and `R`.
- The message is bound through `K_content`, which covers the full `vk`, and `D` binds `root` and `K_pub`.
- No input can make the verifier panic:
  - digits are always ≤ 15;
  - indices are always below 1024;
  - `Pos` assertions always hold for parsed coordinates;
  - slice lengths are fixed.
- Reader errors are returned as `Err` rather than `false`.

### Signing self-verification

- The assembled signature is re-verified via `verify_short` with an independently recomputed `D` (`TreeHasher` versus `convenience`).
- Faults in `D`, the FORS trees, the lower heaps, chain values, or the cached `top_tree` all cause rejection, and the faulty signature is withheld. This defeats grafting-style WOTS+ fault attacks.
- Each WOTS+ position only ever signs a deterministic node (the FORS root or subtree root), which preserves statelessness.
- Content-hash faults are not covered, as the spec documents.

### Streaming I/O

- Every buffer region a reader can see is zeroed before `read`, including the room tail beyond the 16 KiB seed.
- `Interrupted` is retried.
- `n > len` from a misbehaving reader is asserted.
- The total length is checked with `checked_add`.
- A stream of exactly 16,384 bytes takes the pipeline path, consistent with the spec's "≥ 16 KiB" rule.
- A zero-byte final room is not committed.
- Errors abort the pipeline and return before any signing.

### Randomness lifecycle

- `create` uses `create_new` and fails on any existing path, including a symlink. It applies mode `0600`, and syncs the file and its parent.
- `initialize`:
  - checks `is_file` on the opened descriptor and takes a blocking exclusive `flock`;
  - reads up to 49 bytes to enforce an exact length of 48 and checks the magic;
  - uses a checked counter increment;
  - mixes in the order `seed ‖ count ‖ os ‖ clock`, with the variable-length clock bytes last so the encoding is injective;
  - writes bytes `8..48`.
- The lock is released when the descriptor is dropped, on every path.
- Draws are unique per instance and never wrap.

### Timing and secret independence

- **Branches and indices:** In all BLINCS Rust code, these depend only on public or soon-to-be-published values: digits of public nodes, `D` and its indices, `leaf_addr`, and the tree and leaf positions.
- **Secret data:** Secret material is only copied or hashed. No branch, sort key, or index is derived from secret material.
- **Comparisons:** `ct_eq_n` is applied only to public data, so it is defense in depth.

### Lints and overflow

- Release builds disable overflow checks, so every arithmetic site was checked by hand and found bounded or checked:
  - `csum`;
  - `starts + step`;
  - `leaf + i`;
  - `filled + n`;
  - the stream total;
  - generation and worker counters.
- The cast lints are consistent with the code's use of `try_from`.

---

## 4. Residual limits

1. **`blake3-servil` is unverified.** I could not check:
   - that `TreeHasher::hash`, `hash_many` (including 576-byte messages), `convenience::hash_with`, `update_multithreaded`, and `Pipeline` all produce identical, standard keyed/derive-key BLAKE3 output;
   - its constant-time behaviour;
   - its handling of `Pipeline` abort and room recycling;
   - the size of `ROOM_LEN`.

   A divergence between the slice path and the reader path would not be caught by the self-check. Test vectors at the boundaries are recommended: 0, 1, 1023, 1024, 16383, 16384, 16385, `ROOM_LEN ± 1`, and 512 KiB ± 1, compared across `sign`, `sign_reader`, `verify`, and `verify_reader` and against the reference `blake3` crate.
2. **Execution and microarchitecture are out of scope.** No tests or mutation runs were executed. Compiler-introduced timing behaviour and microarchitectural side channels were not assessed.
3. **Security estimates were not recomputed.** The FORS cover-probability figures (133.2 / 126.8 / 119.3 / 110.6 bits) are taken from the spec. Multi-user and quantum security are outside the spec's stated claims.
4. **Some guarantees are operational and outside the library's control:**
   - the per-seed budget of 2^32 signatures across copies;
   - VM snapshot and fork discipline;
   - cooperating advisory-lock writers;
   - absence of memory zeroization, which is documented.

---

## Part 2 — Recall Calibration Run (3 planted defects, verbatim)

Planted defects in the temporary copy: (P1) dropped 33-bit mask in `LeafAddr::from_digest_word`, (P2) dropped serialized-salt equality check in `verify_short`, (P3) dropped `buf[filled..].fill(0)` in `content::fill_buf`. All three were detected (F1, F4, F5 below).

# BLINCS security and contract review

## Type invariants

| Type | Invariant |
|---|---|
| `LeafAddr` | Value `< 2^33` (its doc says "Validated 33-bit"). |
| `Pos` | `tree` is in range for its layer: `< 2^26` for L0, `< 2^19` for L1, `< 2^12` for L2, `== 0` for L3. `leaf < layer.leaves()`. |
| `Layer` | Exactly 4 variants; height, offset and length match the SPEC layout. |
| `Signature` | Any 5,616 bytes. Verification must return `bool` and never panic. |
| `VerifyingKey` | `public_key` = Derive(PUBLIC_HASH, `bytes[..16]`) and `content_key` = Derive(CONTENT, `bytes`). |
| `SigningKey` | `top_tree` is the layer‑3, tree‑0 heap for `seed`, and `verifying_key.root == top_tree[1]`. |
| `Randomness` | `(run_key, n)` is never repeated within an instance, and it is not clonable. |
| `Pool` | One wave is dispatched at a time. Every id is executed exactly once before results are collected. |

---

## F1 — CRITICAL: hypertree address is not masked to 33 bits

**Where:** `src/params.rs` `LeafAddr::from_digest_word`, called from `src/few_time.rs` `parse_digest`.

**Contract violated:** SPEC requires `leaf_addr = u64_le(D[20..28]) & ((1<<33)-1)`. The `LeafAddr` doc says "Validated 33-bit". The code does `Self(word)` with no mask and no check.

**Consequences.** `D[20..28]` is pseudorandom, so the effects below occur for essentially every signature:

**Signer (`finish_signature`):**
- `split_layers` yields `coords[0].0 = addr >> 7`, which is up to 57 bits.
  - `Pos::new` asserts `tree < 2^48`, so it fails with probability ≈ 1 − 2⁻⁹.
  - The FORS tasks call `tweak(FewSecret, 0, leaf_addr, …)`, whose assert `tree < 2^48` fails with probability ≈ 1 − 2⁻¹⁶.
- Both panics occur inside `parallel_collect`, where `catch_unwind` → `std::process::abort()`.
- **Result: `SigningKey::sign`/`sign_reader` aborts the whole process** for ~all inputs.
- In the remaining cases, `coords[3].0 = addr >> 33 ≠ 0` unless the upper 31 bits are zero. The top‑layer WOTS+ then uses tree ≠ 0 tweaks while the auth path comes from `self.top_tree` (tree 0). Self‑verification fails and the `assert!` panics.
- **Net: signing succeeds with probability ≈ 2⁻³¹.**

**Verifier (`verify_short` → `fors_verify`):**
- `tweak(FewLeaf, 0, tree = leaf_addr, …)` panics on the `tree < 2^48` assert for ≈ (1 − 2⁻¹⁶) of all signature/message pairs.
- **Trigger:** any 5,616‑byte value passed to `VerifyingKey::verify`. This is a trivial remote panic (DoS) instead of `false`.
- Signatures from a spec‑conformant signer are rejected (panic, or `false` because the tweaks differ).

**Fix:** In `from_digest_word`, compute `word & ((1u64 << HYPER_BITS) - 1)` and add a `debug_assert`.

## F2 — HIGH: `Pos` and the top‑layer path do not enforce per‑layer tree bounds

**Where:** `src/one_time.rs` `Pos::new`; `src/lib.rs` `finish_signature` top‑layer `write_layer_signature(…, &self.top_tree, …)`.

**Contract violated:** `Pos::new` only checks `tree < 2^48`. Nothing asserts that L3 `tree == 0`, or that `self.top_tree` (built for tree 0) matches `top_tree_idx`. `write_layer_signature` accepts any `tree_nodes` of the correct length.

**Trigger:** Any `LeafAddr ≥ 2^33` (F1). Silent misuse is caught only by the final self‑check.

**Fix:** Have `Pos::new` assert `tree >> (33 − Σheights through layer) == 0`. Assert `top_tree_idx == 0` before using `self.top_tree`.

## F3 — MEDIUM: fail‑stop behaviour of `Pool` is inconsistent

**Where:** `src/pool.rs` `Pool::run`.

**The inconsistency:** The same task panic behaves differently depending on the path:

| Path | `catch_unwind`? | Effect of a task panic |
|---|---|---|
| Worker present, multicore, uncontended | Yes | `abort()` |
| `n_workers == 0` (single core, or spawn failure) | No | Unwinds to the caller as a normal panic |
| Contended `dispatch.try_lock()` failure | No | Unwinds to the caller as a normal panic |

**Effects:**
- A deterministic bug (e.g. F1) kills the process on multicore hosts, but is catchable on single‑core or contended paths.
- Applications cannot reason about recovery.
- Any panic inside a signing task turns into process termination, including in servers that isolate requests via `catch_unwind`.

## F4 — MEDIUM: self‑check does not perform the salt check promised by SPEC

**Where:** `src/lib.rs` `finish_signature` → `verify_short`.

**Contract violated:** SPEC ("Self-check on signing") says it "independently check[s] the serialized salt (`sig[..16]`) against `short[..16]`". `verify_short` never reads `signature.salt()`; it only uses the caller‑supplied `short`.

- A regression that serialized a wrong `e` would pass self‑verification.
- The external verifier recomputes `short` from `sig[..16]`, so it would then reject the signature.

**Fix:** In `finish_signature`, compare `ct_eq_n(signature.salt(), &short[..N])`.

## F5 — LOW/MEDIUM: room slices are not zeroed before `Read::read`

**Where:** `src/content.rs` `fill_buf` (doc: "Zero `buf[filled..]`…") and `content_from_reader` (doc and SPEC: "zeroing each room slice before read").

**Contract violated:** No zeroing occurs. `room.bytes_mut()` is passed directly to `reader.read`.

**Effect:** Rooms are recycled within the 32‑room `Pipeline`. A `Read` implementation that inspects its buffer (permitted in safe Rust) sees earlier bytes of the same stream, or whatever `blake3‑servil` leaves in recycled rooms.

**Fix:** Run `slice.fill(0)` before each `read`, or correct the documentation and SPEC.

## F6 — LOW: a misbehaving `Read` panics instead of returning `io::Result`

**Where:** `src/content.rs` `fill_buf`, `assert!(n <= slice.len())`.

**Trigger:** A reader that returns `Ok(n)` with `n > buf.len()`. `verify_reader`/`sign_reader` then panic rather than returning `Err(InvalidData)`. This happens on the caller thread, so the process is not aborted.

## F7 — LOW: build and toolchain note

**Where:** `src/randomness.rs` `draw`.

`AtomicU64::try_update` may not be available on a stable toolchain; I could not confirm its status. If it is unavailable, `fetch_update` has the same semantics. The logic itself is correct:
- The returned `n` takes values `0..u64::MAX`.
- Exhaustion panics, and `Relaxed` is sufficient for an RMW uniqueness counter.

---

## Verified conformant (no finding)

- **Tweaks and domain separation:**
  - Tweak byte layout (kind, layer, LE u48, LE u16 fields, LE u32) and all nine kind values.
  - FORS tweaks (leaf = t, b = i, a = height); NODE tweak with leaf = 0.
- **WOTS+ chains:**
  - `digits` (nibble order and checksum nibbles).
  - `advance_chains` uses `b = start + step` and retires each chain after `end − start` hashes.
  - `build_wots_leaves_chunk` performs exactly 15 chain hashes.
- **Merkle and FORS trees:**
  - Heap indexing and auth‑path extraction (signer `cursor ^ 1`; verifier parent index `index >> 1`).
  - FORS signature packing matches the `fors_verify` stride.
  - FORS indices via 5‑byte groups equal `u160_le >> 10t`.
  - Signature offsets 0/16/32/2848/3520/4192/4864.
- **Key, content and message derivation:**
  - `msg_digest_input` = tweak‖R‖root‖short.
  - Key derivations `K_pub`, `K_content`, `e`, `K_msg`, `R`.
- **Comparison and timing:**
  - Root comparison is constant‑time (`ct_eq_n`).
  - Secret‑indexed accesses (`chosen_leaf`, `cursor`) use only public, digest‑derived indices.
- **Randomness state file:**
  - `mix` input order.
  - `initialize`: length/magic check (reads 49 bytes, requires 48), `flock` serialization, overflow check.
- **Information leakage:**
  - `Debug` impls do not leak secrets.
  - `Randomness` and `SigningKey` are not `Clone`.
- **Pool wave protocol:** Generation/`remaining_workers` handshake guarantees every id runs once before collection.

---

## Part 3 — Blind Spec-Only TypeScript Ambiguity Notes (verbatim)

## Ambiguities, underspecified points, and inferred details in `SPEC.md`

1. **BLAKE3 internals are not restated.** The spec relies on external BLAKE3 for the IV, message permutation, flag values (`KEYED_HASH=16`, `DERIVE_KEY_CONTEXT=32`, `DERIVE_KEY_MATERIAL=64`) and the tree merge rule. It also does not say that `Derive` is the standard two-stage construction: hash the context with `DERIVE_KEY_CONTEXT`, then use the result as the key for hashing the material with `DERIVE_KEY_MATERIAL`. I assumed standard BLAKE3 with 32-byte output.

2. **Tweak field mapping per kind.**
   - Most mappings are only implied by the argument positions in each formula.
   - `NODE` explicitly uses `leaf = 0`, and the WOTS+ `a = c` / `b = step` mapping is stated, so I followed both literally.
   - `FEW_LEAF` and `FEW_SECRET` use `a = 0` with `b = i`, and `FEW_NODE` uses `a = height`, `b = index`. As a result, the FORS leaf level (height 0) is distinguished from internal nodes only by the kind byte.

3. **Left/right ordering in the WOTS+ Merkle trees is not stated.** The ordering rule is given only for FORS. I applied the same rule to the hypertree trees: the running value goes on the left when `(leaf >> (level-1)) & 1 == 0`.
   - I also inferred that auth node `j` (0-based) corresponds to tweak `level = j + 1` and `index = leaf >> level`.
   - The same applies to FORS: the parenthetical `height` in `(idx[t] >> height)` is the 0-based height of the child, while the tweak uses `height + 1`.

4. **The FORS root note "(`height = 10`, `index = 0`)" is confusing.** It appears to describe where each per-tree root sits. The `FEW_ROOT` tweak itself uses `a = 0`, `b = 0`, and I followed the formula.

5. **Which bytes are hashed in `D`.** I used the 16-byte `vk[16..32]` as `root`, and `R` taken verbatim from `sig[16..32]`.

6. **Bit and byte order of the index fields.**
   - I treated `u160_le` and `u64_le` as little-endian integers over the stated slices.
   - The 33-bit mask means bits 33–63 of `D[20..28]` are discarded, along with `D[28..32]`.
   - The spec says "upper 63 bits unused", which is consistent with this reading.

7. **Nibble order is stated explicitly** (low nibble first, checksum little-nibble-first). I followed it as written; I list it only because it is BLINCS-specific.

8. **Behaviour on malformed input is not specified.** The spec does not say what to do with a wrong signature length, wrong vk length, or invalid hex. I return `false` and exit 1 for malformed verify input; CLI misuse exits 2.

9. **`mix` count semantics.** The spec hashes `new_count = count + 1`, but the `mix(seed, count, …)` API and the CLI `<count>` do not say whether the caller passes the stored count or `new_count`. I encode the given `count` directly, so the caller is assumed to pass `new_count`.

10. **CLI encodings for `mix` and `draw`.**
    - `clock_bytes` is described as opaque `Instant::hash` output. For the CLI I used the UTF-8 bytes of the argument, as the flag name suggests.
    - `sys_hex` length is unconstrained; the spec says 32 bytes of `/dev/urandom`, but I accept any length.
    - `seed` and `run_key` are required to be exactly 32 bytes.
    - `n` and `count` are decimal u64 values.

11. **Unchecked salt and lack of an `e` consistency check.** The verifier relies only on `e` from the signature; there is no separate check of `e`, since the signer's draw is unavailable to the verifier. The "self-check" section's `short[..16]` comparison applies to the signer only.

12. **Tree field width.** `tree` is a u48, but tree values never exceed 2^26 (2^33 >> 7). Encoding was by straightforward little-endian bytes.

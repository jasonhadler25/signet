# BLINCS design rationale

This document records **why** BLINCS is shaped the way it is: the threat model, the "minimax" parameter strategy, the published optimizations we adopted or declined, the salted two-pass streaming content hash, the startup-only signer randomness, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md).

---

## 1. Goals and threat model

BLINCS is designed for a dishonest submitter who does **not** hold the signing key, interacting with an honest signer and honest verifiers. The attacker may:

- observe up to $2^{33}$ signatures and trigger the honest signer to sign messages the signer approves,
- possess a structural weakness in BLAKE3 that produces **collisions** cheaply without yielding **second preimages**, and
- spend enormous classical compute (a 128-bit security target; BLAKE3 itself claims 128-bit security).

The design goals that follow:

- **Post-quantum, hash-only assumptions:** security rests on symmetric hash properties of BLAKE3, not lattices, pairings, or factoring.
- **Stateless signing:** a signing key can be copied across machines, restored from backups, or run in short-lived processes (such as `git commit`) without risking catastrophic one-time-key reuse.
- **Short verifying key (32 bytes):** small enough to embed directly in a name or identifier a user already acquires (for example, a repository or branch name).
- **Fixed-size signatures (3,988 bytes):** practical and ergonomic regardless of whether the signed message is 0 bytes or 100 GiB.
- **Minimize unnecessary reliance on collision resistance:** unsalted hashes belong where independent parties must derive the same name without coordinating (content addressing, Git object IDs, hashsets); salted hashes belong where one party vouches for content (signatures).

---

## 2. Why $2^{33}$ signatures at $\ge 128$ bits

The sizing target comes from a concrete ceiling: **10 signatures every second for 20 years** $= 6{,}311{,}520{,}000 \approx 2^{32.56}$ signatures. Rounding up to **$2^{33} = 8{,}589{,}934{,}592$** (27.2 years at 10/s) gives margin while keeping the budget tight enough for compact signatures.

Security degrades gradually if a key overshoots the budget, rather than collapsing at a cliff:

| Signatures signed by one key | PORS+FP cover bound (classical ROM) |
|---:|---:|
| $2^{33}$ (budget) | 128.4 bits |
| $2^{34}$ ($2\times$) | 124.5 bits |
| $2^{35}$ ($4\times$) | 120.0 bits |
| $2^{36}$ ($8\times$) | 114.8 bits |
| $2^{36.5}$ ($11.3\times$) | 112.0 bits |

Changing the budget moves signature size by roughly **7% per factor of 8** in signing limit (at constant signing/verifying speed caps): $2^{30} \to 3{,}732$ B, $2^{33} \to 3{,}988$ B, $2^{36} \to 4{,}280$ B, $2^{40} \to 4{,}584$ B, $2^{48} \to 5{,}196$ B, $2^{64} \to 6{,}900$ B.

---

## 3. The "minimax" strategy for choosing parameters

Stateless hash-based signatures trade off three competing bad dimensions:

1. **Signature size** (bytes in packets, logs, Git commits, certificates, transactions),
2. **Signing time** (latency and throughput per core), and
3. **Verification time** (latency and throughput per core).

Any of those three bad dimensions may have a hard threshold beyond which it excludes the scheme from a real use case — including uses that have not been invented yet (fitting inside a 4 KiB page or record, sustaining 10 signatures/second with headroom on one core, verifying tens of thousands of signatures/second on a server or client). Because we cannot know every future use case's threshold in advance, our strategy is **minimax**:

> Reduce the extent of every bad dimension as far as possible whenever doing so costs only a little in the other dimensions; refuse the extreme corners of the Pareto frontier where one dimension blows up to squeeze out the last few percent in another.

### The measured Pareto ladder ($2^{33}$ signatures, $\ge 128$ bits, plain shapes, single core on Apple M6)

Searching the full parameter space of WOTS+C + PORS+FP with measured single-core BLAKE3-Servil costs yields this frontier (all four hypertree trees built uncached, as in the parameter-search workload):

| Signature | Sign (mean, uncached) | Verify (batched) | Extra bytes to halve sign time | Parameters (`h d v g S b k gf m`) |
|---:|---:|---:|---:|---|
| 3,380 B | 71.0 ms | 98 µs | — | `36 4 17 9 1080 17 9 5 95` |
| 3,700 B | 33.2 ms | 50 µs | +9.5% | `36 4 21 2 849 17 9 5 99` |
| **3,988 B** | **18.7 ms** *(16.2 ms cached)* | **42 µs** *(33 µs on-core)* | **+7.8%** | **`36 4 24 8 372 15 11 6 103`** |
| 4,536 B | 7.6 ms | 42 µs | +13.7% | `35 5 25 3 488 15 12 2 108` |
| 4,984 B | 5.0 ms | 36 µs | +16.9% | `35 5 31 4 233 15 12 2 106` |
| 5,644 B | 2.5 ms | 42 µs | +13.2% | `36 6 31 4 233 13 15 4 112` |
| 7,188 B | 1.4 ms | 57 µs | +33.0% | `32 8 31 4 233 13 20 8 145` |

*(For reference, plain SPHINCS+ at the same $2^{33}$ budget and $\le 19$ ms signing time requires 5,008 B with 733 µs verification or 5,248 B with 57 µs verification.)*

Why **3,988 bytes** sits at the minimax knee:

- **Under 4,096 bytes:** fits inside a single 4 KiB page/block with 108 bytes to spare.
- **Fast signing with headroom:** 16.2 ms on one M6 core (~61 signatures/second, over $6\times$ headroom above 10/s) and tight tail latency (99.9% within 22.1 ms even uncached). Going one rung smaller (3,700 B) saves only 7% in size while increasing signing time by 78% and raising worst-case search variance.
- **Fast verification:** 33 µs on one M6 core (~30,000 verifications/second), achieved at only 0–3% size cost over unrestricted verification time.
- **Balanced cost of going faster:** below 3,988 B, halving signing time costs ~14–33% more bytes per halving and crosses 4 KiB.

---

## 4. Published optimizations: what we adopted and what we declined

### Adopted

1. **WOTS+C in place of WOTS+** (Hülsing, Kudinov, Ronen, Yogev, S&P 2023, eprint 2022/778): drops the checksum chains by searching a 32-bit counter until the 24 five-bit digits sum to a fixed constant (`372`) and the low 8 digest bits are zero. Every valid digit vector has the same sum, so advancing revealed chain values can never reach another valid vector. It shrinks each layer, cuts signer tree work and verifier chain steps, and rests on target-collision resistance rather than collision resistance.
2. **PORS+FP in place of FORS** (Abri & Katz, CRYPTO 2026, eprint 2025/2069): replaces $k$ separate trees with one perfect tree of $2^{15}$ leaves, merges overlapping authentication paths ("Octopus"), and retries a counter until the merged set has at most `m = 103` nodes and `6` threshold bits are zero. By Abri & Katz Theorem 1, filtering on `merged_len <= m` only rejects candidates and never weakens the cover probability.
3. **Plain shapes (equal layer heights and uniform chain lengths):** allowing unequal heights (Qin, Sun, Zheng, eprint 2025/2236) and mixed chain lengths across the search frontier saved 0–100 bytes at most rungs and **0 bytes** at 3,988 B. Keeping one height (`9`) and one chain length (`32`) removes branches, per-layer tables, and edge cases at zero size cost.
4. **256-bit internal message digest `D` before `PICK`:** Abri & Katz's writeup truncates the pre-counter message digest to $n = 128$ bits. Across $q = 2^{33}$ signatures, any of the $2^{33}$ signed digests would be a multi-target match, dropping security to $128 - 33 = 95$ bits. Keeping `D` at BLAKE3's native 256 bits (`>= 128 + 33 = 161` bits) closes that gap at zero wire-byte cost.

### Declined

- **Top of the Hypercube encodings (TSL / TL1C / TLFC, eprint 2025/889):** retry-free constant-sum encodings must fit $2^{128}$ points in one layer, forcing much longer chains (for example, 16 chains of 512+ instead of 256). When retries are acceptable, WOTS+C with a fixed or raised target sum achieves equal or fewer verification hashes on shorter chains.
- **FORS+C:** superseded by PORS+FP, which saves more than twice as many bytes (~544 B vs. ~240 B in Kudinov–Nick's tables) and has a cleaner formal proof.
- **Unreviewed 2026 few-time preprints** (BPORS+FP 2026/1328, BPORS-C+BFP 2026/2374, BGS-CC 2026/2502): each stacks a newer, unreviewed counting argument; left out until settled.
- **Stateful hybrids and preparation schemes** (SHRINCS, SHRIMPS, SPHINCS-PE): reintroduce state synchronization or preparation episodes, giving up statelessness.
- **Format-level top-tree caching:** caching the 16 KiB top tree is purely a local signer optimization in `SigningKey` — zero change to `SPEC.md`, the verifying key, or the signature format.

---

## 5. Salted two-pass content hashing and 256 KiB chunks

### No pre-hash API

BLINCS exposes `sign` / `sign_reader` and `verify` / `verify_reader`, and no entry point accepting a precomputed digest. Pre-hashing exposes callers to collision attacks on the pre-hash; hashing the stream directly inside BLINCS keeps the signature bound to a freshly chosen salt and runs at multi-GB/s BLAKE3 speed.

### Regenerated per-chunk salts (fixed signature size)

A message is split into 256 KiB chunks `M_0, M_1, ...`. After reading `M_0`, the signer computes the 16-byte content salt `e = Keyed(Keyed(K_salt, draw), M_0)[..16]`, carried once in the signature. For each chunk `i`, both signer and verifier compute:

```text
chunk_key_i  = Keyed(K_content, e || u64_le(i) || x_{i-1})
chunk_salt_i = Keyed(chunk_key_i, M_i)
x_i          = Keyed(chunk_salt_i, M_i)
```

Why two passes with a regenerated per-chunk salt instead of the alternatives:

- **Carrying a 16-byte salt per chunk in the signature** makes signature length grow with message size, breaking fixed-size ergonomics.
- **One pass keyed only by `e` and earlier chunks** collapses to a cheap single-pass collision attack on chunk `i >= 1` whenever `e` is known in advance (for example, after a state reset on a shared prefix `M_0`).
- **Two passes per chunk (`Keyed(Keyed(k, m), m)`)** keeps signatures fixed at 3,988 bytes, requires only a single 256 KiB buffer for streaming, reads the external source only once, keeps generic collision resistance at 128 bits over the 256-bit `x_i`, and blocks single-pass structural collision attacks even when `k` is known.

### Why 256 KiB chunks

Published single-threaded `blake3-servil` benchmarks across Intel (Haswell through Alder Lake and Ice Lake Xeon), AMD (Zen 3, Zen 5 EPYC and Ryzen), and Apple Silicon (M4 Max, M6) showed two competing optima:

- **x86-64** peaks near **64 KiB** (16 KiB loses ~30% throughput on AMD Zen 5).
- **Apple Silicon** keeps speeding up past 64 KiB toward **1 MiB** as SME2 per-call setup amortizes.
- **256 KiB** lands within ~12% of peak throughput on every published CPU (measured 3.2–3.5 GB/s end-to-end for two-pass verification on one M6 core), keeps streaming memory at one 256 KiB buffer, and has zero effect on signature size.

---

## 6. Signer randomness: startup-only state without `fsync`

We reviewed the classic PRNG-with-input and seed-file literature (Barak & Halevi 2005; Ferguson, Schneier & Kohno's Fortuna seed-file management; Dodis et al. 2013; Ristenpart & Yilek 2010; Bellare & Tackmann 2016) and kept only what serves BLINCS:

- **Why no per-signature syscall or disk write:** signing at 10–60/s should not pay OS entropy syscalls or storage flushes per signature. `Randomness::initialize` reads the 48-byte state file, 32 bytes from `/dev/urandom`, and the monotonic clock **once** at process startup, mixes them into `(next_seed, run_key)`, updates bytes `8..48` in place under an exclusive `flock`, and then serves every `draw()` from memory via `Keyed(run_key, u64_le(n))`.
- **Why no forward-security ratchet, entropy pools, entropy estimator, or shutdown hook:** those mechanisms protect secret PRNG outputs after a state compromise. In BLINCS, `Randomness` sits beside the signing key in the same process and its only output is the published content salt `e`. What `draw` needs is **non-repetition**, not secrecy — and secrecy of `e` against an external submitter already comes from `K_salt` derived from the caller-supplied signing key.
- **Why caller-supplied signing seed (no OS-RNG `SigningKey::generate`):** on Linux, `/dev/urandom` is non-blocking by ABI at early boot. That gap does not threaten BLINCS's signing salt (because `K_salt` is mixed into every `e`), whereas key generation genuinely needs full entropy. Requiring the caller to supply the 32-byte seed puts key-generation entropy at the boundary that owns it.
- **Why explicit `Randomness::create`:** silently creating a missing state file hides misconfigured paths and risks restarting from empty state; refusing to overwrite (`create_new`) protects existing files.
- **Why monotonic clock (`Instant::hash`):** immune to NTP clock stepping and requires no `unsafe` code or platform FFI dependency; treated strictly as opaque local diversification.
- **Why `initialize` skips `fsync` (while `create` syncs once):**
  - On one-shot signers invoked per commit (such as `git commit`), blocking on `F_FULLFSYNC` adds milliseconds on SSDs and far more on busy or networked storage — and modern disks and VM snapshots can roll back state regardless of `fsync`.
  - Without `fsync`, `write()` still updates the kernel page cache immediately, so back-to-back processes always see the incremented counter and rotated seed; only a crash/power loss before dirty-page flush reverts the file, and on reboot `/dev/urandom` and the monotonic clock still vary `draw`.
  - Even in the worst case — an attacker resets disk, OS RNG, and clock together so `draw` repeats identically — BLINCS never leaks the signing key, never allows WOTS+C reuse or PORS+FP leaf steering (`R = Keyed(K_R, short)`), and keeps messages $\le 256$ KiB at second-preimage resistance. Only multi-chunk messages ($> 256$ KiB) with a probed shared 256 KiB prefix `M_0` downgrade on chunks $\ge 1$, and even then only to known-key collision resistance of the two-pass `Keyed(Keyed(k, m), m)` (still 128 bits generically).

---

## 7. Crash-only design and performance engineering

BLINCS adopts Servil Software Factory's engineering discipline:

- **Crash-only lifecycle:** `Randomness` has no shutdown hook; a sudden crash loses no teardown invariant. Signing and verification workspaces (`SignWorkspace`, `VerifyWorkspace`, `CHUNK_POOL`) are allocated once per thread and kept until process exit, avoiding per-call allocation, page-fault zeroing, and TLB shootdowns.
- **One bounded `Drop` exception (`ChunkLease`):** an independent contract review caught that handing a dirty reused 256 KiB buffer to a later `Read` implementation exposes the previous caller's message bytes, and holding a `RefCell` borrow across `reader.read()` panics if a custom reader calls back into BLINCS. `ChunkLease` leases the buffer out of `CHUNK_POOL` before `read()` (releasing the `RefCell` borrow immediately) and zeroes all 256 KiB on `Drop` before returning it to the single-slot pool.
- **Unrepresentable invalid states & fail-stop contracts:** `SigningKey` holds only one 32-byte seed and derives its verifying key and cached 16 KiB top tree on construction (so an inconsistent `(seed, vk)` pair cannot exist). `SigningKey::sign` and `sign_reader` run `VerifyingKey::verify_short` (~33 µs, 0.2% of signing time) before returning any signature and panic if self-verification fails. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** measuring BLINCS with `bench-hashes`'s `clocks` crate revealed that calling Apple M6's SME2 kernels for verification's tiny 11–24-element batches downclocked the P-core from ~4,787 MHz to ~4,066 MHz and spent ~47k extra cycles entering/exiting streaming mode. Routing verification's tree/chain hashes through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and batching each level of `few_time_verify` cut 64-byte verification from **57.3 µs** to **33.3 µs** (~1.7× faster, ~5.9–6.0 IPC) while keeping large-message content hashing on SME2 at **3.5 GB/s** on one core.
- **Tiny trusted base:** `#![forbid(unsafe_code)]`, one runtime dependency (`blake3-servil-core = "=0.10.0"`), 10 crates total in `Cargo.lock` all verified by SHA-256 checksum, zero dev-dependencies.

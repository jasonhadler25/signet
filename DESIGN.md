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

## 3. Quantitative unknown-thresholds model ("minimax")

Stateless hash-based signatures trade off three competing costs:

1. **Signature size $B$** (bytes in packets, logs, Git commits, certificates, transactions),
2. **Signing time $S$** (latency and throughput per core), and
3. **Verification time $V$** (latency and throughput per core).

Any of those three costs may have a hard threshold beyond which it disqualifies the scheme from some use case — including uses that have not been invented yet. Rather than picking parameters by eye, we formalize this as a reproducible decision model implemented in [`tools/optimize.py`](tools/optimize.py) (standard-library Python, ~1.5 s to run, exact integer retry DP).

### Model: independent log-uniform unknown thresholds

Suppose an unknown future application $U$ can adopt a parameter set $(B, S, V)$ if and only if all three costs fall below its unknown thresholds $(T_B, T_S, T_V)$:

$$B \le T_B \quad \land \quad S \le T_S \quad \land \quad V \le T_V.$$

When a positive threshold's scale is unknown, the scale-invariant (Jeffreys) uninformative prior is **log-uniform**: $\ln T_i \sim \mathrm{Uniform}[\ln L_i, \ln U_i]$, where $U_i$ is the upper usability ceiling past which a scheme is too expensive to consider. For any $x_i \in [L_i, U_i]$, the probability of qualifying in dimension $i$ is $\Pr[T_i \ge x_i] = \ln(U_i / x_i) / \ln(U_i / L_i)$.

Two natural selection rules follow directly:

1. **Maximum joint survival probability (Nash bargaining):**
   $$\arg\max_{(B, S, V)} \Pr[B \le T_B \land S \le T_S \land V \le T_V] = \arg\max_{(B, S, V)} \; \ln\!\left(\frac{U_B}{B}\right) \cdot \ln\!\left(\frac{U_S}{S}\right) \cdot \ln\!\left(\frac{U_V}{V}\right).$$
   Remarkably, **all three lower bounds $L_i$ cancel out identically** (they enter only as constant denominators) and the rule is completely unit-invariant. Only the upper ceilings $(U_B, U_S, U_V)$ enter. Its first-order optimality condition is
   $$\frac{dB / B}{\ln(U_B / B)} + \frac{dS / S}{\ln(U_S / S)} + \frac{dV / V}{\ln(U_V / V)} = 0,$$
   which automatically pays more to shrink whichever cost is closest (in relative headroom) to its ceiling.

2. **Minimax conditional exclusion risk:**
   Conditioning on $T_i \in [x_{i,\min}, U_i]$ (use cases that at least one $2^{33}$ scheme on the frontier can serve), the exclusion risk in dimension $i$ is $e_i(x_i) = \ln(x_i / x_{i,\min}) / \ln(U_i / x_{i,\min})$. Minimizing the worst-case risk across all three dimensions gives:
   $$\arg\min_{(B, S, V)} \; \max\bigl(e_B(B),\, e_S(S),\, e_V(V)\bigr).$$

### What `tools/optimize.py` produces (Apple M6 single-core cached-top-tree model, $2^{33}$ sigs, $\ge 128$ bits)

Running `python3 tools/optimize.py` evaluates exact integer retry counts and builds the 2,115-point plain-shape Pareto frontier in ~1.5 seconds:

| Ceilings $(U_B, U_S, U_V)$ | Rule | Winner (`bytes`, `sign`, `verify`, `keygen`) | Parameters (`h d v w g S b k gf m`) |
|---|---|---|---|
| `(7,856 B [SLH-DSA-128s], 100 ms [10/s], 1,000 µs)` | Max survival | **4,804 B**, 5.77 ms, 20.1 µs, kg 1.42 ms | `32 4 31 16 4 270 15 14 5 127` |
| `(7,856 B [SLH-DSA-128s], 100 ms [10/s], 1,000 µs)` | Minimax risk | **4,536 B**, 5.43 ms, 40.9 µs, kg 1.14 ms | `35 5 25 32 3 387 14 14 0 106` |
| `(7,856 B, 100 ms, 127 µs [SLH-DSA-B-128s])` | Max survival | **4,804 B**, 6.11 ms, 18.8 µs, kg 1.42 ms | `32 4 31 16 4 287 15 14 5 127` |
| `(7,856 B, 100 ms, 127 µs [SLH-DSA-B-128s])` | Minimax risk | **4,740 B**, 6.31 ms, 22.2 µs, kg 1.38 ms | `32 4 30 16 8 225 15 14 5 127` |
| `(5,000 B [compact], 100 ms, 1,000 µs)` | Max survival | **3,940 B**, 16.81 ms, 31.5 µs, kg 4.37 ms | `36 4 24 32 8 382 15 11 6 100` |
| Zero-parameter frontier `[3,284..8,020 B, ...]` | Minimax risk | **4,616 B**, 5.74 ms, 31.9 µs, kg 1.14 ms | `35 5 25 32 3 488 14 14 0 111` |
| Current draft BLINCS `0.1.0` *(for comparison)* | — | **3,988 B**, 16.22 ms *(meas.)*, 33.3 µs *(meas.)*, kg 4.43 ms | `36 4 24 32 8 372 15 11 6 103` |

*(With `3×` multithreaded signing, `--sign-speedup 3.0`, the `(7,856 B, 100 ms, 1,000 µs)` max-survival winner shifts down to `4,468 B` / 3.27 ms / 18.5 µs because extra signing headroom shifts marginal value toward smaller signatures.)*

**Honest note on `0.1.0`'s 3,988-byte set:** our initial `0.1.0` parameters (`3,988 B`, 16.2 ms sign, 33.3 µs verify) were chosen to stay under a single 4 KiB page (4,096 B) while keeping > 6× headroom above 10 signatures/second, which corresponds quantitatively to a compact size ceiling around $U_B \approx 5{,}000$ B (under `U = (5,000 B, 100 ms, 1,000 µs)`, `3,988 B` achieves 97.3% of the optimal survival score). Under the broader FIPS 205 ceiling `U = (7,856 B, 100 ms, 1,000 µs)` — or zero-parameter frontier log-minimax — the quantitative model prefers the **`4,536–4,804 B`** neighborhood (+14–20% bytes for **~3× faster signing** and **~1.6× faster verification**). Because BLINCS is pre-1.0, both options are kept explicitly visible in `tools/optimize.py`.

### Why `m = 103` is not signing-time-bottlenecked in BLINCS (`tools/optimize.py --grinding-sweep`)

In isolation, a PORS+FP merged-set cap of `m = 103` looks aggressive compared to `m = 112` (+144 bytes, 34.6× fewer `PICK` tries). With batched BLAKE3-Servil (`12.6 ns/try` at `GRIND = 2048`), however, `PICK` grinding is only **1.7%** of BLINCS's signing time (80% is in the three XMSS hypertree builds and ~9% in the four WOTS+C counter searches):

| `m` | Signature bytes | Mean `PICK` tries | Reduction vs. `m = 103` | `PICK` time (M6) | Share of total sign time |
|---:|---:|---:|---:|---:|---:|
| 95 | 3,860 B | 1,114,019 | — | 14.04 ms | 46.8% |
| 98 | 3,908 B | 236,222 | — | 2.98 ms | 15.7% |
| 100 | 3,940 B | 88,058 | — | 1.11 ms | 6.5% |
| **103** | **3,988 B** | **21,642** | **1.0×** | **0.27 ms** | **1.7%** |
| 108 | 4,068 B | 2,631 | 8.2× | 0.03 ms | 0.2% |
| 112 | 4,132 B | 626 | 34.6× | 0.008 ms | 0.05% |

Pushing `m` below 100 blows up signing time and tail latency; relaxing `m` from 103 to 112 buys only 0.26 ms (-1.6% total signing time) at the cost of +144 bytes (crossing 4,096 B). On a slower scalar hash (such as SHAKE256 or unbatched SHA-256), `m = 103` would cost noticeably more and `tools/optimize.py --ns-grind ...` shifts `m` upward automatically.

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

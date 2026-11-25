# BLINCS design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of `SPEC.md`, grinding-vs-signing-time feedback, irregular hypertrees + upper-layer caching, SLH-DSA-B with **julienif**, THINCS, CUTS, and the SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree / partial-caching work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil-core`, SPHINCS/SPHINCS+/FIPS 205, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness/hypertree papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** BLINCS is shaped the way it is: the threat model, the $2^{32}$ signature budget, the minimax tradeoff and simplification to **`12 + 3×7` `WOTS+` + `FORS` (`5,616 B`, `128 KiB` top tree, zero counter grinding, zero disk cache, strictly single-threaded `blake3-servil-core`)**, every candidate technique we evaluated and why each was adopted or declined, the single-pass salted content hash, the startup-only signer randomness, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

---

## 1. Goals and threat model

BLINCS is designed for a dishonest submitter who does **not** hold the signing key, interacting with an honest signer and honest verifiers. The attacker may:

- observe up to $2^{32}$ signatures and trigger the honest signer to sign messages the signer approves,
- possess a structural weakness in BLAKE3 that produces **collisions** cheaply without yielding **second preimages**, and
- spend enormous classical compute (a 128-bit security target; BLAKE3 itself claims 128-bit security).

The design goals that follow:

- **Post-quantum, hash-based assumptions:** security rests on symmetric hash properties of BLAKE3 and this SPHINCS-family construction, not lattices, pairings, or factoring.
- **No synchronized one-time signing state:** a signing key can be copied across machines, restored from backups, or run in short-lived processes (such as `git commit`) without XMSS/LMS-style one-time-key reuse.
- **Short verifying key (32 bytes):** small enough to embed directly in a name or identifier a user already acquires (for example, a repository or branch name).
- **Fixed-size signatures (5,616 bytes / 7,488 bytes Base64):** fixed size regardless of whether the signed message is 0 bytes or 100 GiB.
- **Zero counter grinding & WOTS+ / FORS structure:** bounded chain work with no counter-grinding loop, compact specification and code, and WOTS+ + FORS building blocks (BLINCS-specific nibble/tweak encodings and BLAKE3 instantiation; not FIPS 205 interoperable).
- **No on-disk key cache:** cold key derivation builds the 128 KiB top hypertree in `20.53 ms` on 1 Apple M6 core (`23.07 ms` total cold 1-shot sign), eliminating cache file formats, cache authentication, and cache invalidation.
- **Strictly single-threaded execution:** runs entirely on the calling thread via `blake3-servil-core = "=0.11.0"` — zero background thread pools, zero cross-thread shared state, and clean linear scaling when a host application runs multiple signers across its own threads.
- **Minimize unnecessary reliance on collision resistance:** unsalted hashes belong where independent parties must derive the same name without coordinating (content addressing, Git object IDs, hashsets); salted hashes belong where one party vouches for content (signatures).

---

## 2. Why $2^{32}$ signatures at $\ge 128$ bits

The sizing target is one full `u32` of signatures per signing key: **$2^{32} = 4{,}294{,}967{,}296$** (10 signatures every second nonstop for **13.6 years**). Dropping the budget from FIPS 205's $2^{64}$ to $2^{32}$ cuts hypertree height nearly in half (`h = 33` vs. `63`), shrinking signatures 29% below `SLH-DSA-128s` (`5,616 B` vs. `7,856 B`) while signing **48× faster** and verifying **5.9× faster** than single-threaded `SLH-DSA-BLAKE3-128s` on Apple M6.

Under the single-key ideal-hash FORS leaf-cover model (`h = 33`, `k = 16` trees of $2^{10} = 1{,}024$ leaves, checked by `python3 tools/optimize.py --check`), the single-query cover exponent degrades gradually past $2^{32}$ rather than collapsing at a cliff:

| Signatures signed by one key | Single-query FORS cover exponent (ideal-hash model) |
|---:|---:|
| $2^{32}$ (budget, 4.29B) | **133.2 bits** |
| $2^{33}$ ($2\times$, 8.59B) | **126.8 bits** |
| $2^{34}$ ($4\times$, 17.2B) | **119.3 bits** |
| $2^{35}$ ($8\times$, 34.4B) | **110.6 bits** |

*(These values are $-\log_2 P(q)$ for the single-query FORS leaf-cover event under ideal hashes, not a full multi-user or quantum proof of BLINCS; see `SPEC.md#security-target-model-and-limits`.)*

---

## 3. Minimax tradeoff and why `12 + 3×7` won

Stateless hash-based signatures trade off three costs with completely different units:

1. **Signature size $B$** (bytes — packets, commits, headers, certificates, logs),
2. **Signing time $S$** (milliseconds — interactive latency, release pipelines, servers), and
3. **Verification time $V$** (microseconds — high-fanout verifiers, package registries, constrained clients).

Following Ron Rivest's "minimax strategy" ([`docs/history/manifesto.md`](docs/history/manifesto.md)) — *perform well enough for many use cases instead of maximizing one metric to the detriment of others* — we use **Leximin $L_\infty$ ratio above the candidate-family Pareto floor** (`python3 tools/optimize.py`):

1. **Fix the hard requirements first:** $\ge 128$-bit single-query FORS cover exponent at $q = 2^{32}$ and a top-tree height cap.
2. **Compute the Pareto floor** $(B_{\min}, S_{\min}, V_{\min})$ over the enumerated `WOTS+` + `FORS` candidate family under single-core Apple M6 `blake3-servil-core = "=0.11.0"` timings.
3. **Measure each dimension dimensionlessly** as its blowup above that floor: $r_B = B / B_{\min}$, $r_S = S / S_{\min}$, $r_V = V / V_{\min}$.
4. **Minimize the worst blowup first (Leximin $L_\infty$):** sort $(r_{(1)} \ge r_{(2)} \ge r_{(3)})$ and minimize lexicographically.

### Protocol simplifications that led to `12 + 3×7`

1. **Standard `WOTS+` (`w = 16`, 35 chains) + `FORS` (`16` trees × `1,024` leaves) instead of `WOTS+C` + `PORS+FP`:**
   - Our earliest draft squeezed below 4 KiB (`3,988 B`) using `w = 32` + `WOTS+C` + `PORS+FP` + Octopus path merging, requiring counter grinding loops, deduplication/sorting, and trailing-zero padding checks.
   - Moving into the `~5.5 KiB` band (`5,616 B`, `7,488 B` Base64) eliminated every piece of counter-grinding and path-merging machinery while cutting signing time dramatically, raising the FORS cover margin (`133.2` bits at $2^{32}$), and shrinking specification and code complexity.
2. **Irregular hypertree `12 + 3×7` (128 KiB top tree, zero disk cache) instead of `15 + 3×6` (1 MiB disk cache):**
   - Moving 3 levels from the top tree down to the 3 lower layers keeps identical wire size (`5,616 B`), identical FORS cover exponent (`133.2` bits), and slightly faster verification (`21.3 µs` on 1 core), while cutting top-tree RAM 8× (`1 MiB` → `128 KiB`) and cold `Signet::from_seed` ~8× (`20.53 ms` on 1 core, `23.07 ms` cold 1-shot sign) — fast enough for interactive CLIs with **zero on-disk cache format or API**.
   - Compared to uniform hypertrees at similar size (such as `5×7` at `5,888 B` or `4×8` at `5,488 B`), `12 + 3×7` stays noticeably faster on single-core warm signing (`2.54 ms`) while keeping `TOP_HEIGHT = 12` as a single constant.

---

## 4. Candidate techniques evaluated: adopted and declined

### Adopted in BLINCS

1. **BLAKE3 (`Keyed` + `DeriveKey`) as the sole primitive** (motivated by Project 11's [SLH-DSA-B](https://github.com/PQC-Suite-B/signatures) and [`docs/history/manifesto.md`](docs/history/manifesto.md)): fast on modern CPUs with single-core SIMD/SME2 batching and multi-GB/s streaming content hashing.
2. **Reduced $2^{32}$ lifetime budget** (vs. FIPS 205's $2^{64}$): cuts hypertree height nearly in half (`h = 33` vs. `63`).
3. **Nibble `WOTS+` (`w = 16`, 35 chains) and `FORS` (`16` trees of `1,024` leaves) with zero counter grinding:** bounded chain work and simple byte/nibble arithmetic (BLINCS-specific encodings and BLAKE3 instantiation; not FIPS 205 interoperable).
4. **Irregular hypertree (`12 + 3×7`) with in-memory 128 KiB top tree and no disk cache** (inspired by Project 11's irregular-hypertree work — Alessandro Baiocchi, Matteo Vena, Matteo Vicari, and Conor Deegan: [Companion Guide](https://research.projecteleven.com/articles/sphincs-parameter-explorer-companion-guide), [Raising SPHINCS-like lifetime budgets](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets); and Zhen Qin, Siwei Sun, and Fangyu Zheng, ASIACRYPT 2026, [ePrint 2025/2236](https://eprint.iacr.org/2025/2236)).
5. **256-bit internal message digest `D`:** verification consumes 193 bits of `D` (160 FORS index bits + 33 hypertree address bits; the upper 63 bits are unused), keeping coordinate selection directly in BLAKE3's native 32-byte digest output.
6. **Single-pass salted content hash (`Keyed(Keyed(K_content, e), M)`):** hashes arbitrarily large messages in one salted pass (~6.9–7.4 GB/s slice, ~4.3 GB/s zero-allocation 16 KiB streaming reader on 1 Apple M6 core) with no chunking layer and zero `Drop` implementations (§5).
7. **Strictly single-threaded execution via `blake3-servil-core = "=0.11.0"`:** zero worker threads, zero global pool, zero `abort()` runtime inside a library crate; uses `blake3-servil-core`'s zero-copy `&[[u8; 16/32/48]]` SIMD batching, `TreeHasher::hash_counter_range` for FORS leaf secrets, and `TreeHasher::on_this_core()` for verification to avoid Apple SME2 short-burst downclocking (§7).

### Declined (and why)

8. **Library-internal multithreading (`blake3-servil` thread pool / `Pipeline` / custom worker pool):**
   - Previously prototyped and benchmarked, then removed in favor of single-threaded `blake3-servil-core = "=0.11.0"`. A signature library should not install hidden background worker threads, contend with a host application's runtime/sandbox, or carry multithreaded `Pipeline` complexity — especially when 1-core `blake3-servil-core 0.11.0` already signs in `2.54 ms` (`394 / s`) and verifies in `21.3 µs` (`46,900 / s`) while scaling cleanly when callers run multiple signers across their own threads.
9. **WOTS+C / SPHINCS+C** (Kudinov, Hülsing, Ronen, Yogev, IEEE S&P 2023, [ePrint 2022/778](https://eprint.iacr.org/2022/778)) and **PORS+FP + Octopus merging** (Abri & Katz, CRYPTO 2026, [ePrint 2025/2069](https://eprint.iacr.org/2025/2069); Aumasson & Endignoux, [ePrint 2017/933](https://eprint.iacr.org/2017/933)): replaced by `WOTS+` + `FORS` to eliminate counter grinding, Octopus merging, deduplication/sorting, and zero-padding checks (§3).
10. **On-disk 1 MiB top-tree cache (`15 + 3×6`):** removed in favor of `12 + 3×7` (`20.53 ms` cold 1-core `from_seed`, `128 KiB` RAM) so callers manage no cache-file format or cache MAC.
11. **Custom inline/out-of-tree assembly inside `blincs`:** keeping `blincs` 100% `#![forbid(unsafe_code)]` on `blake3-servil-core` keeps assembly proof and maintenance inside `blake3-servil-core` (we verify and update pinned versions deliberately).
12. **SPHINCS-G offline prepared-slot grinding** (Baiocchi & Vicari, [`sphincs-g-benchmarks`](https://research.projecteleven.com/articles/sphincs-g-benchmarks), Nov 2026): shines on constrained hardware wallets with $h = 24..26$; at $h = 33$, online grinding is orders of magnitude slower than direct BLINCS signing.
13. **Unhashed random episodes + top-tree pruning** (Baiocchi, Vena, Vicari, [`raising-sphincs-lifetime-budgets`](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets), Nov 2026; SPHINCS-PE [ePrint 2026/1708](https://eprint.iacr.org/2026/1708)): keeping $h''$ bits outside the message digest loses $h''$ bits of security without SPHINCS-G grinding.
14. **CUTS / CUTS+C** (Judd, Tajan, Deegan, Akal, [ePrint 2026/2455](https://eprint.iacr.org/2026/2455), Oct 2026): designed for 2-use WOTS; beyond 2 uses loses security faster than FORS and needs combinatorial ranking/unranking.
15. **Stateful-primary + stateless-fallback hybrids (SHRINCS, SHRIMPS)** (Kudinov & Nick, [ePrint 2025/2203](https://eprint.iacr.org/2025/2203); reviewed by Deegan & Pruden in [`a-review-of-shrincs`](https://research.projecteleven.com/articles/a-review-of-shrincs)): restoring a backup or VM snapshot rolls back the one-time counter and leaks the key.
16. **THINCS / truncated 96–112-bit hashes** (Conor Deegan, [`conor-deegan/THINCS`](https://github.com/conor-deegan/THINCS)): drops below our 128-bit target.
17. **Gravity-SPHINCS / unsalted PORS** ([ePrint 2017/933](https://eprint.iacr.org/2017/933)): relies on unsalted collision resistance where salted hashing avoids it.
18. **Top of the Hypercube retry-free encodings (TSL / TL1C / TLFC)** (Khovratovich, Kudinov, Wagner, CRYPTO 2025, [ePrint 2025/889](https://eprint.iacr.org/2025/889)): longer chains and combinatorial ranking for modest byte savings.
19. **FORS+C** ([ePrint 2022/778](https://eprint.iacr.org/2022/778)): adds counter grinding for ~240 B; declined alongside `WOTS+C` and `PORS+FP`.
20. **Unreviewed 2026 few-time preprints** (BPORS+FP 2026/1328, BPORS-C+BFP 2026/2374, BGS-CC 2026/2502) and **hardware-specific hashes (Haraka / AES-NI)**.

---

## 5. Single-pass salted content hashing

### The three message-hashing modes

Discussions of signature schemes often treat message hashing as a binary choice between "pure" signing and unsalted pre-hashing. In fact there are **three** distinct modes:

| Mode | How the message `M` is hashed | Passes over `M` | Hash assumption on `M` | Examples |
|---|---|---:|---|---|
| **1. Unsalted pre-hash** | Hash `M` first with a fixed hash `H(M)`, then sign the digest | 1 | Unsalted collision resistance | HashSLH-DSA, Ed25519ph |
| **2. Two-pass message-dependent randomization** | Pass 1 derives randomizer `R` from `(key, M)`; Pass 2 hashes `(R, pk, M)` | 2 *(must buffer or rewind `M`)* | Randomized target-collision resistance | Pure SLH-DSA (FIPS 205), Ed25519 |
| **3. Single-pass salted streaming** *(BLINCS)* | Derive fresh salt `e` from `(K_salt, draw)` **before** reading `M`; hash `Keyed(Keyed(K_content, e), M)` | 1 *(constant-RAM streaming)* | Randomized target-collision resistance *(falls back to 128-bit known-key collision resistance if `e` repeats predictably)* | **BLINCS** |

BLINCS implements **Mode 3**: it chooses the fresh per-imprint salt `e` upfront so it can stream arbitrarily large inputs in a single BLAKE3 pass (`imprint_reader` / `verify_reader`) while resting message hashing on randomized target-collision resistance (assuming the submitter is committed to `M` before learning `e`). Pass the full message bytes or stream directly into BLINCS to cover the entire input under this salted pass.

```text
e     = Keyed(K_salt, draw)[..16]       # 16-byte per-signature salt, carried in the signature
K_msg = Keyed(K_content, e)             # 32-byte per-signature message key (public once e is known)
h_msg = Keyed(K_msg, M)                 # 32-byte single-pass keyed BLAKE3 hash of M
short = e || h_msg                      # 48 bytes
```

Note that `K_content` and `K_msg` are public once `e` is known (this is a randomized hash family, not a secret-key MAC). When `e` is unpredictable to the submitter until after `M` is committed, `Keyed(K_msg, M)` rests on randomized target-collision resistance. If a salt repeats predictably, content hashing falls back to the 128-bit known-key collision scale of 256-bit keyed BLAKE3 — while signing-key secrecy remains unaffected and `R = Keyed(K_R, e || h_msg)[..16]` still limits advance steering on distinct messages.

---

## 6. Signer randomness: startup-only state without `fsync`

We reviewed the classic PRNG-with-input and seed-file literature (Barak & Halevi, [ePrint 2005/029](https://eprint.iacr.org/2005/029); Ferguson, Schneier & Kohno's Fortuna seed-file management in *Cryptography Engineering* Ch. 9; Dodis et al., [ePrint 2013/338](https://eprint.iacr.org/2013/338); Ristenpart & Yilek, NDSS 2010; Bellare & Tackmann, [ePrint 2016/290](https://eprint.iacr.org/2016/290)) and kept only what serves BLINCS:

- **Why no per-signature syscall or disk write:** `Randomness::initialize` reads the 48-byte state file, 32 bytes from `/dev/urandom`, and the monotonic clock **once** at process startup, mixes them into `(next_seed, run_key)`, updates bytes `8..48` in place under an exclusive `flock`, and then serves every `draw()` from memory via `Keyed(run_key, u64_le(n))`.
- **Why no forward-security ratchet, entropy pools, entropy estimator, or shutdown hook:** `Randomness` sits beside the signing key in the same process and its output only feeds the published content salt `e` (keyed by `K_salt` from the signing key). What `draw` needs is **non-repetition**, not secrecy after compromise.
- **Why caller-supplied seed:** on Linux, `/dev/urandom` is non-blocking at early boot. Requiring the caller to supply the 32-byte seed keeps seed-generation entropy at the boundary that owns it.
- **Why explicit `Randomness::create`:** silently creating a missing state file hides misconfigured paths; refusing to overwrite (`create_new`) protects existing files.
- **Why monotonic clock (`Instant::hash`):** immune to NTP clock stepping and requires no `unsafe` code or FFI; treated strictly as opaque local diversification.
- **Why `initialize` skips `fsync` (while `create` syncs once):** on one-shot signers (such as `git commit`), `F_FULLFSYNC` adds milliseconds and VM snapshots can roll back state regardless of `fsync`. Without `fsync`, `write()` still updates the kernel page cache immediately for back-to-back processes; only a power loss before flush reverts the file, and on reboot `/dev/urandom` and the monotonic clock still vary `draw`.

---

## 7. Crash-only design and single-threaded performance engineering

BLINCS adopts Servil Software Factory's engineering discipline:

- **Pure crash-only lifecycle (zero `Drop` implementations, zero background threads, zero `thread_local!` caches):** `Randomness` has no shutdown hook. Verification (`SignetId::verify` / `verify_reader`) uses only fixed stack arrays (~2.5 KiB for FORS/WOTS+ plus a local zero-initialized 16 KiB stack buffer for streaming `verify_reader`) — **zero heap allocations**. Signing (`Signet::from_seed` / `imprint`) allocates one transient local `SignWorkspace` freed on return, with no cross-call TLS secret buffers and no `RefCell` borrows across `Read` callbacks. Every public operation is tested inside a **128 KiB** thread stack budget on the optimized test profile.
- **Types carry their rules & fail-stop contracts:** `Signet` holds one 32-byte seed and derives its `SignetId` and in-memory 128 KiB top tree on construction. `Signet::imprint` and `imprint_reader` run `SignetId::verify_short` (~21 µs, < 1% of imprinting time) before returning any imprint and panic on mismatch. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** measuring with `bench-hashes`'s `clocks` crate showed that calling Apple M6's SME2 kernels for verification's tiny 16–35-element batches downclocked the P-core from ~4,629 MHz to ~4,050 MHz. Routing verification through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and passing zero-copy `&[[u8; 32]]` / `&[[u8; 48]]` slices brings 64-byte verification to **21.3 µs** (`46,900 / s`, `7.02 IPC` @ `4,629 MHz`), while signing uses `blake3-servil-core 0.11.0`'s direct-load `&[[u8; 16/32/48]]` batching and `TreeHasher::hash_counter_range` for **2.54 ms** 1-core signing (`394 / s`).
- **Tiny base:** `#![forbid(unsafe_code)]`, one runtime dependency (`blake3-servil-core = "=0.11.0"`, **2 external crates** total in `Cargo.lock`, both BLAKE3 + SHA-256 hashset-verified), zero dev-dependencies.

---

## 8. Terminology: `Signet`, `SignetId`, and `Imprint`

Traditional cryptographic terminology — "digital signatures" and "public keys" — borrows a metaphor from handwritten signatures bound to a human identity. As Mark S. Miller (*Robust Composition*) and Ka-Ping Yee & Mark S. Miller (*Capability Myths Demolished*) argue, centering security on *identification* ("who is this person?") instead of *authorization* ("should this action be allowed?") routinely pushes systems toward brittle PKIs, identity directories, and ambient access-control lists.

In reality, a cryptographic signing secret is a transferable **bearer** capability, not a person's hand — closer to a physical **signet** ring handed to an officeholder or steward than to a personal autograph:

- **`Signet`** (traditionally *signing key*): the secret bearer object (derived from a 32-byte seed) that exercises authority by making an imprint.
- **`Imprint`** (traditionally *signature*): the 5,616-byte mark pressed by a `Signet` onto a message or stream. Unlike Morris/Miller *Sealers/Unsealers* (which bundle encryption with brand checking), an `Imprint` provides transparent authenticity only — the message stays in the clear.
- **`SignetId`** (traditionally *verifying key*): the 32-byte public identifier that names *which* signet you mean — and in a 32-byte scheme like BLINCS, naming the signet and having everything needed to verify its imprints (`SignetId::verify`) are literally the same 32 bytes.

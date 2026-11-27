# BLINCS (`BLINCS-128-A2`) and Signet design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of an early `SPEC.md`, constrained-device-first parameter search inspiration, SLH-DSA-B with **julienif**, THINCS, CUTS, and SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil-core`, SPHINCS/SPHINCS+/FIPS 205, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** the **BLINCS** (`BLINCS-128-A2`) signature algorithm and **Signet** (this Rust implementation of `BLINCS-128-A2`) are shaped the way they are: the threat model, the $2^{32}$ signature budget, the global stateless parameter search targeting **≤ 5 s warm `p99` signing on a `160 MHz` ARM Cortex-M33 with a `128 KiB` cached top tree** that selected **`12+7+7+7` (`d = 4, h = 33`) `S-WOTS+Z(n = 24, w = 40, S = 468, z = 8)` + single height-10 `U-PORS(n = 3, w = 24, S = 42, C = 376, A = 10, k = 10, m_max = 44)` (`3,292 B` raw / `4,392 B` Base64, pure 32-byte BLAKE3 with zero XOF mode, 8 tweak kinds, bounded length-framed application `Context`, fail-closed verification, strictly single-threaded `blake3-servil-core`)**, every candidate technique we evaluated and why each was adopted or declined, the single-pass salted content hash, the lock-free atomic state file, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the standalone algorithm spec, Lean 4 formalization, and paper, see [`jasonhadler25/blincs`](https://github.com/jasonhadler25/blincs); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

---

## 1. Goals and threat model

BLINCS is designed for a dishonest submitter who does **not** hold the signing key, interacting with an honest signer and honest verifiers. The attacker may:

- observe up to $2^{32}$ signatures and trigger the honest signer to sign messages the signer approves,
- possess a structural weakness in BLAKE3 that produces **collisions** cheaply without yielding **second preimages**, and
- spend enormous classical compute (a 128-bit security target; BLAKE3 itself claims 128-bit security).

The design goals that follow:

- **Post-quantum, hash-based assumptions:** security rests on symmetric hash properties of BLAKE3 and this SPHINCS-family construction, not lattices, pairings, or factoring.
- **100% pure stateless signing (no synchronized one-time signing state):** a signing key can be copied across machines, restored from backups, or run in short-lived processes (such as `git commit`) without XMSS/LMS-style one-time-key reuse.
- **Short verifying key (32 bytes):** small enough to embed directly in a name or identifier a user already acquires (for example, a repository or branch name).
- **Compact fixed-size signatures (3,292 bytes / 4,392 bytes Base64):** `2.39×` smaller (`4,564 B` saved) than `SLH-DSA-128s` (`7,856 B`), `5.19×` smaller than `SLH-DSA-128f` (`17,088 B`), and smaller than symmetric VOLE-in-the-head `FAEST-EM-128s` (`3,924 B`), regardless of message size.
- **Zero XOF mode & 1-block hot-path hashing:** every hot-path tweak call (`CHAIN_SECRET`, `CHAIN`, `ONE_TIME_MSG`, `NODE`, `FEW_SELECT`, `FEW_CODE`, and `U-PORS` `ONE_TIME_KEY`) fits in a single 64-byte BLAKE3 compression block, and `FewCode` uses indexed 32-byte `Keyed` hashes instead of XOF mode.
- **Constrained-hardware friendly (`≤ 5 s` warm `p99` modeled on `160 MHz` Cortex-M33 with `128 KiB` top tree):** caching the height-12 top Merkle heap (`8,192 × 16 B = 128 KiB`, built once in `31.97 ms` on 1 Apple M6 core) lets warm signing finish in **`4.15 ms`** on Apple M6 (`~4.27 s` modeled `p99` on a `160 MHz` Cortex-M33 — modeled, not measured on Cortex-M hardware) with virtually zero tail jitter (`p99 / mean ≈ 1.013×`), while verification executes constant work (`2,267` short-message compressions, **`39.1 µs`** on 1 Apple M6 core).
- **Suite-separated key schedule, framed application `Context`, and fail-closed verification:** every algorithm key-derivation context binds `BLINCS-128-A2`, every imprint binds a typed `Context` (`0..=255` bytes, framed as `u8(len(ctx)) || ctx`) into `K_msg`, `R`, and `D_seed`, and `verify`/`verify_with` return `Result<(), InvalidImprint>` / `Result<(), VerifyError<E>>`.
- **Strictly single-threaded execution:** runs entirely on the calling thread via `blake3-servil-core = "=0.11.0"` — zero background thread pools, zero cross-thread shared state, and linear scaling across caller-managed threads.
- **Minimize unnecessary reliance on collision resistance:** unsalted hashes belong where independent parties must derive the same name without coordinating (content addressing, Git object IDs, hashsets); salted hashes belong where one party vouches for content (signatures).

---

## 2. Why $2^{32}$ signatures at $\ge 128$ bits

The sizing target is one full `u32` of signatures per signing key: **$2^{32} = 4{,}294{,}967{,}296$** (10 signatures every second nonstop for **13.6 years**). Dropping the budget from FIPS 205's $2^{64}$ to $2^{32}$ cuts hypertree height nearly in half (`h = 33` vs. `63`), and combining `12+7+7+7` `S-WOTS+Z` with single-tree `U-PORS` Octopus cuts signatures to **`3,292 B`** (`2.39×` smaller than `SLH-DSA-128s`).

Under our exact without-replacement hypergeometric elementary DP bound (**zero Octopus-cap credit** — verified directly by `python3 tools/optimize.py --check`, using exact lattice-cover probabilities `q(1) = 1/376`, `q(2) = 0.170004`, `q(3) = 0.336239` on $\mathcal{L}_{42}(3, 24)$), single-query `U-PORS` security starts above 128 bits even **without** counting the Octopus sibling cap, while the importance-sampled cap credit adds another `+6.8` to `+8.3` bits:

| Signatures signed by one key | Elementary exact without-replacement bound (zero cap credit) | True security (with Octopus cap `m_max = 44`) |
|---:|---:|---:|
| $2^{31}$ (2.15B) | **134.58 bits** | ~140.8 bits |
| **$2^{32}$ (budget, 4.29B)** | **128.58 bits** | **135.37 bits** |
| **$2^{33}$ ($2\times$, 8.59B)** | **121.56 bits** | **128.91 bits** *(still $> 128$ b)* |
| $2^{34}$ ($4\times$, 17.2B) | **113.29 bits** | ~121.1 bits |
| $2^{35}$ ($8\times$, 34.4B) | **103.55 bits** | ~111.7 bits |
| $2^{36}$ ($16\times$, 68.7B) | **92.16 bits** | ~100.5 bits |

*(These values are $-\log_2 P(q)$ for the single-key `U-PORS` cover event under ideal hashes, not a full multi-user or quantum proof of BLINCS; see `SPEC.md#12-security-target-model-and-limits`.)*

---

## 3. Why `S-WOTS+Z` + `U-PORS` Octopus (`3,292 B`)

Three simple, complementary mechanisms deliver the `4,564 B` reduction below `SLH-DSA-128s` (`7,856 B` → `3,292 B`):

1. **`S-WOTS+Z(n = 24, w = 40, S = 468, z = 8)` (`2 + 384 = 386 B` per layer):**
   - Constant-sum Sperner unranking on the exact middle slice $\mathcal{L}_{468}(24, 40)$ has kernel-checked cardinality $|\mathcal{L}_{468}(24, 40)| = 1{,}973{,}221{,}677{,}906{,}098{,}493{,}567{,}206{,}234{,}001{,}571{,}000 > 2^{120}$ (whereas $w = 39$ falls strictly below $2^{120}$, proving $w = 40$ is the exact integer minimum).
   - Every valid codeword sums to `468` (eliminating checksum chains and making verification strictly constant work: `468` steps/layer).
   - Deterministic `u16` counter grinding requiring `z = 8` leading zero bits (`H[0] == 0`) reduces the Sperner domain from $2^{128}$ to $2^{120}$ (saving 2 full chains = `128 B` across 4 layers) with `u16` overflow probability $(255/256)^{65536} \approx 2^{-370}$ (avoiding `z = 10`'s `2^{-92}` `u16` hazard) at only ~256 hashes/layer (`< 0.3%` of signing work).
   - Standalone `#![no_std]` `signet-verify` unranks $\mathcal{L}_{468}(24, 40)$ via exact `O(S)` boxcar deconvolution with **0 bytes of ROM tables**.

2. **Single height-10 `U-PORS` Octopus (`1,188 B` total):**
   - Replaces `FORS`'s 15–20 separate trees with ONE height-10 tree (`1,024` leaves) whose `k = 10` opened leaves share internal Merkle siblings via bottom-up Octopus merging capped at `m_max = 44` siblings (`4 + (30 + 44) × 16 = 1,188 B`, with canonical constant-time all-zero trailing padding when `sibs < 44`).
   - Each leaf carries `3` Winternitz chains (`w = 24`, `23` steps/chain, exact `64 B` = 1-block BLAKE3 leaf hash) on the full upper slice $\mathcal{L}_{42}(3, 24)$ (`C = 376` codewords, `27` verify steps/leaf, 0-ROM closed-form hexagon unranking).
   - Choosing `m_max = 44` yields mean ~1,365 `FewSelect` trials (`p99 ≈ 6,287`, `u32` overflow probability $2^{-4.54 \times 10^6}$), keeping joint signing `p99 / mean ≈ 1.013×`.

3. **Cached `128 KiB` height-12 top tree (`12+7+7+7` hypertree, `d = 4, h = 33`):**
   - Moving 12 of the 33 hypertree bits into a `128 KiB` top tree cached in `Signet` cuts the hypertree from `7` layers down to `4` layers (`3` lower height-7 trees of `128` leaves each).
   - Every signing call executes **`3 × 128 × 24 + 1,024 × 3 = 9,216 + 3,072 = 12,288` chains (`384 × 32` exact SIMD waves!)** merged into one unified single-threaded SIMD super-wave (`4.15 ms` on 1 Apple M6 core).

---

## 4. Candidate techniques evaluated: adopted and declined

### Adopted in `BLINCS-128-A2`

1. **BLAKE3 (`Keyed` + `DeriveKey`, zero XOF) as the sole primitive:** single-core SIMD/SME2 batching and multi-GB/s streaming content hashing.
2. **Reduced $2^{32}$ lifetime budget** (vs. FIPS 205's $2^{64}$): cuts hypertree height nearly in half (`h = 33` vs. `63`).
3. **`12+7+7+7` `S-WOTS+Z` + `U-PORS` Octopus (`3,292 B`):** `2.39×` smaller than `SLH-DSA-128s`, zero cap-credit needed for `> 128` bits (`128.58 b` elementary / `135.37 b` true at $2^{32}$), `p99 / mean ≈ 1.013×`, `2,267` constant short-message verify compressions.
4. **Indexed 32-byte `FewCode` extraction & `root`-bound `D_seed`:** eliminates XOF mode completely and binds `root` directly into `D_seed` so verification binds the full `SignetId`.
5. **Single-pass salted content hash (`Keyed(Keyed(K_content, e || u8(len(ctx)) || ctx), M)`):** hashes arbitrarily large messages in one salted pass (`5.57–6.99 GB/s` slice, `3.41–3.94 GB/s` streaming on 1 Apple M6 core) with zero `Drop` implementations (§5).
6. **Strictly single-threaded execution via `blake3-servil-core = "=0.11.0"` (plus standalone `#![no_std]` `signet-verify`):** zero worker threads, zero global pool; standalone `signet-verify` links cleanly as a `28.0 KiB`, `0`-import freestanding `wasm32-unknown-unknown` binary with zero ROM tables.
7. **Lock-free atomic state file + `getrandom` + `Signet::generate`:** zero `flock`, zero blocking/deadlocks, single private `0600` exact-32-byte file rotated via sibling temp file + POSIX atomic `rename` with forward secrecy on disk (§6).

### Declined (and why)

8. **Library-internal multithreading (`blake3-servil` thread pool / `Pipeline`):** removed in favor of single-threaded `blake3-servil-core = "=0.11.0"` so a signature library never installs hidden background worker threads.
9. **Hybrid stateful/stateless signing (SHRINCS / Crash-Safe `U-PORS` Hybrid):** even replacing SHRINCS's fragile 1-time XMSS fast path with `U-PORS` leaves still degrades under sustained read-only-FS rollback and adds variable-size two-branch complexity; once pure stateless `BLINCS-128-A2` reached `3,292 B`, staying 100% stateless was overwhelmingly cleaner.
10. **Larger grinding (`z = 10` on `u16` or tighter `m_max < 44`):** `z = 10` leaves a `2^{-92}` `u16` overflow hazard (`2^{-60}` over $2^{32}$ signatures), and tighter `m_max` balloons `p99` tail latency; `z = 8` (`2^{-370}` overflow) + `m_max = 44` keeps `p99 / mean ≈ 1.013×`.
11. **Zero-cap-deficit candidates (`B1` `3,180 B` requiring Octopus cap credit for 128 bits):** we deliberately chose `BLINCS-128-A2` (`3,292 B`) so elementary without-replacement security exceeds `128` bits (`128.58 b`) with **zero** Monte Carlo assumptions in the formal proof.
12. **Custom inline/out-of-tree assembly inside `signet`:** keeping `signet` 100% `#![forbid(unsafe_code)]` on `blake3-servil-core` keeps assembly proof and maintenance inside `blake3-servil-core`.

---

## 5. Single-pass salted content hashing

### The three message-hashing modes

Discussions of signature schemes often treat message hashing as a binary choice between "pure" signing and unsalted hashing. In fact there are **three** distinct modes:

| Mode | How the message `M` is hashed | Passes over `M` | Hash assumption on `M` | Examples |
|---|---|---:|---|---|
| **1. Unsalted digest-then-sign** | Hash `M` first with a fixed hash `H(M)`, then sign the digest | 1 | Unsalted collision resistance | HashSLH-DSA, Ed25519ph |
| **2. Two-pass message-dependent randomization** | Pass 1 derives randomizer `R` from `(key, M)`; Pass 2 hashes `(R, pk, M)` | 2 *(must buffer or rewind `M`)* | Randomized target-collision resistance | Pure SLH-DSA (FIPS 205), Ed25519 |
| **3. Single-pass salted streaming** *(BLINCS)* | Derive fresh salt `e` from `(K_salt, draw)` **before** reading `M`; hash `Keyed(Keyed(K_content, e || u8(len(ctx)) || ctx), M)` | 1 *(constant-RAM streaming)* | Randomized target-collision resistance *(falls back to 128-bit known-key collision resistance if `e` repeats predictably)* | **BLINCS** |

BLINCS implements **Mode 3**: it chooses the fresh per-imprint salt `e` upfront so it can stream arbitrarily large inputs or structured trees in a single BLAKE3 pass (`imprint_with` / `verify_with`) while resting message hashing on randomized target-collision resistance (assuming the submitter is committed to `M` before learning `e`). Pass the full message bytes or stream directly into BLINCS to cover the entire input under this salted pass.

```text
framed_ctx = u8(len(ctx)) || ctx                   # 1..=256 bytes (bounded application context)
e          = Keyed(K_salt, draw)[..16]             # 16-byte per-signature salt, carried in the signature
K_msg      = Keyed(K_content, e || framed_ctx)     # 32-byte per-signature, per-context message key
h_msg      = Keyed(K_msg, M)                       # 32-byte single-pass keyed BLAKE3 hash of M
short      = e || h_msg                            # 48 bytes
```

Note that `K_content` and `K_msg` are public once `e` is known (this is a randomized hash family, not a secret-key MAC). When `e` is unpredictable to the submitter until after `M` is committed, `Keyed(K_msg, M)` rests on randomized target-collision resistance. If a salt repeats predictably, content hashing falls back to the 128-bit known-key collision scale of 256-bit keyed BLAKE3 — while signing-key secrecy remains unaffected and `R = Keyed(K_R, e || h_msg || framed_ctx)[..16]` still limits advance steering on distinct messages.

---

## 6. Signer randomness: lock-free atomic state file

We reviewed the classic PRNG-with-input and seed-file literature (Barak & Halevi, [ePrint 2005/029](https://eprint.iacr.org/2005/029); Ferguson, Schneier & Kohno's Fortuna seed-file management in *Cryptography Engineering* Ch. 9; Dodis et al., [ePrint 2013/338](https://eprint.iacr.org/2013/338); Ristenpart & Yilek, NDSS 2010; Bellare & Tackmann, [ePrint 2016/290](https://eprint.iacr.org/2016/290)) and settled on a minimal lock-free startup state file:

- **Single private 32-byte file, atomic `rename`, zero locks:**
  - `Randomness::create(path)` creates a private `0600` 32-byte state file durably via sibling temp file + `fsync` + no-replace `hard_link` + parent sync (refusing to overwrite an existing path).
  - `Randomness::initialize(path)` checks that `path` is a private (`0600`) regular non-symlink file, reads its exact 32 bytes, mixes `prior || getrandom(32) || pid(4) || monotonic_clock` under `CTX_MIX`, and derives three independent domain-separated keys: `next_seed` (published atomically onto `path` via a `0600` sibling temp file + POSIX `rename`), `run_key` (in-memory imprint draws), and `keygen_key` (in-memory draws for `Signet::generate`).
  - Splitting `next_seed` from `run_key`/`keygen_key` preserves forward secrecy on disk. Because `rename` is atomic on POSIX, concurrent initializers never block, never deadlock, and never observe a truncated file; mixing `pid` differentiates simultaneous startups even if both `getrandom()` and the clock repeat.
- **Safe `Signet::generate(&rng)`:**
  - Combines a domain-separated draw from `keygen_key` with fresh 32-byte OS `getrandom(2)` entropy (`Derive(CTX_GENERATE_SIGNET, keygen_draw || os_bytes)`), hedging against both weak OS RNGs and compromised disk state, while `Signet::from_seed` remains for restoring persisted seeds and deterministic vectors.

---

## 7. Crash-only design and single-threaded performance engineering

BLINCS adopts Servil Software Factory's engineering discipline:

- **Pure crash-only lifecycle (zero `Drop` implementations, zero background threads, zero `thread_local!` caches):** `Randomness` has no shutdown hook. Verification (`SignetId::verify` / `verify_with`) uses only fixed stack buffers (~9 KiB for `verify`, plus the `Sink`'s 26 KiB BLAKE3 `Hasher` for `verify_with`) — **zero heap allocations**. Signing builds the `128 KiB` top tree once in `Signet::from_seed` (`31.97 ms`) and allocates a transient local super-wave workspace (~1.1 MiB) freed on return. Every public operation is tested inside a **128 KiB** thread stack budget on the optimized test profile.
- **Types carry their rules & fail-stop contracts:** `SecretKey` exposes only narrow `ChainSecret` counter-range batch derivation (`derive_chain_starts`) and never exports a raw `TreeHasher`. `Signet::imprint` and `imprint_with` run `SignetId::verify_short` (~39 µs) before returning any imprint and panic on mismatch. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** routing verification and small-slice content hashing through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and using register-only `hash_counter_range` for `ChainSecret`, `OneTimeMsg`, and `FewSelect` plus 64-byte-aligned `Batch::from_blocks` brings 64-byte verification to **39.1 µs** (`25,600 / s`, `7.04 IPC` @ `4,551 MHz`), while signing steps all `12,288` lower-tree + `U-PORS` chains in one unified SIMD super-wave (`4.15 ms` warm on 1 Apple M6 core).
- **Tiny base:** `#![forbid(unsafe_code)]`, three direct runtime dependencies in `signet` (`blake3-servil-core = "=0.11.0"`, `constant_time_eq = "=0.4.2"`, `getrandom = "=0.4.3"`, plus `signet-verify` dev-dependency for differential testing; 13 total workspace crates in `Cargo.lock`, all BLAKE3 + SHA-256 hashset-verified).

---

## 8. Terminology: `Signet`, `SignetId`, and `Imprint`

Traditional cryptographic terminology — "digital signatures" and "public keys" — borrows a metaphor from handwritten signatures bound to a human identity. As Mark S. Miller (*Robust Composition*) and Ka-Ping Yee & Mark S. Miller (*Capability Myths Demolished*) argue, centering security on *identification* ("who is this person?") instead of *authorization* ("should this action be allowed?") routinely pushes systems toward brittle PKIs, identity directories, and ambient access-control lists.

In reality, a cryptographic signing secret is a transferable **bearer** capability, not a person's hand — closer to a physical **signet** ring handed to an officeholder or steward than to a personal autograph:

- **`Signet`** (traditionally *signing key*): the secret bearer object (derived from a 32-byte seed) that exercises authority by making an imprint.
- **`Imprint`** (traditionally *signature*): the 3,292-byte mark pressed by a `Signet` onto a message or stream. An `Imprint` provides transparent authenticity only — the message stays in the clear.
- **`SignetId`** (traditionally *verifying key*): a publisher's self-certifying 32-byte identifier and its complete BLINCS verifying key — in a 32-byte scheme like BLINCS, naming the signet and having everything needed to verify its imprints (`expected_publisher.verify(...)`) are literally the same 32 bytes.

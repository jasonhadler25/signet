# BLINCS (`BLINCS-128-7x5`) and Signet design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of `SPEC.md`, constrained-device-first parameter search inspiration, SLH-DSA-B with **julienif**, THINCS, CUTS, and the SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil-core`, SPHINCS/SPHINCS+/FIPS 205, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** the **BLINCS** (`BLINCS-128-7x5`) signature algorithm and **Signet** (this Rust implementation of `BLINCS-128-7x5`) are shaped the way they are: the threat model, the $2^{32}$ signature budget, the constrained-device-first parameter search targeting **≤ 5 s `p99` signing on a Ledger ST33 Secure Element** that selected **uniform `7×5` `WOTS+` + byte-aligned `FORS(8, 20)` (`7,392 B`, `1 KiB` top tree, zero counter grinding, zero disk cache, suite-separated key schedule, bounded length-framed application `Context`, fail-closed verification, strictly single-threaded `blake3-servil-core`)**, every candidate technique we evaluated and why each was adopted or declined, the single-pass salted content hash, the lock-free content-addressed seed directory, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

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
- **Fixed-size signatures (7,392 bytes / 9,856 bytes Base64):** smaller than `SLH-DSA-128s` (`7,856 B`) and 2.3× smaller than `SLH-DSA-128f` (`17,088 B`), regardless of whether the signed message is 0 bytes or 100 GiB.
- **Zero counter grinding & byte-aligned `7×5` `WOTS+` / `FORS(8, 20)` structure:** constant algorithmic signing time (`p99 = mean = max`, zero grinding tail spikes), identical height-5 trees across all 7 layers, and byte-aligned FORS indices (`indices[t] = D[t]`, zero cross-byte bit-unpacking anywhere).
- **Constrained-hardware friendly (≤ 5 s `p99` on Ledger ST33) & zero disk cache:** the 1 KiB top tree builds in `0.17 ms` on 1 Apple M6 core (`1.42 ms` cold 1-shot sign) and `~0.46 s` on a Ledger ST33 Secure Element (`~3.6 s` uncached `p99` sign — right at `~5.0 s` even with +40% DPA wait states), eliminating any need for an on-disk or Flash key cache.
- **Suite-separated key schedule, framed application `Context`, and fail-closed verification:** every algorithm key-derivation context binds `BLINCS-128-7x5`, every imprint binds a typed `Context` (`0..=255` bytes, framed as `u8(len(ctx)) || ctx`) into `K_msg`, `R`, and `D` so cross-protocol replay is impossible, and `verify`/`verify_with` return `Result<(), InvalidImprint>` / `Result<(), VerifyError<E>>` so verification fails closed.
- **Strictly single-threaded execution:** runs entirely on the calling thread via `blake3-servil-core = "=0.11.0"` — zero background thread pools, zero cross-thread shared state, and clean linear scaling when a host application runs multiple signers across its own threads.
- **Minimize unnecessary reliance on collision resistance:** unsalted hashes belong where independent parties must derive the same name without coordinating (content addressing, Git object IDs, hashsets); salted hashes belong where one party vouches for content (signatures).

---

## 2. Why $2^{32}$ signatures at $\ge 128$ bits

The sizing target is one full `u32` of signatures per signing key: **$2^{32} = 4{,}294{,}967{,}296$** (10 signatures every second nonstop for **13.6 years**). Dropping the budget from FIPS 205's $2^{64}$ to $2^{32}$ cuts hypertree height nearly in half (`h = 35` vs. `63`), keeping signatures smaller than `SLH-DSA-128s` (`7,392 B` vs. `7,856 B`) while signing **97× faster** and verifying **3.7× faster** than single-threaded `SLH-DSA-BLAKE3-128s` on Apple M6.

Under the single-key ideal-hash FORS leaf-cover model (`h = 35`, `k = 20` trees of $2^8 = 256$ leaves, checked by `python3 tools/optimize.py --check`), the single-query cover exponent degrades gradually past $2^{32}$ and still stays above 128 bits even at $2\times$ the budget:

| Signatures signed by one key | Single-query FORS cover exponent (ideal-hash model) |
|---:|---:|
| $2^{32}$ (budget, 4.29B) | **134.5 bits** |
| $2^{33}$ ($2\times$, 8.59B) | **128.8 bits** |
| $2^{34}$ ($4\times$, 17.2B) | **122.4 bits** |
| $2^{35}$ ($8\times$, 34.4B) | **114.9 bits** |
| $2^{36}$ ($16\times$, 68.7B) | **106.2 bits** |

*(These values are $-\log_2 P(q)$ for the single-query FORS leaf-cover event under ideal hashes, not a full multi-user or quantum proof of BLINCS; see `SPEC.md#security-target-model-and-limits`.)*

---

## 3. Parameter search: constrained-device-first UX while minimizing desktop costs

*Design approach inspired by **Conor Deegan** of [Project 11](https://research.projecteleven.com/), who pointed out that tuning solely for an implicit desktop CPU can leave constrained signing hardware (such as a Ledger hardware wallet) with poor keygen or signing latency.*

Instead of optimizing solely on a desktop machine, BLINCS's reproducible parameter search (`python3 tools/optimize.py`) works in three transparent steps:

### Step 1 — Fix security target and construction family

- Standard `WOTS+` ($w \in \{8, 16, 32\}$) + `FORS` (zero counter grinding, zero Octopus path merging).
- Per-signet budget $q = 2^{32}$, with $\ge 128$-bit single-query FORS leaf-cover exponent under ideal hashes (`h + a * k <= 256`).

### Step 2 — Enforce "Good Enough UX" on the most constrained feasible signing devices

Not every hardware security device can run custom BLAKE3/BLINCS code:

- **Closed-firmware silicon (cannot run custom algorithms unless added by the vendor):** Apple Secure Enclave (SEP), Android StrongBox / Titan M2 / Knox Vault / Qualcomm SPU, YubiKey 5 / Bio / FIPS, and TPM 2.0. Generic JavaCard 3.x smartcards lack native BLAKE3 and run interpreted bytecode too slowly.
- **Programmable constrained signing hardware (within reach today):**
  - **Ledger Nano S+ / Flex / Stax** (`ST33K1M5` Secure Element: ~60 MHz ARM SC300/Cortex-M33, 160 KB RAM, 1.5 MB Flash, Rust `no_std`) and **Nordic `nRF52840`** BLE/NFC keys (64 MHz Cortex-M4) — **our reference constrained signer (`~25 µs/comp`, up to `~35 µs/comp` on `ST33` with DPA/FI wait states)**.
  - **Nitrokey 3 / SoloKey 2** (`LPC55S69` Cortex-M33 @ 150 MHz, 320 KB RAM, Rust `trussed`), **Trezor Safe 3 / Safe 5** (`STM32U585` Cortex-M33 @ 160 MHz, 786 KB RAM, 2 MB Flash), **BitBox02** (`ATSAMD51` 120 MHz M4), and **OpenTitan Earl Grey silicon** (`Ibex` 100 MHz `RV32IMCB` with `Zbb` bitmanip) — ~2.0–2.7× faster than `ST33K1M5`.
  - **Coldcard Mk4 / Q, Keystone 3 Pro, Passport, Jade** (`STM32L4/H7` @ 80–480 MHz or `ESP32-S3` @ 240 MHz) and **TrustZone OP-TEE / Nitro Enclaves / NetHSM**.
  - **Below our floor (ARMv6-M / Thumb-1):** 48 MHz Cortex-M0+ (`~75 µs/comp`) and discontinued 33 MHz Ledger Nano S (`ST31H320`, `~105 µs/comp`) lack Thumb-2 barrel-shifter rotates and have only 8 low registers (~3,500 cycles/comp); hitting ≤ 5 s there pushes signatures past `SLH-DSA-128s` (`10–12 KiB`), so `ST33` is the lowest-power target we optimize for.

Using a hypothetical embedded streaming Merkle `TreeHash` (`O(h)` stack, ~1.5 KiB working RAM, zero per-key Flash cache — **modeled, not measured on ST33 hardware**; this Rust host signer uses a ~475 KiB SIMD workspace instead), at ~1,500 cycles per scalar Thumb-2 BLAKE3 compression (~25 µs/comp on 60 MHz `ST33K1M5`, up to ~35 µs/comp with DPA/FI wait states; ~9.4–12.5 µs/comp on 100–160 MHz Trezor Safe 5 / Nitrokey 3 / OpenTitan silicon), the constrained-device constraint is **99th-percentile (`p99`) signing time**: we enforce **≤ 5.0 s nominal uncached `p99` signing on `ST33K1M5`**. Because BLINCS uses zero counter grinding, every signing call executes a fixed number of compressions (avoiding the `4.6×` geometric `p99` tail of `FORS+C` grinding). Slower ARMv6-M chips (48 MHz Cortex-M0+ or discontinued 33 MHz `ST31` Nano S) would push signatures past `SLH-DSA-128s` (`10–12 KiB`), making `ST33` the lowest-power target we model for.

### Step 3 — Minimize desktop costs over the feasible set

Among all parameter sets that satisfy Steps 1 and 2 and stay smaller than `SLH-DSA-128s` (`<= 7,856 B`), `tools/optimize.py` evaluates signature bytes, single-core warm signing, and single-core verification (calibrated to Apple M6 `blake3-servil-core = "=0.11.0"`). Among uniform nibble (`w = 16`, zero-grinding) designs, **uniform `7×5` (`h = 35`), `FORS(8, 20)` (`7,392 B` / `9,856 B` Base64)** hits the sweet spot: byte-aligned FORS (`indices[t] = D[t]`, zero cross-byte bit-unpacking), `3.63 s` nominal `p99` on ST33 (`~5.08 s` even with +40% DPA wait states), `1.25 ms` warm / `1.42 ms` cold on 1 Apple M6 core, and `134.5 / 128.8 b` at $2^{32}/2^{33}$:

| Profile (`q = 2^32`, `>= 128b` FORS, zero grinding) | Size (Base64) | FORS ($2^{32}/2^{33}$) | Top tree | Ledger `ST33` kg / **`p99` uncached** (`DPA-35`) | NK3 / Trezor | M6 1-core kg / warm / cold / verify |
|---|---:|---|---:|---|---|---|
| **Adopted (`BLINCS-128-7x5`, `F(8,20)`)** | **7,392 B** (`9,856`) | **134.5 / 128.8 b** | **1 KiB** | **0.46 s / 3.63 s** (`5.08 s`) | **1.36 s** | **0.17 ms** / **1.25 ms** / **1.42 ms** / **34.2 µs** |
| Smallest uniform `w=16` (`7×5`, `F(10,15)`) | 7,152 B (`9,536`) | 135.5 / 131.0 b | 1 KiB | 0.46 s / 4.40 s (`6.15 s`) | 1.65 s | 0.17 ms / 1.47 ms / 1.64 ms / 33 µs |
| Smallest `8 KiB` Base64 (`5×7`, `w=16`, `F(11,13)`) | 5,888 B (`7,852`) | 132.5 / 128.5 b | 4 KiB | 1.82 s / 11.15 s (`15.6 s`) | 4.19 s | 0.65 ms / 3.47 ms / 4.12 ms / 26.3 µs |
| Cortex-M0+ 48 MHz ≤ 5 s (`9×4`, `w=8`, `F(7,22)`) | 10,048 B (`13,400`) | 129.1 / 123.9 b | 0.5 KiB | 0.15 s / 1.63 s (`2.28 s`) | 0.61 s | 0.05 ms / 0.54 ms / 0.59 ms / 29 µs |

Reproduce directly:

```sh
python3 tools/optimize.py --max-ledger-keygen 2.0 --max-ledger-sign 5.0 --max-bytes 7856
```

---

## 4. Candidate techniques evaluated: adopted and declined

### Adopted in BLINCS

1. **BLAKE3 (`Keyed` + `DeriveKey`) as the sole primitive** (motivated by Project 11's [SLH-DSA-B](https://github.com/PQC-Suite-B/signatures) and [`docs/history/manifesto.md`](docs/history/manifesto.md)): fast on modern CPUs with single-core SIMD/SME2 batching and multi-GB/s streaming content hashing.
2. **Reduced $2^{32}$ lifetime budget** (vs. FIPS 205's $2^{64}$): cuts hypertree height nearly in half (`h = 35` vs. `63`).
3. **Uniform `7×5` hypertree with nibble `WOTS+` (`w = 16`, 35 chains) and byte-aligned `FORS(8, 20)` with zero counter grinding:** identical height-5 trees across all 7 layers, 1 KiB top tree (`0.17 ms` M6 keygen, `~0.46 s` Ledger ST33 keygen), constant `p99 = 3.63 s` ST33 signing, and byte-aligned FORS indices (`D[t]`, zero bit-unpacking).
4. **256-bit internal message digest `D`:** verification consumes 195 bits of `D` (20 byte-aligned FORS indices in `D[0..20]` + 35 hypertree address bits in `D[20..28]`), keeping coordinate selection directly in BLAKE3's native 32-byte digest output.
5. **Single-pass salted content hash (`Keyed(Keyed(K_content, e || u8(len(ctx)) || ctx), M)`):** hashes arbitrarily large messages in one salted pass (~6.9–7.4 GB/s slice, ~4.3 GB/s zero-allocation 16 KiB streaming reader on 1 Apple M6 core) with no chunking layer and zero `Drop` implementations (§5).
6. **Strictly single-threaded execution via `blake3-servil-core = "=0.11.0"` (plus standalone `#![no_std]` `signet-verify`):** zero worker threads, zero global pool, zero `abort()` runtime inside a library crate; uses `blake3-servil-core`'s zero-copy `&[[u8; 16/32/48]]` SIMD batching, `TreeHasher::hash_counter_range` for FORS leaf secrets, and `TreeHasher::on_this_core()` for verification (§7), alongside standalone `#![no_std]` zero-alloc verifier crate `crates/signet-verify` tested natively and on freestanding `wasm32-unknown-unknown`.
7. **Lock-free atomic state file + `getrandom` + `Signet::generate`:** zero `flock`, zero blocking/deadlocks, single private `0600` exact-32-byte file rotated via sibling temp file + POSIX atomic `rename` with forward secrecy on disk, mixing prior state + OS `getrandom(2)` + PID + monotonic clock (§6).

### Declined (and why)

8. **Library-internal multithreading (`blake3-servil` thread pool / `Pipeline` / custom worker pool):** removed in favor of single-threaded `blake3-servil-core = "=0.11.0"` so a signature library never installs hidden background worker threads or contends with a host application's runtime/sandbox.
9. **WOTS+C / SPHINCS+C** (Kudinov, Hülsing, Ronen, Yogev, IEEE S&P 2023, [ePrint 2022/778](https://eprint.iacr.org/2022/778)), **FORS+C**, and **PORS+FP + Octopus merging** (Abri & Katz, CRYPTO 2026, [ePrint 2025/2069](https://eprint.iacr.org/2025/2069); Aumasson & Endignoux, [ePrint 2017/933](https://eprint.iacr.org/2017/933)): declined in favor of maximum simplicity and zero tail variance. Under our `ST33 p99 ≤ 5.0 s` constraint, `FORS+C`'s `4.6×` geometric `p99` tail penalty erodes grinding headroom (uniform `7×5` `WOTS+C(z=1)` + `FORS+C(f=12)` reaches `6,384 B` at `4.51 s p99`, still above 8 KiB Base64), whereas zero-grinding `7×5` + byte-aligned `FORS(8, 20)` delivers constant `p99 = mean = 3.63 s` with zero grinding code.
10. **Tall top trees & on-disk caches (`15+3×6` / `12+3×7`):** a tall top tree slows constrained-device keygen (58 s on Ledger for `h_top = 12`) and cold desktop 1-shot signing; uniform `7×5` (`1 KiB` top tree, `0.17 ms` M6 keygen, `0.46 s` Ledger keygen) needs no disk or Flash cache.
11. **Custom inline/out-of-tree assembly inside `blincs`:** keeping `blincs` 100% `#![forbid(unsafe_code)]` on `blake3-servil-core` keeps assembly proof and maintenance inside `blake3-servil-core`.
12. **SPHINCS-G offline prepared-slot grinding** (Baiocchi & Vicari, [`sphincs-g-benchmarks`](https://research.projecteleven.com/articles/sphincs-g-benchmarks), Nov 2026): shines on tiny hardware-wallet-only budgets ($q \le 2^{14}$); at $q = 2^{32}$ ($h \ge 32$), online grinding takes hours on Ledger.
13. **Unhashed random episodes + top-tree pruning** (Baiocchi, Vena, Vicari, [`raising-sphincs-lifetime-budgets`](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets), Nov 2026; SPHINCS-PE [ePrint 2026/1708](https://eprint.iacr.org/2026/1708)), **CUTS / CUTS+C** ([ePrint 2026/2455](https://eprint.iacr.org/2026/2455), 2-use WOTS only), **SHRINCS / SHRIMPS** ([ePrint 2025/2203](https://eprint.iacr.org/2025/2203), stateful backup-rollback risk), **THINCS** (< 128 bits), **Gravity-SPHINCS** (unsalted collision resistance), **Top of the Hypercube (TSL / TL1C / TLFC)** ([ePrint 2025/889](https://eprint.iacr.org/2025/889), big-integer unranking complexity), and **Haraka / AES-NI**.

---

## 5. Single-pass salted content hashing

### The three message-hashing modes

Discussions of signature schemes often treat message hashing as a binary choice between "pure" signing and unsalted pre-hashing. In fact there are **three** distinct modes:

| Mode | How the message `M` is hashed | Passes over `M` | Hash assumption on `M` | Examples |
|---|---|---:|---|---|
| **1. Unsalted pre-hash** | Hash `M` first with a fixed hash `H(M)`, then sign the digest | 1 | Unsalted collision resistance | HashSLH-DSA, Ed25519ph |
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

- **Pure crash-only lifecycle (zero `Drop` implementations, zero background threads, zero `thread_local!` caches):** `Randomness` has no shutdown hook. Verification (`SignetId::verify` / `verify_with`) uses only fixed stack buffers (~2.5 KiB for `verify`, plus the `Sink`'s 26 KiB BLAKE3 `Hasher` for `verify_with`) — **zero heap allocations**. Signing (`Signet::from_seed` / `imprint`) allocates one transient local `SignWorkspace` (~475 KiB for cross-tree FORS batching, reading directly from `ws.out` with no separate FORS copy) freed on return. Every public operation is tested inside a **128 KiB** thread stack budget on the optimized test profile.
- **Types carry their rules & fail-stop contracts:** `Signet` holds one 32-byte seed and derives its `SignetId` and inline 1 KiB top tree on construction. `SecretKey` exposes only narrow secret-domain batch derivations (`ChainSecret`, `FewSecret`) and never exports a raw `TreeHasher`. `Signet::imprint` and `imprint_with` run `SignetId::verify_short` (~35 µs) before returning any imprint and panic on mismatch. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** routing verification and small-slice content hashing through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and passing zero-copy `&[[u8; 32]]` / `&[[u8; 48]]` slices brings 64-byte verification to **34.3 µs** (`29,200 / s`, `7.01 IPC` @ `4,616 MHz`), while signing batches all 20 FORS trees together across Merkle levels (`5,120 → 2,560 → 1,280 → 640 → 320 → 160`) on top of `blake3-servil-core 0.11.0`'s `&[[u8; 16/32/48]]` batching and `TreeHasher::hash_counter_range` for **1.24 ms** 1-core signing (`0.17 ms` `from_seed`, `1.41 ms` cold 1-shot).
- **Tiny base:** `#![forbid(unsafe_code)]`, three direct runtime dependencies in `signet` (`blake3-servil-core = "=0.11.0"`, `constant_time_eq = "=0.4.2"`, `getrandom = "=0.4.3"`, plus `signet-verify` dev-dependency for differential testing; 13 total workspace crates in `Cargo.lock`, all BLAKE3 + SHA-256 hashset-verified).

---

## 8. Terminology: `Signet`, `SignetId`, and `Imprint`

Traditional cryptographic terminology — "digital signatures" and "public keys" — borrows a metaphor from handwritten signatures bound to a human identity. As Mark S. Miller (*Robust Composition*) and Ka-Ping Yee & Mark S. Miller (*Capability Myths Demolished*) argue, centering security on *identification* ("who is this person?") instead of *authorization* ("should this action be allowed?") routinely pushes systems toward brittle PKIs, identity directories, and ambient access-control lists.

In reality, a cryptographic signing secret is a transferable **bearer** capability, not a person's hand — closer to a physical **signet** ring handed to an officeholder or steward than to a personal autograph:

- **`Signet`** (traditionally *signing key*): the secret bearer object (derived from a 32-byte seed) that exercises authority by making an imprint.
- **`Imprint`** (traditionally *signature*): the 7,392-byte mark pressed by a `Signet` onto a message or stream. Unlike Morris/Miller *Sealers/Unsealers* (which bundle encryption with brand checking), an `Imprint` provides transparent authenticity only — the message stays in the clear.
- **`SignetId`** (traditionally *verifying key*): a publisher's self-certifying 32-byte identifier and its complete BLINCS verifying key — in a 32-byte scheme like BLINCS, naming the signet and having everything needed to verify its imprints (`expected_publisher.verify(...)`) are literally the same 32 bytes.

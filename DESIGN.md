# BLINCS design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of `SPEC.md`, constrained-device-first parameter search inspiration, SLH-DSA-B with **julienif**, THINCS, CUTS, and the SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil-core`, SPHINCS/SPHINCS+/FIPS 205, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** BLINCS is shaped the way it is: the threat model, the $2^{32}$ signature budget, the constrained-device-first parameter search that selected **uniform `5×7` `WOTS+` + `FORS(11, 13)` (`5,888 B`, `4 KiB` top tree, zero counter grinding, zero disk cache, strictly single-threaded `blake3-servil-core`)**, every candidate technique we evaluated and why each was adopted or declined, the single-pass salted content hash, the lock-free content-addressed seed directory, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

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
- **Fixed-size signatures (5,888 bytes / 7,852 bytes Base64):** clears default Apache (`8,190 B`) and nginx (`8,192 B`) HTTP header limits regardless of whether the signed message is 0 bytes or 100 GiB.
- **Zero counter grinding & uniform `5×7` `WOTS+` / `FORS` structure:** bounded chain work with no counter-grinding loop, identical height-7 trees across all 5 layers, and compact specification and code (BLINCS-specific nibble/tweak encodings and BLAKE3 instantiation; not FIPS 205 interoperable).
- **Constrained-hardware friendly & zero disk cache:** the 4 KiB top tree builds in `0.65 ms` on 1 Apple M6 core (`4.12 ms` cold 1-shot sign) and `~1.8 s` on a Ledger ST33 Secure Element, eliminating any need for an on-disk or Flash key cache.
- **Strictly single-threaded execution:** runs entirely on the calling thread via `blake3-servil-core = "=0.11.0"` — zero background thread pools, zero cross-thread shared state, and clean linear scaling when a host application runs multiple signers across its own threads.
- **Minimize unnecessary reliance on collision resistance:** unsalted hashes belong where independent parties must derive the same name without coordinating (content addressing, Git object IDs, hashsets); salted hashes belong where one party vouches for content (signatures).

---

## 2. Why $2^{32}$ signatures at $\ge 128$ bits

The sizing target is one full `u32` of signatures per signing key: **$2^{32} = 4{,}294{,}967{,}296$** (10 signatures every second nonstop for **13.6 years**). Dropping the budget from FIPS 205's $2^{64}$ to $2^{32}$ cuts hypertree height nearly in half (`h = 35` vs. `63`), shrinking signatures 25% below `SLH-DSA-128s` (`5,888 B` vs. `7,856 B`) while signing **35× faster** and verifying **4.8× faster** than single-threaded `SLH-DSA-BLAKE3-128s` on Apple M6.

Under the single-key ideal-hash FORS leaf-cover model (`h = 35`, `k = 13` trees of $2^{11} = 2{,}048$ leaves, checked by `python3 tools/optimize.py --check`), the single-query cover exponent degrades gradually past $2^{32}$ and still stays above 128 bits even at $2\times$ the budget:

| Signatures signed by one key | Single-query FORS cover exponent (ideal-hash model) |
|---:|---:|
| $2^{32}$ (budget, 4.29B) | **132.5 bits** |
| $2^{33}$ ($2\times$, 8.59B) | **128.5 bits** |
| $2^{34}$ ($4\times$, 17.2B) | **123.8 bits** |
| $2^{35}$ ($8\times$, 34.4B) | **118.3 bits** |
| $2^{36}$ ($16\times$, 68.7B) | **111.9 bits** |

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
  - **Ledger Nano S+ / Flex / Stax** (`ST33K1M5` Secure Element: ~60 MHz ARM SC300/Cortex-M33, 160 KB RAM, 1.5 MB Flash, Rust `no_std`) — **our reference constrained signer**.
  - **Nitrokey 3 / SoloKey 2** (`LPC55S69` Cortex-M33 @ 150 MHz, 320 KB RAM, Rust `trussed`) and **Trezor Safe 3 / Safe 5** (`STM32U585` Cortex-M33 @ 160 MHz, 786 KB RAM, 2 MB Flash) — ~2.6× faster than `ST33K1M5`.
  - **Coldcard Mk4 / Q, Keystone 3 Pro, Passport, Jade** (`STM32L4/H7` @ 80–480 MHz or `ESP32-S3` @ 240 MHz) and **TrustZone OP-TEE / Nitro Enclaves / NetHSM**.

Using streaming Merkle `TreeHash` (`O(h)` stack), working RAM on embedded devices is only **~1.5 KiB** with **zero per-key Flash cache** (important for multi-account BIP-32/SLIP-10 wallets). At ~1,500 cycles per scalar Thumb-2 BLAKE3 compression (~25 µs/comp on 60 MHz `ST33K1M5`, ~9.4 µs/comp on 150–160 MHz Cortex-M33), the constrained-device constraint is **compute time**, not RAM: we filter to candidates that satisfy explicit **keygen (`SignetId`)** and **uncached signing** latency caps on `ST33K1M5`.

### Step 3 — Minimize desktop costs over the feasible set

Among all parameter sets that satisfy Steps 1 and 2 and clear the 8 KiB Base64 HTTP-header ceiling (`<= 5,950 B` raw), `tools/optimize.py` computes the desktop Pareto frontier on **signature bytes $B$**, **single-core warm signing $S_{\text{1T}}$**, and **single-core verification $V_{\text{1T}}$** (calibrated to Apple M6 `blake3-servil-core = "=0.11.0"`), and selects the **Leximin $L_\infty$** winner minimizing the worst desktop cost ratio $\max_i (x_i / x_{i,\min})$.

The mathematical winner is **uniform `5×7` (`h = 35`), nibble `WOTS+` (`w = 16`, 35 chains), `FORS(11, 13)` (`5,888 B` / `7,852 B` Base64)**:

| Profile (`q = 2^32`, `>= 128b` FORS, zero grinding) | Size (Base64) | FORS ($2^{32}/2^{33}$) | Top tree | Ledger `ST33` kg / **uncached sign** | Nitrokey 3 / Trezor uncached | M6 1-core kg / warm / cold / verify |
|---|---:|---|---:|---|---|---|
| **Adopted (`5×7`, `w=16`, `F(11,13)`)** | **5,888 B** (`7,852`) | **132.5 / 128.5 b** | **4 KiB** | **1.8 s / 11.2 s** | **4.2 s** | **0.65 ms** / 3.47 ms / **4.12 ms** / **26.3 µs** |
| *Previous desktop-tuned `12+3×7`, `w=16`, `F(10,16)`* | *5,616 B (`7,488`)* | *133.2 / 126.8 b* | *128 KiB* | *58.4 s / **65.1 s*** | *24.5 s* | *20.5 ms / 2.54 ms / 23.1 ms / 21.3 µs* |
| Ledger ≤ 10 s smallest (`6×6`, `w=32`, `F(10,14)`) | 5,760 B (`7,680`) | 131.3 / 127.6 b | 2 KiB | 1.4 s / 9.8 s | 3.7 s | 0.5 ms / 3.0 ms / 3.5 ms / 43.1 µs |
| Ledger ≤ 7 s nibble (`6×6`, `w=16`, `F(10,14)`) | 6,432 B (`8,576`) | 131.3 / 127.6 b | 2 KiB | 0.9 s / 6.5 s | 2.5 s | 0.3 ms / 2.1 ms / 2.4 ms / 28.4 µs |
| Ledger ≤ 5 s nibble (`6+6×5`, `w=16`, `F(9,16)`) | 7,088 B (`9,452`) | 131.6 / 127.4 b | 2 KiB | 0.9 s / 4.3 s | 1.6 s | 0.3 ms / 1.2 ms / 1.6 ms / 32.6 µs |

Reproduce directly:

```sh
python3 tools/optimize.py --max-bytes 5950 --max-ledger-keygen 3.0 --max-ledger-sign 12.0
```

---

## 4. Candidate techniques evaluated: adopted and declined

### Adopted in BLINCS

1. **BLAKE3 (`Keyed` + `DeriveKey`) as the sole primitive** (motivated by Project 11's [SLH-DSA-B](https://github.com/PQC-Suite-B/signatures) and [`docs/history/manifesto.md`](docs/history/manifesto.md)): fast on modern CPUs with single-core SIMD/SME2 batching and multi-GB/s streaming content hashing.
2. **Reduced $2^{32}$ lifetime budget** (vs. FIPS 205's $2^{64}$): cuts hypertree height nearly in half (`h = 35` vs. `63`).
3. **Uniform `5×7` hypertree with nibble `WOTS+` (`w = 16`, 35 chains) and `FORS(11, 13)` with zero counter grinding:** identical height-7 trees across all 5 layers, 4 KiB top tree (`0.65 ms` M6 keygen, `~1.8 s` Ledger ST33 keygen), bounded chain work, and zero counter-grinding machinery.
4. **256-bit internal message digest `D`:** verification consumes 178 bits of `D` (143 FORS index bits in `D[0..18]` + 35 hypertree address bits in `D[20..28]`), keeping coordinate selection directly in BLAKE3's native 32-byte digest output.
5. **Single-pass salted content hash (`Keyed(Keyed(K_content, e), M)`):** hashes arbitrarily large messages in one salted pass (~6.9–7.4 GB/s slice, ~4.3 GB/s zero-allocation 16 KiB streaming reader on 1 Apple M6 core) with no chunking layer and zero `Drop` implementations (§5).
6. **Strictly single-threaded execution via `blake3-servil-core = "=0.11.0"`:** zero worker threads, zero global pool, zero `abort()` runtime inside a library crate; uses `blake3-servil-core`'s zero-copy `&[[u8; 16/32/48]]` SIMD batching, `TreeHasher::hash_counter_range` for FORS leaf secrets, and `TreeHasher::on_this_core()` for verification (§7).
7. **Lock-free content-addressed seed directory + `getrandom` + `Signet::generate`:** zero `flock`, zero inode-unlink lock races, domain-separated filenames leaking zero bits of future salts or secrets, self-healing on crash/concurrency, and safe fresh signet generation layering our persisted RNG with OS `getrandom(2)` (§6).

### Declined (and why)

8. **Library-internal multithreading (`blake3-servil` thread pool / `Pipeline` / custom worker pool):** removed in favor of single-threaded `blake3-servil-core = "=0.11.0"` so a signature library never installs hidden background worker threads or contends with a host application's runtime/sandbox.
9. **WOTS+C / SPHINCS+C** (Kudinov, Hülsing, Ronen, Yogev, IEEE S&P 2023, [ePrint 2022/778](https://eprint.iacr.org/2022/778)), **FORS+C**, and **PORS+FP + Octopus merging** (Abri & Katz, CRYPTO 2026, [ePrint 2025/2069](https://eprint.iacr.org/2025/2069); Aumasson & Endignoux, [ePrint 2017/933](https://eprint.iacr.org/2017/933)): declined in favor of maximum simplicity (zero grinding, zero Octopus path merging, zero deduplication/sorting, bounded worst-case signing work).
10. **Tall top trees & on-disk caches (`15+3×6` / `12+3×7`):** a tall top tree slows constrained-device keygen (58 s on Ledger for `h_top = 12`) and cold desktop 1-shot signing; uniform `5×7` (`4 KiB` top tree, `0.65 ms` M6 keygen, `1.8 s` Ledger keygen) needs no disk or Flash cache.
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

## 6. Signer randomness: lock-free content-addressed seed directory

We reviewed the classic PRNG-with-input and seed-file literature (Barak & Halevi, [ePrint 2005/029](https://eprint.iacr.org/2005/029); Ferguson, Schneier & Kohno's Fortuna seed-file management in *Cryptography Engineering* Ch. 9; Dodis et al., [ePrint 2013/338](https://eprint.iacr.org/2013/338); Ristenpart & Yilek, NDSS 2010; Bellare & Tackmann, [ePrint 2016/290](https://eprint.iacr.org/2016/290)) and designed a minimal, lock-free startup state mechanism:

- **Why a content-addressed directory instead of a single `flock`-locked file:**
  - Advisory `flock` on a single overwritten file suffers from inode-replacement races (unlinking/recreating a file while live processes hold locks on the old inode silently breaks mutual exclusion) and relies on local-kernel locking semantics.
  - Instead, BLINCS stores state in a private directory (`0700` on Unix) containing immutable regular files named `blincs-r2-<32 hex>` holding up to 32 raw bytes.
- **Why the filename reveals zero bits of future salts or secrets:**
  - From `pool = Derive(CTX_MIX, material)`, BLINCS derives four independent domain-separated outputs: `file_id` (filename only), `next_seed` (32 bytes written inside the `0600` file), `run_key` (in-memory imprint draws), and `keygen_key` (in-memory keygen draws). Listing directory filenames reveals zero bits about `pool`, `next_seed`, `run_key`, `keygen_key`, or any future salt or signet.
- **Zero `flock`, zero PID, zero retry counter, zero temp-file dance, self-healing:**
  - On `Randomness::initialize`, BLINCS reads all `blincs-r2-<32 hex>` files in the directory (rejecting unexpected entries, symlinks, files `> 32` bytes, or empty directories without touching anything), mixes them with OS entropy (`getrandom(2)` / `getentropy`) and the monotonic clock, creates the new file atomically via `create_new` (`O_CREAT | O_EXCL`, no `fsync`), and unlinks the old filenames it read.
  - If two processes ever collide on `AlreadyExists`, `pool = Derive(CTX_MIX, pool)` advances the chain cleanly with no PID or retry counter. If a crash leaves a partial/0-byte file or concurrent startups leave two files, the next startup reads all of them, folds them into one fresh 32-byte file, and cleans up all old files automatically (~71 µs on Apple M6).
- **Safe `Signet::generate(&rng)`:**
  - Combines a domain-separated draw from `keygen_key` with fresh 32-byte OS `getrandom(2)` entropy (`Derive(CTX_GENERATE_SIGNET, keygen_draw || os_bytes)`), hedging against both weak OS RNGs and compromised disk seed state, while `Signet::from_seed` remains for restoring persisted seeds and deterministic vectors.

---

## 7. Crash-only design and single-threaded performance engineering

BLINCS adopts Servil Software Factory's engineering discipline:

- **Pure crash-only lifecycle (zero `Drop` implementations, zero background threads, zero `thread_local!` caches):** `Randomness` has no shutdown hook. Verification (`SignetId::verify` / `verify_reader`) uses only fixed stack arrays (~2.5 KiB for FORS/WOTS+ plus a local zero-initialized 16 KiB stack buffer for streaming `verify_reader`) — **zero heap allocations**. Signing (`Signet::from_seed` / `imprint`) allocates one transient local `SignWorkspace` freed on return, with no cross-call TLS secret buffers and no `RefCell` borrows across `Read` callbacks. Every public operation is tested inside a **128 KiB** thread stack budget on the optimized test profile.
- **Types carry their rules & fail-stop contracts:** `Signet` holds one 32-byte seed and derives its `SignetId` and inline 4 KiB top tree on construction. `Signet::imprint` and `imprint_reader` run `SignetId::verify_short` (~26 µs, < 1% of imprinting time) before returning any imprint and panic on mismatch. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** routing verification through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and passing zero-copy `&[[u8; 32]]` / `&[[u8; 48]]` slices brings 64-byte verification to **26.3 µs** (`38,000 / s`, `7.03 IPC` @ `4,607 MHz`), while signing uses `blake3-servil-core 0.11.0`'s direct-load `&[[u8; 16/32/48]]` batching and `TreeHasher::hash_counter_range` for **3.47 ms** 1-core signing (`0.65 ms` `from_seed`, `4.12 ms` cold 1-shot).
- **Tiny base:** `#![forbid(unsafe_code)]`, two runtime dependencies (`blake3-servil-core = "=0.11.0"` and `getrandom = "=0.4.3"`, 6 external crates total in `Cargo.lock`, all BLAKE3 + SHA-256 hashset-verified), zero dev-dependencies.

---

## 8. Terminology: `Signet`, `SignetId`, and `Imprint`

Traditional cryptographic terminology — "digital signatures" and "public keys" — borrows a metaphor from handwritten signatures bound to a human identity. As Mark S. Miller (*Robust Composition*) and Ka-Ping Yee & Mark S. Miller (*Capability Myths Demolished*) argue, centering security on *identification* ("who is this person?") instead of *authorization* ("should this action be allowed?") routinely pushes systems toward brittle PKIs, identity directories, and ambient access-control lists.

In reality, a cryptographic signing secret is a transferable **bearer** capability, not a person's hand — closer to a physical **signet** ring handed to an officeholder or steward than to a personal autograph:

- **`Signet`** (traditionally *signing key*): the secret bearer object (derived from a 32-byte seed) that exercises authority by making an imprint.
- **`Imprint`** (traditionally *signature*): the 5,888-byte mark pressed by a `Signet` onto a message or stream. Unlike Morris/Miller *Sealers/Unsealers* (which bundle encryption with brand checking), an `Imprint` provides transparent authenticity only — the message stays in the clear.
- **`SignetId`** (traditionally *verifying key*): a publisher's self-certifying 32-byte identifier and its complete BLINCS verifying key — in a 32-byte scheme like BLINCS, naming the signet and having everything needed to verify its imprints (`expected_publisher.verify(...)`) are literally the same 32 bytes.

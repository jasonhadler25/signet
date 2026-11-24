# BLINCS design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of `SPEC.md`, grinding-vs-signing-time feedback, irregular hypertrees + upper-layer caching, SLH-DSA-B with **julienif**, THINCS, CUTS, and the SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree / partial-caching work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil`, SPHINCS/SPHINCS+/FIPS 205, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness/hypertree papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** BLINCS is shaped the way it is: the threat model, the $2^{32}$ signature budget, the minimax tradeoff and protocol simplification ladder that led to **`12 + 3×7` textbook `WOTS+` + `FORS` (`5,616 B`, `128 KiB` top tree, zero counter grinding, zero disk cache)**, every candidate technique we evaluated (both earlier literature and Project 11's latest hash-based signature work) and why each was adopted or declined, the single-pass salted content hash, the startup-only signer randomness, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

---

## 1. Goals and threat model

BLINCS is designed for a dishonest submitter who does **not** hold the signing key, interacting with an honest signer and honest verifiers. The attacker may:

- observe up to $2^{32}$ signatures and trigger the honest signer to sign messages the signer approves,
- possess a structural weakness in BLAKE3 that produces **collisions** cheaply without yielding **second preimages**, and
- spend enormous classical compute (a 128-bit security target; BLAKE3 itself claims 128-bit security).

The design goals that follow:

- **Post-quantum, hash-only assumptions:** security rests on symmetric hash properties of BLAKE3, not lattices, pairings, or factoring.
- **Stateless signing:** a signing key can be copied across machines, restored from backups, or run in short-lived processes (such as `git commit`) without risking catastrophic one-time-key reuse.
- **Short verifying key (32 bytes):** small enough to embed directly in a name or identifier a user already acquires (for example, a repository or branch name).
- **Fixed-size signatures (5,616 bytes / 7,488 bytes Base64):** clears default Apache (`8,190 B`) and nginx (`8,192 B`) HTTP header limits with 702 B to spare, regardless of whether the signed message is 0 bytes or 100 GiB.
- **Zero counter grinding & WOTS+ / FORS structure:** bounded chain work with no grinding tail variance, ~40% simpler specification and code, and WOTS+ + FORS building blocks (BLINCS-specific nibble/tweak encodings and BLAKE3 instantiation; not FIPS 205 interoperable).
- **No on-disk key cache:** cold key derivation builds the 128 KiB top hypertree in `5.43 ms` on Apple M6 (`6.16 ms` total cold 1-shot sign), eliminating cache file formats, cache authentication, and cache invalidation.
- **Minimize unnecessary reliance on collision resistance:** unsalted hashes belong where independent parties must derive the same name without coordinating (content addressing, Git object IDs, hashsets); salted hashes belong where one party vouches for content (signatures).

---

## 2. Why $2^{32}$ signatures at $\ge 128$ bits

The sizing target is one full `u32` of signatures per signing key: **$2^{32} = 4{,}294{,}967{,}296$** (10 signatures every second nonstop for **13.6 years**). Dropping the budget from FIPS 205's $2^{64}$ to $2^{32}$ cuts hypertree height nearly in half (`h = 33` vs. `63`), shrinking signatures well below `SLH-DSA-128s` (`7,856 B`) while signing **167× faster** and verifying **5.0× faster** than `SLH-DSA-BLAKE3-128s` on Apple M6.

Security degrades gradually if a key overshoots the budget, rather than collapsing at a cliff (exact FIPS 205 / SPHINCS+ FORS cover bound for `h = 33`, `k = 16` trees of $2^{10} = 1{,}024$ leaves, checked by `python3 tools/optimize.py --check`):

| Signatures signed by one key | FORS cover bound (classical ROM) |
|---:|---:|
| $2^{32}$ (budget, 4.29B) | **133.2 bits** |
| $2^{33}$ ($2\times$, 8.59B) | **126.8 bits** |
| $2^{34}$ ($4\times$, 17.2B) | **119.3 bits** |
| $2^{35}$ ($8\times$, 34.4B) | **110.6 bits** |

---

## 3. Minimax tradeoff algorithm, protocol simplification, and why `12 + 3×7` won

Stateless hash-based signatures trade off three costs with completely different units:

1. **Signature size $B$** (bytes — packets, commits, HTTP headers, certificates, logs),
2. **Signing time $S$** (milliseconds — interactive latency, release pipelines, servers), and
3. **Verification time $V$** (microseconds — high-fanout verifiers, package registries, constrained clients).

Following Ron Rivest's "minimax strategy" ([`docs/history/manifesto.md`](docs/history/manifesto.md)) — *perform well enough for many use cases instead of maximizing one metric to the detriment of others* — we use **one simple, transparent, zero-knob algorithm** whose sole objective is to **reduce the magnitude of the worst problem**.

### Leximin $L_\infty$ ratio above the physical Pareto floor

1. **Fix the hard requirements first:** $\ge 128$ bits of classical security at the target signature budget, and an optional top-tree cap.
2. **Compute the physical Pareto floor** $(B_{\min}, S_{\min}, V_{\min})$: the best physically achievable value of each dimension anywhere on the valid frontier under directly measured Apple M6 `blake3-servil` timings ([`BENCHMARKS.md`](BENCHMARKS.md) §3–4).
3. **Measure each problem dimensionlessly** as its multiplicative blowup above the physical floor:
   $$r_B = \frac{B}{B_{\min}}, \qquad r_S = \frac{S}{S_{\min}}, \qquad r_V = \frac{V}{V_{\min}}.$$
4. **Minimize the worst problem first (Leximin $L_\infty$):** sort each candidate's three ratios descending, $\big(r_{(1)} \ge r_{(2)} \ge r_{(3)}\big)$, and pick the candidate that minimizes that sorted tuple lexicographically.

Why $L_\infty$ beats $L_1$ and $L_2$ for minimax: plain product $B \cdot S \cdot V$ ($L_1$ in log-space) happily accepts a 10× blowup on one axis to shave 10× off another, and quadratic log-regret $L_2$ still lets signature size drift up to 7.8–8.8 KiB to polish signing from `0.31 ms` to `0.25 ms`. **Leximin $L_\infty$ refuses to make the worst problem worse just to polish an axis that is already fast**, with zero invented ceilings or hand-tuned weights and complete invariance to units and search caps.

### Empirical byte thresholds vs. BLINCS's physical range (`~2.9–6.2 KiB` at $2^{32}$)

Both pure Leximin $L_\infty$ and smooth exchange-rate models must be checked against **real-world byte cliffs**. Checking primary specifications and live-Internet measurements shows which limits are unreachable for *any* 128-bit stateless hash-based signature ($\ge 2{,}928$ B at $2^{32}$) and which sit directly inside BLINCS's range:

| Protocol / storage threshold | Primary-source limit | What breaks when exceeded | Impact on BLINCS (`3.9–6.2 KiB`) |
|---|---|---|---|
| **DNSSEC over UDP** | **`1,232 B`** (RFC 9715 / IPv6 1,280 B min MTU) or **`1,400 B`** IPv4 | IP fragmentation or mandatory TCP fallback | Unreachable for all stateless HBS (`>= 2,928 B`). |
| **PostgreSQL inline row (`TOAST`)** | **`2,000 B`** (`TOAST_TUPLE_THRESHOLD`, 1/4 of 8 KiB page) | Column moved out-of-line to TOAST table | Unreachable for all stateless HBS. |
| **QUIC anti-amplification (unvalidated client)** | **`3,600 B`** (`3 × 1,200 B` min Client Initial, RFC 9000 §8.1), leaving ~`2,300 B` after ML-KEM + framing | Extra RTT unless client pads Initial or uses Retry | Unreachable for all stateless HBS. |
| **HTTP Cookie** | **`4,096 B`** total per cookie (RFC 6265 §6.1; ~`3,000 B` raw after Base64) | Cookie rejected or truncated by browsers | Unreachable for all stateless HBS after Base64. |
| **Single 4 KiB OS / DB page (binary storage)** | **`4,096 B`** (SQLite default `page_size = 4096`; Linux/x86-64 page; macOS arm64 uses `16 KiB`) | Binary record spills to a 2nd 4 KiB page | Tightening below 4 KiB (`3,988 B` early draft) forced `w = 32` + `WOTS+C` + `PORS+FP` grinding (`16.4 ms` sign). |
| **TCP segment count (`MSS = 1,448–1,460 B`)** | **`4,344 B`** (3 MSS), **`5,792 B`** (4 MSS), **`7,240 B`** (5 MSS) | +1 TCP packet per crossing | `5,616 B` fits cleanly in **4 TCP segments** (`<= 5,792 B`). |
| **HTTP single header limit (Base64-encoded — RFC 9421, proxies, APIs)** | **Apache `LimitRequestFieldSize = 8,190 B`**; **nginx `large_client_header_buffers = 4 × 8k` (`8,192 B`)** | **Hard HTTP `400`/`431` request failure**! Allowing Base64 `4/3` expansion + ~200 B header name/params puts the raw binary ceiling at **`~5,950 B`** | **Hard real-world ceiling:** `6,152 B` Base64-encoded is `8,204 B` and fails default Apache & nginx. **`5,616 B` Base64-encoded is `7,488 B` (702 B margin).** |
| **TLS 1.3 `IW10` & middlebox breakage (Cloudflare live-Internet measurements)** | **RFC 6928 `IW10 = 14,600 B`** (~**`10 kB`** extra cert/sig budget); Bas Westerbaan (Cloudflare) measured steep middlebox/client failure jumps at `10 kB` and `30 kB` | Hard middlebox failure + extra RTT | **1-sig Merkle Tree Certificates** (`draft-ietf-plants-merkle-tree-certs`, ~500 B proof + 1.1 kB ML-KEM): **`5,616 B` fits comfortably under `10 kB`**. |
| **Git `pkt-line`, TLS struct, OpenSSH packet** | `65,520 B` (Git `pkt-line`), `65,535 B` (TLS `2^16-1`), `256 KiB` (OpenSSH) | Protocol limit | Far above BLINCS; no cliff. |

Notice also the opposing hardware trends: faster SIMD/matrix units and core counts push toward smaller bytes, while proliferating cheap low-power single-core CPUs (Cortex-M, RISC-V microcontrollers, smartcards) push toward lower cycle counts and smaller RAM. Leximin $L_\infty$ checked against the one live hard ceiling (`~5,950 B` raw for 8 KiB HTTP headers) balances both.

### Protocol simplification ladder at `~5.5–5.9 KiB` ($q = 2^{32}$)

Once Leximin $L_\infty$ placed BLINCS in the `~5.5–5.9 KiB` band (instead of squeezing below 4 KiB as in our earliest `0.1.0` draft), a striking simplification opened up: **we could delete every piece of non-standard grinding machinery (`WOTS+C`, `PORS+FP`, Octopus merging, deduplication, sorting, trailing-zero padding checks, and `3`-bit packing) while *shrinking* signature size, *raising* the security margin, eliminating signing tail-latency variance, and returning to textbook FIPS 205 (`WOTS+` + `FORS`) proofs.**

Comparing each simplification step on Apple M6 (`blake3-servil = "=0.10.0"`, all clearing the 8 KiB Apache/nginx HTTP header cliff):

| Simplification step ($q = 2^{32}$) | Size (Base64) | Sign `12T` | Cold 1-shot | Verify (1c) | Keygen `12T` | Top tree | Security ($2^{32} / 2^{33} / 2^{34}$) | Protocol machinery eliminated |
|---|---:|---:|---:|---:|---:|---:|---|---|
| **Step 0 — Full (`WOTS+C` + `PORS+FP` + `15+4×5` `w=8`)** | 5,944 B (`7,928`) | 0.35 ms | 27.0 ms | 20.1 µs | 26.6 ms | 1 MiB | 129.9 / 124.8 / 118.9 b | *(Baseline: WOTS+C grind, PORS+FP grind, Octopus merging, dedup/sort, zero-pad check, 3-bit packing, 1 MiB disk cache)* |
| **Step 1a (`Plain WOTS+` `w=16` + `FORS(8,19)` + `15+3×7`)** | 5,584 B (`7,448`) | 0.71 ms | 45.3 ms | 26.3 µs | 44.6 ms | 1 MiB | 133.5 / 128.8 / 123.4 b | Deletes `WOTS+C`, `PORS+FP`, ALL counter grinding, Octopus merging, dedup/sort, zero-pad checks, and FORS bit-unpacking. |
| **Step 1b (`Plain WOTS+` `w=16` + `FORS(10,16)` + `15+3×6`)** | 5,616 B (`7,488`) | **0.44 ms** | 40.8 ms | 26.2 µs | 40.3 ms | 1 MiB | 133.2 / 126.8 / 119.3 b | Same zero-grinding textbook `WOTS+` + `FORS`, faster warm sign, but needs an authenticated 1 MiB disk cache for fast 1-shot signers. |
| **Adopted (`Plain WOTS+` `w=16` + `FORS(10,16)` + `12+3×7`)** | **5,616 B** (`7,488`) | **0.73 ms** | **6.16 ms** | **25.3 µs** | **5.43 ms** | **128 KiB** | **133.2 / 126.8 / 119.3 b** | **Same exact 5,616 B wire size, 25.3 µs verify, and 133.2-bit security as `15+3×6`, while cutting top-tree RAM 8× (`128 KiB`) and cold `from_seed` 7.4× (`5.43 ms`) — deleting the entire disk cache format and API.** |
| **Step 2a (uniform `5×7`, `FORS(11,13)`)** | 5,888 B (`7,852`) | 1.05 ms | 1.35 ms | 31.3 µs | 0.3 ms | 4 KiB | 132.5 / 128.5 / 123.8 b | Also deletes `TOP_HEIGHT != LOWER_HEIGHT`, at the cost of +272 B, +44% slower warm sign, and +24% slower verify. |
| **Step 2b (uniform `4×8`, `FORS(12,13)`)** | 5,488 B (`7,320`) | 1.59 ms | 1.99 ms | 26.1 µs | 0.4 ms | 8 KiB | 131.3 / 124.9 / 117.4 b | Deletes `TOP_HEIGHT != LOWER_HEIGHT` and saves 128 B, but more than doubles warm signing time (`1.59 ms` vs `0.73 ms`). |

### Why `12 + 3×7` (zero disk cache) beats `15 + 3×6` (1 MiB disk cache)

Moving 3 levels from the top hypertree down to the 3 lower layers (`15 + 3×6` → `12 + 3×7`):

- Keeps **identical wire size** (`5,616 B` / `7,488 B` Base64), **identical security** (`133.2 / 126.8 / 119.3` bits), and **slightly faster verification** (`25.3 µs` on 1 core).
- Shrinks top-tree memory **8×** (`1 MiB` → `128 KiB`) and speeds up cold `Signet::from_seed` **7.4×** (`40.33 ms` → **`5.43 ms`** on `blake3-servil = "=0.10.0"`, **`3.64 ms`** on `origin/next` with [`servil-software-factory/BLAKE3#509`](https://github.com/servil-software-factory/BLAKE3/issues/509)).
- Makes cold 1-shot signing (**`6.16 ms`** today, projected `~3.9 ms` with `#509`) fast enough for interactive CLIs like `git commit` with **zero disk cache** — deleting `save_top_tree_cache`, `from_seed_with_cache`, `CTX_TOP_CACHE`, `BLINCS-TOP-V1`, and ~150 lines of cache file I/O, locking, and MAC verification.
- Costs only `+0.29 ms` on warm multi-signature servers (`0.73 ms` today = `1,370 sigs/s`, projected `~0.46 ms` with `#509`), while keeping `TOP_HEIGHT = 12` as a single constant rather than adding any extra layer or runtime mode.

*(Our earlier `3,988 B` `0.1.0` draft — `4×9`, `w = 32`, `WOTS+C`, `PORS+FP` with `m = 103`, `16.4 ms` 1-core sign, `33.3 µs` verify — remains reproducible via `python3 tools/optimize.py --grinding-sweep` and `--check` for historical comparison.)*

---

## 4. Candidate techniques evaluated: adopted and declined

This section records every hash-based signature technique we evaluated — both the earlier literature and Project 11's latest research — along with the decision and reason.

### Adopted in BLINCS

1. **BLAKE3 (`Keyed` + `DeriveKey`) as the sole primitive** (motivated by Project 11's [SLH-DSA-B](https://github.com/PQC-Suite-B/signatures) and [`docs/history/manifesto.md`](docs/history/manifesto.md)): 2–5× faster than SHA-256 and ~15× faster than SHAKE on modern CPUs, multi-GB/s streaming content hashing, and zero additional cryptographic assumptions for users already relying on BLAKE3.
2. **Reduced $2^{32}$ lifetime budget** (vs. FIPS 205's $2^{64}$): 4.29 billion signatures (10/s nonstop for 13.6 years) with graceful degradation past the budget (`126.8` bits at $2^{33}$, `119.3` bits at $2^{34}$), cutting hypertree height nearly in half (`h = 33` vs. `63`).
3. **Nibble `WOTS+` (`w = 16`, 35 chains) and `FORS` (`16` trees of `1,024` leaves) with zero counter grinding:** bounded chain work (no grinding tail latency), clean byte/nibble arithmetic, and ~40% smaller spec and codebase than `WOTS+C` + `PORS+FP` (BLINCS-specific encodings and BLAKE3 instantiation; not FIPS 205 interoperable).
4. **Irregular hypertree (`12 + 3×7`) with in-memory 128 KiB top tree and no disk cache** (inspired by Project 11's irregular-hypertree work — Alessandro Baiocchi, Matteo Vena, Matteo Vicari, and Conor Deegan: [Companion Guide](https://research.projecteleven.com/articles/sphincs-parameter-explorer-companion-guide), [Raising SPHINCS-like lifetime budgets](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets); and Zhen Qin, Siwei Sun, and Fangyu Zheng, ASIACRYPT 2026, [ePrint 2025/2236](https://eprint.iacr.org/2025/2236)): putting 12 levels in the in-memory top tree gives `5,616 B` signatures, `0.73 ms` warm signing, and `25.3 µs` verification while keeping cold keygen at `5.43 ms` so no on-disk cache file is needed.
5. **256-bit internal message digest `D`:** verification consumes 193 bits of `D` (160 FORS index bits + 33 hypertree address bits; the upper 63 bits are unused), keeping coordinate selection directly in BLAKE3's native 32-byte digest output.
6. **Single-pass salted content hash (`Keyed(Keyed(K_content, e), M)`):** eliminates pre-hash collision exposure with no chunking layer, keeping signatures fixed-size, zero `Drop` implementations, and multi-core streaming up to **27.7–28.6 GB/s** on Apple M6 via `blake3-servil` `Pipeline::room()` / `update_multithreaded` (§5).
7. **Default multithreading via `blake3-servil` + coarse leaf-parallel signing wave** (motivated by Conor Deegan's independent-hash parallelism note): builds all 4,096 top-tree leaves in parallel during `from_seed`, and builds all 384 lower-layer WOTS+ leaves and all 16 FORS trees in one parallel wave during `sign` / `sign_reader` (1 SME2 core + worker cores via `TreeHasher::on_this_core()`), while verification of small messages stays single-core on `TreeHasher::on_this_core()` to avoid Apple SME2 short-burst downclocking (§7).

### Declined (and why)

8. **WOTS+C / SPHINCS+C** (Mikhail Kudinov, Andreas Hülsing, Eyal Ronen, and Eylon Yogev, IEEE S&P 2023, [ePrint 2022/778](https://eprint.iacr.org/2022/778)) and **PORS+FP + Octopus merging** (Mehdi Abri and Jonathan Katz, CRYPTO 2026, [ePrint 2025/2069](https://eprint.iacr.org/2025/2069); Jean-Philippe Aumasson and Guillaume Endignoux, [ePrint 2017/933](https://eprint.iacr.org/2017/933)):
   - Implemented in our earliest `0.1.0` `3,988 B` draft, then deliberately replaced by textbook `WOTS+` + `FORS`. Once Leximin $L_\infty$ moved BLINCS into the `~5.5–5.9 KiB` band, `WOTS+` + `FORS` at `5,616 B` actually came out *smaller* and *higher-security* than `WOTS+C` + `PORS+FP` at `5,944 B` while deleting all counter grinding, tail-latency variance, Octopus path merging, deduplication, sorting, and trailing-zero padding checks (§3).
9. **On-disk 1 MiB top-tree cache (`15 + 3×6`, `BLINCS-TOP-V1`):**
   - Implemented and benchmarked (`40.3 ms` cold, `203 µs` cached, `0.44 ms` sign), then removed in favor of `12 + 3×7` (`5.43 ms` cold, `0.73 ms` sign, `128 KiB` RAM) so callers manage only one 32-byte seed and one 48-byte randomness state file with zero cache-file format or key-derivation context.
10. **Custom inline/out-of-tree assembly inside `blincs`:**
    - We built and verified standalone AArch64 SME2 + NEON prototypes (shared upstream on [`servil-software-factory/BLAKE3#509`](https://github.com/servil-software-factory/BLAKE3/issues/509)), confirming that ~80–85% of the speedup comes from general, scheme-agnostic `blake3-servil` improvements (`Packed<16/32/48/64>`, zero-spill NEON `p10/p11`, and `Pipeline::batch`). Keeping `blincs` 100% `#![forbid(unsafe_code)]` on `blake3-servil` captures those gains automatically across all architectures with zero assembly maintenance burden in `blincs`.
11. **SPHINCS-G offline prepared-slot grinding** (Alessandro Baiocchi and Matteo Vicari, Project 11, [`sphincs-g-benchmarks`](https://research.projecteleven.com/articles/sphincs-g-benchmarks), Nov 2026): precomputes $B$ random hypertree leaf slots before the message arrives, then grinds `R` online ($2^h / B$ expected tries). Shines on extreme-latency hardware wallets with $h = 24..26$; at $h = 33$, online grinding takes ~1.5–3 seconds on M6 — orders of magnitude slower than direct BLINCS signing (`0.73 ms`).
12. **Unhashed random episodes + top-tree pruning** (Alessandro Baiocchi, Matteo Vena, and Matteo Vicari, Project 11, [`raising-sphincs-lifetime-budgets`](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets), Nov 2026; inspired by Chongxu Ren, Kaiyi Zhang, Haorui Cui, and Hongbo Yu's SPHINCS-PE, [ePrint 2026/1708](https://eprint.iacr.org/2026/1708)): keeping $h''$ bits outside the message digest loses $h''$ bits of security and buys nothing without SPHINCS-G grinding; pruning introduces per-signer budget choices that leak over time.
13. **CUTS / CUTS+C** (Jamie Judd, Louis Tajan, Conor Deegan, and Furkan Akal, Project 11, [ePrint 2026/2455](https://eprint.iacr.org/2026/2455), Oct 2026): designed as a safer drop-in for stateful 2-use WOTS; beyond 2 uses CUTS loses security faster than FORS and requires big-integer combinatorial ranking/unranking.
14. **Stateful-primary + stateless-fallback hybrids (SHRINCS, SHRIMPS)** (Mikhail Kudinov and Jonas Nick, [ePrint 2025/2203](https://eprint.iacr.org/2025/2203); reviewed by Conor Deegan and Alex Pruden in [`a-review-of-shrincs`](https://research.projecteleven.com/articles/a-review-of-shrincs)): restoring a backup or VM snapshot silently rolls back the one-time counter and leaks the key.
15. **THINCS / truncated 96–112-bit hashes** (Conor Deegan, [`conor-deegan/THINCS`](https://github.com/conor-deegan/THINCS)): drops below our 128-bit security target (`conor-deegan/THINCS#1`).
16. **Gravity-SPHINCS / unsalted PORS** (Jean-Philippe Aumasson and Guillaume Endignoux, [ePrint 2017/933](https://eprint.iacr.org/2017/933)): relies on collision resistance of the hash function where salted hashing avoids it.
17. **Top of the Hypercube retry-free encodings (TSL / TL1C / TLFC)** (Dmitry Khovratovich, Mikhail Kudinov, and Benedikt Wagner, CRYPTO 2025, [ePrint 2025/889](https://eprint.iacr.org/2025/889)): requires much longer chains and combinatorial ranking for modest byte savings.
18. **FORS+C** (Mikhail Kudinov, Andreas Hülsing, Eyal Ronen, and Eylon Yogev, [ePrint 2022/778](https://eprint.iacr.org/2022/778)): adds counter grinding for ~240 B; declined alongside `WOTS+C` and `PORS+FP`.
19. **Unreviewed 2026 few-time preprints** (BPORS+FP 2026/1328, BPORS-C+BFP 2026/2374, BGS-CC 2026/2502): each stacks a newer, unreviewed counting argument; left out until settled.
20. **Hardware-specific hashes (Haraka / AES-NI):** poor portability and adds a second cryptographic assumption beyond BLAKE3.

---

## 5. Single-pass salted content hashing

### No pre-hash API

BLINCS exposes `sign` / `sign_reader` and `verify` / `verify_reader`, and no entry point accepting a precomputed digest. Pre-hashing exposes callers to collision attacks on the pre-hash; hashing the stream directly inside BLINCS keeps the signature bound to a freshly chosen salt and runs at full BLAKE3 speed.

### Why single-pass salted BLAKE3 instead of two-pass chunking

When signing with a 32-byte per-signature draw `draw`, the signer computes:

```text
e     = Keyed(K_salt, draw)[..16]       # 16-byte per-signature salt, carried in the signature
K_msg = Keyed(K_content, e)             # 32-byte per-signature message key
h_msg = Keyed(K_msg, M)                 # 32-byte single-pass keyed BLAKE3 hash of M
short = e || h_msg                      # 48 bytes
```

Earlier drafts hashed 256 KiB chunks in two sequential keyed passes (`Keyed(Keyed(chunk_key_i, M_i), M_i)`). Benchmarking all four content-hashing options on Apple M6 (`100 MiB`, `blake3-servil = "=0.10.0"`, [`BENCHMARKS.md`](BENCHMARKS.md) §3.4) showed why single-pass salted BLAKE3 won decisively:

| Content-hashing design (100 MiB, Apple M6) | 1 core | 12 cores (`blake3-servil`) | Complexity & trade-off |
|---|---:|---:|---|
| Chained 2-pass 256 KiB chunks *(earlier draft)* | 3,322 MB/s | 3,324 MB/s *(3,990 MB/s via `Pipeline`)* | Sequential chaining blocks parallelism; `< 512 KiB` stays 1T in `hash_multithreaded`; requires 256 KiB buffer & `Drop` zeroing |
| Chained 2-pass 1 MiB chunks | 3,701 MB/s | 8,843 MB/s (`hash_multithreaded`) | Still hashes every byte twice; 1 MiB buffer |
| Unchained parallel 2-pass 256 KiB chunks | ~3,320 MB/s | 16,592 MB/s *(custom 12-core split)* | Needs chunk Merkle tree & custom worker split; still hashes every byte twice |
| **Single-pass salted BLAKE3 *(adopted)*** | **7,400 MB/s** | **30,409–30,629 MB/s** (`Pipeline::room()` / `hash_multithreaded`) | Zero chunking layer in `SPEC.md`, zero chunk pool / zero `Drop` impls, >2× faster on 1 core and **9.2× faster** on 12 cores |

Whenever `draw` is fresh (every normal signature), `e` is unpredictable to the submitter until after the signature is published, so `Keyed(K_msg, M)` rests on **randomized target-collision resistance** of keyed BLAKE3 (zero collision-resistance assumption). If `draw` ever repeats identically (such as after a VM snapshot clone without re-running `initialize`, or a triple reset of disk, OS RNG, and clock), content hashing falls back to 128-bit known-key collision resistance of 256-bit keyed BLAKE3 — while signing-key secrecy remains unaffected and `R = Keyed(K_R, e || h_msg)[..16]` still limits advance steering on distinct messages (WOTS+ safety on hypertree address collisions comes from signing the same FORS/subtree root at that position).

---

## 6. Signer randomness: startup-only state without `fsync`

We reviewed the classic PRNG-with-input and seed-file literature (Boaz Barak & Shai Halevi, [ePrint 2005/029](https://eprint.iacr.org/2005/029); Niels Ferguson, Bruce Schneier & Tadayoshi Kohno's Fortuna seed-file management in *Cryptography Engineering* Ch. 9; Yevgeniy Dodis, David Pointcheval, Sylvain Ruhault, Damien Vergnaud & Daniel Wichs, [ePrint 2013/338](https://eprint.iacr.org/2013/338); Thomas Ristenpart & Scott Yilek, NDSS 2010; Mihir Bellare & Björn Tackmann, [ePrint 2016/290](https://eprint.iacr.org/2016/290)) and kept only what serves BLINCS:

- **Why no per-signature syscall or disk write:** signing at 10–1,000+/s should not pay OS entropy syscalls or storage flushes per signature. `Randomness::initialize` reads the 48-byte state file, 32 bytes from `/dev/urandom`, and the monotonic clock **once** at process startup, mixes them into `(next_seed, run_key)`, updates bytes `8..48` in place under an exclusive `flock`, and then serves every `draw()` from memory via `Keyed(run_key, u64_le(n))`.
- **Why no forward-security ratchet, entropy pools, entropy estimator, or shutdown hook:** those mechanisms protect secret PRNG outputs after a state compromise. In BLINCS, `Randomness` sits beside the signing key in the same process and its only output is the published content salt `e`. What `draw` needs is **non-repetition**, not secrecy — and secrecy of `e` against an external submitter already comes from `K_salt` derived from the caller-supplied signing key.
- **Why caller-supplied seed (no OS-RNG `Signet::generate`):** on Linux, `/dev/urandom` is non-blocking by ABI at early boot. That gap does not threaten BLINCS's imprinting salt (because `K_salt` is mixed into every `e`), whereas signet creation genuinely needs full entropy. Requiring the caller to supply the 32-byte seed puts seed-generation entropy at the boundary that owns it.
- **Why explicit `Randomness::create`:** silently creating a missing state file hides misconfigured paths and risks restarting from empty state; refusing to overwrite (`create_new`) protects existing files.
- **Why monotonic clock (`Instant::hash`):** immune to NTP clock stepping and requires no `unsafe` code or platform FFI dependency; treated strictly as opaque local diversification.
- **Why `initialize` skips `fsync` (while `create` syncs once):**
  - On one-shot signers invoked per commit (such as `git commit`), blocking on `F_FULLFSYNC` adds milliseconds on SSDs and far more on busy or networked storage — and modern disks and VM snapshots can roll back state regardless of `fsync`.
  - Without `fsync`, `write()` still updates the kernel page cache immediately, so back-to-back processes always see the incremented counter and rotated seed; only a crash/power loss before dirty-page flush reverts the file, and on reboot `/dev/urandom` and the monotonic clock still vary `draw`.
  - Even if disk, OS RNG, and clock are reset together so `draw` repeats identically, BLINCS never leaks the signing key, `R = Keyed(K_R, e || h_msg)[..16]` still limits advance steering on distinct messages, and WOTS+ safety on hypertree address collisions comes from signing the same FORS/subtree root at that position. Only content hashing downgrades from randomized target-collision resistance to 128-bit known-key collision resistance of 256-bit keyed BLAKE3 `Keyed(K_msg, M)`.

---

## 7. Crash-only design and performance engineering

BLINCS adopts Servil Software Factory's engineering discipline:

- **Pure crash-only lifecycle (zero `Drop` implementations, no unwind-recovery state machines):** `Randomness` has no shutdown hook; a sudden crash loses no teardown invariant. Worker scratch workspaces (`WorkerScratch`) and verifier workspaces (`VerifyWorkspace`) are allocated once per thread and kept until thread exit, avoiding per-call allocation, page-fault zeroing, and TLB shootdowns. An internal panic inside a parallel wave aborts the process cleanly rather than attempting half-baked unwind recovery or leaving waiters hung. Streaming readers (`sign_reader` / `verify_reader`) use a fresh zero-initialized local 16 KiB buffer ($< 16$ KiB) or a fresh per-call `Pipeline` ($\ge 16$ KiB, zeroing each newly acquired room slice before `Read::read`) with no shared cross-caller buffer pool, no held `RefCell` borrow across `Read` callbacks, and every public operation tested inside a **128 KiB** thread stack budget on the optimized test profile.
- **Types carry their rules & fail-stop contracts:** `Signet` holds one 32-byte seed and derives its `SignetId` and in-memory 128 KiB top tree on construction (so an inconsistent `(seed, id)` pair cannot exist). `Signet::imprint` and `imprint_reader` run `SignetId::verify_short` (~25 µs, ~3.5% of imprinting time) before returning any imprint and panic if self-verification fails. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** measuring BLINCS with `bench-hashes`'s `clocks` crate revealed that calling Apple M6's SME2 kernels for verification's tiny 16–35-element batches downclocked the P-core from ~4,611 MHz to ~4,050 MHz and spent tens of thousands of extra cycles entering/exiting streaming mode. Routing verification's tree/chain hashes through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and batching each level of `fors_verify` brings 64-byte verification to **25.3 µs** (39,500/s, 5.58 IPC @ 4,611 MHz) while multi-core content verification runs at **28.2–28.6 GB/s** (`16–100 MiB` slices) and **27.7 GB/s** (`100 MiB` zero-copy `Pipeline` streams).
- **Tiny base:** `#![forbid(unsafe_code)]`, one runtime dependency (`blake3-servil = "=0.10.0"`), 10 crates total in `Cargo.lock` all verified by BLAKE3 + SHA-256 hashsets before building, zero dev-dependencies.

---

## 8. Terminology: `Signet`, `SignetId`, and `Imprint`

Traditional cryptographic terminology — "digital signatures" and "public keys" — borrows a metaphor from handwritten signatures bound to a human identity. As Mark S. Miller (*Robust Composition*) and Ka-Ping Yee & Mark S. Miller (*Capability Myths Demolished*) argue, centering security on *identification* ("who is this person?") instead of *authorization* ("should this action be allowed?") routinely pushes systems toward brittle PKIs, identity directories, and ambient access-control lists.

In reality, a cryptographic signing secret is a transferable **bearer** capability, not a person's hand — closer to a physical **signet** ring handed to an officeholder or steward than to a personal autograph:

- **`Signet`** (traditionally *signing key*): the secret bearer object (derived from a 32-byte seed) that exercises authority by making an imprint.
- **`Imprint`** (traditionally *signature*): the 5,616-byte mark pressed by a `Signet` onto a message or stream. Unlike Morris/Miller *Sealers/Unsealers* (which deliberately bundle encryption/opacity with brand checking), an `Imprint` provides transparent authenticity only — the message stays in the clear.
- **`SignetId`** (traditionally *verifying key*): the 32-byte public identifier that names *which* signet you mean — and in a 32-byte scheme like BLINCS, naming the signet and having everything needed to verify its imprints (`SignetId::verify`) are literally the same 32 bytes.

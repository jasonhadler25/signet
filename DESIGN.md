# BLINCS design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of `SPEC.md`, grinding-vs-signing-time feedback, irregular hypertrees + upper-layer caching, SLH-DSA-B with **julienif**, THINCS, CUTS, and the SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree / partial-caching work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil`, SPHINCS/SPHINCS+, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness/hypertree papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** BLINCS is shaped the way it is: the threat model, the quantitative tradeoff ("minimax" and log-regret) models, every candidate optimization we evaluated (both earlier literature and Project 11's latest hash-based signature work) and why each was adopted, kept open, or declined, the salted two-pass streaming content hash, the startup-only signer randomness, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

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

## 3. Simplified minimax tradeoff algorithm ("reduce the magnitude of the worst problem")

Stateless hash-based signatures trade off three costs with completely different units:

1. **Signature size $B$** (bytes — packets, commits, certificates, logs, witness space),
2. **Signing time $S$** (milliseconds — interactive latency, release pipelines, servers), and
3. **Verification time $V$** (microseconds — high-fanout verifiers, package registries, constrained clients).

Any of those three can become the bottleneck that disqualifies BLINCS from a real application. Following Ron Rivest's "minimax strategy" ([`docs/history/manifesto.md`](docs/history/manifesto.md)) — *perform well enough for many use cases instead of maximizing one metric to the detriment of others* — we need **one simple, transparent, zero-knob algorithm** whose sole objective is to **reduce the magnitude of the worst problem**.

### The algorithm: Leximin $L_\infty$ ratio above the physical Pareto floor

1. **Fix the hard requirements first:**
   - Security $\ge 128$ bits at $2^{33}$ signatures per key (exact PORS+FP + hypertree cover bound).
   - Optional stateless top-tree cache budget: at most **1 MiB** (`h_top <= 15`, where implementations remain free to cache anywhere from `0 B` through `2 KiB`, `8 KiB`, `32 KiB`, `1 MiB`, or even `65 MiB` with zero wire-format change; we also evaluate uniform `h_top == h_low` as a zero-cache baseline).
2. **Compute the physical Pareto floor** $(B_{\min}, S_{\min}, V_{\min})$: the best physically achievable value of each dimension anywhere on the valid $2^{33}$ frontier under our measured `blake3-servil 0.10.0` timings ([`BENCHMARKS.md`](BENCHMARKS.md) §3–4).
3. **Measure each problem dimensionlessly** as its multiplicative blowup above the physical floor:
   $$r_B = \frac{B}{B_{\min}}, \qquad r_S = \frac{S}{S_{\min}}, \qquad r_V = \frac{V}{V_{\min}}.$$
4. **Minimize the worst problem first (Leximin $L_\infty$):**
   Sort each candidate's three ratios from largest to smallest, $\big(r_{(1)} \ge r_{(2)} \ge r_{(3)}\big)$, and pick the candidate that minimizes that sorted tuple lexicographically:
   $$\arg\min_{(B, S, V)} \; \mathrm{sort\_desc}\!\left(\frac{B}{B_{\min}},\; \frac{S}{S_{\min}},\; \frac{V}{V_{\min}}\right).$$

### Why this algorithm (and why we dropped more complicated rules)

- **Directly minimizes the worst problem:** $r_{(1)} = \max(r_B, r_S, r_V)$ is literally the magnitude of the single worst blowup across all three axes. Breaking ties by $r_{(2)}$ and $r_{(3)}$ guarantees the winner is strictly Pareto-optimal and leaves no free improvements on the table.
- **Zero arbitrary knobs:** no invented usability ceilings (`max_bytes`, `max_sign_ms`), no hand-tuned weights, completely invariant to units (bytes vs. KiB, µs vs. ms), and **completely independent of the search cap** (unlike span-normalized rules, whose scores shift if you change the 100 ms search ceiling).
- **Why $L_\infty$ beats $L_1$ and $L_2$ for minimax:**
  - Plain product $B \cdot S \cdot V$ ($L_1$ in log-space) happily accepts a 10× blowup on one axis to shave 10× off another — it does not protect against a bad worst case.
  - Quadratic log-regret $L_2 = \sum (\ln r_i)^2$ penalizes large ratios smoothly, but on our frontier it still lets signature size drift up to **2.6–2.8×** (`7.7–8.8 KiB`) just to shave signing from `2.0×` (`0.31 ms`) down to `1.6×` (`0.25 ms`). **Leximin $L_\infty$ refuses to make the worst problem (`B / B_min`) worse just to polish an axis that is already fast.**

### Optional stateless top-tree caching (`h_top <= 15`, 1 MiB full cache) and 1-shot signers

A natural question for irregular hypertrees (`h_top > h_low`) is how a **1-shot signer** (such as `git commit` or a fresh CI container) behaves:

- **With an optional stateless cache file on disk:** the signer does **not** rebuild the top tree — and does not even need to read the entire file. Seeking just the $h_{\text{top}}$ sibling nodes along its authentication path reads only **$16 \cdot h_{\text{top}}$ bytes** (`240 B` at `h_top = 15`), taking **~0.01–0.02 ms** from warm OS page cache or **~0.05–0.3 ms** cold on NVMe SSD — **~1,000×–4,000× faster** than rebuilding from the seed. Because the cache is purely deterministic from the 32-byte signing seed, losing it never threatens security; the signer simply rebuilds it.
- **Without any cache on disk (0 B cold start / key generation):** the signer must hash all $2^{h_{\text{top}}}$ top-tree leaves (`~117–177 ms` on 1 core or **`27–43 ms` on 12 cores** at `h_top = 15`, `w = 8..16`).
- **Continuous partial caching (caching *less* or *more* with zero wire change):** because the top layer is a plain Merkle tree, an implementation can cache only the top $c$ levels (shrinking memory by $2^{h_{\text{top}} - c}$ and rebuilding only one tiny $2^{h_{\text{top}} - c}$-leaf subtree per signature), or cache even *more* (e.g. caching the next layer down on a server). For example, on `6,088 B` (`15 + 4×5`, `w = 8`), single-core signing scales smoothly from **`0.84 ms`** (1 MiB) → **`0.95 ms`** (32 KiB, top 10 levels) → **`1.30 ms`** (8 KiB) → **`2.72 ms`** (2 KiB, embedded/MCU) → **`118 ms`** (0 B cold; **`28 ms`** on 12 cores). On `4,868 B` (`15 + 3×6`, `w = 16`), it scales from **`1.78 ms`** (1 MiB) → **`1.99 ms`** (32 KiB) → **`2.57 ms`** (8 KiB) → **`4.62 ms`** (2 KiB) → **`172 ms`** (0 B cold; **`41 ms`** on 12 cores).

### Fresh optimization results on measured `blake3-servil 0.10.0` timings (`python3 tools/optimize.py`)

We re-ran the full $2^{33}$ search across all three directly measured Apple M6 `blake3-servil 0.10.0` execution models ([`BENCHMARKS.md`](BENCHMARKS.md) §3):
- **`1t`:** single-threaded `blake3-servil-core` with merged lower XMSS batches on SME2.
- **`b3mt`:** `blake3-servil`'s built-in `hash_many_multithreaded` (zero custom threads, 512 KiB split threshold).
- **`12t`:** persistent coarse 12-core hybrid (1 SME2 thread + 11 `TreeHasher::on_this_core()` NEON threads, zero per-step barriers).

#### A. Leximin $L_\infty$ winners with 1 MiB optional stateless top-tree cache (`h_top <= 15`)

| Timing mode & shape | Size | Sign `1T` | Sign `b3-MT` | Sign `12T` | Verify (1c) | Keygen (`1T` / `12T`) | Ratios `(B, S, V)` to floor | Parameters |
|---|---:|---:|---:|---:|---:|---:|---|---|
| **`12t` Leximin $L_\infty$ (clean lower)** | **6,088 B** | **0.84 ms** | **0.78 ms** | **0.31 ms** | **20.8 µs** | 117 / 27.2 ms | **(2.05×, 2.03×, 2.16×)** | `h=35 (15+4×5) w=8 v=42 g=2 S=147 b=13 k=16 gf=4 m=116` |
| **`12t` Leximin $L_\infty$ (all irregular)** | **6,024 B** | 0.95 ms | 0.88 ms | 0.32 ms | 20.7 µs | 117 / 27.2 ms | **(2.02×, 2.12×, 2.15×)** | `h=36 (15+6+3×5) w=8 v=42 g=2 S=147 b=13 k=15 gf=4 m=112` |
| **`b3mt` Leximin $L_\infty$ (clean lower)** | **6,812 B** | 0.70 ms | **0.63 ms** | 0.31 ms | 20.9 µs | 117 / 27.2 ms | **(2.28×, 2.38×, 2.17×)** | `h=35 (15+5×4) w=8 v=42 g=2 S=176 b=13 k=16 gf=4 m=119` |
| **`1t` Leximin $L_\infty$ (all irregular)** | **6,844 B** | **0.65 ms** | 0.65 ms | 0.32 ms | 20.9 µs | 117 / 27.2 ms | **(2.20×, 2.43×, 2.18×)** | `h=36 (15+5+4×4) w=8 v=42 g=2 S=176 b=12 k=17 gf=10 m=119` |
| *`12t` $L_2$ log-regret (sensitivity check)* | *7,816 B* | *0.70 ms* | *0.63 ms* | *0.25 ms* | *17.1 µs* | *90 / 21.0 ms* | *(2.63×, 1.63×, 1.78×)* | *`h=35 (15+4×5) w=4 v=63 g=2 S=94 b=13 k=16 gf=4 m=119`* |

#### B. Leximin $L_\infty$ winners with uniform heights (`--max-top-height 0`, zero tall-top-tree rebuild)

| Timing mode (uniform heights) | Size | Sign `1T` | Sign `b3-MT` | Sign `12T` | Verify (1c) | Keygen (`1T` / `12T`) | Ratios `(B, S, V)` to floor | Parameters |
|---|---:|---:|---:|---:|---:|---:|---|---|
| **`12t` / `b3mt` uniform Leximin $L_\infty$** | **6,844 B** | 1.48 ms | **0.93 ms** | **0.51 ms** | **20.9 µs** | **0.3 / 0.1 ms** | **(2.25×, 2.38×, 2.17×)** | `h=36 (6×6) w=8 v=42 g=2 S=176 b=12 k=17 gf=10 m=119` |
| **`1t` uniform Leximin $L_\infty$** | **7,488 B** | **1.14 ms** | 1.07 ms | 0.42 ms | 23.6 µs | **0.1 / 0.1 ms** | **(2.28×, 2.42×, 2.45×)** | `h=35 (7×5) w=8 v=42 g=2 S=176 b=13 k=16 gf=4 m=119` |

#### C. Direct comparison with compact `w = 16` / `< 4 KiB` candidates, BLINCS `0.1.0`, and SLH-DSA-B

| Candidate / reference scheme | Size | Sign `1T` | Sign `b3-MT` | Sign `12T` | Verify (1c) | Keygen (`1T` / `12T`) | Sign @ 2 KiB cache (`1T`) | Shape |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| **Leximin $L_\infty$ (`12t`, clean, 1 MiB cache)** | **6,088 B** | **0.84 ms** | **0.78 ms** | **0.31 ms** | **20.8 µs** | 117 / 27 ms | **2.72 ms** | `35 (15+4×5) w=8 v=42` |
| **Leximin $L_\infty$ (uniform, zero tall tree)** | **6,844 B** | 1.48 ms | 0.93 ms | 0.51 ms | 20.9 µs | **0.3 / 0.1 ms** | **1.48 ms** | `36 (6×6) w=8 v=42` |
| **Compact `w = 16` sweet spot (1 MiB cache)** | **4,868 B** | 1.78 ms | 1.54 ms | 0.59 ms | 19.6 µs | 171 / 41 ms | 4.62 ms | `33 (15+3×6) w=16 v=32 g=0` |
| **Compact `w = 16` (1 MiB cache)** | **4,500 B** | 2.80 ms | 1.66 ms | 0.87 ms | 20.3 µs | 165 / 40 ms | 5.56 ms | `36 (15+3×7) w=16 v=31` |
| **Fits in 4 KiB (1 MiB cache)** | **4,084 B** | 4.24 ms | 2.58 ms | 1.23 ms | 29.1 µs | 264 / 63 ms | 8.71 ms | `36 (15+3×7) w=32 v=25` |
| **BLINCS `0.1.0` *(implemented, measured)*** | **3,988 B** | 16.22 ms | ~7.7 ms | ~3.8 ms | 33.3 µs | 4.4 / 1.1 ms | 16.2 ms | `36 (4×9) w=32 v=24` |
| *SLH-DSA-BLAKE3-128s ($2^{64}$, FIPS 205)* | *7,856 B* | *121.7 ms* | — | — | *126.6 µs* | — | — | *`63 (7×9) w=16 FORS`* |
| *SLH-DSA-BLAKE3-128f ($2^{64}$, FIPS 205)* | *17,088 B* | *5.81 ms* | — | — | *353.7 µs* | — | — | *`66 (22×3) w=16 FORS`* |

### What the simplified Leximin $L_\infty$ search reveals

1. **Every single Leximin $L_\infty$ winner converges on the exact same family (`w = 8, v = 42`, `6.0–6.9 KiB`, `0.3–1.5 ms` sign, `20.8 µs` verify):** whether you optimize for 1 core, `blake3-servil`'s built-in `hash_many_multithreaded`, or 12-core coarse parallelism — and whether you use a 1 MiB top-tree cache (`6,088 B`, **`2.05× / 2.03× / 2.16×`** of the physical floor!) or uniform heights (`6,844 B`, `2.25× / 2.38× / 2.17×`) — every single dimension stays within **~2.1× of its theoretical physical floor**.
2. **Versus SLH-DSA-B:** **`6,088 B`** (`15 + 4×5`) is **23% smaller** than `SLH-DSA-BLAKE3-128s`, **145× faster to sign** on 1 core (**390×** on 12 cores), and **6.1× faster to verify** — while also being **2.8× smaller**, **6.9× faster to sign on 1 core** (**18.7×** on 12 cores), and **17× faster to verify** than `SLH-DSA-BLAKE3-128f`.
3. **Why `4,868 B` (`15 + 3×6`, `w = 16`) sits just below Leximin $L_\infty$:** spending `-1,220 B` (-20% bytes, `1.56×` floor) roughly doubles signing time (`0.31 → 0.59 ms` on 12 cores, `3.86×` floor; `0.84 → 1.78 ms` on 1 core, `6.70×` floor) while keeping verification at **`19.6 µs`** (`2.04×` floor). Under strict equal-ratio minimax (`Leximin L_inf`), `6,088 B` wins (`max ratio = 2.16×` vs. `3.86×`); if bytes carry a mild extra preference (because signatures are stored and replicated forever while signing happens once), `4,868 B` (`w = 16, v = 32, g = 0`) is the cleanest compact step down. BLINCS stays at `0.1.0` (`3,988 B`) until the final 1.0 parameter choice is locked.

### Why `m = 103` is not signing-time-bottlenecked in BLINCS `0.1.0` (`tools/optimize.py --grinding-sweep`)

In isolation, a PORS+FP merged-set cap of `m = 103` looks aggressive compared to `m = 112` (+144 bytes, 34.6× fewer `PICK` tries). With batched BLAKE3-Servil (`12.6 ns/try` at `GRIND = 2048`), however, `PICK` grinding is only **1.7%** of BLINCS `0.1.0`'s signing time (80% is in the three XMSS hypertree builds and ~9% in the four WOTS+C counter searches):

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

## 4. Candidate techniques evaluated: adopted, open, and declined

This table records every hash-based signature technique we evaluated — both the earlier literature and Project 11's latest research — along with the decision and reason.

### Adopted in BLINCS `0.1.0`

1. **BLAKE3 (`Keyed` + `DeriveKey`) as the sole primitive** (motivated by Project 11's [SLH-DSA-B](https://github.com/PQC-Suite-B/signatures) and [`docs/history/manifesto.md`](docs/history/manifesto.md)): 2–5× faster than SHA-256 and ~15× faster than SHAKE on modern CPUs, multi-GB/s streaming content hashing, and zero additional cryptographic assumptions for users already relying on BLAKE3.
2. **Reduced $2^{33}$ lifetime budget** (vs. FIPS 205's $2^{64}$): 8.59 billion signatures (10/s for 27 years) with graceful degradation past the budget, cutting hypertree height nearly in half (`h = 33..36` vs. `63`).
3. **WOTS+C in place of WOTS+** (Mikhail Kudinov, Andreas Hülsing, Eyal Ronen, and Eylon Yogev, IEEE S&P 2023, [ePrint 2022/778](https://eprint.iacr.org/2022/778)): drops the checksum chains by grinding a 32-bit counter until the digits sum to a fixed constant and `g` low digest bits are zero. Every valid digit vector has the same sum, so advancing revealed chain values can never reach another valid vector. Shrinks each layer, halves worst-case verification work, and rests on target-collision resistance.
4. **PORS+FP in place of FORS** (Mehdi Abri and Jonathan Katz, CRYPTO 2026, [ePrint 2025/2069](https://eprint.iacr.org/2025/2069), building on Jean-Philippe Aumasson and Guillaume Endignoux's PORS & Octopus merging in [ePrint 2017/933](https://eprint.iacr.org/2017/933)): replaces $k$ separate trees with one single tree of $2^b$ leaves, deduplicates overlapping authentication paths ("Octopus"), and filters via a counter until `merged_len <= m` and `gf` threshold bits are zero. Saves ~500–800 B over FORS/FORS+C with a clean security reduction (Theorem 1).
5. **256-bit internal message digest `D` before `PICK`:** Abri & Katz's writeup truncates the pre-counter message digest to $n = 128$ bits, which loses $\log_2 q = 33$ bits to multi-target queries across $2^{33}$ signatures (dropping to 95 bits). Keeping `D` at BLAKE3's native 256 bits (`>= 128 + 33 = 161` bits) closes that gap at zero wire-byte cost.
6. **Two-pass salted streaming content hash over 256 KiB chunks:** eliminates pre-hash collision exposure while keeping signatures fixed-size and verification at 3.5 GB/s on one M6 core (§5).
7. **Stateless top-tree caching in `SigningKey`:** building the top XMSS tree once at key load and keeping it in memory (16 KiB in `0.1.0`) is purely a signer-side optimization — losing the cache only means recomputing it from the 32-byte seed, with zero change to the wire format or security.
8. **Single-core SIMD batching + on-core verification dispatch:** `blake3-servil-core` `Batch` + `TreeHasher::on_this_core()` keeps all tree/chain hashing wide across NEON/AVX2/AVX-512 lanes without triggering Apple SME2 downclocking on tiny verification batches (§7).

### Open pre-1.0 candidates (from Project 11's latest feedback)

9. **Irregular hypertrees with a taller cached top tree (`h_top > h_low`)** (Alessandro Baiocchi, Matteo Vena, Matteo Vicari, and Conor Deegan at Project 11: [Companion Guide](https://research.projecteleven.com/articles/sphincs-parameter-explorer-companion-guide), [Raising SPHINCS-like lifetime budgets](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets); and Zhen Qin, Siwei Sun, and Fangyu Zheng, ASIACRYPT 2026, [ePrint 2025/2236](https://eprint.iacr.org/2025/2236)):
   - Earlier (without considering a taller cached top tree), irregular heights saved only 0–100 bytes and added complexity for zero gain at 3,988 B.
   - **Re-evaluated WITH Project 11's top-tree and partial-tree caching insight (§3 above):** putting extra height into the cached top tree improves bytes, cached signing, and verification **simultaneously** (for example `6,088 B / 0.84 ms (1T) / 0.31 ms (12T) / 20.8 µs` under Leximin $L_\infty$, or `4,868 B / 1.78 ms (1T) / 0.59 ms (12T) / 19.6 µs` compact at `h_top = 15`), while implementations can smoothly trade cache size from `0 B` through `2 KiB / 8 KiB / 32 KiB / 1 MiB / 65 MiB` with zero wire-format change.
10. **Optimizing parameters for signing time rather than minimum bytes** (Conor Deegan's review note): moving from `3,988 B` (`w = 32`) up to `6,088 B` (`w = 8`, Leximin $L_\infty$) or `4,868 B` (`w = 16`, compact) cuts single-core signing time **9×–19×** and verification **1.6×** while staying 23–38% smaller than `SLH-DSA-128s` (§3 Table C).
11. **Optional coarse leaf-parallel multi-core signing** (Conor Deegan's implementation note; measured in [`BENCHMARKS.md`](BENCHMARKS.md) §3): splitting each XMSS tree's leaves across 8 threads speeds up tree building **3.35×** (`4.42 -> 1.32 ms` on M6) using `blake3-servil-core` directly with zero per-step barriers and zero wire-format change. Can be added as an optional opt-in method/feature without complicating the zero-thread default core.

### Declined (and why)

12. **SPHINCS-G offline prepared-slot grinding** (Alessandro Baiocchi and Matteo Vicari, Project 11, [`sphincs-g-benchmarks`](https://research.projecteleven.com/articles/sphincs-g-benchmarks), Nov 2026): precomputes $B$ random hypertree leaf slots before the message arrives, then grinds `R` online until the digest lands on a prepared slot ($2^h / B$ expected attempts).
    - **Why declined:** SPHINCS-G shines on extreme-latency devices (Ledger Nano S+ at 19.5 s, 2-of-3 MPC at 92 s) with short hypertrees ($h = 24..26$, $q_S = 2^{24}..2^{30}$). At BLINCS's $2^{33}$ budget ($h = 33..36$), even with $B = 64$ prepared slots, online grinding takes $2^{33}/64 \approx 134\text{M}$ hashes (~1.5–3 seconds on an M6) — **100×–1,000× slower** than direct BLINCS signing (`1.9–16.2 ms`). Project 11's own benchmark notes that even at $2^{24}$, SPHINCS-G makes no sense on a laptop.
13. **Unhashed random episodes + top-tree pruning** (Alessandro Baiocchi, Matteo Vena, and Matteo Vicari, Project 11, [`raising-sphincs-lifetime-budgets`](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets), Nov 2026; inspired by Chongxu Ren, Kaiyi Zhang, Haorui Cui, and Hongbo Yu's SPHINCS-PE, [ePrint 2026/1708](https://eprint.iacr.org/2026/1708)): moves $h''$ high bits of the leaf index outside the message digest so SPHINCS-G grinds only $h_0$ bits, and optionally replaces unused subtrees ("episodes") with PRF placeholders ("pruning") to cut keygen time.
    - **Why declined:** keeping $h''$ bits outside the message digest **loses $h''$ bits of security** (forcing an extra FTS tree, larger signatures, and slower verification) and buys nothing when you are not running SPHINCS-G grinding. Pruning introduces per-signer budget choices that leak over time (hurting privacy, as Project 11's article notes) and conflicts with BLINCS's "one uniform algorithm, no hidden tuning modes" strategy.
14. **CUTS / CUTS+C** (Jamie Judd, Louis Tajan, Conor Deegan, and Furkan Akal, Project 11, [ePrint 2026/2455](https://eprint.iacr.org/2026/2455), Oct 2026): a binary tree of hash chains whose signature reveals a constant-sum frontier, retaining 128-bit security after 2 signatures (1,360–1,424 B) or 53–80 bits near one-time size (546–994 B).
    - **Why declined:** CUTS is designed as a safer drop-in for *stateful WOTS* (surviving accidental 2-use state rollback), not for stateless multi-use FTS leaves. In a stateless hypertree at $2^{33}$ signatures and $h = 33..36$, millions of leaves are hit 3–10+ times; Project 11's own writeup notes that beyond 2 uses CUTS currently loses security faster than FORS. Even at 2-use security, `CUTS (15, 5, 84, 201)` costs 327,671 signing hashes and 546 verification hashes (vs. 98,303 signing hashes and ~114 verification hashes for PORS+FP at $r \ge 10$ uses) and adds big-integer combinatorial ranking/unranking.
15. **Stateful-primary + stateless-fallback hybrids (SHRINCS, SHRIMPS)** (Mikhail Kudinov and Jonas Nick, [ePrint 2025/2203](https://eprint.iacr.org/2025/2203); reviewed by Conor Deegan and Alex Pruden in Project 11's [`a-review-of-shrincs`](https://research.projecteleven.com/articles/a-review-of-shrincs)): Project 11's own analysis states the decisive objection — restoring a backup or VM snapshot silently rolls back the one-time counter and leaks the key, shifting cryptographic safety onto fragile operational state and adding a second signing path.
16. **THINCS / truncated 96–112-bit hashes** (Conor Deegan, [`conor-deegan/THINCS`](https://github.com/conor-deegan/THINCS)): drops below our 128-bit security target (and `conor-deegan/THINCS#1` documented multi-target/birthday accounting issues in its security tables).
17. **Gravity-SPHINCS / unsalted PORS** (Jean-Philippe Aumasson and Guillaume Endignoux, [ePrint 2017/933](https://eprint.iacr.org/2017/933)): relies on collision resistance of the hash function where salted hashing avoids it.
18. **Top of the Hypercube retry-free encodings (TSL / TL1C / TLFC)** (Dmitry Khovratovich, Mikhail Kudinov, and Benedikt Wagner, CRYPTO 2025, [ePrint 2025/889](https://eprint.iacr.org/2025/889)): fitting $2^{128}$ points in one layer without retries forces much longer chains (for example, 16 chains of 512+ instead of 256). When modest BLAKE3 counter retries are acceptable, WOTS+C achieves equal or fewer verification hashes on shorter chains with much simpler code.
19. **FORS+C** (Mikhail Kudinov, Andreas Hülsing, Eyal Ronen, and Eylon Yogev, [ePrint 2022/778](https://eprint.iacr.org/2022/778)): superseded by PORS+FP, which saves more than twice as many bytes (~544 B vs. ~240 B) with a cleaner formal proof.
20. **Unreviewed 2026 few-time preprints** (BPORS+FP 2026/1328, BPORS-C+BFP 2026/2374, BGS-CC 2026/2502): each stacks a newer, unreviewed counting argument; left out until settled.
21. **Hardware-specific hashes (Haraka / AES-NI):** poor portability and adds a second cryptographic assumption beyond BLAKE3.

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

We reviewed the classic PRNG-with-input and seed-file literature (Boaz Barak & Shai Halevi, [ePrint 2005/029](https://eprint.iacr.org/2005/029); Niels Ferguson, Bruce Schneier & Tadayoshi Kohno's Fortuna seed-file management in *Cryptography Engineering* Ch. 9; Yevgeniy Dodis, David Pointcheval, Sylvain Ruhault, Damien Vergnaud & Daniel Wichs, [ePrint 2013/338](https://eprint.iacr.org/2013/338); Thomas Ristenpart & Scott Yilek, NDSS 2010; Mihir Bellare & Björn Tackmann, [ePrint 2016/290](https://eprint.iacr.org/2016/290)) and kept only what serves BLINCS:

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

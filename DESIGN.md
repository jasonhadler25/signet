# BLINCS design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan** (direct review of `SPEC.md`, grinding-vs-signing-time feedback, irregular hypertrees + upper-layer caching, SLH-DSA-B with **julienif**, THINCS, CUTS, and the SHRINCS review with **Alex Pruden**), **Alessandro Baiocchi, Matteo Vena, and Matteo Vicari** ([SPHINCS+ Parameter Explorer](https://research.projecteleven.com/tools/sphincs-parameter), [SPHINCS-G benchmarks](https://research.projecteleven.com/articles/sphincs-g-benchmarks), and [taller cached top-tree / partial-caching work](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets)), and **Jamie Judd, Louis Tajan, and Furkan Akal** (CUTS) — as well as the authors of BLAKE3, `blake3-servil`, SPHINCS/SPHINCS+, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness/hypertree papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** BLINCS is shaped the way it is: the threat model, the simplified minimax tradeoff algorithm, every candidate optimization we evaluated (both earlier literature and Project 11's latest hash-based signature work) and why each was adopted, kept open, or declined, the single-pass salted content hash, the startup-only signer randomness, and the crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

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

### Empirical evidence on byte costs, protocol thresholds, and hardware trends

Both pure Leximin $L_\infty$ (equal ratios) and smooth exchange-rate models need to be checked against **real-world byte costs and hard/firm protocol cliffs**. Being 1 byte past a fixed-capacity slot or default server limit can be as bad as being 2× too large.

#### 1. Real-world byte thresholds vs. BLINCS's physical range (`~2.9–6.2 KiB` at $2^{32}$)

At $q = 2^{32}$ signatures ($\approx 4.29$ billion, one full `u32`, 10/s nonstop for 13.6 years), the physical minimum size for a 128-bit stateless hash-based signature is **`~2,928 B`**, and practical fast parameter sets span **`~3,900–6,200 B`**. Checking primary specifications and live-Internet measurements shows which cliffs are unreachable for *any* stateless hash-based signature and which cliffs actually sit right inside BLINCS's range:

| Protocol / storage threshold | Primary-source limit | What breaks when exceeded | Impact on BLINCS (`3.9–6.2 KiB`) |
|---|---|---|---|
| **DNSSEC over UDP** | **`1,232 B`** (RFC 9715 / IPv6 1,280 B min MTU) or **`1,400 B`** IPv4; `draft-hoffman-pq-dnssec-considerations-02` classifies `> 1,400 B` as "forces TCP" and `> 3,000 B` as "Jumbo" | IP fragmentation or mandatory TCP fallback | Unreachable for all stateless HBS (`>= 2,928 B`; even ML-DSA-44 at 2,420 B misses 1,232 B). Does not distinguish 3.9 vs. 6.1 KiB. |
| **PostgreSQL inline row (`TOAST`)** | **`2,000 B`** (`TOAST_TUPLE_THRESHOLD`, 1/4 of 8 KiB page, PostgreSQL docs) | Column moved out-of-line to TOAST table | Unreachable for all stateless HBS (`>= 2,928 B`). |
| **QUIC anti-amplification (unvalidated client)** | **`3,600 B`** (`3 × 1,200 B` min Client Initial, RFC 9000 §8.1), minus ~1,100 B ML-KEM + framing $\approx$ **`~2,300 B`** left | Extra RTT for address validation unless client pads Initial or uses Retry | Unreachable for all stateless HBS even for 1 signature. |
| **HTTP Cookie** | **`4,096 B`** total per cookie (RFC 6265 §6.1); after Base64 `4/3` expansion + name/attributes, raw binary limit is **`~3,000 B`** | Cookie rejected or truncated by browsers | Unreachable for all stateless HBS after Base64. |
| **Single 4 KiB OS / filesystem / DB page (binary storage)** | **`4,096 B`** (SQLite default `page_size = 4096`; Linux/ext4/NVMe/x86-64 page `4 KiB`; Apple Silicon macOS uses `16 KiB`) | Binary record spills to a 2nd 4 KiB page / SQLite overflow page | **Live cliff near `3,900–4,096 B`:** `3,984 B` fits in one 4 KiB binary page with `112 B` left for header/verifying key; `4,336 B` and `4,816 B` spill to 2 pages. |
| **TCP segment count (`MSS = 1,448–1,460 B`)** | **`4,344 B`** (3 MSS), **`5,792 B`** (4 MSS), **`7,240 B`** (5 MSS) | +1 TCP packet per crossing (smooth-ish latency/loss step) | `3,984 B` and `4,336 B` fit in **3 TCP segments**; `4,816 B` and `5,284 B` take **4**; `6,152 B` takes **5**. |
| **HTTP single header limit (Base64-encoded signature — RFC 9421, proxies, APIs)** | **Apache `LimitRequestFieldSize = 8,190 B`**; **nginx `large_client_header_buffers = 4 × 8k` (`8,192 B`)** | **Hard HTTP `400`/`431` request failure**! Allowing Base64 `4/3` expansion + ~200 B header name/params puts the raw binary ceiling at **`~5,950 B`** | **Hard real-world ceiling at `~5,950 B`:** **`6,152 B` Base64-encoded is `8,204 B` and fails default Apache & nginx!** `3,984 B` (`5,312 B` b64), `4,336 B` (`5,784 B` b64), `4,816 B` (`6,424 B` b64), and `5,284 B` (`7,048 B` b64) all pass with wide margin. |
| **TLS 1.3 `IW10` & middlebox breakage (Cloudflare live-Internet measurements)** | **RFC 6928 `IW10 = 14,600 B`** (~**`10 kB`** extra cert/sig budget above ~4 kB base handshake); Bas Westerbaan (Cloudflare, *Sizing Up Post-Quantum Signatures* & *Another Look at PQ Signatures*) measured **steep middlebox/client failure jumps at `10 kB` and `30 kB`**, a **+60–80%** handshake slowdown (+1 RTT) past `IW10`, and **~15–20%** slowdown even *within* the congestion window | Hard middlebox failure + full extra RTT | • Legacy 5–6 sig TLS chains: no HBS fits.<br>• **2-sig chain** (leaf + handshake, minus ~1.1 kB ML-KEM $\approx$ `8.9 kB` for 2 sigs): **`<= 4,450 B/sig`** stays under `10 kB` (`3,984 B` and `4,336 B` fit; `4,816 B` crosses).<br>• **1-sig Merkle Tree Certificates** (`draft-ietf-plants-merkle-tree-certs`, ~500 B Merkle proof + 1.1 kB ML-KEM): all BLINCS candidates `3.9–6.1 KiB` fit comfortably under `10 kB`. |
| **Git `pkt-line`, TLS struct, OpenSSH packet** | `65,520 B` (Git `pkt-line`), `65,535 B` (TLS `2^16-1`), `256 KiB` (OpenSSH) | Protocol limit | Far above BLINCS; no cliff. |

#### 2. Smooth economic costs and opposing hardware trends

Beyond hard cliffs, three smooth forces push bytes and CPU time in opposite directions:

- **Replication asymmetry (bytes & verification vs. signing):** a signature is created **once**, stored and replicated **forever** (Git clones, logs, packages, backups), and verified **$N_{\text{ver}}$ times** (often `100` to `1,000,000`×). Even inside Cloudflare's generous 30-packet congestion window, adding bytes still slowed median handshakes smoothly (+20% at 17 kB, +40% at 35 kB). In cloud pricing, egressing 1 KiB to 100–1,000 readers costs ~800×–8,000× more than 1 ms of signing CPU; over a 10 Mbps WAN link, 1 ms of wire transfer equals **1,250 B** (1 Mbps = 125 B/ms).
- **Hardware trend favoring smaller bytes over time:** SIMD/matrix width (AVX-512, SME2) and core counts keep speeding up parallelizable hash-based signing and verification, whereas network MTUs, `IW10`, HTTP header defaults, and 4 KiB storage pages stay frozen for decades.
- **Countervailing hardware trend favoring lower CPU time & small cache:** cheap, ultra-low-power, single-core, small-RAM CPUs (Cortex-M, RISC-V microcontrollers, IoT, smartcards — ~50×–200× slower than one Apple M6 core and limited to `2–32 KiB` RAM) are becoming *more* common, not less. On a ~100× slower scalar MCU with a `2 KiB` top-tree cache, `16.4 ms` (`0.1.0`) stretches to `~1.6 s`, whereas `3.5–5.2 ms` (`4,816–5,284 B`) stays ~0.35–0.5 s and verification (`12.6–17.3 µs` on M6) stays `~1–2 ms`.

#### 3. Encoding bytes-vs.-time taste explicitly (`P` and `N_ver`) at $q = 2^{32}$

To keep taste explicit and reproducible instead of eyeballing tables, we can pair Leximin $L_\infty$ with an explicit marginal price model:

$$\min \; B + P \cdot \big(S_{\text{ms}} + N_{\text{ver}} \cdot V_{\text{ms}}\big)$$

- **$P$ (`B/ms`):** how many permanent signature bytes we are willing to pay to save 1 ms of CPU time on the reference machine (e.g., `250 B/ms` for tight 4 KiB/WAN bias, `1,000 B/ms` for ~10 Mbps wire parity).
- **$N_{\text{ver}}$ (verify-to-sign ratio):** how many times a typical signature is verified per signing (e.g., `N_ver = 100`). Including $N_{\text{ver}}$ stops the optimizer from choosing very slow `w = 128`/`256` verification (`90–156 µs`) to save a couple hundred bytes.

Evaluating at **$q = 2^{32}$** with multithreading on by default (`12T` on M6) and **`h_top <= 15`** (1 MiB optional stateless cache — the saturation knee where `h_top = 16` doubles cache/keygen for near-zero gain):

| Explicit rule (`q = 2^32`, `h_top <= 15`) | Size | Base64 size | Sign `12T` | Sign `1T` | Sign @ `2 KiB` (`1T`) | Verify (1c) | Keygen (`12T`) | Thresholds cleared | Shape & security |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| **`P = 250 B/ms`, `N_ver = 100`** | **3,984 B** | 5,312 B | 2.10 ms | 7.97 ms | 10.78 ms | **16.1 µs** | 39.5 ms | **4 KiB binary page**, **3 MSS**, **2-sig TLS `IW10`**, **8 KiB HTTP hdr** | `33 (15+2×9) w=16 v=31 g=4` (128.0 b) |
| **`P = 500 B/ms`, `N_ver = 100`** | **4,336 B** | 5,784 B | 1.17 ms | 4.25 ms | 7.15 ms | **15.8 µs** | 40.8 ms | **3 MSS (`4,344 B`)**, **2-sig TLS `IW10`**, **8 KiB HTTP hdr** | `31 (15+2×8) w=16 v=32 g=0` (128.5 b) |
| **`P = 1,000 B/ms`, `N_ver = 100`** | **4,816 B** | 6,424 B | **0.92 ms** | 3.27 ms | 5.18 ms | **12.6 µs** | **27.2 ms** | 4 MSS, 1-sig MTC TLS, **8 KiB HTTP hdr** (+1.7 KiB margin) | `31 (15+2×8) w=8 v=42 g=2` (128.5 b) |
| **Leximin $L_\infty$, `p = 2`** *(2×B = 4×S)* | **5,284 B** | 7,048 B | **0.52 ms** | 1.64 ms | 3.51 ms | 17.3 µs | 26.6 ms | 4 MSS, 1-sig MTC TLS, **8 KiB HTTP hdr** (+1.1 KiB margin) | `36 (15+3×7) w=8 v=41 g=5` (128.4 b) |
| **Leximin $L_\infty$, `p = 1`** *(clean lower, HTTP-safe)* | **5,944 B** | 7,928 B | **0.35 ms** | **0.87 ms** | **2.75 ms** | **20.4 µs** | **26.6 ms** | 1-sig MTC TLS, **8 KiB HTTP hdr** (+262 B margin) | `35 (15+4×5) w=8 v=41 g=5 gf=0` (**129.9 b**) |
| **Leximin $L_\infty$, `p = 1`** *(unconstrained, all shapes)* | **5,928 B** | 7,904 B | **0.32 ms** | 0.95 ms | 2.86 ms | 20.6 µs | 27.2 ms | 1-sig MTC TLS, **8 KiB HTTP hdr** (+286 B margin) | `36 (15+6+3×5) w=8 v=42 g=2 gf=0` (128.8 b) |
| *Leximin $L_\infty$, `p = 1` (clean lower, unconstrained)* | *6,152 B* | ***8,204 B*** | *0.33 ms* | *0.76 ms* | *2.67 ms* | *18.2 µs* | *27.2 ms* | ***Exceeds Apache `8,190 B` / nginx `8,192 B` HTTP header by 14 B!*** | *`35 (15+4×5) w=8 v=42 g=2 gf=10` (128.3 b)* |

Note the symmetry between hardware trends: faster parallel/SIMD CPUs argue for smaller bytes, while proliferating cheap low-power CPUs (where cycles are scarce and memory is plentiful relative to CPU speed) argue for lower cycle counts — bringing us back to pure worst-dimension minimization (**Leximin $L_\infty$**), checked against the one live hard ceiling (`~5,950 B` raw for default 8 KiB Apache/nginx Base64 HTTP headers). Unconstrained `clean_lower=False` Leximin $L_\infty$ already lands below it (`5,928 B`), and `clean_lower=True` lands at `5,944 B` (`2.03×, 2.20×, 2.13×` of the physical floor) with `gf = 0` and `129.9` bits of security.

#### 4. Protocol simplification ladder at `~5.5–5.9 KiB` ($q = 2^{32}$)

Once BLINCS narrows in on the `~5.5–5.9 KiB` band (instead of squeezing below 4 KiB as in `0.1.0`), an important engineering question appears: **how much protocol complexity (`WOTS+C`, `PORS+FP`, counter grinding, Octopus merging, bit-packing, irregular trees, and external 1 MiB disk cache) can we delete outright, and what does each deletion actually cost?**

Evaluating every simplification step on the same calibrated Apple M6 `blake3-servil 0.10.0` timing model at $q = 2^{32}$ (all clearing the 8 KiB Apache/nginx Base64 HTTP header cliff):

| Simplification step ($q = 2^{32}$) | Size (Base64) | Sign `12T` | Sign `1T` | Sign @ `2 KiB` / `0 B` | Verify (1c) | Keygen `12T` | Security ($2^{32} / 2^{33} / 2^{34}$) | Protocol machinery eliminated |
|---|---:|---:|---:|---:|---:|---:|---|---|
| **Step 0 — Full (`WOTS+C` + `PORS+FP` + `15+4×5` `w=8`)** | 5,944 B (`7,928`) | **0.35 ms** | **0.87 ms** | 2.75 ms (`2K`) | **20.1 µs** | 26.6 ms | 129.9 / 124.8 / 118.9 b | *(Baseline: WOTS+C grind, PORS+FP grind, Octopus merging, dedup/sort, zero-pad check, 3-bit packing, 1 MiB cache API)* |
| **Step 1a — Zero grinding + byte-aligned FORS (`Plain WOTS+` nibbles `w=16` + `Plain FORS(8,19)` + `15+3×7`)** | **5,584 B** (`7,448`) | **0.71 ms** | **2.58 ms** | 5.74 ms (`2K`) | **26.3 µs** | 44.6 ms | **133.5 / 128.8 / 123.4 b** | **Deletes `WOTS+C`, `PORS+FP`, ALL counter grinding & tail-latency variance, Octopus merging, dedup/sort, zero-padding check, `KIND_PICK`, `KIND_WOTS_MSG`, 3-bit packing, and FORS bit-unpacking (each FORS index is 1 plain byte `D[i]`, each WOTS digit is 1 nibble). 100% textbook FIPS 205 security proofs.** |
| **Step 1b (`15 + 3×6`, 1 MiB disk cache)** | **5,616 B** (`7,488`) | **0.44 ms** | **1.80 ms** | 4.96 ms (`2K`) | **26.2 µs** | 40.3 ms | 133.2 / 126.8 / 119.3 b | Same zero-grinding textbook `WOTS+` + `FORS(10,16)` as Step 1a, but relies on an authenticated 1 MiB disk cache for fast 1-shot signers. |
| **Adopted (`12 + 3×7`, 128 KiB in RAM, no disk cache)** | **5,616 B** (`7,488`) | **0.73 ms** | **2.9 ms** | **6.16 ms (`0 B`!)** | **25.3 µs** | **5.43 ms** | **133.2 / 126.8 / 119.3 b** | **Same exact 5,616 B wire size, same 133.2-bit security, and slightly faster 25.3 µs verify as `15 + 3×6`, while cutting top-tree RAM 8× (`128 KiB`) and cold `from_seed` 7.4× (`5.43 ms`) — fast enough to delete the entire disk cache format and API.** |
| **Step 2a — Zero grinding + uniform `5×7` (`Plain WOTS+` nibbles `w=16` + `Plain FORS(11,13)` + `5×7`)** | **5,888 B** (`7,852`) | **1.05 ms** | **4.04 ms** | **4.06 ms (`0 B`!)** | **31.3 µs** | **0.3 ms** | **132.5 / 128.5 / 123.8 b** | **Deletes everything in Step 1 PLUS deletes irregular tree heights (`TOP_HEIGHT != LOWER_HEIGHT`) and the entire 1 MiB disk cache / partial-cache API** (top tree is 4 KiB in RAM; keygen is `0.3 ms` `12T` / `0.8 ms` `1T`). |
| **Step 2b — Zero grinding + uniform `4×8` (`Plain WOTS+` nibbles `w=16` + `Plain FORS(12,13)` + `4×8`)** | **5,488 B** (`7,320`) | **1.59 ms** | **6.37 ms** | **6.40 ms (`0 B`!)** | **26.1 µs** | **0.4 ms** | 131.3 / 124.9 / 117.4 b | Same zero-grinding, zero-cache simplicity as Step 2a, **−400 B smaller**, **`26.1 µs` verify**, and every hypertree layer index is literally 1 byte (`u8`, `h = 32 = 4×8`) with 3-nibble (`12`-bit) FORS indices (8 KiB top tree in RAM). |

**The surprising takeaway:** at `~5.5–5.9 KiB`, **all of `WOTS+C`, `PORS+FP`, counter grinding, Octopus merging, deduplication, sorting, and trailing-zero padding checks can be deleted outright while *shrinking* signature size (`5,944 B -> 5,488–5,888 B`), *increasing* security margin (`129.9 -> 131.3–133.5` bits), removing 100% of signing tail-latency variance, cutting the spec and codebase by ~40%, and falling back strictly onto textbook FIPS 205 (`WOTS+` + `FORS`) security proofs**. Choosing **`12 + 3×7`** (`h = 33, d = 4, w = 16, FORS 16 × 2^{10}`) over `15 + 3×6` keeps the exact same `5,616 B` wire size (`7,488 B` Base64), `25.3 µs` verification, and `133.2 / 126.8 / 119.3`-bit security curve while shrinking the top tree 8× to `128 KiB` and cutting cold `from_seed` 7.4× (`40.3 ms -> 5.43 ms` on `blake3-servil 0.10.0`, projected `~3.5 ms` once upstream `Packed<32>` / NEON / SME2 extensions in [`servil-software-factory/BLAKE3#509`](https://github.com/servil-software-factory/BLAKE3/issues/509) land) — eliminating the entire on-disk top-tree cache file format and API for only `+0.29 ms` on warm signing (`0.73 ms` today, projected `~0.46 ms` with `#509`).

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
6. **Single-pass salted content hash (`Keyed(Keyed(K_content, e), M)`):** eliminates pre-hash collision exposure with no chunking layer, keeping signatures fixed-size, streaming memory tiny, single-core verification at **7.40 GB/s** (16 MiB) / **6.97 GB/s** (100 MiB) on Apple M6, and multi-core streaming up to **30.4–30.6 GB/s** via `blake3-servil` `Pipeline::room()` / `hash_multithreaded` (§5).
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

Whenever `draw` is fresh (every normal signature), `e` is unpredictable to the submitter until after the signature is published, so `Keyed(K_msg, M)` rests purely on **second-preimage / target-collision resistance** of keyed BLAKE3 (zero collision-resistance assumption). Only in the extreme triple-reset failure mode where state file, `/dev/urandom`, and monotonic clock *all* repeat identically does content hashing fall back to 128-bit known-key collision resistance of 256-bit keyed BLAKE3 — while signing-key secrecy, WOTS+C, and PORS+FP remain unaffected because `R = Keyed(K_R, e || h_msg)[..16]` still varies with `M`.

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
  - Even in the worst case — an attacker resets disk, OS RNG, and clock together so `draw` repeats identically — BLINCS never leaks the signing key and never allows WOTS+C reuse or PORS+FP leaf steering (`R = Keyed(K_R, e || h_msg)[..16]` still depends on `M`). Only content hashing downgrades from second-preimage resistance to 128-bit known-key collision resistance of 256-bit keyed BLAKE3 `Keyed(K_msg, M)`.

---

## 7. Crash-only design and performance engineering

BLINCS adopts Servil Software Factory's engineering discipline:

- **Pure crash-only lifecycle (zero `Drop` implementations):** `Randomness` has no shutdown hook; a sudden crash loses no teardown invariant. Signing and verification workspaces (`SignWorkspace`, `VerifyWorkspace`) are allocated once per thread and kept until process exit, avoiding per-call allocation, page-fault zeroing, and TLB shootdowns. Streaming readers (`sign_reader` / `verify_reader`) use a fresh zero-initialized 64 KiB local stack buffer per call with no shared cross-caller pool and no held `RefCell` borrow across `Read` callbacks.
- **Unrepresentable invalid states & fail-stop contracts:** `SigningKey` holds only one 32-byte seed and derives its verifying key and cached 16 KiB top tree on construction (so an inconsistent `(seed, vk)` pair cannot exist). `SigningKey::sign` and `sign_reader` run `VerifyingKey::verify_short` (~33 µs, 0.2% of signing time) before returning any signature and panic if self-verification fails. Counter exhaustion panics rather than wrapping.
- **Wall time and cycles together (`clocks`):** measuring BLINCS with `bench-hashes`'s `clocks` crate revealed that calling Apple M6's SME2 kernels for verification's tiny 11–24-element batches downclocked the P-core from ~4,787 MHz to ~4,066 MHz and spent ~47k extra cycles entering/exiting streaming mode. Routing verification's tree/chain hashes through `TreeHasher::on_this_core()` (a no-op on non-Apple CPUs) and batching each level of `few_time_verify` cut 64-byte verification from **57.3 µs** to **33.3 µs** (~1.7× faster, ~5.9–6.0 IPC) while keeping large-message content hashing on SME2 at **3.5 GB/s** on one core.
- **Tiny trusted base:** `#![forbid(unsafe_code)]`, one runtime dependency (`blake3-servil-core = "=0.10.0"`), 10 crates total in `Cargo.lock` all verified by SHA-256 checksum, zero dev-dependencies.

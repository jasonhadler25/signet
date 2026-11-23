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

## 3. Quantitative tradeoff models ("minimax" and scale-free log-regret)

Stateless hash-based signatures trade off three competing costs:

1. **Signature size $B$** (bytes in packets, logs, Git commits, certificates, transactions),
2. **Signing time $S$** (latency and throughput per core), and
3. **Verification time $V$** (latency and throughput per core).

Any of those three costs may have a hard threshold beyond which it disqualifies the scheme from some use case — including uses that have not been invented yet. Rather than choosing parameters by eye, we formalize the tradeoff in [`tools/optimize.py`](tools/optimize.py) (standard-library Python, ~3.4 s to run, exact integer retry DPs, calibrated to within 1% of our measured Apple M6 `blake3-servil-core 0.10.0` numbers).

### Model A: Scale-free sum of squares of log-ratios above the achievable minimum

A simple, scale-free preference is: *accept an $X\%$ improvement in one dimension for a $Y\%$ worsening in other dimensions whenever $Y \ll X$, without letting any single dimension blow up relative to its achievable best.*

Let $(B_{\min}, S_{\min}, V_{\min})$ be the best achievable value of each dimension on the $2^{33}$ Pareto frontier, and define each dimension's **log-regret** (multiplicative distance above its achievable minimum):

$$r_i = \ln\!\left(\frac{x_i}{x_{i,\min}}\right) \ge 0.$$

Minimize the **sum of squares** (Euclidean $L_2$ distance in log-space from the utopia point):

$$\mathcal{L}_2(B, S, V) = \left(\ln \frac{B}{B_{\min}}\right)^2 + \left(\ln \frac{S}{S_{\min}}\right)^2 + \left(\ln \frac{V}{V_{\min}}\right)^2.$$

Why this captures the preference cleanly:

- **100% scale-free, zero arbitrary ceilings or weights:** switching bytes $\leftrightarrow$ KiB or µs $\leftrightarrow$ ms cancels out of $x_i / x_{i,\min}$.
- **Its differential is an automatic "$Y \ll X$" rule:**
  $$d\mathcal{L}_2 = 2\!\left(r_B \frac{dB}{B} + r_S \frac{dS}{S} + r_V \frac{dV}{V}\right) = 0.$$
  Trading an $X\%$ gain in dimension $i$ for a $Y\%$ cost in dimension $j$ is accepted if and only if
  $$\frac{Y}{X} < \frac{\ln(x_i / x_{i,\min})}{\ln(x_j / x_{j,\min})}.$$
  When dimension $i$ is far from its minimum (say $30\times$ above min, $\ln 30 = 3.4$) while $j$ is near its minimum ($1.2\times$, $\ln 1.2 = 0.18$), the rule accepts any trade better than ~19:1 ($Y \ll X$). Unlike plain unsquared $\sum \ln x_i = \ln(B \cdot S \cdot V)$ (which trades 49% for 50% forever), **squaring** creates a rising wall that stops once every dimension sits at roughly the same multiple of its minimum.
- **Closely related zero-knob variants:** the $L_\infty$ limit minimizes the worst ratio $\max(x_i / x_{i,\min})$; squared percentage excess minimizes $\sum (x_i / x_{i,\min} - 1)^2$; span-normalized $L_2$ divides each $r_i$ by $\ln(x_{i,\max} / x_{i,\min})$; and weighted $L_2$ ($\sum w_i r_i^2$) makes any explicit size preference $w_B > 1$ (bytes are stored and replicated forever while signing runs once) completely transparent.

### Model B: Unknown application cutoffs (how likely is BLINCS to pass an unknown app's limits?)

Suppose a future application we have not met yet will adopt BLINCS if and only if BLINCS fits under three hard pass/fail cutoffs:

- a maximum signature size $T_B$ the application can tolerate,
- a maximum signing time $T_S$ the application can tolerate, and
- a maximum verification time $T_V$ the application can tolerate.

If BLINCS exceeds **any one** of those three cutoffs, that application cannot use BLINCS. Because we do not know each future application's cutoffs in advance, Model B picks each cutoff randomly across a plausible range up to a chosen **upper ceiling** `(max_bytes, max_sign_ms, max_verify_us)` — for example, `(7,856 B, 100 ms, 1,000 µs)` means *"we assume every application we care about can live with at least something smaller than SLH-DSA-128s (7,856 B), faster than 100 ms signing, and faster than 1 ms verification, though we do not know how much tighter its real cutoff is."*

Using the scale-invariant (log-uniform) distribution on each cutoff up to its ceiling $(U_B, U_S, U_V)$:

1. **Maximum joint pass probability (Nash bargaining):**
   $$\arg\max_{(B, S, V)} \Pr[B \le T_B \land S \le T_S \land V \le T_V] = \arg\max_{(B, S, V)} \; \ln\!\left(\frac{U_B}{B}\right) \cdot \ln\!\left(\frac{U_S}{S}\right) \cdot \ln\!\left(\frac{U_V}{V}\right).$$
   All three lower bounds $L_i$ cancel out identically; only the three upper ceilings $(U_B, U_S, U_V)$ enter, and the result is independent of units.
2. **Minimax exclusion risk:**
   Conditioning on each cutoff falling between the achievable minimum $x_{i,\min}$ and the upper ceiling $U_i$, minimize the worst-case chance of failing any single cutoff:
   $$\arg\min_{(B, S, V)} \; \max_{i \in \{B, S, V\}} \frac{\ln(x_i / x_{i,\min})}{\ln(U_i / x_{i,\min})}.$$

Compared with Model B, **Model A** (scale-free sum of squares of log-ratios above the achievable minimum) has the advantage that it invents **no** arbitrary upper ceilings at all — every number comes straight from the cryptographic frontier.

### Calibrated uniform-hypertree results (`python3 tools/optimize.py`) vs. SLH-DSA-B

Using our concrete Apple M6 measurements of `blake3-servil-core = "=0.10.0"` (`xmss = 11.1 + 3.8 \cdot 1024/(c + 1024)` ns/comp, `pors = 10.0 + 4.8 \cdot 2048/(t + 2048)` ns/comp, `grind = 12.6` ns/try, `verify = 18.5` ns/batched + `45` ns/scalar; predicts BLINCS `0.1.0` to within 1%: `16.33` vs. `16.22 ms` sign, `33.1` vs. `33.3 µs` verify, `4.53` vs. `4.43 ms` keygen), the full $2^{33}$ uniform-hypertree Pareto frontier (`d = 2..12`, `w = 4..256`, `sign <= 100 ms`) has **3,096** points with minima **$B_{\min} = 3{,}284\text{ B}$, $S_{\min} = 0.51\text{ ms}$, $V_{\min} = 9.6\text{ µs}$**:

| Rule / reference scheme | Bytes | Sign (1 core) | Verify (1 core) | Keygen | Ratios to `(Bmin, Smin, Vmin)` | Parameters (`h d v w g S b k gf m`) |
|---|---:|---:|---:|---:|---|---|
| **Scale-free $L_\infty$ minimax ratio** $\max(x/x_{\min})$ | **7,440 B** | **1.24 ms** | **23.5 µs** | 0.14 ms | **(2.27×, 2.43×, 2.44×)** | `35 7 42 8 2 176 13 16 4 116` |
| **Squared % excess** $\sum(x/x_{\min} - 1)^2$ | **7,488 B** | **1.22 ms** | **23.6 µs** | 0.14 ms | **(2.28×, 2.39×, 2.45×)** | `35 7 42 8 2 176 13 16 4 119` |
| **Scale-free $L_2$ log-regret** $\sum(\ln(x/x_{\min}))^2$ | **9,840 B** | **1.01 ms** | **19.6 µs** | 0.11 ms | **(3.00×, 1.97×, 2.03×)** | `35 7 63 4 2 114 13 16 4 119` |
| **Span-normalized $L_2$** | **5,928 B** | **2.89 ms** | **17.2 µs** | 0.52 ms | (1.81×, 5.64×, 1.79×) | `35 5 42 8 2 183 14 14 0 108` |
| **Weighted $L_2$**, $w = (16, 1, 1)$ | **5,048 B** | **3.88 ms** | **24.3 µs** | 0.77 ms | (1.54×, 7.59×, 2.52×) | `35 5 31 16 4 270 14 14 0 108` |
| **Unknown cutoffs**, max `(7,856 B, 100 ms, 1 ms)` pass prob | **4,804 B** | **5.91 ms** | **20.5 µs** | 1.49 ms | (1.46×, 11.6×, 2.13×) | `32 4 31 16 4 270 15 14 5 127` |
| **Unknown cutoffs**, max `(7,856 B, 100 ms, 1 ms)` minimax | **4,536 B** | **5.83 ms** | **41.9 µs** | 1.24 ms | (1.38×, 11.4×, 4.34×) | `35 5 25 32 3 387 14 14 0 106` |
| **Unknown cutoffs**, max `(5,000 B, 100 ms, 1 ms)` pass prob | **3,940 B** | **17.21 ms** | **32.3 µs** | 4.53 ms | (1.20×, 33.7×, 3.35×) | `36 4 24 32 8 382 15 11 6 100` |
| **BLINCS `0.1.0` *(implemented, measured)*** | **3,988 B** | **16.22 ms** | **33.3 µs** | **4.43 ms** | (1.21×, 31.7×, 3.46×) | `36 4 24 32 8 372 15 11 6 103` |
| *SLH-DSA-BLAKE3-128s* ($2^{64}$, FIPS 205, measured M6) | *7,856 B* | *121.7 ms* | *126.6 µs* | — | *(2.39×, 238×, 13.1×)* | *`h=63 d=7 w=16 (35 ch) FORS k=14 a=12`* |
| *SLH-DSA-BLAKE3-128f* ($2^{64}$, FIPS 205, measured M6) | *17,088 B* | *5.81 ms* | *353.7 µs* | — | *(5.20×, 11.4×, 36.7×)* | *`h=66 d=22 w=16 (35 ch) FORS k=33 a=6`* |

*(With `3×` multithreaded signing via `--sign-speedup 3.0`, $L_2$ log-regret shifts to `8,764 B` / 0.42 ms / 18.2 µs, span-normalized $L_2$ to `5,540 B` / 1.44 ms / 14.9 µs, and max-cutoffs `(7,856 B, 100 ms, 1 ms)` pass probability to `4,468 B` / 3.35 ms / 19.0 µs.)*

### What this comparison reveals

1. **Versus SLH-DSA-B's proposed parameters:** SLH-DSA-B preserves FIPS 205's exact `128s` and `128f` parameter sets (plain WOTS+ with 3 checksum chains, plain FORS with $k$ trees, $2^{64}$ signing budget) and swaps only the hash to BLAKE3. Because BLINCS trades the $2^{64}$ budget down to $2^{33}$, adopts WOTS+C and PORS+FP, and batches hashes on `blake3-servil-core`:
   - Every candidate from **`3,988 B`** to **`7,440 B`** strictly beats `SLH-DSA-BLAKE3-128s` on **all three** dimensions simultaneously (smaller signatures, 7–98× faster signing, 3.8–6.2× faster verification).
   - The **`4,804 B`**, **`5,048 B`**, and **`7,440 B`** candidates also match or beat `SLH-DSA-BLAKE3-128f`'s 5.81 ms signing time while being **2.3–3.6× smaller** and **15–17× faster to verify**.
2. **Why equal-ratio rules pick ~7.4–9.8 KB while `0.1.0` sits at 3,988 B:** the hash-based frontier is highly asymmetric — signature size only spans **4.6×** across the full search space (`3.3–15.1 KB`), whereas signing spans **190×** (`0.51–98 ms`). Treating a 2× worsening in size as equally costly as a 2× worsening in signing time lands at **`7,440 B` (1.24 ms, 23.5 µs)** under $L_\infty$/squared-excess or **`9,840 B` (1.01 ms, 19.6 µs)** under $L_2$ log-regret. Staying under 4 KiB (`3,988 B`) corresponds to weighting size roughly 64–100× heavier than signing in squared log-regret (or assuming a 5 KiB size ceiling), while the intermediate **`4,804–5,048 B`** sets sit at `w_B ≈ 16` or the SLH-DSA-128s ceiling `7,856 B` (+20–26% bytes over `0.1.0` for **3–4× faster signing** and **1.4–1.6× faster verification**).

### Re-running the selection WITH Project 11's latest ideas: irregular hypertrees, top-tree caching, and 1-shot rebuild costs

Prompted by Conor Deegan and Project 11's [SPHINCS-G](https://research.projecteleven.com/articles/raising-sphincs-lifetime-budgets) and [SPHINCS+ Parameter Explorer](https://research.projecteleven.com/articles/sphincs-parameter-explorer-companion-guide) work, we re-ran the full parameter search allowing **general irregular hypertrees** — any top-tree height `h_top <= 16` and maximally balanced lower layers (by convexity of $2^x$, the $d - 1$ uncached lower layers should always differ in height by at most 1).

#### What happens for a 1-shot signer (and what rebuilding the cache actually costs)

A critical question for any irregular hypertree with a taller cached top tree (`h_top > h_low`) is how a **1-shot signer** (such as `git commit`, a CI job, or a hardware device) behaves:

- **If the 1-shot signer has NO cache file on disk (or on a cold cache miss):** it **cannot** skip building the top tree. Producing the top layer's Merkle authentication path requires sibling hashes derived from all $2^{h_{\text{top}}}$ leaves, so an uncached 1-shot signer must compute the entire top tree from scratch on every signature (`uncached 1-shot time = cached sign time + top-tree rebuild time`).
- **If the 1-shot signer keeps an optional stateless cache file on disk:** it does **not** rebuild the tree — and does not even need to read the entire cache file. Seeking just the $h_{\text{top}}$ sibling nodes along its authentication path reads only **$16 \cdot h_{\text{top}}$ bytes** (160–240 bytes!), taking **~0.01–0.02 ms** from warm OS page cache or **~0.05–0.3 ms** cold on NVMe SSD (roughly 1,000×–4,000× faster than rebuilding `h_top = 15`). Because the cache is purely deterministic from the 32-byte signing seed, losing or corrupting it never threatens security — the signer simply rebuilds it.
- **Continuous partial caching (caching *less* or *more* with zero wire change):** because the top layer is a plain Merkle tree, an implementation can cache only the top $c$ levels (shrinking memory by $2^{h_{\text{top}} - c}$ and rebuilding only one $2^{h_{\text{top}} - c}$-leaf subtree per signature), or cache even *more* (for example, all $2^{15}$ height-6 layer-2 trees in `15 + 3×6` take 64 MiB and drop signing from `1.90 ms` to `~1.4 ms`). For example, on `4,868 B` (`h = 33 (15 + 3×6)`, `w = 16, v = 32, g = 0`), single-core signing scales smoothly across every cache budget: **1.90 ms** (1 MiB full top tree) → **2.11 ms** (32 KiB, top 10 levels) → **2.69 ms** (8 KiB, top 8 levels) → **4.92 ms** (2 KiB, top 6 levels) → **192 ms** (0 B cold, or ~59 ms on 8 cores).
- **Exact rebuild cost on Apple M6 (`w = 16`, `v = 31..32`):**
  - `h_top = 7` (128 leaves, **4 KiB** cache): **0.8 ms** (1 core) / **0.2 ms** (8 cores) — negligible even uncached.
  - `h_top = 9` (512 leaves, **16 KiB** cache): **2.9–4.4 ms** (1 core) / **0.9–1.3 ms** (8 cores) — negligible even uncached.
  - `h_top = 10` (1,024 leaves, **32 KiB** cache): **5.8 ms** (1 core) / **1.7 ms** (8 cores).
  - `h_top = 12` (4,096 leaves, **128 KiB** cache): **23.8 ms** (1 core) / **7.1 ms** (8 cores).
  - `h_top = 14` (16,384 leaves, **512 KiB** cache): **95.0 ms** (1 core) / **28.4 ms** (8 cores).
  - `h_top = 15` (32,768 leaves, **1 MiB** cache): **190 ms** (1 core) / **57 ms** (8 cores).

#### Unconstrained 4-axis minimax vs. cached-signer 3-axis sweep (`python3 tools/optimize.py --four-axis` and `--max-top-height 15`)

Evaluating all **1,114,160** 4-D non-dominated candidates across uniform and irregular hypertrees (`h_top <= 16`, ~4.5 s in `tools/optimize.py --four-axis`) yields a sharp structural insight:

1. **When uncached 1-shot signing is included as a 4th axis** `(bytes, cached sign, uncached 1-shot sign, verify)`, **no arbitrary cap on `h_top` is needed — the optimizer automatically stops at `h_top = 6..8` (`2–8 KiB` cache, `0.2–1.5 ms` rebuild)!** Doubling `h_top` past 10 doubles uncached 1-shot cost exponentially while trimming cached signing only modestly.
2. **When cached signing dominates (daemons/servers, or 1-shot signers with an optional stateless disk cache)**, a taller top tree shrinks signature size, cached signing time, and verification time **all at once** (`--max-top-height 15` = 1 MiB cache):
   - $L_\infty$ minimax ratio drops from `7,440 B / 1.24 ms / 23.5 µs` to **`6,844 B / 0.70 ms / 20.9 µs`** (`h=36 (15+5+4×4)`, rebuild `127 ms` 1-core / `38 ms` 8-core).
   - Weighted $L_2$ `w = (16, 1, 1)` drops from `5,048 B / 3.88 ms / 24.3 µs` to **`4,868 B / 1.90 ms / 19.6 µs`** (`h=33 (15+3×6)`, rebuild `190 ms` 1-core / `57 ms` 8-core).
   - Compact unknown-cutoffs (`max 7,856 B`) drops from `4,804 B / 5.91 ms / 20.5 µs` to **`4,548 B / 2.71 ms / 20.3 µs`** (`h=35 (15+2×7+6)`, rebuild `184 ms` 1-core / `55 ms` 8-core).
   - Even staying **under 4 KiB (`4,084 B`)**, just `h_top = 10` (**32 KiB** cache, `9.3 ms` rebuild) gives `h=34 (10+3×8)`: **`10.28 ms` cached sign, `19.6 ms` uncached 1-shot, `29.0 µs` verify** — faster than `0.1.0` on **all three** timing metrics (cached, 1-shot, and verify) while still fitting inside a 4 KiB page!

#### Head-to-head final candidates table (calibrated Apple M6, 1 core, `2^33` budget, `>= 128` bits)

| Candidate family | Size | Cached sign | Uncached 1-shot | Verify | Rebuild (1c / 8c) | Cache size | Shape & params |
|---|---:|---:|---:|---:|---:|---:|---|
| **A. Current `0.1.0` draft *(uniform, <4 KiB)*** | **3,988 B** | 16.22 ms | 20.7 ms | 33.3 µs | 4.4 / 1.3 ms | 16 KiB | `36 (4×9) w=32 v=24` |
| **B. Nearly-uniform <4 KiB *(Project 11 irregular)*** | **4,084 B** | 10.28 ms | 19.6 ms | 29.0 µs | 9.3 / 2.8 ms | 32 KiB | `34 (10+3×8) w=32 v=25` |
| **C. Uniform minimax sweet spot *(zero-cache friendly)*** | **5,048 B** | **3.88 ms** | **4.6 ms** | **24.3 µs** | **0.8 / 0.2 ms** | **4 KiB** | `35 (5×7) w=16 v=31` |
| **D. 4-axis balanced irregular *(8 KiB cache)*** | **5,304 B** | **2.77 ms** | **4.3 ms** | **24.6 µs** | **1.5 / 0.4 ms** | **8 KiB** | `33 (8+7+3×6) w=16 v=31` |
| **E. Medium irregular cache *(128 KiB cache)*** | **5,240 B** | **1.89 ms** | 25.7 ms | **23.3 µs** | 23.8 / 7.1 ms | 128 KiB | `35 (12+3×6+5) w=16 v=32` |
| **F. Tall irregular cache *(1 MiB cache, P11 style)*** | **4,868 B** | **1.90 ms** | 191.8 ms | **19.6 µs** | 190 / 57 ms | 1 MiB | `33 (15+3×6) w=16 v=32` |
| **G. Uniform fast / span-norm $L_2$ *(w=8)*** | **5,928 B** | **2.89 ms** | **3.4 ms** | **17.2 µs** | **0.5 / 0.2 ms** | **4 KiB** | `35 (5×7) w=8 v=42` |
| **H. Uniform $L_\infty$ minimax ratio *(w=8)*** | **7,440 B** | **1.24 ms** | **1.4 ms** | **23.5 µs** | **0.1 / 0.04 ms** | **1 KiB** | `35 (7×5) w=8 v=42` |

All eight remain strictly smaller, faster to sign (cached), and faster to verify than `SLH-DSA-BLAKE3-128s` (`7,856 B`, `121.7 ms`, `126.6 µs`). BLINCS remains at `0.1.0` (`3,988 B`) while the final pre-1.0 parameter choice is settled.

### Why `m = 103` is not signing-time-bottlenecked in BLINCS (`tools/optimize.py --grinding-sweep`)

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
   - **Re-evaluated WITH Project 11's top-tree and partial-tree caching insight (§3 above):** putting extra height into the cached top tree improves bytes, cached signing, and verification **simultaneously** (for example `4,868 B / 1.90 ms / 19.6 µs` at `h_top = 15`, or `4,084 B / 4.66 ms / 29.1 µs` at `h_top = 15`), while implementations can smoothly trade cache size from `0 B` through `2 KiB / 8 KiB / 32 KiB / 1 MiB / 65 MiB` with zero wire-format change. Kept open as Candidates B, D, E, F in the Head-to-Head table above.
10. **Optimizing parameters for signing time rather than minimum bytes** (Conor Deegan's review note): moving from `3,988 B` (`w = 32`) up by ~900–1,060 bytes to `4,868–5,048 B` (`w = 16`) cuts signing time 4–8× and verification 1.4–1.7× while staying 36–38% smaller than `SLH-DSA-128s`. Kept open as Candidates C–F above.
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

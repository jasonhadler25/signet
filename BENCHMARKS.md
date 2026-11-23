# Benchmarks: Project 11 SLH-DSA-B reproduction and BLINCS

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (12 cores, macOS arm64, Rust 1.100.0).

## 1. Project 11 SLH-DSA-B reproduction vs. BLINCS (Criterion methodology)

Source reproduced: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (`slh-dsa/benches/sign_verify.rs` and `slh-dsa/benches/sign_large_msg.rs`: Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). BLINCS was measured with the exact same Criterion configuration.

> **Threading note:** `PQC-Suite-B/signatures` enables `blake3 = { version = "1.8.2", features = ["rayon"] }` and uses `update_rayon` on message segments $\ge 256$ KiB, so its `SLH-DSA-BLAKE3` 1 MiB and 100 MiB runs use **all CPU cores** for message hashing while its tree hashing is single-threaded. We measured `SLH-DSA-BLAKE3` both as-shipped (default 12 threads) and single-threaded (`RAYON_NUM_THREADS=1`). **BLINCS (Step 1b, `5,616 B`, `WOTS+` + `FORS`)** enables multithreading by default via `blake3-servil = "=0.10.0"` (single-pass salted content hashing + coarse leaf-parallel tree/FORS wave) while verification of small messages stays single-core.

### Published Apple M3 (PQC-Suite-B charts) vs. Apple M6 reproduction vs. BLINCS

| Scheme | Sig bytes | Budget | Verify 64 B (M3 pub.) | Verify 64 B (M6) | Sign 64 B (M3 pub.) | Sign 64 B (M6) | Sign 1 MiB (M6) | Sign 100 MiB (M6) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 665 µs | 509.0 µs | 696.0 ms | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 115 µs | 74.4 µs | 113.8 ms | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(as-shipped, rayon)* | 7,856 B | $2^{64}$ | 159 µs | 126.6 µs | 155.3 ms | 121.7 ms | 122.1 ms | 131.9 ms *(12 cores)* |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | — | 126.6 µs | — | 121.7 ms | — | 222.8 ms *(1 core)* |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,943 µs | 1,539.9 µs | 33.6 ms | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 328 µs | 219.9 µs | 5.54 ms | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(as-shipped, rayon)* | 17,088 B | $2^{64}$ | 459 µs | 353.7 µs | 7.42 ms | 5.81 ms | 6.26 ms | 15.8 ms *(12 cores)* |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | — | 353.7 µs | — | 5.81 ms | — | 89.1 ms *(1 core)* |
| **BLINCS *(Step 1b, multithreaded default)*** | **5,616 B** | **$2^{32}$** | — | **26.2 µs** | — | **0.44 ms** | **0.50 ms** | **4.06–4.37 ms** *(12 cores)* |
| *BLINCS 0.1.0 draft (1 thread, 3,988 B, WOTS+C + PORS+FP)* | *3,988 B* | *$2^{33}$* | — | *31.8 µs* | — | *16.44 ms* | *16.67 ms* | *31.33 ms (1 core)* |

Additional BLINCS (Step 1b) verification numbers on M6 (`clocks`, single-pass salted, `blake3-servil = "=0.10.0"`):

- `verify 64 B` (1 core): **26.2 µs** (38,200 / s)
- `verify 1 MiB`: **111.9 µs** (9,367 MB/s)
- `verify 16 MiB`: **601–638 µs** (26.3–27.9 GB/s)
- `verify_reader 100 MiB` (zero-copy `Pipeline`): **3.89 ms** (26,941 MB/s)

Key takeaways on M6:

- **Size:** BLINCS (`5,616 B`, `7,488 B` Base64) is **29% smaller** than `SLH-DSA-128s` (`7,856 B`), **3.0× smaller** than `SLH-DSA-128f` (`17,088 B`), and clears default Apache (`8,190 B`) and nginx (`8,192 B`) HTTP header limits with 702 B to spare.
- **Verification (64 B, 1 core):** BLINCS (**26.2 µs**) is **2.8× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (74.4 µs), **4.8× faster** than `SLH-DSA-BLAKE3-128s` (126.6 µs), **13.5× faster** than `SLH-DSA-BLAKE3-128f` (353.7 µs), and **19.4× faster** than `SLH-DSA-SHAKE-128s` (509.0 µs).
- **Signing (64 B):** BLINCS (**0.44 ms**) is **276× faster** than `SLH-DSA-BLAKE3-128s` (121.7 ms), **13.2× faster** than `SLH-DSA-BLAKE3-128f` (5.81 ms), and **8.3× faster** than `SLH-DSA-SHA2-128f` (3.63 ms) — with **zero counter grinding** and zero tail-latency spikes.
- **Signing (100 MiB):** BLINCS (**4.06–4.37 ms**, **4.35 ms** via zero-copy `Pipeline` streaming) is **31× faster** than 12-core `SLH-DSA-BLAKE3-128s` (131.9 ms) and **3.7× faster** than 12-core `SLH-DSA-BLAKE3-128f` (15.8 ms).

## 2. Wall time and core cycles (`bench/`, `clocks` crate)

Measured on a quiet machine (`bench/` with `blake3-servil = "=0.10.0"`, Step 1b `5,616 B`, 0% E-cores on all signing/verifying runs):

| Operation | Wall time | Main-thread cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `SigningKey::from_seed` (cold 1 MiB top tree) | 40.33 ms | 143.7M | 313.4M | 2.18 | 4,315 MHz | 24.8 / s |
| `SigningKey::from_seed_with_cache` (auth 1 MiB cache) | **203.4 µs** | 887.6k | 3.20M | 3.61 | 4,372 MHz | **4,916 / s** |
| `sign` 64 B | **439.8 µs** | 1.48M | 3.41M | 2.31 | 3,924 MHz | **2,274 / s** |
| `sign_reader` 64 B | **440.3 µs** | 1.48M | 3.42M | 2.31 | 3,924 MHz | **2,271 / s** |
| `verify` 64 B (1 core) | **26.2 µs** | 119.8k | 673.5k | 5.62 | 4,583 MHz | **38,200 / s** |
| `verify_reader` 64 B (1 core) | **26.4 µs** | 121.0k | 677.8k | 5.60 | 4,583 MHz | **37,900 / s** |
| `verify` 256 KiB | 63.2 µs | 284.3k | 1.12M | 3.95 | 4,499 MHz | 4,147 MB/s |
| `verify_reader` 256 KiB | 64.6 µs | 278.7k | 1.49M | 5.36 | 4,315 MHz | 4,058 MB/s |
| `verify` 1 MiB | 111.9 µs | 489.0k | 2.55M | 5.21 | 4,389 MHz | 9,367 MB/s |
| `verify_reader` 1 MiB | 126.2 µs | 516.6k | 2.95M | 5.71 | 4,231 MHz | 8,309 MB/s |
| `sign` 16 MiB | **1.01 ms** | 3.94M | 17.21M | 4.37 | 4,177 MHz | **16,651 MB/s** |
| `verify` 16 MiB | **637.6 µs** | 2.48M | 13.86M | 5.58 | 3,896 MHz | **26,312 MB/s** |
| `sign` 100 MiB | **4.37 ms** | 15.95M | 79.29M | 4.97 | 3,707 MHz | **23,999 MB/s** |
| `sign_reader` 100 MiB (`Pipeline`) | **4.35 ms** | 16.42M | 91.60M | 5.58 | 3,831 MHz | **24,096 MB/s** |
| `verify` 100 MiB | **4.20 ms** | 13.94M | 71.83M | 5.15 | 3,320 MHz | **24,971 MB/s** |
| `verify_reader` 100 MiB (`Pipeline`) | **3.89 ms** | 15.15M | 89.12M | 5.88 | 3,891 MHz | **26,941 MB/s** |
| `Randomness::initialize` | 24.7 µs | 104.8k | 454.5k | 4.34 | 4,246 MHz | — |

## 3. Optimized `blake3-servil` `0.10.0` benchmarks (single-threaded & multithreaded)

We audited and benchmarked every relevant API in `blake3-servil-core = "=0.10.0"` and `blake3-servil = "=0.10.0"` (`Batch`, `TreeHasher::on_this_core()`, `hash_many`, `hash_many_multithreaded`, `hash_multithreaded`, and `Pipeline`) on a quiet Apple M6 using `clocks`.

### 3.1. Raw `hash_many` (32-byte messages: WOTS+C chain steps & PORS+FP leaves)

| Count | 1T SME2 (`hash_many`) | 1T NEON (`on_this_core`) | `hash_many_multithreaded` (`b3-MT`) | `b3-MT` vs. 1T |
|---:|---:|---:|---:|---:|
| 32 – 4,096 | 8.69 ns/hash | 14.78 ns/hash | 8.69 ns/hash | 1.00× *(< 512 KiB)* |
| 8,192 (512 KiB) | 8.69 ns/hash | 14.78 ns/hash | 5.57 ns/hash | 1.56× |
| 16,384 (1 MiB) | 8.69 ns/hash | 14.77 ns/hash | 5.21 ns/hash | 1.67× |
| 32,768 (2 MiB) | 8.69 ns/hash | 14.79 ns/hash | 3.77 ns/hash | 2.30× |
| 65,536 (4 MiB) | 8.69 ns/hash | 14.79 ns/hash | 3.22 ns/hash | 2.70× |

### 3.2. Full XMSS tree builds (single tree, merged lower layers, and `h_top = 15` keygen)

In BLINCS signing, all $d - 1$ lower XMSS trees depend only on `(sk_seed, pk_seed, tree_idx)` and can be built together in **one merged batch** (`3× h=6`, `3× h=7`, `3× h=9`). We compare:

- **`1T-SME`:** single-threaded `blake3-servil-core` `Batch` on SME2.
- **`b3-MT`:** `blake3-servil`'s built-in `hash_many_multithreaded` (zero custom threads; 512 KiB split threshold; barrier per chain step).
- **`12T-HYB`:** persistent coarse leaf split across all 12 M6 cores — 1 thread on SME2 + 11 threads using `TreeHasher::on_this_core()` NEON, running all $w$ chain steps + copy-back + `ONE_TIME_KEY` locally in L1/L2 with **one** barrier at the end (no SME2 contention).

| XMSS workload | `1T-SME` | `1T-NEON` | `b3-MT` (zero custom threads) | `8T-HYB` | `12T-HYB` |
|---|---:|---:|---:|---:|---:|
| `1× h=6` (`w=16, v=32`) | 418 µs | 539 µs | 421 µs (0.99×) | 153 µs (2.73×) | **142 µs (2.95×)** |
| `3× h=6` (`w=16, v=32`, merged) | 1.18 ms | 1.62 ms | 1.19 ms (1.00×) | 355 µs (3.33×) | **309 µs (3.82×)** |
| `1× h=7` (`w=16, v=31`) | 784 µs | 1.04 ms | 786 µs (1.00×) | 251 µs (3.12×) | **215 µs (3.65×)** |
| `3× h=7` (`w=16, v=31`, merged) | 2.20 ms | 3.12 ms | 1.57 ms (1.40×) | 666 µs (3.31×) | **530 µs (4.16×)** |
| `4× h=7` (`w=16, v=31`, merged) | 2.90 ms | 4.17 ms | 1.89 ms (1.54×) | 879 µs (3.30×) | **689 µs (4.21×)** |
| `3× h=9` (`w=32, v=24`, BLINCS `0.1.0`) | 12.73 ms | 19.30 ms | 7.66 ms (1.66×) | 4.04 ms (3.15×) | **2.98 ms (4.27×)** |
| **`h_top = 15` keygen** (`32,768` leaves, `w=16, v=32`) | 177.05 ms | — | 72.33 ms (2.45×) | 59.61 ms (2.97×) | **42.56 ms (4.16×)** |

### 3.3. PORS+FP tree builds (`b = 12..16`) and counter grinding

| Workload | `1T-SME` | `b3-MT` | `8T-HYB` | `12T-HYB` |
|---|---:|---:|---:|---:|
| PORS+FP `b = 12` (4,096 leaves) | 158 µs | 166 µs (1.00×) | 94 µs (1.68×) | **86 µs (1.83×)** |
| PORS+FP `b = 13` (8,192 leaves) | 299 µs | 279 µs (1.12×) | 134 µs (2.23×) | **115 µs (2.61×)** |
| PORS+FP `b = 14` (16,384 leaves) | 565 µs | 427 µs (1.35×) | 201 µs (2.81×) | **174 µs (3.26×)** |
| PORS+FP `b = 15` (32,768 leaves) | 1.08 ms | 688 µs (1.59×) | 335 µs (3.22×) | **295 µs (3.65×)** |
| PORS+FP `b = 16` (65,536 leaves) | 2.10 ms | 1.08 ms (1.98×) | 669 µs (3.14×) | **531 µs (3.95×)** |
| Grinding `52 B × 8,192` *(incl. counter write)* | 11.38 ns/try | 5.59 ns/try (1.55×) | 8.33 ns/try (1.37×) | 8.33 ns/try (1.37×) |
| Grinding `52 B × 16,384` | 11.09 ns/try | 5.22 ns/try (1.67×) | 6.18 ns/try (1.79×) | **5.20 ns/try (2.13×)** |
| Grinding `52 B × 32,768` | 10.75 ns/try | — | 4.79 ns/try (2.25×) | **3.85 ns/try (2.79×)** |

### 3.4. Large-message content hashing (`100 MiB`): why BLINCS switched to single-pass salted BLAKE3

We compared the earlier chained two-pass 256 KiB design against larger chunks, unchained parallel two-pass chunks, and single-pass salted BLAKE3 (`Keyed(Keyed(K_content, e), M)`) on a quiet Apple M6:

| Content-hashing design (100 MiB, Apple M6) | Single thread | Multithreaded (`blake3-servil 0.10.0`) | Speedup vs. 2-pass 256 KiB 1T |
|---|---:|---:|---:|
| Chained 2-pass 256 KiB *(earlier draft)* | 31.56 ms (3,322 MB/s) | 31.55 ms (`hash_multithreaded`, 1.00×) / 26.28 ms (`Pipeline::lent`, 1.20×) | 1.00× – 1.20× |
| Chained 2-pass 1 MiB | 28.33 ms (3,701 MB/s) | 11.86 ms (`hash_multithreaded`, 8,843 MB/s) | 2.66× |
| Unchained parallel 2-pass 256 KiB *(12-core 1 SME2 + 11 NEON)* | ~31.6 ms | 6.32 ms (16,592 MB/s) | 4.99× |
| **Single-pass salted BLAKE3 *(adopted)*** | **15.06 ms (6,963 MB/s)** | **3.42 ms (`hash_multithreaded`, 30,629 MB/s) / 3.45 ms (`Pipeline::room()`, 30,409 MB/s)** | **9.22×** |

### 3.5. Highest-impact `blake3-servil` API optimizations for BLINCS

In BLINCS, **`32 B` messages** (`16 B tweak || 16 B node`) account for **80–88% of all signing compressions** (WOTS+C chains and PORS+FP leaves), `48 B` Merkle internal nodes for ~5–10%, and `16 B` messages (tweak-only leaf seeds) for only ~4–7%. Based on the measurements and `blake3-servil 0.10.0` source audit, we filed four upstream feature requests on `servil-software-factory/BLAKE3`:

1. **Fused in-place hash-chain primitive ([#510](https://github.com/servil-software-factory/BLAKE3/issues/510)):** stepping `Packed<32>` WOTS+C chains `s` times in registers with incrementing tweak counter, zero intermediate RAM writes, and zero per-step thread barriers (~3.8–4.3× on M6, +20–28% even on 1 core).
2. **Fast `Packed<32>` batch hashing in low-latency & `Pipeline::batch` modes + optional 16-byte truncated output ([#509](https://github.com/servil-software-factory/BLAKE3/issues/509), building on [#501](https://github.com/servil-software-factory/BLAKE3/issues/501) / [#502](https://github.com/servil-software-factory/BLAKE3/issues/502) / [#503](https://github.com/servil-software-factory/BLAKE3/issues/503)):** zero-copy `Packed<32>` kernels with implicit zero padding in registers and `[u8; 16]` output cut hot-loop L1/L2 bandwidth in half.
3. **Register-only counter-grinding batch ([#511](https://github.com/servil-software-factory/BLAKE3/issues/511)):** hashing one fixed $\le 64\text{ B}$ template with an incrementing `u32` counter in registers eliminates writing 2,048–32,768 duplicated slots to RAM.
4. **General `Pipeline` ergonomics ([#512](https://github.com/servil-software-factory/BLAKE3/issues/512)):** per-message `Mode` (`message_with_mode`), safe zero-copy owned buffers for pre-existing slices, and calling-thread participation at low queue depth (note that zero-copy single-pass streaming directly into `Pipeline::room()` already reaches **30.4 GB/s** safely in `0.10.0`).

## 4. Calibrated timing fit summary (used by `tools/optimize.py`)

`tools/optimize.py --check` verifies the fitted M6 models directly against the measurements in Section 3:

- **1T-SME (merged lower trees):** XMSS `10.25 + 2.2 * 6144 / (chains + 6144)` ns/comp (`h_top = 15` predicts `175.5 ms` vs. `177.1 ms` measured); PORS `10.2 + 4.4 * 6144 / (leaves + 6144)` ns/comp; grinding `11.4` ns/try.
- **`b3-MT` (`hash_many_multithreaded`):** stays single-threaded below 8,192 slots (`512 KiB`), scaling smoothly up to `2.45×` on `h_top = 15` and `1.98×` on `b = 16` PORS.
- **`12T-HYB` (1 SME2 + 11 NEON `on_this_core()`):** XMSS `2.38 + 3.6 * 1500 / (chains + 1500)` ns/comp + `15 µs` (`h_top = 15` predicts `40.8 ms` vs. `42.6 ms` measured); PORS `2.45 * (3 * leaves - 1) + 56,000` ns (within 1.7% across `b = 12..16`); grinding `4.8` ns/try above 10,000 tries.
- **Verification (1 core, `on_this_core()`):** `18.5` ns/batched + `45.0` ns/scalar (`33.1 µs` predicted vs. `33.3 µs` measured for BLINCS `0.1.0`).

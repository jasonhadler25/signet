# Benchmarks: Project 11 SLH-DSA-B reproduction and BLINCS

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (12 cores, macOS arm64, Rust 1.100.0).

## 1. Project 11 SLH-DSA-B reproduction vs. BLINCS (Criterion methodology)

Source reproduced: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (`slh-dsa/benches/sign_verify.rs` and `slh-dsa/benches/sign_large_msg.rs`: Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). BLINCS was measured with the exact same Criterion configuration.

> **Threading note:** `PQC-Suite-B/signatures` enables `blake3 = { version = "1.8.2", features = ["rayon"] }` and uses `update_rayon` on message segments $\ge 256$ KiB, so its `SLH-DSA-BLAKE3` 1 MiB and 100 MiB runs use **all CPU cores** for message hashing while its tree hashing is single-threaded. We measured `SLH-DSA-BLAKE3` both as-shipped (default 12 threads) and single-threaded (`RAYON_NUM_THREADS=1`). BLINCS below is **100% single-threaded** (`blake3-servil-core = "=0.10.0"`, zero threads) and hashes messages in **two salted passes** per 256 KiB chunk.

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
| **BLINCS 0.1.0 *(1 thread, 2-pass salted)*** | **3,988 B** | **$2^{33}$** | — | **32.9 µs** | — | **16.49 ms** | **16.81 ms** | **48.06 ms** *(1 core)* |

Additional BLINCS Criterion verification numbers on M6 (1 thread, 2-pass salted):

- `verify 64 B`: **32.8 µs**
- `verify 1 MiB`: **342.1 µs** (2.85 GiB/s)
- `verify 100 MiB`: **31.58 ms** (3.09 GiB/s)

Key takeaways on M6 (1 thread vs. 1 thread):

- **Size:** BLINCS (3,988 B) is **half** the size of SLH-DSA-128s (7,856 B) and **less than one quarter** of SLH-DSA-128f (17,088 B), trading the $2^{64}$ signing budget for $2^{33}$ plus WOTS+C and PORS+FP.
- **Verification (64 B):** BLINCS (**32.9 µs**) is **2.3× faster** than hardware-accelerated SLH-DSA-SHA2-128s (74.4 µs), **3.8× faster** than SLH-DSA-BLAKE3-128s (126.6 µs), **10.8× faster** than SLH-DSA-BLAKE3-128f (353.7 µs), and **15.5× faster** than SLH-DSA-SHAKE-128s (509.0 µs).
- **Signing (64 B):** BLINCS (**16.5 ms**) is **7.4× faster** than SLH-DSA-BLAKE3-128s (121.7 ms), **4.6× faster** than SLH-DSA-SHA2-128s (75.5 ms), and **33× faster** than SLH-DSA-SHAKE-128s (548.4 ms).
- **Signing (100 MiB, single thread):** despite hashing every 256 KiB chunk **twice**, BLINCS (**48.1 ms**) is **4.6× faster** than single-threaded SLH-DSA-BLAKE3-128s (222.8 ms) and **1.85× faster** than single-threaded SLH-DSA-BLAKE3-128f (89.1 ms), because `blake3-servil-core` uses Apple Silicon SME2 (~6.8 GB/s per pass vs. ~1.2 GB/s in official `blake3 1.8.2`).

## 2. Wall time and core cycles (`bench/`, `clocks` crate)

Measured on a quiet machine (`clocks::load` reported zero busy windows, 0% E-cores):

| Operation | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `SigningKey::from_seed` | 4.43 ms | 19.82M | 42.56M | 2.15 | 4,476 MHz | 226 / s |
| `sign` 64 B | 16.22 ms | 72.51M | 157.85M | 2.18 | 4,472 MHz | 61.7 / s |
| `verify` 64 B | 33.3 µs | 152.4k | 902.9k | 5.92 | 4,582 MHz | 30,000 / s |
| `verify_reader` 64 B | 34.8 µs | 159.6k | 919.6k | 5.76 | 4,582 MHz | 28,700 / s |
| `verify` 256 KiB | 105.0 µs | 469.3k | 1.72M | 3.66 | 4,474 MHz | 2,498 MB/s |
| `verify` 1 MiB | 323.9 µs | 1.43M | 4.19M | 2.93 | 4,413 MHz | 3,238 MB/s |
| `verify` 16 MiB | 4.77 ms | 20.58M | 53.43M | 2.60 | 4,315 MHz | 3,516 MB/s |
| `sign` 16 MiB | 20.96 ms | 92.66M | 209.54M | 2.26 | 4,422 MHz | 800 MB/s |
| `Randomness::initialize` | 23.1 µs | 104.6k | 452.7k | 4.33 | 4,536 MHz | — |

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

### 3.4. Large-message two-pass salted content hashing (`100 MiB`, `hash_multithreaded`)

Because `blake3-servil`'s `hash_multithreaded` splits only at `MIN_SPLIT_LEN = 512 KiB`, BLINCS `0.1.0`'s 256 KiB chunks run single-threaded (`1.00×`). Larger chunks are faster even on 1 core and unlock multi-GB/s multithreaded verification/signing directly via `blake3-servil`:

| Chunk size (100 MiB message, 2 salted passes) | Single thread (`throughput::hash`) | `hash_multithreaded` (`b3-MT`) | Speedup |
|---:|---:|---:|---:|
| 256 KiB *(BLINCS `0.1.0`)* | 31.57 ms (3,322 MB/s) | 31.56 ms (3,323 MB/s) | 1.00× |
| 512 KiB | 29.35 ms (3,573 MB/s) | 20.23 ms (5,183 MB/s) | 1.45× |
| 1 MiB | **28.27 ms (3,709 MB/s)** | 18.70 ms (5,608 MB/s) | 1.51× |
| 2 MiB | 28.57 ms (3,671 MB/s) | 12.92 ms (8,115 MB/s) | 2.21× |
| 4 MiB | 28.68 ms (3,656 MB/s) | **10.93 ms (9,596 MB/s)** | **2.62×** |

### 3.5. Highest-impact `blake3-servil` API optimizations for BLINCS

In BLINCS, **`32 B` messages** (`16 B tweak || 16 B node`) account for **80–88% of all signing compressions** (WOTS+C chains and PORS+FP leaves), `48 B` Merkle internal nodes for ~5–10%, and `16 B` messages (tweak-only leaf seeds) for only ~4–7%. Based on the measurements and `blake3-servil 0.10.0` source audit, the best `blake3-servil` optimizations for BLINCS (in order of impact) are:

1. **Coarse multi-step chain / pool-dispatch support (~3.8–4.3× signing speedup, +20–28% even on 1 core):** a fused in-place chain primitive (`N` messages of `16 B tweak || 16 B value` stepped `s` times with incrementing tweak word in registers, zero intermediate RAM writes, zero per-step barriers, using `blake3-servil`'s existing `Sme2Turn` + NEON worker pool) — or exposing a small coarse-work callback on `blake3-servil`'s warm worker pool so BLINCS doesn't pay 15–31 barriers per tree.
2. **Native zero-copy `Packed<32>` / `Packed<16>` / `Packed<48>` kernels + optional 16-byte truncated output + `Pipeline::batch` accepting `Packed<N>` (~15–25% on 1 core, 2× less L1/L2 traffic):** `hash_packed` currently expands 16 messages into stack `Block`s (`src/many.rs:149`), and `Pipeline::batch` (`TASK_LEN = 64 KiB`, which already splits far below `hash_many_multithreaded`'s 512 KiB floor!) currently accepts only `Batch<'static>`. Native packed kernels with implicit zero padding words in registers and 16-byte output cut both read and write bandwidth in half.
3. **Register-only counter-grinding batch:** hashing a single fixed 32 B / 48 B prefix with an incrementing `u32` counter word in registers avoids materializing 2,048–32,768 nearly-identical 64-byte slots in memory.
4. **256 KiB chunk splitting via `Pipeline` (or 1–2 MiB chunks):** `Pipeline` already splits at `TASK_LEN = 64 KiB`, unlocking multi-core streaming even below `hash_multithreaded`'s 512 KiB threshold.

## 4. Calibrated timing fit summary (used by `tools/optimize.py`)

`tools/optimize.py --check` verifies the fitted M6 models directly against the measurements in Section 3:

- **1T-SME (merged lower trees):** XMSS `10.25 + 2.2 * 6144 / (chains + 6144)` ns/comp (`h_top = 15` predicts `175.5 ms` vs. `177.1 ms` measured); PORS `10.2 + 4.4 * 6144 / (leaves + 6144)` ns/comp; grinding `11.4` ns/try.
- **`b3-MT` (`hash_many_multithreaded`):** stays single-threaded below 8,192 slots (`512 KiB`), scaling smoothly up to `2.45×` on `h_top = 15` and `1.98×` on `b = 16` PORS.
- **`12T-HYB` (1 SME2 + 11 NEON `on_this_core()`):** XMSS `2.38 + 3.6 * 1500 / (chains + 1500)` ns/comp + `15 µs` (`h_top = 15` predicts `40.8 ms` vs. `42.6 ms` measured); PORS `2.45 * (3 * leaves - 1) + 56,000` ns (within 1.7% across `b = 12..16`); grinding `4.8` ns/try above 10,000 tries.
- **Verification (1 core, `on_this_core()`):** `18.5` ns/batched + `45.0` ns/scalar (`33.1 µs` predicted vs. `33.3 µs` measured for BLINCS `0.1.0`).

# Benchmarks: Project 11 SLH-DSA-B reproduction and BLINCS

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

## 3. Multithreading experiment (`blake3-servil = "=0.10.0"`)

Tested on a quiet Apple M6 using `clocks` (wall time and process CPU time together) on BLINCS's exact batch and chunk shapes:

| Workload | Single-threaded (`blake3-servil-core`) | Multithreaded | CPU used | Speedup |
|---|---:|---:|---:|---:|
| 1 XMSS tree (512 leaves × 24 chains × 31 steps) | 4.42 ms | 3.02 ms (`hash_many_multithreaded`) | 3.5× | 1.46× |
| 1 XMSS tree, leaves split across 4 threads (zero per-step barriers) | 4.42 ms | 2.12 ms | 3.3× | 2.08× |
| 1 XMSS tree, leaves split across 8 threads (zero per-step barriers) | 4.42 ms | 1.32 ms | 6.3× | 3.35× |
| 100 MiB two-pass 256 KiB chunks (`hash_multithreaded`) | 31.11 ms | 31.11 ms | 1.0× | 1.00× |
| 100 MiB two-pass 1 MiB chunks (`hash_multithreaded`, comparison) | 27.58 ms | 18.49 ms | 4.4× | 1.49× |

Observations:

1. Calling `blake3_servil::throughput::hash_many_multithreaded` inside each of the 31 sequential chain steps speeds up an XMSS tree by only **1.46×** (`4.42 → 3.02 ms`), because 31 pool barriers plus the single-threaded 12,288-element copy-back loop dominate.
2. Parallelizing across the **512 independent leaves** of an XMSS tree (so each thread runs all 31 steps + copy-back + `ONE_TIME_KEY` with zero barriers, while `blake3-servil-core`'s `Sme2Turn` lets one thread use SME2 and the rest run NEON concurrently) reaches **1.32 ms per XMSS tree** (**3.35× faster**) even with fresh thread spawns — projecting **~4.5–5 ms total signing** on 8 cores.
3. For 256 KiB content chunks, `blake3_servil::throughput::hash_multithreaded` stays single-threaded (its multithreading threshold is above 256 KiB; at 1 MiB chunks it speeds up 100 MiB two-pass hashing from 27.6 ms to 18.5 ms).
4. The core `blincs` crate stays single-threaded (`blake3-servil-core`, zero threads, zero locks); coarse leaf parallelism belongs in an optional feature or companion multithreaded API if needed.

# Benchmarks: Project 11 SLH-DSA-B reproduction and Signet (`BLINCS-128-7x5`, single-threaded)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **Signet runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: Project 11 SLH-DSA-B reproduction vs. Signet (`BLINCS-128-7x5`)

Source reproduced for SLH-DSA: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). Because `PQC-Suite-B/signatures` enables `blake3/rayon` for message segments $\ge 256$ KiB, we measured `SLH-DSA-BLAKE3` with `RAYON_NUM_THREADS=1` so every row below compares **1 core vs. 1 core** cleanly. Signet (`BLINCS-128-7x5`: `7×5` uniform, `6,432 B`, `WOTS+` + `U-FORS(3, 10, 16, 64, 5, 15)` with lockstep cross-tree SIMD batching, 1 KiB top tree, framed `Context`, zero grinding so `p99 = mean`, no disk cache, `blake3-servil-core = "=0.11.0"`) was measured with `bench/` (`clocks`, 0% E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 509.0 µs | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 74.4 µs | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,539.9 µs | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 219.9 µs | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **Signet (`BLINCS-128-7x5`, `blake3-servil-core 0.11.0`)** | **6,432 B** | **$2^{32}$** | **36.2 µs** | **1.22 ms** | **1.36 ms** | **16.25 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** `BLINCS-128-7x5` (`6,432 B`, `8,576 B` Base64) is **1,424 B smaller** than `SLH-DSA-128s` (`7,856 B`) and **2.66× smaller** than `SLH-DSA-128f` (`17,088 B`).
- **Signing (64 B, 1 core, constant algorithmic work):** Signet (**1.22 ms** warm, **1.39 ms** cold 1-shot with no disk cache) is **100× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`), **62× faster** than `SLH-DSA-SHA2-128s` (`75.5 ms`), **4.8× faster** than `SLH-DSA-BLAKE3-128f` (`5.81 ms`) while 2.66× smaller, and **3.0× faster** than hardware-accelerated `SLH-DSA-SHA2-128f` (`3.63 ms`) — with zero counter grinding.
- **Verification (64 B, 1 core):** Signet (**36.2 µs**, `27,600 / s`) is **2.1× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (`74.4 µs`), **3.5× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`), **9.8× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`), and **14.1× faster** than `SLH-DSA-SHAKE-128s` (`509.0 µs`).
- **Cold startup (`Signet::from_seed`):** **170.1 µs** (`0.17 ms`, `5,879 / s`, 1 KiB top tree — no disk cache needed).
- **Signing (100 MiB, 1 core):** Signet (**16.25 ms** slice / **27.87 ms** `imprint_with` streaming) is **13.7× faster** than 1-core `SLH-DSA-BLAKE3-128s` (`222.8 ms`) and **5.5× faster** than 1-core `SLH-DSA-BLAKE3-128f` (`89.1 ms`), hashing the message in a single salted BLAKE3 pass (~6.46 GB/s signing, ~6.95 GB/s verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0% E-cores` on every row):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (1 KiB top tree, no disk cache) | **170.1 µs** | 695.6k | 984.5k | 1.42 | 4,091 MHz | **5,879 / s** |
| `Signet::imprint` 64 B | **1.22 ms** | 5.04M | 8.63M | 1.71 | 4,119 MHz | **820 / s** |
| `Signet::imprint_with` 64 B | **1.23 ms** | 5.05M | 8.63M | 1.71 | 4,119 MHz | **813 / s** |
| `SignetId::verify` 64 B | **36.2 µs** | 166.5k | 1.19M | **7.14** | 4,600 MHz | **27,600 / s** |
| `SignetId::verify_with` 64 B | **36.2 µs** | 166.6k | 1.19M | **7.14** | 4,600 MHz | **27,600 / s** |
| `SignetId::verify` 1 KiB | 38.7 µs | 177.6k | 1.27M | 7.17 | 4,596 MHz | — |
| `SignetId::verify` 64 KiB | 47.1 µs | 204.5k | 1.19M | 5.84 | 4,343 MHz | 1,392 MB/s |
| `SignetId::verify` 256 KiB | 74.9 µs | 334.0k | 1.68M | 5.02 | 4,458 MHz | 3,498 MB/s |
| `SignetId::verify_with` 256 KiB | 103.7 µs | 444.8k | 1.70M | 3.82 | 4,290 MHz | 2,527 MB/s |
| `Signet::imprint` 1 MiB | **1.36 ms** | 5.65M | 10.92M | 1.93 | 4,143 MHz | 768 MB/s |
| `SignetId::verify` 1 MiB | 171.5 µs | 764.8k | 3.45M | 4.52 | 4,462 MHz | 6,115 MB/s |
| `SignetId::verify_with` 1 MiB | 301.3 µs | 1.24M | 2.89M | 2.33 | 4,114 MHz | 3,480 MB/s |
| `Signet::imprint` 16 MiB | **3.59 ms** | 15.38M | 45.83M | 2.98 | 4,286 MHz | **4,672 MB/s** |
| `SignetId::verify` 16 MiB | **2.40 ms** | 10.49M | 38.41M | 3.66 | 4,379 MHz | **7,001 MB/s** |
| `Signet::imprint` 100 MiB | **16.25 ms** | 70.80M | 241.27M | 3.41 | 4,360 MHz | **6,455 MB/s** |
| `Signet::imprint_with` 100 MiB (`Sink` / `io::copy`) | 27.87 ms | 112.60M | 181.47M | 1.61 | 4,042 MHz | 3,762 MB/s |
| `SignetId::verify` 100 MiB | **15.10 ms** | 66.11M | 233.79M | 3.54 | 4,381 MHz | **6,946 MB/s** |
| `SignetId::verify_with` 100 MiB (`Sink` / `io::copy`) | 26.38 ms | 106.55M | 173.99M | 1.63 | 4,041 MHz | 3,975 MB/s |
| `Randomness::initialize` (lock-free atomic file) | 92.9 µs | 416.4k | 2.17M | 5.20 | 4,534 MHz | — |

## 3. Reproducing

```sh
cd bench && cargo run --release
```

x86-64 and non-Apple ARM measurements have not yet been published here.

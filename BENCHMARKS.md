# Benchmarks: Project 11 SLH-DSA-B reproduction and BLINCS (single-threaded)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **BLINCS runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: Project 11 SLH-DSA-B reproduction vs. BLINCS

Source reproduced for SLH-DSA: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). Because `PQC-Suite-B/signatures` enables `blake3/rayon` for message segments $\ge 256$ KiB, we measured `SLH-DSA-BLAKE3` with `RAYON_NUM_THREADS=1` so every row below compares **1 core vs. 1 core** cleanly. BLINCS (`5×7` uniform, `5,888 B`, `WOTS+` + `FORS(11, 13)`, 4 KiB top tree, no disk cache, `blake3-servil-core = "=0.11.0"`) was measured with `bench/` (`clocks`, 0% E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 509.0 µs | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 74.4 µs | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,539.9 µs | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 219.9 µs | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **BLINCS (`5×7`, `blake3-servil-core 0.11.0`)** | **5,888 B** | **$2^{32}$** | **26.3 µs** | **3.47 ms** | **3.60 ms** | **18.57 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** BLINCS (`5,888 B`, `7,852 B` Base64) is **25% smaller** than `SLH-DSA-128s` (`7,856 B`) and **2.9× smaller** than `SLH-DSA-128f` (`17,088 B`).
- **Verification (64 B, 1 core):** BLINCS (**26.3 µs**, `38,000 / s`) is **2.8× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (`74.4 µs`), **4.8× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`), **13.4× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`), and **19.4× faster** than `SLH-DSA-SHAKE-128s` (`509.0 µs`).
- **Signing (64 B, 1 core):** BLINCS (**3.47 ms** warm, **4.12 ms** cold 1-shot with no disk cache) is **35× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`), **22× faster** than `SLH-DSA-SHA2-128s` (`75.5 ms`), **1.67× faster** than `SLH-DSA-BLAKE3-128f` (`5.81 ms`) while 2.9× smaller, and faster than `SLH-DSA-SHA2-128f` (`3.63 ms`) — with zero counter grinding.
- **Cold startup (`Signet::from_seed`):** **649.7 µs** (`0.65 ms`, 4 KiB top tree — no disk cache needed).
- **Signing (100 MiB, 1 core):** BLINCS (**18.57 ms** slice / **28.01 ms** zero-allocation 16 KiB streaming reader) is **12.0× faster** than 1-core `SLH-DSA-BLAKE3-128s` (`222.8 ms`) and **4.8× faster** than 1-core `SLH-DSA-BLAKE3-128f` (`89.1 ms`), hashing the message in a single salted BLAKE3 pass (~5.6 GB/s signing, ~6.9 GB/s verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0% E-cores` on every row):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (4 KiB top tree, no disk cache) | **649.7 µs** | 2.68M | 3.56M | 1.33 | 4,122 MHz | **1,539 / s** |
| `Signet::imprint` 64 B | **3.47 ms** | 14.29M | 19.72M | 1.38 | 4,125 MHz | **288 / s** |
| `Signet::imprint_reader` 64 B | **3.47 ms** | 14.30M | 19.72M | 1.38 | 4,123 MHz | **288 / s** |
| `SignetId::verify` 64 B | **26.3 µs** | 120.9k | 850.4k | **7.03** | 4,607 MHz | **38,000 / s** |
| `SignetId::verify_reader` 64 B | **26.4 µs** | 121.5k | 851.8k | **7.01** | 4,601 MHz | **37,900 / s** |
| `SignetId::verify` 1 KiB | 26.5 µs | 121.8k | 855.6k | 7.02 | 4,601 MHz | — |
| `SignetId::verify` 64 KiB | 38.5 µs | 159.0k | 854.5k | 5.38 | 4,133 MHz | 1,703 MB/s |
| `SignetId::verify` 256 KiB | 62.5 µs | 274.3k | 1.24M | 4.51 | 4,394 MHz | 4,198 MB/s |
| `SignetId::verify_reader` 256 KiB | 90.3 µs | 381.2k | 1.23M | 3.22 | 4,223 MHz | 2,903 MB/s |
| `Signet::imprint` 1 MiB | 3.60 ms | 14.89M | 22.01M | 1.48 | 4,138 MHz | 291 MB/s |
| `SignetId::verify` 1 MiB | 164.0 µs | 729.2k | 3.20M | 4.39 | 4,448 MHz | 6,395 MB/s |
| `SignetId::verify_reader` 1 MiB | 288.3 µs | 1.18M | 2.50M | 2.12 | 4,089 MHz | 3,637 MB/s |
| `Signet::imprint` 16 MiB | **5.72 ms** | 24.12M | 56.92M | 2.36 | 4,219 MHz | **2,934 MB/s** |
| `SignetId::verify` 16 MiB | **2.27 ms** | 9.90M | 38.00M | 3.84 | 4,371 MHz | **7,407 MB/s** |
| `Signet::imprint` 100 MiB | **18.57 ms** | 80.46M | 252.36M | 3.14 | 4,334 MHz | **5,645 MB/s** |
| `Signet::imprint_reader` 100 MiB (16 KiB stack buf) | 28.01 ms | 113.48M | 179.69M | 1.58 | 4,054 MHz | 3,744 MB/s |
| `SignetId::verify` 100 MiB | **15.13 ms** | 66.25M | 233.49M | 3.52 | 4,383 MHz | **6,932 MB/s** |
| `SignetId::verify_reader` 100 MiB (16 KiB stack buf) | 24.15 ms | 97.59M | 160.80M | 1.65 | 4,043 MHz | 4,342 MB/s |
| `Randomness::initialize` (lock-free seed dir) | 71.3 µs | 323.2k | 1.54M | 4.75 | 4,536 MHz | — |

## 3. Reproducing

```sh
cd bench && cargo run --release
```

x86-64 and non-Apple ARM measurements have not yet been published here.

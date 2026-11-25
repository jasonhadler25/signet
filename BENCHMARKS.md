# Benchmarks: Project 11 SLH-DSA-B reproduction and BLINCS (single-threaded)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **BLINCS runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: Project 11 SLH-DSA-B reproduction vs. BLINCS

Source reproduced for SLH-DSA: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). Because `PQC-Suite-B/signatures` enables `blake3/rayon` for message segments $\ge 256$ KiB, we measured `SLH-DSA-BLAKE3` with `RAYON_NUM_THREADS=1` so every row below compares **1 core vs. 1 core** cleanly. BLINCS (`12 + 3×7`, `5,616 B`, `WOTS+` + `FORS`, no disk cache, `blake3-servil-core = "=0.11.0"`) was measured with `bench/` (`clocks`, 0% E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 509.0 µs | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 74.4 µs | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,539.9 µs | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 219.9 µs | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **BLINCS (`12 + 3×7`, `blake3-servil-core 0.11.0`)** | **5,616 B** | **$2^{32}$** | **21.3 µs** | **2.54 ms** | **2.68 ms** | **17.61 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** BLINCS (`5,616 B`, `7,488 B` Base64) is **29% smaller** than `SLH-DSA-128s` (`7,856 B`) and **3.0× smaller** than `SLH-DSA-128f` (`17,088 B`).
- **Verification (64 B, 1 core):** BLINCS (**21.3 µs**, `46,900 / s`) is **3.5× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (`74.4 µs`), **5.9× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`), **16.6× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`), and **23.9× faster** than `SLH-DSA-SHAKE-128s` (`509.0 µs`).
- **Signing (64 B, 1 core):** BLINCS (**2.54 ms** warm, **23.07 ms** cold 1-shot with no disk cache) is **48× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`), **30× faster** than `SLH-DSA-SHA2-128s` (`75.5 ms`), **2.3× faster** than `SLH-DSA-BLAKE3-128f` (`5.81 ms`) while 3× smaller, and **1.43× faster** than `SLH-DSA-SHA2-128f` (`3.63 ms`) — with zero counter grinding.
- **Signing (100 MiB, 1 core):** BLINCS (**17.61 ms** slice / **27.00 ms** zero-allocation 16 KiB streaming reader) is **12.7× faster** than 1-core `SLH-DSA-BLAKE3-128s` (`222.8 ms`) and **5.1× faster** than 1-core `SLH-DSA-BLAKE3-128f` (`89.1 ms`), because BLINCS hashes the message in a single salted BLAKE3 pass (~6.0 GB/s signing, ~6.9 GB/s verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0% E-cores` on every row):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (128 KiB top tree, no disk cache) | **20.53 ms** | 84.48M | 115.85M | 1.37 | 4,116 MHz | **49 / s** |
| `Signet::imprint` 64 B | **2.54 ms** | 10.44M | 14.97M | 1.43 | 4,109 MHz | **394 / s** |
| `Signet::imprint_reader` 64 B | **2.54 ms** | 10.44M | 14.98M | 1.43 | 4,108 MHz | **394 / s** |
| `SignetId::verify` 64 B | **21.3 µs** | 98.5k | 691.4k | **7.02** | 4,629 MHz | **46,900 / s** |
| `SignetId::verify_reader` 64 B | **21.5 µs** | 99.0k | 692.8k | **7.00** | 4,615 MHz | **46,500 / s** |
| `SignetId::verify` 1 KiB | 23.2 µs | 107.3k | 757.1k | 7.06 | 4,617 MHz | — |
| `SignetId::verify` 64 KiB | 35.5 µs | 144.8k | 764.9k | 5.28 | 4,078 MHz | 1,845 MB/s |
| `SignetId::verify` 256 KiB | 58.8 µs | 256.6k | 1.11M | 4.33 | 4,369 MHz | 4,462 MB/s |
| `SignetId::verify_reader` 256 KiB | 86.6 µs | 363.2k | 1.10M | 3.04 | 4,198 MHz | 3,029 MB/s |
| `Signet::imprint` 1 MiB | 2.68 ms | 11.04M | 17.27M | 1.56 | 4,120 MHz | 391 MB/s |
| `SignetId::verify` 1 MiB | 159.3 µs | 706.7k | 3.03M | 4.29 | 4,437 MHz | 6,580 MB/s |
| `SignetId::verify_reader` 1 MiB | 283.3 µs | 1.16M | 2.34M | 2.03 | 4,080 MHz | 3,701 MB/s |
| `Signet::imprint` 16 MiB | **4.79 ms** | 20.27M | 52.17M | 2.57 | 4,230 MHz | **3,500 MB/s** |
| `SignetId::verify` 16 MiB | **2.27 ms** | 9.90M | 37.97M | 3.83 | 4,371 MHz | **7,401 MB/s** |
| `Signet::imprint` 100 MiB | **17.61 ms** | 76.44M | 247.61M | 3.24 | 4,342 MHz | **5,953 MB/s** |
| `Signet::imprint_reader` 100 MiB (16 KiB stack buf) | 27.00 ms | 109.27M | 174.93M | 1.60 | 4,049 MHz | 3,884 MB/s |
| `SignetId::verify` 100 MiB | **15.16 ms** | 66.40M | 233.34M | 3.51 | 4,382 MHz | **6,917 MB/s** |
| `SignetId::verify_reader` 100 MiB (16 KiB stack buf) | 24.45 ms | 98.92M | 160.66M | 1.62 | 4,047 MHz | 4,288 MB/s |
| `Randomness::initialize` | 23.0 µs | 104.5k | 450.6k | 4.31 | 4,540 MHz | — |

## 3. Reproducing

```sh
cd bench && cargo run --release
```

x86-64 and non-Apple ARM measurements have not yet been published here.

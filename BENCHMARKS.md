# Benchmarks: Project 11 SLH-DSA-B reproduction and BLINCS (single-threaded)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **BLINCS runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: Project 11 SLH-DSA-B reproduction vs. BLINCS

Source reproduced for SLH-DSA: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). Because `PQC-Suite-B/signatures` enables `blake3/rayon` for message segments $\ge 256$ KiB, we measured `SLH-DSA-BLAKE3` with `RAYON_NUM_THREADS=1` so every row below compares **1 core vs. 1 core** cleanly. BLINCS (`7×5` uniform, `7,392 B`, `WOTS+` + byte-aligned `FORS(8, 20)`, 1 KiB top tree, zero grinding so `p99 = mean`, no disk cache, `blake3-servil-core = "=0.11.0"`) was measured with `bench/` (`clocks`, 0% E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 509.0 µs | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 74.4 µs | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,539.9 µs | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 219.9 µs | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **BLINCS (`7×5`, `blake3-servil-core 0.11.0`)** | **7,392 B** | **$2^{32}$** | **34.9 µs** | **1.31 ms** | **1.45 ms** | **16.36 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** BLINCS (`7,392 B`, `9,856 B` Base64) is **464 B smaller** than `SLH-DSA-128s` (`7,856 B`) and **2.31× smaller** than `SLH-DSA-128f` (`17,088 B`).
- **Signing (64 B, 1 core, constant `p99 = mean`):** BLINCS (**1.31 ms** warm, **1.48 ms** cold 1-shot with no disk cache) is **93× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`), **58× faster** than `SLH-DSA-SHA2-128s` (`75.5 ms`), **4.4× faster** than `SLH-DSA-BLAKE3-128f` (`5.81 ms`) while 2.3× smaller, and **2.8× faster** than hardware-accelerated `SLH-DSA-SHA2-128f` (`3.63 ms`) — with zero counter grinding and zero tail spikes.
- **Verification (64 B, 1 core):** BLINCS (**34.9 µs**, `28,700 / s`) is **2.1× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (`74.4 µs`), **3.6× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`), **10.1× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`), and **14.6× faster** than `SLH-DSA-SHAKE-128s` (`509.0 µs`).
- **Cold startup (`Signet::from_seed`):** **170.1 µs** (`0.17 ms`, `5,879 / s`, 1 KiB top tree — no disk cache needed).
- **Signing (100 MiB, 1 core):** BLINCS (**16.36 ms** slice / **25.47 ms** zero-allocation 16 KiB streaming reader) is **13.6× faster** than 1-core `SLH-DSA-BLAKE3-128s` (`222.8 ms`) and **5.4× faster** than 1-core `SLH-DSA-BLAKE3-128f` (`89.1 ms`), hashing the message in a single salted BLAKE3 pass (~6.4 GB/s signing, ~7.0 GB/s verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0% E-cores` on every row):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (1 KiB top tree, no disk cache) | **170.1 µs** | 695.9k | 912.6k | 1.31 | 4,092 MHz | **5,879 / s** |
| `Signet::imprint` 64 B | **1.31 ms** | 5.40M | 8.44M | 1.56 | 4,110 MHz | **763 / s** |
| `Signet::imprint_reader` 64 B | **1.31 ms** | 5.40M | 8.45M | 1.57 | 4,111 MHz | **763 / s** |
| `SignetId::verify` 64 B | **34.9 µs** | 161.5k | 1.14M | **7.05** | 4,632 MHz | **28,700 / s** |
| `SignetId::verify_reader` 64 B | **35.1 µs** | 162.1k | 1.14M | **7.03** | 4,619 MHz | **28,500 / s** |
| `SignetId::verify` 1 KiB | 36.8 µs | 169.9k | 1.20M | 7.08 | 4,622 MHz | — |
| `SignetId::verify` 64 KiB | 49.1 µs | 209.9k | 1.24M | 5.89 | 4,274 MHz | 1,334 MB/s |
| `SignetId::verify` 256 KiB | 72.2 µs | 321.0k | 1.57M | 4.88 | 4,447 MHz | 3,630 MB/s |
| `SignetId::verify_reader` 256 KiB | 100.2 µs | 427.9k | 1.56M | 3.64 | 4,272 MHz | 2,616 MB/s |
| `Signet::imprint` 1 MiB | **1.45 ms** | 6.01M | 10.74M | 1.79 | 4,133 MHz | 721 MB/s |
| `SignetId::verify` 1 MiB | 171.9 µs | 766.9k | 3.48M | 4.54 | 4,464 MHz | 6,100 MB/s |
| `SignetId::verify_reader` 1 MiB | 296.9 µs | 1.22M | 2.79M | 2.28 | 4,110 MHz | 3,532 MB/s |
| `Signet::imprint` 16 MiB | **3.56 ms** | 15.21M | 45.64M | 3.00 | 4,273 MHz | **4,712 MB/s** |
| `SignetId::verify` 16 MiB | **2.28 ms** | 9.97M | 38.35M | 3.84 | 4,373 MHz | **7,352 MB/s** |
| `Signet::imprint` 100 MiB | **16.36 ms** | 71.29M | 241.08M | 3.38 | 4,360 MHz | **6,409 MB/s** |
| `Signet::imprint_reader` 100 MiB (16 KiB stack buf) | 25.47 ms | 103.05M | 168.40M | 1.63 | 4,047 MHz | 4,117 MB/s |
| `SignetId::verify` 100 MiB | **15.05 ms** | 65.93M | 233.74M | 3.55 | 4,382 MHz | **6,966 MB/s** |
| `SignetId::verify_reader` 100 MiB (16 KiB stack buf) | 24.30 ms | 98.25M | 161.06M | 1.64 | 4,045 MHz | 4,315 MB/s |
| `Randomness::initialize` (lock-free seed dir) | 72.9 µs | 324.7k | 1.53M | 4.71 | 4,543 MHz | — |

## 3. Reproducing

```sh
cd bench && cargo run --release
```

x86-64 and non-Apple ARM measurements have not yet been published here.

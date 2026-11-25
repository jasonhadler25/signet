# Benchmarks: Project 11 SLH-DSA-B reproduction and Signet (`BLINCS-128-7x5`, single-threaded)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **Signet runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: Project 11 SLH-DSA-B reproduction vs. Signet (`BLINCS-128-7x5`)

Source reproduced for SLH-DSA: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). Because `PQC-Suite-B/signatures` enables `blake3/rayon` for message segments $\ge 256$ KiB, we measured `SLH-DSA-BLAKE3` with `RAYON_NUM_THREADS=1` so every row below compares **1 core vs. 1 core** cleanly. Signet (`BLINCS-128-7x5`: `7×5` uniform, `7,392 B`, `WOTS+` + byte-aligned `FORS(8, 20)` with cross-tree FORS batching, 1 KiB top tree, framed `Context`, zero grinding so `p99 = mean`, no disk cache, `blake3-servil-core = "=0.11.0"`) was measured with `bench/` (`clocks`, 0% E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 509.0 µs | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 74.4 µs | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,539.9 µs | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 219.9 µs | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **Signet (`BLINCS-128-7x5`, `blake3-servil-core 0.11.0`)** | **7,392 B** | **$2^{32}$** | **34.2 µs** | **1.25 ms** | **1.39 ms** | **16.28 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** `BLINCS-128-7x5` (`7,392 B`, `9,856 B` Base64) is **464 B smaller** than `SLH-DSA-128s` (`7,856 B`) and **2.31× smaller** than `SLH-DSA-128f` (`17,088 B`).
- **Signing (64 B, 1 core, constant algorithmic work):** Signet (**1.25 ms** warm, **1.42 ms** cold 1-shot with no disk cache) is **97× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`), **60× faster** than `SLH-DSA-SHA2-128s` (`75.5 ms`), **4.6× faster** than `SLH-DSA-BLAKE3-128f` (`5.81 ms`) while 2.3× smaller, and **2.9× faster** than hardware-accelerated `SLH-DSA-SHA2-128f` (`3.63 ms`) — with zero counter grinding.
- **Verification (64 B, 1 core):** Signet (**34.2 µs**, `29,200 / s`) is **2.2× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (`74.4 µs`), **3.7× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`), **10.3× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`), and **14.9× faster** than `SLH-DSA-SHAKE-128s` (`509.0 µs`).
- **Cold startup (`Signet::from_seed`):** **170.2 µs** (`0.17 ms`, `5,875 / s`, 1 KiB top tree — no disk cache needed).
- **Signing (100 MiB, 1 core):** Signet (**16.28 ms** slice / **25.59 ms** zero-allocation 16 KiB streaming reader) is **13.7× faster** than 1-core `SLH-DSA-BLAKE3-128s` (`222.8 ms`) and **5.5× faster** than 1-core `SLH-DSA-BLAKE3-128f` (`89.1 ms`), hashing the message in a single salted BLAKE3 pass (~6.4 GB/s signing, ~7.0 GB/s verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0% E-cores` on every row):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (1 KiB top tree, no disk cache) | **170.2 µs** | 696.5k | 916.9k | 1.32 | 4,093 MHz | **5,875 / s** |
| `Signet::imprint` 64 B | **1.25 ms** | 5.15M | 8.41M | 1.63 | 4,128 MHz | **800 / s** |
| `Signet::imprint_reader` 64 B | **1.25 ms** | 5.15M | 8.41M | 1.63 | 4,128 MHz | **800 / s** |
| `SignetId::verify` 64 B | **34.2 µs** | 158.9k | 1.12M | **7.02** | 4,653 MHz | **29,200 / s** |
| `SignetId::verify_reader` 64 B | **34.3 µs** | 159.5k | 1.12M | **7.01** | 4,655 MHz | **29,200 / s** |
| `SignetId::verify` 1 KiB | 35.7 µs | 165.7k | 1.17M | 7.08 | 4,641 MHz | — |
| `SignetId::verify` 64 KiB | 49.2 µs | 210.0k | 1.23M | 5.86 | 4,274 MHz | 1,333 MB/s |
| `SignetId::verify` 256 KiB | 72.1 µs | 320.6k | 1.56M | 4.87 | 4,446 MHz | 3,634 MB/s |
| `SignetId::verify_reader` 256 KiB | 100.0 µs | 427.5k | 1.55M | 3.63 | 4,277 MHz | 2,622 MB/s |
| `Signet::imprint` 1 MiB | **1.39 ms** | 5.75M | 10.70M | 1.86 | 4,152 MHz | 757 MB/s |
| `SignetId::verify` 1 MiB | 171.0 µs | 762.7k | 3.44M | 4.51 | 4,462 MHz | 6,133 MB/s |
| `SignetId::verify_reader` 1 MiB | 295.5 µs | 1.21M | 2.75M | 2.26 | 4,108 MHz | 3,548 MB/s |
| `Signet::imprint` 16 MiB | **3.50 ms** | 14.96M | 45.61M | 3.05 | 4,282 MHz | **4,799 MB/s** |
| `SignetId::verify` 16 MiB | **2.28 ms** | 9.96M | 38.33M | 3.85 | 4,373 MHz | **7,366 MB/s** |
| `Signet::imprint` 100 MiB | **16.28 ms** | 70.99M | 241.05M | 3.40 | 4,362 MHz | **6,440 MB/s** |
| `Signet::imprint_reader` 100 MiB (16 KiB stack buf) | 25.59 ms | 103.54M | 168.37M | 1.63 | 4,049 MHz | 4,098 MB/s |
| `SignetId::verify` 100 MiB | **15.09 ms** | 66.09M | 233.79M | 3.54 | 4,383 MHz | **6,951 MB/s** |
| `SignetId::verify_reader` 100 MiB (16 KiB stack buf) | 24.32 ms | 98.30M | 161.11M | 1.64 | 4,044 MHz | 4,311 MB/s |
| `Randomness::initialize` (lock-free seed dir) | 72.0 µs | 326.0k | 1.55M | 4.75 | 4,550 MHz | — |

## 3. Reproducing

```sh
cd bench && cargo run --release
```

x86-64 and non-Apple ARM measurements have not yet been published here.

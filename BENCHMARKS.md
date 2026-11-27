# Benchmarks: Project 11 SLH-DSA-B reproduction and Signet (`BLINCS-128-A2`, single-threaded)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation, benchmark harness, and charts reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All local measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **Signet runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: Project 11 SLH-DSA-B reproduction vs. Signet (`BLINCS-128-A2`)

Source reproduced for SLH-DSA: [`PQC-Suite-B/signatures`](https://github.com/PQC-Suite-B/signatures) branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a` (Criterion 0.5, `sample_size(10)`, `measurement_time(10s)` for `sign_large` over 64 B, 1 MiB, and 100 MiB, and `verify` over 64 B). Because `PQC-Suite-B/signatures` enables `blake3/rayon` for message segments $\ge 256$ KiB, we measured `SLH-DSA-BLAKE3` with `RAYON_NUM_THREADS=1` so every row below compares **1 core vs. 1 core** cleanly. Signet (`BLINCS-128-A2`: `12+7+7+7` hypertree, `3,292 B`, `S-WOTS+Z(n=24, w=40, S=468, z=8)` + `U-PORS(n=3, w=24, S=42, C=376, A=10, k=10, m_max=44)` with merged `12,288`-chain SIMD super-wave, `128 KiB` cached top tree, framed `Context`, no disk cache, `blake3-servil-core = "=0.11.0"`) was measured with `bench/` (`clocks`, `0–1%` E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| SLH-DSA-SHAKE-128s | 7,856 B | $2^{64}$ | 509.0 µs | 548.4 ms | 550.1 ms | 738.7 ms |
| SLH-DSA-SHA2-128s | 7,856 B | $2^{64}$ | 74.4 µs | 75.5 ms | 76.1 ms | 132.6 ms |
| SLH-DSA-BLAKE3-128s *(1 thread)* | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-SHAKE-128f | 17,088 B | $2^{64}$ | 1,539.9 µs | 26.3 ms | 28.2 ms | 215.5 ms |
| SLH-DSA-SHA2-128f | 17,088 B | $2^{64}$ | 219.9 µs | 3.63 ms | 4.19 ms | 60.6 ms |
| SLH-DSA-BLAKE3-128f *(1 thread)* | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **Signet (`BLINCS-128-A2`, `blake3-servil-core 0.11.0`)** | **3,292 B** | **$2^{32}$** | **39.1 µs** | **4.15 ms** | **4.26 ms** | **18.83 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** `BLINCS-128-A2` (**3,292 B**, **4,392 B** Base64) is **2.39× smaller** (`4,564 B` saved) than `SLH-DSA-128s` (`7,856 B`), **5.19× smaller** than `SLH-DSA-128f` (`17,088 B`), and smaller than symmetric VOLE-in-the-head `FAEST-EM-128s` (`3,924 B`).
- **Signing (64 B, 1 core, warm):** Signet (**4.15 ms** warm, `241 / s`, `p99 / mean ≈ 1.013×`) is **29× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`), **18× faster** than `SLH-DSA-SHA2-128s` (`75.5 ms`), and **1.40× faster** than `SLH-DSA-BLAKE3-128f` (`5.81 ms`) while **5.19× smaller**.
- **Verification (64 B, 1 core, zero heap alloc):** Signet (**39.1 µs**, `25,600 / s`, `7.04 IPC`) is **1.9× faster** than hardware-accelerated `SLH-DSA-SHA2-128s` (`74.4 µs`), **3.2× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`), **9.0× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`), and **13.0× faster** than `SLH-DSA-SHAKE-128s` (`509.0 µs`).
- **Key load (`Signet::from_seed`):** **31.97 ms** (`31 / s`, builds the `128 KiB` cached height-12 top Merkle heap via 1,024-leaf SIMD tiling — no disk cache needed).
- **Signing (100 MiB, 1 core):** Signet (**18.83 ms** slice / **30.77 ms** `imprint_with` streaming) is **11.8× faster** than 1-core `SLH-DSA-BLAKE3-128s` (`222.8 ms`) and **4.7× faster** than 1-core `SLH-DSA-BLAKE3-128f` (`89.1 ms`), hashing the message in a single salted BLAKE3 pass (**~5.57 GB/s** signing, **~6.99 GB/s** verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0–1% E-cores`):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (`128 KiB` height-12 top tree) | **31.97 ms** | 141.40M | 175.60M | 1.24 | 4,425 MHz | **31 / s** |
| `Signet::imprint` 64 B | **4.15 ms** | 18.17M | 25.34M | 1.39 | 4,380 MHz | **241 / s** |
| `Signet::imprint_with` 64 B | **4.14 ms** | 18.17M | 25.33M | 1.39 | 4,388 MHz | **242 / s** |
| `SignetId::verify` 64 B | **39.1 µs** | 178.0k | 1.25M | **7.04** | 4,551 MHz | **25,600 / s** |
| `SignetId::verify_with` 64 B | **39.2 µs** | 178.0k | 1.25M | **7.04** | 4,540 MHz | **25,500 / s** |
| `SignetId::verify` 1 KiB | 40.1 µs | 182.7k | 1.26M | 6.90 | 4,556 MHz | — |
| `SignetId::verify` 64 KiB | 49.4 µs | 223.3k | 1.30M | 5.84 | 4,524 MHz | 1,327 MB/s |
| `SignetId::verify` 256 KiB | 74.9 µs | 337.7k | 1.67M | 4.94 | 4,509 MHz | 3,498 MB/s |
| `SignetId::verify_with` 256 KiB | 105.6 µs | 449.2k | 1.69M | 3.76 | 4,254 MHz | 2,482 MB/s |
| `Signet::imprint` 1 MiB | **4.26 ms** | 18.69M | 27.48M | 1.47 | 4,383 MHz | 246 MB/s |
| `SignetId::verify` 1 MiB | 173.8 µs | 779.6k | 3.53M | 4.53 | 4,486 MHz | 6,032 MB/s |
| `SignetId::verify_with` 1 MiB | 304.3 µs | 1.26M | 2.97M | 2.36 | 4,128 MHz | 3,446 MB/s |
| `Signet::imprint` 16 MiB | **6.28 ms** | 27.79M | 62.11M | 2.24 | 4,424 MHz | **2,670 MB/s** |
| `SignetId::verify` 16 MiB | **2.25 ms** | 10.01M | 38.44M | 3.84 | 4,453 MHz | **7,461 MB/s** |
| `Signet::imprint` 100 MiB | **18.83 ms** | 83.69M | 258.07M | 3.08 | 4,446 MHz | **5,568 MB/s** |
| `Signet::imprint_with` 100 MiB (`Sink` / `io::copy`) | 30.77 ms | 125.64M | 198.10M | 1.58 | 4,085 MHz | 3,408 MB/s |
| `SignetId::verify` 100 MiB | **15.00 ms** | 66.69M | 233.89M | 3.51 | 4,449 MHz | **6,993 MB/s** |
| `SignetId::verify_with` 100 MiB (`Sink` / `io::copy`) | 26.58 ms | 107.41M | 174.10M | 1.62 | 4,042 MHz | 3,944 MB/s |
| `Randomness::initialize` (lock-free atomic file) | 93.7 µs | 424.4k | 2.20M | 5.18 | 4,534 MHz | — |

## 3. Reproducing

```sh
cd bench && cargo run --release --locked
```

x86-64 and non-Apple ARM measurements have not yet been published here.

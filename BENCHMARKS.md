# Benchmarks: Single-core Apple M6 & QEMU Cortex-M33 (`BLINCS-48-X`)

*Thanks to [Project 11](https://research.projecteleven.com/) — specifically **Conor Deegan** and **julienif** on [PQC Suite B (`PQC-Suite-B/signatures`)](https://github.com/PQC-Suite-B/signatures) (building on the **RustCrypto** `slh-dsa` crate) — for publishing the SLH-DSA-B implementation and benchmark harness reproduced here, and to **Servil Software Factory** for [`blake3-servil-core`](https://github.com/servil-software-factory/BLAKE3) and [`bench-hashes`](https://github.com/servil-software-factory/bench-hashes) (`clocks`).*

All desktop measurements below ran on an **Apple M6** (macOS arm64, Rust 1.100.0). **Signet runs strictly single-threaded** on the calling thread via `blake3-servil-core = "=0.11.0"` (zero worker threads, zero background runtime).

## 1. Single-core comparison: OpenSSL 4.1.0 & Project 11 SLH-DSA-B vs. Signet (`BLINCS-48-X`)

Sources reproduced on the same Apple M6 host (single-threaded, 1 core vs. 1 core):
- **OpenSSL 4.1.0:** ARMv8 SHA2/SHA3 hardware extensions, uncached.
- **PQC Suite B (`PQC-Suite-B/signatures`):** branch `b3`, commit `b392fe82d2d9770142477a576a758a233888bc0a`, `RAYON_NUM_THREADS=1`, uncached.
- **Signet (`BLINCS-48-X`):** `13+7×5` hypertree, `3,990 B`, packed `WOTS+C(n=21, w=60, z=2, S=679)` + chained `U-PORS(n=3, w=24, S=42, C=376, A=11, k=9, m_max=45)`, `19,584`-chain SIMD super-wave, `256 KiB` cached top tree, framed `Context`, full verification self-check enabled, `blake3-servil-core = "=0.11.0"`, measured via `bench/` (`clocks`, `0–1%` E-cores).

| Scheme (Apple M6, **1 core**) | Sig bytes | Per-key budget | Verify 64 B | Sign 64 B (warm) | Sign 1 MiB | Sign 100 MiB |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 (OpenSSL 4.1, lattice) | 2,420 B | — | 31.0 µs | 0.15 ms | — | — |
| SLH-DSA-SHAKE-128s (OpenSSL 4.1) | 7,856 B | $2^{64}$ | 278.0 µs | 274.5 ms | — | — |
| SLH-DSA-SHA2-128s (OpenSSL 4.1) | 7,856 B | $2^{64}$ | 50.0 µs | 52.4 ms | — | — |
| SLH-DSA-BLAKE3-128s (PQC Suite B, 1c) | 7,856 B | $2^{64}$ | 126.6 µs | 121.7 ms | 122.1 ms | 222.8 ms |
| SLH-DSA-BLAKE3-128f (PQC Suite B, 1c) | 17,088 B | $2^{64}$ | 353.7 µs | 5.81 ms | 6.26 ms | 89.1 ms |
| **Signet (`BLINCS-48-X`, `blake3-servil-core 0.11.0`)** | **3,990 B** | **$2^{48}$** | **62.7 µs** | **8.45 ms** | **8.61 ms** | **23.41 ms** |

Key takeaways on 1 Apple M6 core:

- **Size:** `BLINCS-48-X` (**3,990 B**, **5,320 B** Base64) is **49.2% smaller** (`3,866 B` saved) than `SLH-DSA-128s` (`7,856 B`) and **4.28× smaller** than `SLH-DSA-128f` (`17,088 B`).
- **Signing (64 B, 1 core, warm):** Signet (**8.45 ms**, `118 / s`, `p99 / mean ≈ 1.042×`) is **14.4× faster** than `SLH-DSA-BLAKE3-128s` (`121.7 ms`) and **6.2× faster** than hardware-accelerated OpenSSL `SLH-DSA-SHA2-128s` (`52.4 ms`).
- **Verification (64 B, 1 core, zero heap alloc):** Signet (**62.7 µs**, `15,950 / s`, `7.44 IPC`, `3,761` compressions) is **2.0× faster** than `SLH-DSA-BLAKE3-128s` (`126.6 µs`) and **5.6× faster** than `SLH-DSA-BLAKE3-128f` (`353.7 µs`).
- **Key load (`Signet::from_seed`):** **82.74 ms** (`12 / s`, builds the `256 KiB` cached height-13 top Merkle heap — no disk cache needed).
- **Signing (100 MiB, 1 core):** Signet (**23.41 ms** slice / **35.04 ms** `imprint_with` streaming) hashes the message in a single salted BLAKE3 pass (**4,479 MB/s** signing, **6,951 MB/s** verifying on 1 core).

## 2. Wall time, core cycles, and IPC (`bench/`, `clocks` crate)

Measured on a quiet Apple M6 (`bench/`, `blake3-servil-core = "=0.11.0"`, single-threaded, `0–1% E-cores`):

| Operation (1 core) | Wall time | Core cycles | Instructions | IPC | Clock | Throughput |
|---|---:|---:|---:|---:|---:|---:|
| `Signet::from_seed` (`256 KiB` height-13 top tree) | **82.74 ms** | 368.41M | 458.78M | 1.25 | 4,455 MHz | **12 / s** |
| `Signet::imprint` 64 B | **8.45 ms** | 36.94M | 50.27M | 1.36 | 4,372 MHz | **118 / s** |
| `Signet::imprint_with` 64 B | **8.45 ms** | 36.92M | 50.17M | 1.36 | 4,372 MHz | **118 / s** |
| `SignetId::verify` 64 B | **62.7 µs** | 288.1k | 2.14M | **7.44** | 4,597 MHz | **15,950 / s** |
| `SignetId::verify_with` 64 B | **62.7 µs** | 288.2k | 2.14M | **7.43** | 4,597 MHz | **15,950 / s** |
| `SignetId::verify` 1 KiB | 63.5 µs | — | — | 7.42 | — | — |
| `SignetId::verify` 64 KiB | 73.4 µs | — | — | — | — | 893 MB/s |
| `SignetId::verify` 256 KiB | 98.6 µs | — | — | — | — | 2,659 MB/s |
| `Signet::imprint` 1 MiB | **8.61 ms** | — | — | — | — | 122 MB/s |
| `SignetId::verify` 1 MiB | 196.3 µs | — | — | — | — | 5,340 MB/s |
| `Signet::imprint` 16 MiB | **10.72 ms** | — | — | — | — | **1,565 MB/s** |
| `SignetId::verify` 16 MiB | **2.31 ms** | — | — | — | — | **7,275 MB/s** |
| `Signet::imprint` 100 MiB | **23.41 ms** | — | — | — | — | **4,479 MB/s** |
| `Signet::imprint_with` 100 MiB (`Sink` / `io::copy`) | 35.04 ms | — | — | — | — | 2,992 MB/s |
| `SignetId::verify` 100 MiB | **15.08 ms** | — | — | — | — | **6,951 MB/s** |
| `SignetId::verify_with` 100 MiB (`Sink` / `io::copy`) | 26.72 ms | — | — | — | — | 3,925 MB/s |
| `Randomness::initialize` (lock-free atomic file) | **92.1 µs** | 417.4k | — | 5.21 | 4,535 MHz | — |

## 3. Bare-metal QEMU ARM Cortex-M33 emulation (NOT silicon measurements)

Measured under bare-metal `thumbv8m.main-none-eabihf` on `qemu-system-arm 11.1.3 -machine mps2-an505 -cpu cortex-m33` with a custom TCG Thumb-2 instruction-class counter and `0xA5A5A5A5` SRAM sentinel stack watermark probing. **Physical Cortex-M33 silicon has not been measured; 160 MHz cycle/time figures are Arm Cortex-M33 TRM 0-wait-state models only, and Cortex-M is not a supported platform of this crate.**

- **6-layer `WOTS+C` decode:** `3,577` Thumb-2 instructions (`1,816×` fewer than zero-table Sperner DP's `6,497,391` instructions).
- **Full pure-Rust 1-block verification (specialized single-block `CHAIN` kernel):** `3.12M` Thumb-2 instructions (`~23.2 ms` TRM-modeled @ 160 MHz) and **`988 B`** observed verification stack sentinel watermark (`23.0×` smaller than Sperner DP's `22,756 B`). Streaming `TreeHash` watermarks: `996 B` (`h = 7` lower tree), `636 B` (`h = 11` `U-PORS` tree).
- **Hand-written Thumb-2+FPU `32 B` `CHAIN` kernel:** `653.2` Thumb-2 instructions/compression (`1.83×` fewer instructions than stock general-purpose `blake3::keyed_hash`'s `1,193.4` instructions; TRM-modeled `~655` vs. `~1,459` 0-wait cycles). On the TRM 160 MHz model with a `16 KiB` depth-10 partial top cache (`973,574` ideal harvested fixed + `34,019` mean / `75,533` exact discrete `p99` grind), warm signing models at `~4.44 s` mean / `~4.82 s` `p99` and short-message verification models at `~16.2 ms`.

## 4. Reproducing

```sh
cd bench && cargo run --release --locked
```

x86-64 and non-Apple ARM measurements have not yet been published here.

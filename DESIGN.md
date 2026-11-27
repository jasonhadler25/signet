# BLINCS (`BLINCS-48-X`) and Signet design rationale

*Thanks to the [Project 11](https://research.projecteleven.com/) research team — **Conor Deegan**, **Alessandro Baiocchi**, **Matteo Vena**, and **Matteo Vicari** — for early specification feedback and constrained-device parameter-search inspiration, as well as the authors of BLAKE3, `blake3-servil-core`, SPHINCS/SPHINCS+/FIPS 205, WOTS+C, PORS+FP, Gravity-SPHINCS, and the randomness papers credited in [`README.md`](README.md#credits-and-thanks) and Section 4 below.*

This document records **why** **`BLINCS-48-X`** and its companion Rust implementation **Signet** (`jasonhadler25/signet`) are shaped the way they are: the threat model, the $2^{48}$ lifetime signing budget, the two-pillar **`WOTS+C` + chained `U-PORS` Octopus** architecture (`3,990` bytes, `5,320` B Base64 — **49.2% smaller than `SLH-DSA-128s`**), the exhaustive zero-Monte-Carlo all-`1,614,132`-orbits rational-interval certification (`tools/upors_cert.rs`), hardware–software co-design across single-core Apple M6 SIMD and QEMU ARM Cortex-M33 emulation, single-pass salted content hashing, the lock-free state file, and crash-only engineering choices. For the normative byte-level definition, see [`SPEC.md`](SPEC.md); for the full security proof and tables, see [`paper/blincs.pdf`](paper/blincs.pdf); for the original strategy note that launched the project, see [`docs/history/manifesto.md`](docs/history/manifesto.md).

---

## 1. Goals and threat model

BLINCS is designed for a dishonest submitter who does **not** hold the signing key, interacting with an honest signer and honest verifiers. The attacker may:

- observe up to $2^{48}$ signatures and trigger the honest signer to sign messages the signer approves (while committing `(ctx, M)` before learning the per-signature salt `e` per `SPEC.md §7`),
- possess a structural weakness in BLAKE3 that produces **collisions** cheaply without yielding **second preimages**, and
- spend enormous classical compute (a 128-bit classical single-user security target; BLAKE3 itself claims 128-bit security).

Security-analysis priorities:
1. **Primary:** correct use — unique unpredictable salt per imprint, `< 2^{48}` imprints per signet, secret `seed` (classical single-user 128-bit target; physical CRQC hash-collision costs per Bernstein SHARCS 2009; QROM and multi-user proofs noted as open work).
2. **Secondary:** cheap mitigations for stuck or leaked salt randomness (`saltseed`) or modest overuse (`2^{49}` imprints: `>= 125.3590 b` deterministic all-orbits envelope bound).
3. **Out of scope:** predictable or leaked `seed`.

The design goals that follow:

- **Post-quantum, pure-BLAKE3 assumptions:** security rests solely on symmetric hash properties of BLAKE3 (`KEYED_HASH` and `DERIVE_KEY`, zero XOF mode required) and this SPHINCS-family construction — no lattices, pairings, AES, or factoring.
- **100% pure stateless (no synchronized one-time signing state):** a signing key can be copied across machines, restored from backups, or run in short-lived processes (such as `git commit`) without XMSS/LMS or hybrid stateful rollback hazards.
- **Short verifying key (`32` bytes):** small enough to embed directly in a name or identifier a user already acquires (for example, a repository or branch name).
- **Sub-4 KiB fixed-size signatures (`3,990` bytes / `5,320` bytes Base64):** **49.2% smaller** than `SLH-DSA-128s` (`7,856 B`) and **4.28× smaller** than `SLH-DSA-128f` (`17,088 B`), regardless of whether the signed message is 0 bytes or 100 GiB.
- **Two-pillar `13+7×5` packed `WOTS+C` + chained `U-PORS` architecture (`8` tweak kinds, `0 B` coding lookup tables):**
  - **Hypertree:** `d = 6` layers (`h = 48`), one optional `256 KiB` cached top tree (`h_top = 13`, `8,192` leaves; or `16 KiB` depth-10 partial cut at `+1.08%` ideal fixed compressions with identical signatures) + five uniform height-`7` lower trees (`128` leaves each), using ONE uniform OTS primitive (`WOTS+C`: `n = 21, w = 60, z = 2, S = 679`, `3`-byte `u24` LE counter).
  - **Few-time signature:** ONE height-`11` binary Merkle tree (`2,048` leaves) using `U-PORS(n = 3, w = 24, S = 42, C = 376, k = 9, m_max = 45)` with 24-row bounded arithmetic unranking (`0 B` coding lookup tables), exact `64`-byte single-block BLAKE3 leaf hashing (`16 + 3 × 16 = 64 B`), Octopus path merging with canonical trailing zero-padding, and indexed `32`-byte `FEW_CODE` blocks chained directly from the `32`-byte `FEW_SELECT` digest `H_sel` (zero XOF).
- **Fast constant-work verification & 100% SIMD-aligned single-threaded signing:** short-message verification executes **`3,715 + m + b` BLAKE3 compressions** (**`3,761`** at `m = 45, b = 1`; exact constant chain work: `560` steps/hypertree layer, `27` steps/opened `U-PORS` leaf) and zero heap allocations; every lower and few-time tree (`128`, `2,048` leaves -> `19,584 = 612 × 32` chains total) is an exact multiple of `32` SIMD lanes via `blake3-servil-core = "=0.11.0"`.
- **Suite-separated key schedule, framed application `Context`, and fail-closed verification:** every algorithm key-derivation context binds `BLINCS-48-X`, every imprint binds a typed `Context` (`0..=255` bytes, framed as `u8(len(ctx)) || ctx`) into `K_msg`, `R`, and `D_seed`, and verification fails closed.

---

## 2. Why $2^{48}$ signatures and exact all-orbits rational-interval `U-PORS` certification

The operational budget is **$q_s \le 2^{48} = 281{,}474{,}976{,}710{,}656$** signatures per signing key (one million signatures every second nonstop for **8.9 years**), providing ample headroom against signing-oracle exhaustion ("milking") while keeping fixed wire length below `4 KiB` (`3,990 B`). **Do not imprint more than `2^48` things with one signet.**

### Zero-Monte-Carlo, exact-`BigInt` all-orbits `U-PORS` certification (`tools/upors_cert.rs`)

Enforcing the Octopus cap `sibs(S) <= 45` on honest signatures conditions leaf sets onto `F = {S subset [2048] : |S| = 9, sibs(S) <= 45}` (exact `|F| = 180,700,154,447,569,471,488`, exact `p_cap = 1.0529230957e-4`, mean `9,497.37` trials). Because `sibs(S) <= 45` forces `sum_{j=1}^{10} n_j <= 52`, conditioning on `F` **destroys negative association** (`paper/blincs.pdf` Proposition 2) and creates `30.35×` adjacent-sibling clustering (`d = 1`), invalidating naive marginal-product approximations.

Our standalone zero-dependency verifier (`tools/upors_cert.rs`):
1. Proves the 3-term exponential upper envelope `u_3(t) = 1 - (7495/5546)(79/100)^t + (1949/5546)(20/100)^t >= q_C(t)` for **all** integers $t \ge 0$ in exact 256-bit integers, plus exact coefficient $\ell_1$-norm `(14990/5546)^9 < 7,700`;
2. Enumerates **all `1,614,132` `Aut(T_11)`-orbits** of `F` (verifying `sum(orbit_size) == |F|`) and evaluates exact binomial moments (`K = 44`) in `256`-bit fractional arithmetic (`eps = 2^-256`), accumulating global signed sums `S_1..S_44` in exact 448-bit integers;
3. Certifies every table entry in **zero-`f64` arbitrary-precision `BigInt` rational interval arithmetic** (exact integer `C(q_s, k)`, proved per-moment error `340,122,240 * 2^-256` added strictly upward, exact Leibniz remainder, outward-rounded decimal upper bounds on `P`, odd-Taylor $T_{19}$-certified downward-rounded bit lower bounds, and exact integer $q_{96}$ comparison `P_UB(48, q_96) * 2^96 <= 1`):

| $(h, q_s)$ | Certified Capped Envelope (`Cap+Cap`) | Certified Uncapped Envelope (`Unc+Unc`) |
|---:|---:|---:|
| $(48, 2^{46})$ (`0.25×`) | `>= 141.7220` bits (`P <= 2.1748e-43`) | `>= 138.8182` bits (`P <= 1.6276e-42`) |
| $(48, 2^{47})$ (`0.50×`) | `>= 137.1012` bits (`P <= 5.3506e-42`) | `>= 133.8571` bits (`P <= 5.0697e-41`) |
| **$(48, 2^{48})$ (budget)** | **`>= 131.7076` bits (`P <= 2.2493e-40`)** | `>= 127.9743` bits (`P <= 2.9914e-39`) |
| $(48, 2^{49})$ (`2.00×`) | `>= 125.3590` bits (`P <= 1.8330e-38`) | `>= 120.9424` bits (`P <= 3.9148e-37`) |
| $(48, 2^{50})$ (`4.00×`) | `>= 117.8522` bits (`P <= 3.3338e-36`) | `>= 112.5196` bits (`P <= 1.3434e-34`) |
| $(48, 2^{51})$ (`8.00×`) | `>= 108.9894` bits (`P <= 1.5521e-33`) | `>= 102.4964` bits (`P <= 1.3980e-31`) |
| $(64, 2^{64})$ (`1.00×`) | `>= 131.7076` bits (`P <= 2.2493e-40`) | `>= 127.9743` bits (`P <= 2.9914e-39`) |

*(Values above are verified by `tools/upors_cert.rs --fast` in CI; exact integer `q_96 = 5,291,482,952,600,082` certifies `P_UB(48, q_96) <= 2^-96`, `~21.11` Exabytes of `3,990`-byte signatures.)*

---

## 3. Parameter choices & cross-architecture co-design

### Why every parameter has its exact value

- **Packed `WOTS+C(n = 21, w = 60, z = 2, S = 679, u24 LE ctr)`:**
  - `2 + 21 × 6 = 128` bits exact: every bit of the 16-byte `ONE_TIME_MSG` prefix `H_l` is checked (`(lo & 3) == 0`, all 21 6-bit digits `< 60`, `sum(d_i) == 679`) via pure shifts, masks, and additions — zero division, zero 128-bit DP, zero coding lookup tables.
  - Exact bijection from valid 128-bit prefixes onto the antichain `L_679(21, 60)` of cardinality `83,261,328,062,314,682,436,358,950,675,433,803 > 2^{116}` (whereas `N(60, 21, 680) < 2^{116}` and `N(59, 21, 609) < 2^{116}`, all mechanically verified directly on `sliceCount` in Lean 4).
  - Shifting `S` from midpoint `619` to `679` cuts verification work from `620` to an exact constant **`560` steps/layer** (`-360` compressions across 6 layers) while keeping per-key `u24` counter exhaustion below `2^{-5,923.1}` (and global exhaustion across all `< 2^{49}` physical hypertree keys below `2^{-5,874}`).
- **Chained `U-PORS(n = 3, w = 24, S = 42, C = 376, A = 11, k = 9, m_max = 45, u32 ctr)`:**
  - `n = 3` chains keep `ONE_TIME_KEY` leaf input to `16 + 3 × 16 = 64` bytes (**exact 1 BLAKE3 compression**).
  - Upper-layer slice `S = 42` in `{0..=23}^3` exploits Lattice-Meet Asymmetry (`q_C(1) = 1/376`, `q_C(2) = 0.17000`, `q_C(3) = 0.33624`), fixes verification steps at `27` per leaf (`243` total), and unranks via a 24-row arithmetic scan (`0 B` coding tables).
  - Chaining `FEW_CODE` (`48 B`) directly from the 32-byte `FEW_SELECT` output `H_sel` saves 4 input bytes, removes BLAKE3 XOF mode completely, and blocks code-first pre-filtering on a fixed selection input in the ROM+PRF proof (`paper/blincs.pdf` §5).
- **Apple M6 SIMD + QEMU ARM Cortex-M33 co-design:**
  - *Single-core Apple M6 (`signet`, `blake3-servil-core 0.11.0`, `clocks`, `256 KiB` top cache, self-check enabled):* `from_seed` **`82.74 ms`**, warm `sign 64 B` **`8.45 ms`** (`118/s`, 19,584-chain SIMD wave + SWAR `WOTS+C` test + proved zero-false-negative pure-`u64` bit-fold `U-PORS` prefilter cutting desktop grinding `20.1×`), zero-alloc `verify 64 B` **`62.7 µs`** (`15,950/s` @ `7.44 IPC`), freestanding zero-import WASM **`27.1 KiB`**.
  - *Bare-metal QEMU ARM Cortex-M33 (`mps2-an505 -cpu cortex-m33`, explicitly distinguished from silicon measurements):* packed `WOTS+C` executes `3,577` Thumb-2 instructions across 6 layers (`1,816×` fewer than zero-table Sperner DP) and lowers verification sentinel stack watermark from `22,756 B` to **`988 B`** (`< 1 KiB`). A hand-written Thumb-2+FPU `CHAIN` kernel executes `653.2` Thumb-2 instructions/compression (`1.83×` fewer instructions than stock `blake3::keyed_hash`; modeled at `~655` 0-wait TRM cycles -> `~4.44 s` mean / `~4.82 s` `p99` warm sign with `16 KiB` partial cut and `~16.2 ms` verify at `160 MHz`; physical Cortex-M33 silicon has not been measured).

---

## 4. Candidate techniques evaluated: adopted and declined

### Adopted in `BLINCS-48-X`

1. **BLAKE3 (`Keyed` + `DeriveKey`, zero XOF) as the sole primitive** (`blake3-servil-core = "=0.11.0"`, strictly single-threaded).
2. **`13+7×5` hypertree with optional top-tree caching** (`256 KiB` full heap, `32 KiB` upper heap, `16 KiB` depth-10 cut, or `0 B` — all producing byte-for-byte identical signatures).
3. **Bit-packed shifted constant-sum `WOTS+C(21, 60, 2, 679)`** (building on Bos & Chaum 1992, Kudinov 2022 [ePrint 2022/778](https://eprint.iacr.org/2022/778), and Zhang–Cui–Yu 2023 [ePrint 2023/850](https://eprint.iacr.org/2023/850), eliminating DP unranking and lookup tables completely).
4. **Zero-coding-table chained `U-PORS` + Octopus merging** (building on `PORS+FP`, Abri & Katz [ePrint 2025/2069](https://eprint.iacr.org/2025/2069), and Octopus, Aumasson & Endignoux [ePrint 2017/933](https://eprint.iacr.org/2017/933), upgraded with 3-chain single-block leaves, chained `FEW_CODE(H_sel)`, canonical zero-padding, and exact-`BigInt` all-orbits certification in `tools/upors_cert.rs`).
5. **Single-pass salted content hashing (`K_content -> K_msg -> h_msg`)** + hedged post-hash randomizer `R = Keyed(K_R, short || framed_ctx)[..16]` + `D_seed` binding `root`, `R`, `short`, and `framed_ctx`.
6. **Lock-free single-file atomic-rename `Randomness` state** + `Signet::generate(&rng)`.

### Declined (and why)

7. **Zero-table Sperner DP unranking:** on Cortex-M33 QEMU, 6-layer `u128` boxcar deconvolution executes `6.50M` Thumb-2 instructions (`1,816×` more than packed `WOTS+C`) and consumes `22.22 KiB` stack (`23×` more than `988 B`), while desktop table-based unranking requires `115 KiB` of static ROM tables.
8. **`52`-byte Round-0-skip `CHAIN` layout:** saved `6.1%` modeled Cortex-M33 cycles (`~655 -> 615`) but exited `blake3-servil-core`'s 32-byte packed SIMD path and regressed Apple M6 signing `+37%` and verification `+50%`. The standard `32`-byte `CHAIN` layout is jointly optimal.
9. **`+96 B` parallel-verify root hints:** cut M6 verification from `62.7 µs` to `45.0 µs`, but pushed signatures above `4 KiB` (`4,086 B`). Declined to preserve sub-`4 KiB` (`3,990 B`) fixed wire length.
10. **Hybrid stateful/stateless (`SHRINCS` [ePrint 2025/2203](https://eprint.iacr.org/2025/2203)):** keeping BLINCS 100% pure stateless avoids read-only-filesystem hazards, dual-branch format complexity, and privacy/state trade-offs.
11. **BLAKE3 XOF mode & library-internal multithreading:** avoided so verifiers across Rust `#![no_std]`, WASM, Python, TypeScript, and Lean 4 stay minimal and predictable, and libraries never spawn background threads.

---

## 5. Single-pass salted content hashing

| Mode | How the message `M` is hashed | Passes over `M` | Hash assumption on `M` | Examples |
|---|---|---:|---|---|
| **1. Unsalted first-stage digest** | Hash `M` first with a fixed hash `H(M)`, then sign the digest | 1 | Unsalted collision resistance | HashSLH-DSA, Ed25519ph |
| **2. Two-pass message-dependent randomization** | Pass 1 derives randomizer `R` from `(key, M)`; Pass 2 hashes `(R, pk, M)` | 2 *(must buffer or rewind `M`)* | Randomized target-collision resistance | Pure SLH-DSA (FIPS 205), Ed25519 |
| **3. Single-pass salted streaming** *(BLINCS)* | Derive fresh salt `e` from `(K_salt, draw)` **before** reading `M`; hash `Keyed(Keyed(K_content, e || framed_ctx), M)` | 1 *(constant-RAM streaming)* | Randomized target-collision resistance *(falls back to 128-bit known-key collision scale if `e` repeats predictably)* | **BLINCS** |

```text
framed_ctx = u8(len(ctx)) || ctx                   # 1..=256 bytes (bounded application context)
e          = Keyed(K_salt, draw)[..16]             # 16-byte per-signature salt, carried in the signature
K_msg      = Keyed(K_content, e || framed_ctx)     # 32-byte per-signature, per-context message key
h_msg      = Keyed(K_msg, M)                       # 32-byte single-pass keyed BLAKE3 hash of M
short      = e || h_msg                            # 48 bytes
```

Per `SPEC.md §7`, signers MUST NOT disclose `e` or `K_msg` before `(ctx, M)` is committed. When `e` is unpredictable until after commitment, `Keyed(K_msg, M)` rests on randomized target-collision resistance. If a salt repeats predictably across distinct `(ctx, M)`, `rng_failure_hedged_fallback` (verified in Lean 4) proves that either `ctx_1 = ctx_2` with a collision on 256-bit `h_msg` or `R = Keyed(K_R, short || framed_ctx)[..16]` receives strictly distinct inputs.

---

## 6. Signer randomness: lock-free atomic state file

Signet uses a single private `0600` 32-byte state file rotated via sibling temp file + POSIX atomic `rename` (zero `flock`, zero blocking/deadlocks, forward secrecy on disk by splitting `next_seed`, `run_key`, and `keygen_key` from `prior || getrandom(32) || pid(4) || monotonic_clock`). `Signet::generate(&rng)` combines a domain-separated `keygen_key` draw with fresh 32-byte OS `getrandom(2)` entropy (`Derive(CTX_GENERATE_SIGNET, keygen_draw || os_bytes)`).

---

## 7. Crash-only design and single-threaded SIMD performance engineering

- **Pure crash-only lifecycle (zero `Drop`, zero background threads, zero `thread_local!`):** `Signet` caches its `256 KiB` top tree in memory once on construction. Verification (`SignetId::verify` / `verify_with`) executes `3,761` short-message compressions (`3,715 + m + b` at `m = 45, b = 1`) with **zero heap allocations** via `TreeHasher::on_this_core()`. Signing uses a **merged 19,584-chain single-threaded SIMD super-wave** (`5` height-7 trees × `128 × 21 = 13,440` chains + `1` height-11 `U-PORS` tree × `2,048 × 3 = 6,144` chains = `612 × 32` exact SIMD batches) plus branchless SWAR `WOTS+C` checks and the proved zero-false-negative pure-`u64` bit-fold `U-PORS` prefilter.
- **Types carry their rules & fail-stop contracts:** `#![forbid(unsafe_code)]`; `Signet::imprint` / `imprint_with` self-verify every produced imprint (~`63 µs`) before returning and panic on mismatch.

---

## 8. Terminology: `Signet`, `SignetId`, and `Imprint`

Following Mark S. Miller (*Robust Composition*) and Ka-Ping Yee & Mark S. Miller (*Capability Myths Demolished*), a cryptographic signing secret is a transferable **bearer** capability rather than a human identity:

- **`Signet`**: the secret bearer object (derived from a 32-byte seed) that exercises authority by making an imprint.
- **`Imprint`**: the `3,990`-byte mark pressed by a `Signet` onto a message or stream (transparent authenticity only — the message stays in the clear).
- **`SignetId`**: a publisher's self-certifying `32`-byte identifier and complete BLINCS verifying key (`expected_publisher.verify(...)`).

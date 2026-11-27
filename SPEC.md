# BLINCS Specification (`BLINCS-128-A2`, draft)

> **Pre-1.0 — Experimental & Unsupported.** This specification is under active development (draft `0.4.0`); wire formats, parameters, and context strings may still change incompatibly before 1.0. Written primarily by an AI assistant at the direction of this repository's owner; **no independent human cryptographic review or security audit has been performed**. Do not rely on BLINCS to protect production assets.

*Builds on BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn) and SPHINCS / SPHINCS+ / FIPS 205 SLH-DSA (Bernstein, Hopwood, Hülsing, Kölbl, Lange, Niederhagen, Papachristodoulou, Rijneveld, Schneider, Schwabe, Wilcox-O'Hearn, and the NIST SLH-DSA team). Thanks to [Project 11](https://research.projecteleven.com/) — especially **Conor Deegan**, **Alessandro Baiocchi**, **Matteo Vena**, and **Matteo Vicari** — for direct review feedback, benchmarks, and constrained-device design insights.*

---

## 1. Overview

**BLINCS** is a stateless hash-based signature algorithm based on BLAKE3 and SPHINCS. This specification defines the **`BLINCS-128-A2`** suite, which compresses a 128-bit stateless BLAKE3 signature down to **`3,292` bytes** (`4,392` bytes Base64) with zero static lookup tables and exact 32-lane SIMD alignment:

- **One-time signature (`S-WOTS+Z`):** Single OTS type across all 4 hypertree layers — `n = 24` equal-length hash chains of `39` steps (`w = 40`), mapped onto the middle constant-sum Sperner slice (`sum = 468`, exact constant `468` verification steps/layer) with a deterministic `u16` counter enforcing `z = 8` leading zero bits (`2^{-370}` counter overflow probability). Zero checksum chains, zero static lookup tables (`O(S)` boxcar deconvolution unranking).
- **Few-time signature (`U-PORS` — Upper-Layer Constant-Sum Lattice Octopus):** A single height-`10` binary Merkle tree (`1,024` leaves), where each leaf is a 3-chain hash-chain key (`n = 3` equal-length chains of `23` steps, `w = 24`, fitting in **one single 64-byte BLAKE3 compression**), encoded by the full upper constant-sum slice `a + b + c = 42` (`C = 376` codewords, exact constant `27` verification steps/leaf, zero static lookup tables via closed-form hexagon unranking). Opening `k = 10` distinct leaves with Octopus path merging and a verifier-enforced sibling cap `sibs <= 44` (`u32` counter, exact `p_cap = 7.6637e-4`, mean `1,304.8` trials) compresses the entire few-time section to **`1,188` bytes**.
- **Hypertree (`12 + 7 + 7 + 7 = 33`):** `4`-layer binary Merkle hypertree (`h = 33`): a `128 KiB` cached top height-`12` tree (`4,096` leaves) above `3` uniform height-`7` lower trees (`128` leaves each).
- **Exact 32-lane SIMD alignment & constant chain verification work:** Top tree `4,096 = 128 × 32`, every lower tree `128 = 4 × 32` (`3,072 = 96 × 32` chains), `U-PORS` tree `1,024 = 32 × 32` (`3,072 = 96 × 32` chains). All `9,216` lower-hypertree chains and `3,072` `U-PORS` chains merge into a single `12,288`-chain lockstep SIMD wave on signing. Short-message (`|M| <= 64`, `|ctx| <= 31`) verification with prederived verifier keys executes `2,231 + m + b` BLAKE3 compressions (`m <= 44` consumed Octopus siblings, `b >= 1` `FEW_CODE` blocks — i.e., `2,276` compressions at `m = 44, b = 1`, with exact constant chain work: `468` steps/hypertree layer and `27` steps/opened `U-PORS` leaf).
- **Single-pass salted content hashing:** Every imprint binds a caller-chosen bounded application context (`0..=255` bytes) and hashes an arbitrary-length message in one streaming pass under a fresh per-imprint salt drawn before reading the message.
- **Terminology:** This specification uses **`Signet`** (private signing capability), **`SignetId`** (32-byte verifying identifier), and **`Imprint`** (`3,292`-byte signature). These correspond directly to conventional `(SK, VK, \sigma)` notation; the companion paper (`paper/blincs.pdf`) states all theorems in standard cryptographic notation alongside this mapping.

An `Imprint` is **`3,292` bytes** (`4,392` bytes Base64), a `SignetId` is **`32` bytes**, and a `Signet` derives from a **`32`-byte seed**. The design target is **128-bit classical single-user security** at up to **$2^{32}$ imprints** per signet (4,294,967,296), with certified capped-history `U-PORS` raw-query security of **`132.13` bits** (`99%` LCB, accounting for Octopus sibling clustering via `blincs/tools/upors_cert.rs`, vs. `129.63` bits exact zero-MC uncapped) at $q = 2^{32}$ and `125.48` bits at $2\times$ overuse ($q = 2^{33}$). Do not imprint more than $2^{32}$ things with one signet.

### Notation

All fixed-width integers are unsigned and encoded in **little-endian** byte order. Ranges written `a..b` are half-open `[a, b)` and `a..=b` are closed `[a, b]`. Concatenation is written `||`, byte slicing `x[a..b]` takes bytes `a` through `b - 1`, and `x[..n]` takes the first `n` bytes. Maximum message length is $2^{64} - 1$ bytes; maximum application context length is `255` bytes.

---

## 2. Hash Primitive

BLINCS uses **only** the two standard 32-byte modes of **BLAKE3** (no extendable-output XOF mode required):

- `Keyed(K, M)`: BLAKE3 keyed hash (`KEYED_HASH` mode) with 32-byte key `K` over byte string `M`, returning 32 bytes.
- `Derive(ctx, M)`: BLAKE3 key derivation (`DERIVE_KEY` mode) with UTF-8 context string `ctx` over input byte string `M`, returning 32 bytes.

---

## 3. Suite Identity and Parameters

Suite identifier: **`BLINCS-128-A2`**.

| Symbol | Value | Meaning |
|---|---:|---|
| `N` | 16 | Byte length of truncated tree, chain, salt, and randomizer values (`h_msg`, `D_seed`, and derived keys are 32 bytes) |
| `LAYERS` | 4 | Hypertree layers (`d`): layers `0, 1, 2` have height `7`; top layer `3` has height `12` |
| `LOW_HEIGHT` | 7 | Height of each of the 3 lower hypertree layers (`2^7 = 128` leaves/tree) |
| `TOP_HEIGHT` | 12 | Height of the cached top hypertree layer (`2^{12} = 4,096` leaves, `128 KiB` heap) |
| `HYPER_BITS` | 33 | Total hypertree height (`3 * 7 + 12 = 33`) |
| `WOTS_N` | 24 | `S-WOTS+Z` chains per hypertree leaf |
| `WOTS_W` | 40 | `S-WOTS+Z` chain cardinality (`WOTS_STEPS = 39`, digits in `0..=39`) |
| `WOTS_SUM` | 468 | Middle Sperner slice sum (`24 * 39 / 2 = 468`; exact constant `468` verify steps/layer) |
| `WOTS_Z` | 8 | Leading zero bits required on `OneTimeMsg` (`H[0] == 0`; deterministic `u16` counter `ctr_l`) |
| `UPORS_HEIGHT` | 10 | Height of the single `U-PORS` binary Merkle tree (`2^{10} = 1,024` leaves) |
| `UPORS_N` | 3 | Equal-length hash chains per `U-PORS` leaf (`16 + 3 * 16 = 64` B = 1 BLAKE3 block) |
| `UPORS_W` | 24 | `U-PORS` chain cardinality (`UPORS_STEPS = 23`, digits in `0..=23`) |
| `UPORS_SUM` | 42 | Constant sum `a + b + c = 42` for every `U-PORS` codeword (`69 - 42 = 27` verify steps/leaf) |
| `UPORS_C` | 376 | Cardinality of full upper slice `L_42(3, 24)` (`0 B` ROM closed-form hexagon unranking) |
| `UPORS_K` | 10 | Number of distinct `U-PORS` leaves opened per imprint |
| `UPORS_M_MAX` | 44 | Verifier-enforced maximum Octopus authentication siblings (`u32` counter `ctr_ft`) |
| `UPORS_LAYER` | 128 | Tweak layer byte `0x80` separating `U-PORS` (`128`) from hypertree layers (`0..4`) |
| `MAX_CONTEXT_LEN` | 255 | Maximum byte length of the framed application context `ctx` |

Derived lengths:

- `UPORS_LEN = 4 + (UPORS_K * UPORS_N + UPORS_M_MAX) * N = 4 + (30 + 44) * 16 = 1,188` bytes.
- `LOW_LAYER_LEN = 2 + (WOTS_N + LOW_HEIGHT) * N = 2 + 31 * 16 = 498` bytes (layers `0, 1, 2`).
- `TOP_LAYER_LEN = 2 + (WOTS_N + TOP_HEIGHT) * N = 2 + 36 * 16 = 578` bytes (layer `3`).
- `IMPRINT_LEN = 2 * N + UPORS_LEN + 3 * LOW_LAYER_LEN + TOP_LAYER_LEN = 3,292` bytes.

---

## 4. Key-Derivation Contexts

Every derived 32-byte key uses a distinct UTF-8 context string binding the suite name `BLINCS-128-A2`, ensuring separate suites never share derived keys:

| Name | Context string |
|---|---|
| `SECRET_VALUES` | `"BLINCS-128-A2 2026-11-26 secret values"` |
| `CONTENT_SALT` | `"BLINCS-128-A2 2026-11-26 content salt"` |
| `RANDOMIZER` | `"BLINCS-128-A2 2026-11-26 randomizer"` |
| `PUBLIC_SEED` | `"BLINCS-128-A2 2026-11-26 public seed"` |
| `PUBLIC_HASH` | `"BLINCS-128-A2 2026-11-26 public hash"` |
| `CONTENT` | `"BLINCS-128-A2 2026-11-26 content"` |
| `GENERATE_SIGNET` | `"Signet BLINCS-128-A2 2026-11-26 generate signet"` |
| `MIX` | `"Signet 2026-11-26 randomness: mix"` |
| `NEXT_SEED` | `"Signet 2026-11-26 randomness: next seed"` |
| `RUN_KEY` | `"Signet 2026-11-26 randomness: key of this run"` |
| `KEYGEN_KEY` | `"Signet 2026-11-26 randomness: keygen key"` |

---

## 5. Tweaks

Every tree, chain, counter-grinding, and message-binding hash is domain-separated by a 16-byte tweak:

```text
tweak(kind, layer, tree, leaf, a, b) =
    kind  (u8,  1 byte)
 || layer (u8,  1 byte)
 || tree  (u48, 6 bytes LE)
 || leaf  (u16, 2 bytes LE)
 || a     (u16, 2 bytes LE)
 || b     (u32, 4 bytes LE)
```

Unused fields MUST be zero. Hypertree layers use `layer in 0..4`; the single `U-PORS` tree uses `layer = 0x80` (`128`). Eight tweak kinds partition every hash call unambiguously:

| Value | Name | Key | Tweak fields `(layer, tree, leaf, a, b)` | Data appended after tweak | Output used |
|---:|---|---|---|---|---|
| 1 | `CHAIN_SECRET` | `K_sec` | `(layer, tree, 0, 0, leaf * n_chains + c)` | *(empty)* | 16 B |
| 2 | `CHAIN` | `K_pub` | `(layer, tree, leaf, c, step)` | current 16-byte chain value | 16 B |
| 3 | `ONE_TIME_KEY` | `K_pub` | `(layer, tree, leaf, 0, 0)` | `24` chain ends (`384` B, HT) or `3` chain ends (`48` B, `U-PORS`) | 16 B |
| 4 | `NODE` | `K_pub` | `(layer, tree, 0, level, parent_idx)` | `left (16) \|\| right (16)` | 16 B |
| 5 | `ONE_TIME_MSG` | `K_pub` | `(layer, tree, leaf, 0, 0)` | `child_root (16) \|\| u32_le(ctr_l) (4)` | 32 B |
| 6 | `MESSAGE` | `K_pub` | `(0, 0, 0, 0, 0)` | `R (16) \|\| root (16) \|\| short (48) \|\| framed_ctx` | 32 B |
| 7 | `FEW_SELECT` | `K_pub` | `(0x80, 0, 0, 0, 0)` | `D_seed (32) \|\| u32_le(ctr_ft) (4)` | 32 B |
| 8 | `FEW_CODE` | `K_pub` | `(0x80, 0, 0, block_idx, 0)` | `D_seed (32) \|\| u32_le(ctr_ft) (4)` | 32 B |

Define `ShortHash(K, T, data) = Keyed(K, T || data)[..16]`.

Notice that every hot-path call — `CHAIN_SECRET` (`16 B`), `CHAIN` (`32 B`), `ONE_TIME_MSG` (`36 B`), `NODE` (`48 B`), `FEW_SELECT` (`52 B`), `FEW_CODE` (`52 B`), and `U-PORS` `ONE_TIME_KEY` (`64 B`) — fits inside **one single 64-byte BLAKE3 compression block**, and all three counter-indexed loops (`CHAIN_SECRET` at word `3`, `ONE_TIME_MSG` at word `8`, `FEW_SELECT` at word `12`) place the incrementing `u32` counter on a 4-byte word boundary for register-only SIMD counter-range hashing.

---

## 6. Signet and SignetId

A `Signet` derives deterministically from a 32-byte `seed`:

```text
K_sec   = Derive(SECRET_VALUES, seed)
K_salt  = Derive(CONTENT_SALT,  seed)
K_R     = Derive(RANDOMIZER,    seed)
pk_seed = Derive(PUBLIC_SEED,   seed)[..16]
K_pub   = Derive(PUBLIC_HASH,   pk_seed)
root    = top hypertree root at layer = 3, tree = 0 (height 12, 4,096 leaves)
```

The 32-byte `SignetId` is `id = pk_seed || root`. A verifier derives from `id`:

```text
K_pub     = Derive(PUBLIC_HASH, id[..16])
root      = id[16..32]
K_content = Derive(CONTENT,     id)
```

Signers SHOULD cache the `128 KiB` top height-12 Merkle heap (`8,192 × 16 B` nodes) in memory (or Flash on embedded devices) inside `Signet` so signing never rebuilds layer `3`.

---

## 7. Framed Application Context and Single-Pass Salted Content Hashing

Every imprint binds a caller-chosen application context `ctx` of `0..=255` bytes, framed unambiguously as:

```text
framed_ctx = u8(len(ctx)) || ctx                  # 1..=256 bytes
```

When imprinting with a fresh 32-byte per-imprint random draw `draw`:

```text
e = Keyed(K_salt, draw)[..16]                     # 16-byte per-imprint content salt
```

Given the 16-byte content salt `e`, application context `ctx`, and message `M` (any length in `0..2^64`):

```text
K_msg = Keyed(K_content, e || framed_ctx)         # 32-byte per-imprint, per-context message key
h_msg = Keyed(K_msg, M)                           # 32-byte keyed BLAKE3 hash of M (single pass)
short = e || h_msg                                # 48 bytes
```

Because `e` is derived before reading `M`, signers stream arbitrarily large messages through `Keyed(K_msg, M)` in a single pass. Verifiers read `e` from the first 16 bytes of the imprint and stream `M` in a single pass as well.

---

## 8. Message Digest Seed, Leaf Selection, and Codeword Extraction

The signer computes the hedged per-imprint randomizer `R` and 32-byte digest seed `D_seed`:

```text
R      = Keyed(K_R, short || framed_ctx)[..16]
D_seed = Keyed(K_pub, tweak(MESSAGE, 0, 0, 0, 0, 0) || R || root || short || framed_ctx)
```

Even if the salt source fails or repeats `draw` (and hence `e`) across two distinct `(ctx, M)` pairs while `seed` remains secret, either `ctx_1 == ctx_2` with `M_1 != M_2` and a 256-bit keyed-BLAKE3 collision occurs on `h_msg`, or the inputs `short || framed_ctx` fed into `Keyed(K_R, ·)` are strictly distinct — so under a PRF assumption on `Keyed(K_R, ·)` the randomizer `R` remains computationally pseudorandom (up to 128-bit truncation collision probability) without a second pass over `M`. If `(draw, ctx, M)` repeats identically, `e`, `h_msg`, and `R` repeat deterministically.

Treat any 32-byte digest `B` as an LSB-first little-endian 256-bit bitstream, where `read_bits(B, off, width)` returns `(nat_le(B) >> off) & ((1 << width) - 1)`.

### 8.1 `U-PORS` Leaf Selection and Octopus Cap (`FEW_SELECT`)

For a candidate `ctr_ft: u32`:

```text
H_sel = Keyed(K_pub, tweak(FEW_SELECT, 0x80, 0, 0, 0, 0) || D_seed || u32_le(ctr_ft))
```

1. Read up to `22` consecutive `10`-bit chunks `x_i = read_bits(H_sel, 10 * i, 10)` (`i in 0..22`, bits `0..220`), keeping the first **`10` distinct** leaf indices in `0..1024`. If fewer than `10` distinct indices appear in those `22` chunks, `ctr_ft` is **invalid**.
2. Sort the `10` distinct leaf indices into strictly ascending order `leaves[0] < leaves[1] < ... < leaves[9]`.
3. Compute the exact Octopus sibling count `sibs = count_octopus_sibs(leaves)` in a binary tree of height `10` (§10.2). If `sibs > 44`, `ctr_ft` is **invalid**.
4. Extract the `33`-bit hypertree leaf address `leaf_addr = read_bits(H_sel, 220, 33)` (bits `220..253`; bits `253..256` are unused).

A deterministic signer chooses the **smallest** `ctr_ft in 0..=2^32 - 1` that is valid (exact cap mass `|F| / C(1024, 10) = 7.6637e-4`, mean `~1,305` trials, `p99 ≈ 6,009` trials; `u32` exhaustion probability $< 2^{-4.7 \times 10^6}$). If `ctr_ft` exhausts `u32` (`2^32` trials without a valid selection), the signer MUST fail closed (abort/error without wrapping). A verifier checks only the single `ctr_ft` encoded in the imprint and MUST reject if it is invalid.

### 8.2 Unbiased `U-PORS` Codeword Extraction (`FEW_CODE`)

Given a valid `ctr_ft`, draw `10` unbiased indices `c_0, ..., c_9 in 0..376` using `block_idx in 0..=65535` (`u16`):

```text
block_idx = 0, got = 0
while got < 10:
    if block_idx > 65535: fail closed (reject / abort)
    B = Keyed(K_pub, tweak(FEW_CODE, 0x80, 0, 0, block_idx, 0) || D_seed || u32_le(ctr_ft))
    for j in 0..28:                       # 28 * 9 = 252 <= 256 bits
        v = read_bits(B, 9 * j, 9)        # uniform in 0..512
        if v < 376:
            codeword[got] = hex_unrank(v)
            got += 1
            if got == 10: break
    block_idx += 1
```

Each `9`-bit value is accepted with probability `376 / 512 = 73.44%` with **zero modulo bias**; in the ideal-output model `Pr[Bin(28j, 376/512) < 10]` is `~5.9e-6` after `j = 1` block (`99.9994%` finish in 1 block) and `~2^{-61}` after `j = 2` blocks (`< 2^{-10^6}` for `u16` exhaustion). Both signer and verifier MUST fail closed (abort / reject) if `block_idx` would exceed `65535` (`u16::MAX`), never wrapping `block_idx` or substituting default codewords.

---

## 9. Unified Chain-and-Merkle Primitive

Both `U-PORS` (`layer = 0x80`, `height = 10`, `n_chains = 3`, `steps = 23`) and every hypertree layer (`layer in 0..4`, `height in {7, 12}`, `n_chains = 24`, `steps = 39`) use the **exact same** hash-chain and binary Merkle primitive:

- **Chain `c in 0..n_chains` at `(layer, tree, leaf)`:**
  - Start value: `x_0 = ShortHash(K_sec, tweak(CHAIN_SECRET, layer, tree, 0, 0, leaf * n_chains + c), empty)`.
  - Step `s -> s + 1` (`s in 0..steps`): `x_{s+1} = ShortHash(K_pub, tweak(CHAIN, layer, tree, leaf, c, s), x_s)`.
  - Signature value for digit `d[c] in 0..=steps`: `x_{d[c]}`. Verifier completes steps `s = d[c]..steps` to recover `x_{steps}`.
- **Merkle leaf hash (`ONE_TIME_KEY`):**
  - `leaf_hash = ShortHash(K_pub, tweak(ONE_TIME_KEY, layer, tree, leaf, 0, 0), x_{steps}[0] || ... || x_{steps}[n_chains - 1])`.
- **Binary Merkle internal node (`level in 1..=height`, `p in 0..(2^{height} >> level)`):**
  - `node = ShortHash(K_pub, tweak(NODE, layer, tree, 0, level, p), left || right)`.

---

## 10. Few-Time Signatures (`U-PORS`)

### 10.1 Zero-Table Closed-Form Hexagon Unranking (`hex_unrank`)

The `U-PORS` codeword set is the full upper constant-sum slice $\mathcal{L}_{42}(3, 24) = \{(a, b, c) \in \{0,\dots,23\}^3 : a + b + c = 42\}$ sorted lexicographically (`C = 376` codewords). Because every codeword sums to `42`, $\mathcal{L}_{42}(3, 24)$ is a strict antichain in $\{0,\dots,23\}^3$ and every leaf requires an **exact constant `69 - 42 = 27` verification chain steps**.

For `idx in 0..376`, `hex_unrank(idx)` requires **zero lookup tables**:

```text
for a in 0..=23:
    rem  = 42 - a
    b_lo = max(0, rem - 23)
    b_hi = min(23, rem)
    if b_hi < b_lo: continue
    len  = b_hi - b_lo + 1
    if idx < len:
        b = b_lo + idx
        return (a, b, rem - b)
    idx -= len
```

### 10.2 Single-Tree Octopus Signing, Padding, and Verification

At hypertree address `leaf_addr` (`0..2^33`), `U-PORS` builds a single height-`10` binary Merkle tree (`1,024` leaves) via §9 with `layer = 0x80`, `tree = leaf_addr`, `n_chains = 3`, and `steps = 23`:

- **Chain values (`480` B):** For `t in 0..10`, sign `leaves[t]` with its `3` chain values `(x_{d_0}, x_{d_1}, x_{d_2})` where `(d_0, d_1, d_2) = codeword[t]`.
- **Octopus authentication siblings (`704` B, canonical zero-padded):**
  Starting with the strictly ascending active index list `cur = leaves[0..10]` at leaf level `0`, for `level = 1..=10`:
  - Scan `cur` left to right:
    - If `i + 1 < len(cur)` and `(cur[i] ^ 1) == cur[i + 1]`: both children are active; merge them into parent `cur[i] >> 1` with **no** sibling emitted (`i += 2`).
    - Otherwise: emit the sibling node at `(level - 1, cur[i] ^ 1)` into the Octopus list, push parent `cur[i] >> 1` (`i += 1`).
  - Let `sibs` be the total number of siblings emitted (`sibs <= 44`). Append `(44 - sibs) * 16` zero bytes so the Octopus field is always exactly `44 * 16 = 704` bytes.
- **Verification:** Reconstruct all `10` leaf hashes via §9, climb the `10` Octopus levels consuming siblings in the exact same left-to-right scan order (placing `cur_val` left if `(x & 1) == 0` else right, hashed with `tweak(NODE, 0x80, leaf_addr, 0, level, x >> 1)`), **verify in constant time that all `(44 - sibs) * 16` trailing padding bytes are zero** (reject if any padding byte is non-zero), and output the level-10 root as `upors_root`.

The `U-PORS` section is `4 + 480 + 704 = 1,188` bytes.

---

## 11. Hypertree (`S-WOTS+Z`) and Imprint Wire Format

### 11.1 `S-WOTS+Z` Message Grinding and Sperner Unranking

Given a 16-byte child root `node` to sign at hypertree position `(layer, tree, leaf)` (`layer in 0..4`):

1. **Deterministic `z = 8` counter grinding (`ONE_TIME_MSG`):** Find the smallest `ctr_l in 0..=65535` (`u16`) such that
   ```text
   H_l = Keyed(K_pub, tweak(ONE_TIME_MSG, layer, tree, leaf, 0, 0) || node || u32_le(ctr_l))
   ```
   satisfies **`H_l[0] == 0`** (if all `65,536` values fail, the signer MUST fail closed without wrapping; exhaustion probability $(255/256)^{65536} \approx 2^{-370}$). Verifier computes `H_l` for the encoded `ctr_l` and MUST reject if `H_l[0] != 0`.
2. **120-bit rank:** `rank = u128_le(H_l[1..16] || 0x00)` (an integer in `0..2^120`).
3. **Middle-slice Sperner unranking (`n = 24, w = 40, S = 468`):**
   Let $N(k, s)$ denote the number of tuples $(d_0,\dots,d_{k-1}) \in \{0,\dots,39\}^k$ with $\sum_j d_j = s$, defined by $N(0, 0) = 1$, $N(0, s > 0) = 0$, and $N(k, s) = \sum_{d=0}^{\min(39, s)} N(k-1, s-d)$.
   Exact cardinality:
   $$N(24, 468) = 1{,}973{,}221{,}677{,}906{,}098{,}493{,}567{,}206{,}234{,}001{,}571{,}000 > 2^{120}.$$
   Map `rank` injectively to the `rank`-th lexicographic tuple `digits[0..24]` in $\mathcal{L}_{468}(24, 40)$:
   ```text
   rem = 468
   for i in 0..24:
       k_rem = 23 - i
       for d in 0..=min(39, rem):
           cnt = N(k_rem, rem - d)
           if rank < cnt:
               digits[i] = d
               rem -= d
               break
           rank -= cnt
   ```
   Because every tuple sums to `468`, $\mathcal{L}_{468}(24, 40)$ is a strict antichain in $\{0,\dots,39\}^{24}$, and verification performs an **exact constant `24 * 39 - 468 = 468` chain steps per layer**.

### 11.2 Hypertree Walk and Wire Format (`3,292` Bytes)

Starting with `addr = leaf_addr` and `node = upors_root`:

- For `layer in 0..4`:
  - `h_l = 12` if `layer == 3` else `7`.
  - `leaf = addr & ((1 << h_l) - 1)`; `tree = addr >> h_l` (at `layer == 3`, `tree == 0`).
  - Grind `ctr_l` and compute `digits = sperner_unrank(rank)` for `node`.
  - Sign `node` via §9 with `(layer, tree, leaf, n_chains = 24, steps = 39)` and append its `h_l`-node Merkle authentication path (`112 B` for layers `0..3`, `192 B` for layer `3`).
  - Set `node = tree_root` and `addr = tree`.
- Verification succeeds iff all `ctr_ft`, canonical Octopus padding, and `ctr_0..3` checks pass AND the reconstructed layer-3 root equals `id[16..32]` in constant time.

Wire layout of a `BLINCS-128-A2` `Imprint` (`3,292` bytes):

```text
0..16        salt e (16 B)
16..32       randomizer R (16 B)
32..1220     U-PORS (1,188 B): ctr_ft (4 B) || 10 x 3 x 16 B chains (480 B) || 44 x 16 B Octopus sibs + zero pad (704 B)
1220..1718   Layer 0 (498 B): ctr_0 (2 B) || 24 x 16 B S-WOTS+Z (384 B) || 7 x 16 B auth path (112 B)
1718..2216   Layer 1 (498 B): ctr_1 (2 B) || 24 x 16 B S-WOTS+Z (384 B) || 7 x 16 B auth path (112 B)
2216..2714   Layer 2 (498 B): ctr_2 (2 B) || 24 x 16 B S-WOTS+Z (384 B) || 7 x 16 B auth path (112 B)
2714..3292   Layer 3 (578 B): ctr_3 (2 B) || 24 x 16 B S-WOTS+Z (384 B) || 12 x 16 B auth path (192 B)
```

---

## 12. Startup Self-Test (Recommended for Every Implementation)

Every production or library implementation of BLINCS — especially implementations using optimized assembly, SIMD/vector hashing, custom compilers, or cross-compiled targets — is **strongly recommended** to execute a **quick, fail-closed startup self-test** once per process before accepting or generating imprints (following Ferguson–Schneier–Kohno, `pycryptopp`, and `blake3-servil-core::initialize()`):

1. **Initialize the underlying BLAKE3 implementation's own self-test** (for example `blake3_servil_core::initialize()`).
2. **Positive verification KAT (~39 µs):** Verify `test_vectors/reference-imprint-1.bin` (`ctx = b"BLINCS-128-A2 reference vector v1"`, `M = b"hello, BLINCS"`), exercising `Derive`, `Keyed`, context framing, `FEW_SELECT`, `FEW_CODE`, `hex_unrank`, Octopus verification, canonical padding checks, `ONE_TIME_MSG`, Sperner unranking, all 4 hypertree layers, and constant-time root comparison.
3. **Negative verification KATs (~78 µs):** Flip one bit in the imprint and confirm rejection; pass a different context (`b""`) and confirm rejection.
4. **Fail closed:** Refuse to proceed on any mismatch.

See [`reference/src/lib.rs`](reference/src/lib.rs) for a concrete implementation of `self_test()`.

# BLINCS Specification (`BLINCS-48-X`, draft)

> **Pre-1.0 — Experimental & Unsupported.** This specification is under active development (draft `0.5.0`); wire formats, parameters, and context strings may still change incompatibly before 1.0. Written primarily by an AI assistant at the direction of this repository's owner; **no independent human cryptographic review or security audit has been performed**. Do not rely on BLINCS to protect production assets.

*Builds on BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn) and SPHINCS / SPHINCS+ / FIPS 205 SLH-DSA (Bernstein, Hopwood, Hülsing, Kölbl, Lange, Niederhagen, Papachristodoulou, Rijneveld, Schneider, Schwabe, Wilcox-O'Hearn, and the NIST SLH-DSA team). Thanks to [Project 11](https://research.projecteleven.com/) — especially **Conor Deegan**, **Alessandro Baiocchi**, **Matteo Vena**, and **Matteo Vicari** — for direct review feedback, benchmarks, and constrained-device design insights.*

---

## 1. Overview

**BLINCS** is a stateless hash-based signature algorithm based on BLAKE3 and SPHINCS. This specification defines the **`BLINCS-48-X`** suite, which achieves **sub-4 KiB (`3,990` bytes, `5,320` bytes Base64)** 128-bit pure stateless BLAKE3 signatures at a **$2^{48}$ per-key imprint budget** (281.5 trillion imprints/signet; certified all-orbits `U-PORS` upper-envelope security remains `>= 96` bits through `21.11 Exabytes` of wire imprints), with zero static lookup tables and exact 32-lane SIMD alignment:

- **One-time signature (`WOTS+C`):** Single OTS type across all 6 hypertree layers — `n = 21` equal-length hash chains of `59` steps (`w = 60`), decoded directly as 21 packed 6-bit fields plus `z = 2` LSB-first zero bits from `H_l[0..16]` (`2 + 21 × 6 = 128` bits exact; requires no division, no Sperner DP, no `u128` arithmetic, and zero static coding tables), with a deterministic 3-byte (`u24` LE) counter enforcing `d_i < 60` for all `i` and constant upper-half sum `sum(d_i) = 679` (mean `2^{128} / |L_679(21, 60)| = 4,086.92` trials/layer, `2^{-5,923}` counter overflow probability; exact constant `560` verification steps/layer — saving `-360` verification compressions over the midpoint `619` at zero wire or security cost). Zero checksum chains.
- **Few-time signature (`U-PORS` — Upper-Layer Constant-Sum Lattice Octopus):** A single height-`11` binary Merkle tree (`2,048` leaves), where each leaf is a 3-chain hash-chain key (`n = 3` equal-length chains of `23` steps, `w = 24`, fitting in **one single 64-byte BLAKE3 compression**), encoded by the full upper constant-sum slice `a + b + c = 42` (`C = 376` codewords, exact constant `27` verification steps/leaf, zero static lookup tables via closed-form hexagon unranking). Opening `k = 9` distinct leaves with Octopus path merging and a verifier-enforced sibling cap `sibs <= 45` (`u32` counter, exact `p_cap = 1.052923e-4`, mean `9,497.4` trials) compresses the entire few-time section to **`1,156` bytes**.
- **Hypertree (`13 + 7 + 7 + 7 + 7 + 7 = 48`):** `6`-layer binary Merkle hypertree (`h = 48`): a height-`13` top tree (`8,192` leaves; optional cache `256 KiB` full heap, `16 KiB` partial cut `c = 10` of `1,024` subtree roots, or `0 B` stateless — all byte-for-byte identical on the wire) above `5` completely uniform height-`7` lower trees (`128` leaves each).
- **Exact 32-lane SIMD alignment & constant chain verification work:** Top tree `8,192 = 256 × 32`, every lower tree `128 = 4 × 32` (`5 × 128 × 21 = 13,440 = 420 × 32` chains), `U-PORS` tree `2,048 = 64 × 32` (`6,144 = 192 × 32` chains). All `13,440` lower-hypertree chains and `6,144` `U-PORS` chains merge into a single `19,584`-chain (`612 × 32`) lockstep SIMD super-wave on signing. Short-message (`|M| <= 64`, `|ctx| <= 31`) verification with prederived verifier keys executes `3,715 + m + b` BLAKE3 compressions (`m <= 45` consumed Octopus siblings, `b >= 1` `FEW_CODE` blocks — i.e., `3,761` compressions at `m = 45, b = 1`, with exact constant chain work: `560` steps/hypertree layer and `27` steps/opened `U-PORS` leaf).
- **Single-pass salted content hashing:** Every imprint binds a caller-chosen bounded application context (`0..=255` bytes) and hashes an arbitrary-length message in one streaming pass under a fresh per-imprint salt drawn before reading the message.
- **Terminology:** This specification uses **`Signet`** (private signing capability), **`SignetId`** (32-byte verifying identifier), and **`Imprint`** (`3,990`-byte signature). These correspond directly to conventional `(SK, VK, \sigma)` notation; the companion paper (`paper/blincs.pdf`) states all theorems in standard cryptographic notation alongside this mapping.

An `Imprint` is **`3,990` bytes** (`5,320` bytes Base64), a `SignetId` is **`32` bytes**, and a `Signet` derives from a **`32`-byte seed**. The design target is **128-bit classical single-user security** at up to **$2^{48}$ imprints** per signet (281,474,976,710,656), with deterministic, zero-Monte-Carlo, exact-`BigInt` all-orbits capped-history `U-PORS` upper-envelope security of **`>= 131.7076` bits** (`P <= 2.2493e-40`, accounting for Octopus sibling clustering across all `1,614,132` `Aut(T_11)`-orbits via `tools/upors_cert.rs`, vs. `>= 127.9743` bits uncapped upper-envelope) at $q = 2^{48}$ and `>= 125.3590` bits at $2\times$ overuse ($q = 2^{49}$). Do not imprint more than $2^{48}$ things with one signet.

### Notation

All fixed-width integers are unsigned and encoded in **little-endian** byte order. Ranges written `a..b` are half-open `[a, b)` and `a..=b` are closed `[a, b]`. Concatenation is written `||`, byte slicing `x[a..b]` takes bytes `a` through `b - 1`, and `x[..n]` takes the first `n` bytes. Maximum message length is $2^{64} - 1$ bytes; maximum application context length is `255` bytes.

---

## 2. Hash Primitive

BLINCS uses **only** the two standard 32-byte modes of **BLAKE3** (no extendable-output XOF mode required):

- `Keyed(K, M)`: BLAKE3 keyed hash (`KEYED_HASH` mode) with 32-byte key `K` over byte string `M`, returning 32 bytes.
- `Derive(ctx, M)`: BLAKE3 key derivation (`DERIVE_KEY` mode) with UTF-8 context string `ctx` over input byte string `M`, returning 32 bytes.

---

## 3. Suite Identity and Parameters

Suite identifier: **`BLINCS-48-X`**.

| Symbol | Value | Meaning |
|---|---:|---|
| `N` | 16 | Byte length of truncated tree, chain, salt, and randomizer values (`h_msg`, `D_seed`, and derived keys are 32 bytes) |
| `LAYERS` | 6 | Hypertree layers (`d`): layers `0, 1, 2, 3, 4` have height `7`; top layer `5` has height `13` |
| `LOW_HEIGHT` | 7 | Height of each of the 5 lower hypertree layers (`2^7 = 128` leaves/tree) |
| `TOP_HEIGHT` | 13 | Height of the top hypertree layer (`2^{13} = 8,192` leaves; optional `256 KiB` full or `16 KiB` `c=10` partial cache) |
| `HYPER_BITS` | 48 | Total hypertree height (`5 * 7 + 13 = 48`) |
| `WOTS_N` | 21 | `WOTS+C` chains per hypertree leaf (`WOTS_PK_IN_LEN = 352` B = 6 BLAKE3 blocks) |
| `WOTS_W` | 60 | `WOTS+C` chain cardinality (`WOTS_STEPS = 59`, 6-bit digits in `0..=59`) |
| `WOTS_SUM` | 679 | Constant upper-half digit sum (`2^{128} / \|L_679(21, 60)\| = 4,086.9` mean trials; exact constant `21 * 59 - 679 = 560` verify steps/layer) |
| `WOTS_Z` | 2 | LSB-first zero bits required on `OneTimeMsg` (`(H[0] & 0x03) == 0`; `2 + 21 * 6 = 128` bits exact) |
| `WOTS_CTR_LEN` | 3 | Byte length of `u24` LE `WOTS+C` wire counter (`ctr_l in 0..2^24`, zero-extended to `u32` LE in `OneTimeMsg`) |
| `UPORS_HEIGHT` | 11 | Height of the single `U-PORS` binary Merkle tree (`2^{11} = 2,048` leaves) |
| `UPORS_N` | 3 | Equal-length hash chains per `U-PORS` leaf (`16 + 3 * 16 = 64` B = 1 BLAKE3 block) |
| `UPORS_W` | 24 | `U-PORS` chain cardinality (`UPORS_STEPS = 23`, digits in `0..=23`) |
| `UPORS_SUM` | 42 | Constant sum `a + b + c = 42` for every `U-PORS` codeword (`69 - 42 = 27` verify steps/leaf) |
| `UPORS_C` | 376 | Cardinality of full upper slice `L_42(3, 24)` (`0 B` static tables via closed-form hexagon unranking) |
| `UPORS_K` | 9 | Number of distinct `U-PORS` leaves opened per imprint |
| `UPORS_M_MAX` | 45 | Verifier-enforced maximum Octopus authentication siblings (`u32` counter `ctr_ft`) |
| `UPORS_SELECT_MAX_DRAWS` | 18 | Consecutive 11-bit leaf draws in `FEW_SELECT` (`18 * 11 + 48 = 246 <= 256` bits) |
| `UPORS_LAYER` | 128 | Tweak layer byte `0x80` separating `U-PORS` (`128`) from hypertree layers (`0..6`) |
| `MAX_CONTEXT_LEN` | 255 | Maximum byte length of the framed application context `ctx` |

Derived lengths:

- `UPORS_LEN = 4 + (UPORS_K * UPORS_N + UPORS_M_MAX) * N = 4 + (27 + 45) * 16 = 1,156` bytes.
- `LOW_LAYER_LEN = 3 + (WOTS_N + LOW_HEIGHT) * N = 3 + 28 * 16 = 451` bytes (layers `0..5`).
- `TOP_LAYER_LEN = 3 + (WOTS_N + TOP_HEIGHT) * N = 3 + 34 * 16 = 547` bytes (layer `5`).
- `IMPRINT_LEN = 2 * N + UPORS_LEN + 5 * LOW_LAYER_LEN + TOP_LAYER_LEN = 3,990` bytes.

---

## 4. Key-Derivation Contexts

Every derived 32-byte key uses a distinct UTF-8 context string binding the suite name `BLINCS-48-X`, domain-separating KDF inputs across suites:

| Name | Context string |
|---|---|
| `SECRET_VALUES` | `"BLINCS-48-X 2026-11-26 secret values"` |
| `CONTENT_SALT` | `"BLINCS-48-X 2026-11-26 content salt"` |
| `RANDOMIZER` | `"BLINCS-48-X 2026-11-26 randomizer"` |
| `PUBLIC_SEED` | `"BLINCS-48-X 2026-11-26 public seed"` |
| `PUBLIC_HASH` | `"BLINCS-48-X 2026-11-26 public hash"` |
| `CONTENT` | `"BLINCS-48-X 2026-11-26 content"` |
| `GENERATE_SIGNET` | `"Signet BLINCS-48-X 2026-11-26 generate signet"` |
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

Unused fields MUST be zero. Hypertree layers use `layer in 0..6`; the single `U-PORS` tree uses `layer = 0x80` (`128`), whose `tree` field carries the full 48-bit `leaf_addr in 0..2^48`. Eight tweak kinds partition every hash call unambiguously:

| Value | Name | Key | Tweak fields `(layer, tree, leaf, a, b)` | Data appended after tweak | Output used |
|---:|---|---|---|---|---|
| 1 | `CHAIN_SECRET` | `K_sec` | `(layer, tree, 0, 0, leaf * n_chains + c)` | *(empty)* | 16 B |
| 2 | `CHAIN` | `K_pub` | `(layer, tree, leaf, c, step)` | current 16-byte chain value | 16 B |
| 3 | `ONE_TIME_KEY` | `K_pub` | `(layer, tree, leaf, 0, 0)` | `21` chain ends (`336` B, HT) or `3` chain ends (`48` B, `U-PORS`) | 16 B |
| 4 | `NODE` | `K_pub` | `(layer, tree, 0, level, parent_idx)` | `left (16) \|\| right (16)` | 16 B |
| 5 | `ONE_TIME_MSG` | `K_pub` | `(layer, tree, leaf, 0, 0)` | `child_root (16) \|\| u32_le(ctr_l) (4)` | 32 B |
| 6 | `MESSAGE` | `K_pub` | `(0, 0, 0, 0, 0)` | `R (16) \|\| root (16) \|\| short (48) \|\| framed_ctx` | 32 B |
| 7 | `FEW_SELECT` | `K_pub` | `(0x80, 0, 0, 0, 0)` | `D_seed (32) \|\| u32_le(ctr_ft) (4)` | 32 B |
| 8 | `FEW_CODE` | `K_pub` | `(0x80, 0, 0, block_idx, 0)` | `H_sel (32)` | 32 B |

Define `ShortHash(K, T, data) = Keyed(K, T || data)[..16]`.

Every hot-path call — `CHAIN_SECRET` (`16 B`), `CHAIN` (`32 B`), `ONE_TIME_MSG` (`36 B`), `NODE` (`48 B`), `FEW_CODE` (`48 B`), `FEW_SELECT` (`52 B`), and `U-PORS` `ONE_TIME_KEY` (`64 B`) — fits inside **one single 64-byte BLAKE3 compression block**, and all three counter-indexed loops (`CHAIN_SECRET` at word `3`, `ONE_TIME_MSG` at word `8`, `FEW_SELECT` at word `12`) place the incrementing `u32` counter on a 4-byte word boundary for register-only SIMD counter-range hashing.

---

## 6. Signet and SignetId

A `Signet` derives deterministically from a 32-byte `seed`:

```text
K_sec   = Derive(SECRET_VALUES, seed)
K_salt  = Derive(CONTENT_SALT,  seed)
K_R     = Derive(RANDOMIZER,    seed)
pk_seed = Derive(PUBLIC_SEED,   seed)[..16]
K_pub   = Derive(PUBLIC_HASH,   pk_seed)
root    = top hypertree root at layer = 5, tree = 0 (height 13, 8,192 leaves)
```

The 32-byte `SignetId` is `id = pk_seed || root`. A verifier derives from `id`:

```text
K_pub     = Derive(PUBLIC_HASH, id[..16])
root      = id[16..32]
K_content = Derive(CONTENT,     id)
```

Top-tree caching is purely internal to the signer and produces byte-for-byte identical imprints at every cache level:
- Desktop/server signers SHOULD cache the full height-13 top Merkle heap (`2 * 8,192 × 16 B = 256 KiB`) in memory inside `Signet`.
- Memory-constrained embedded signers (e.g., Cortex-M33 with Flash) MAY cache a partial cut at depth `c = 10` (`2^{10} = 1,024` subtree roots = `16 KiB` — recomputing only `2^{13-10} = 8` top leaves per imprint, `< 1.1%` overhead), or store `0 B` and recompute layer 5 when signing.

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

Because `e` is derived before reading `M`, signers stream arbitrarily large messages through `Keyed(K_msg, M)` in a single pass. Verifiers read `e` from the first 16 bytes of the imprint and stream `M` in a single pass as well. **Commitment requirement:** signers MUST NOT disclose `e` (or `K_msg`) to a message submitter before `(ctx, M)` is committed, so `M` cannot be chosen adaptively as a function of `e`.

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

1. Read up to `18` consecutive `11`-bit chunks `x_i = read_bits(H_sel, 11 * i, 11)` (`i in 0..18`, bits `0..198`), keeping the first **`9` distinct** leaf indices in `0..2048`. If fewer than `9` distinct indices appear in those `18` chunks (probability $\approx 2^{-73}$), `ctr_ft` is **invalid**.
2. Sort the `9` distinct leaf indices into strictly ascending order `leaves[0] < leaves[1] < ... < leaves[8]`.
3. Compute the exact Octopus sibling count `sibs = count_octopus_sibs(leaves)` in a binary tree of height `11` (§10.2). If `sibs > 45`, `ctr_ft` is **invalid**.
4. Extract the `48`-bit hypertree leaf address `leaf_addr = read_bits(H_sel, 198, 48)` (bits `198..246`; bits `246..256` are not parsed for leaves or address, and all 32 bytes of `H_sel` MUST be hashed unchanged into `FEW_CODE`).

A deterministic signer chooses the **smallest** `ctr_ft in 0..=2^32 - 1` that is valid (exact cap mass `|F| / C(2048, 9) = 180,700,154,447,569,471,488 / C(2048, 9) = 1.052923e-4`, mean `9,497.4` trials, `p99 ≈ 43,737` trials; `u32` exhaustion probability $< 2^{-6.5 \times 10^5}$). If `ctr_ft` exhausts `u32` (`2^32` trials without a valid selection), the signer MUST fail closed (abort/error without wrapping). A verifier checks only the single `ctr_ft` encoded in the imprint and MUST reject if it is invalid.

### 8.2 Unbiased `U-PORS` Codeword Extraction (`FEW_CODE`)

Given the accepted `FEW_SELECT` digest `H_sel` (32 bytes), draw `9` unbiased indices `c_0, ..., c_8 in 0..376` using `block_idx in 0..=65535` (`u16`):

```text
block_idx = 0, got = 0
while got < 9:
    if block_idx > 65535: fail closed (reject / abort)
    B = Keyed(K_pub, tweak(FEW_CODE, 0x80, 0, 0, block_idx, 0) || H_sel)
    for j in 0..28:                       # 28 * 9 = 252 <= 256 bits
        v = read_bits(B, 9 * j, 9)        # uniform in 0..512
        if v < 376:
            codeword[got] = hex_unrank(v)
            got += 1
            if got == 9: break
    block_idx += 1
```

Chaining `FEW_CODE` directly from the 32-byte `FEW_SELECT` digest `H_sel` (`48 B` total input, still one single BLAKE3 block) binds the codeword stream to the selection output so adversaries cannot evaluate `FEW_CODE` for a fixed candidate `(D_seed, ctr_ft)` before evaluating `FEW_SELECT`. Each `9`-bit value is accepted with probability `376 / 512 = 73.44%` with **zero modulo bias**; in the ideal-output model `Pr[Bin(28j, 376/512) < 9]` is `~9.29e-7` (`2^{-20.0}`) after `j = 1` block (`99.99991%` finish in 1 block) and `~2^{-65}` after `j = 2` blocks (`< 2^{-10^6}` for `u16` exhaustion). Both signer and verifier MUST fail closed (abort / reject) if `block_idx` would exceed `65535` (`u16::MAX`), never wrapping `block_idx` or substituting default codewords.

---

## 9. Unified Chain-and-Merkle Primitive

Both `U-PORS` (`layer = 0x80`, `height = 11`, `n_chains = 3`, `steps = 23`) and every hypertree layer (`layer in 0..6`, `height in {7, 13}`, `n_chains = 21`, `steps = 59`) use the **exact same** hash-chain and binary Merkle primitive:

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

At hypertree address `leaf_addr` (`0..2^48`), `U-PORS` builds a single height-`11` binary Merkle tree (`2,048` leaves) via §9 with `layer = 0x80`, `tree = leaf_addr`, `n_chains = 3`, and `steps = 23`:

- **Chain values (`432` B):** For `t in 0..9`, sign `leaves[t]` with its `3` chain values `(x_{d_0}, x_{d_1}, x_{d_2})` where `(d_0, d_1, d_2) = codeword[t]`.
- **Octopus authentication siblings (`720` B, canonical zero-padded):**
  Starting with the strictly ascending active index list `cur = leaves[0..9]` at leaf level `0`, for `level = 1..=11`:
  - Scan `cur` left to right:
    - If `i + 1 < len(cur)` and `(cur[i] ^ 1) == cur[i + 1]`: both children are active; merge them into parent `cur[i] >> 1` with **no** sibling emitted (`i += 2`).
    - Otherwise: emit the sibling node at `(level - 1, cur[i] ^ 1)` into the Octopus list, push parent `cur[i] >> 1` (`i += 1`).
  - Let `sibs` be the total number of siblings emitted (`sibs <= 45`). Append `(45 - sibs) * 16` zero bytes so the Octopus field is always exactly `45 * 16 = 720` bytes.
- **Verification:** Reconstruct all `9` leaf hashes via §9, climb the `11` Octopus levels consuming siblings in the exact same left-to-right scan order (placing `cur_val` left if `(x & 1) == 0` else right, hashed with `tweak(NODE, 0x80, leaf_addr, 0, level, x >> 1)`), **verify in constant time that all `(45 - sibs) * 16` trailing padding bytes are zero** (reject if any padding byte is non-zero), and output the level-11 root as `upors_root`.

The `U-PORS` section is `4 + 432 + 720 = 1,156` bytes.

---

## 11. Hypertree (`WOTS+C`) and Imprint Wire Format

### 11.1 `WOTS+C` Message Grinding and Direct 6-Bit Decoding

Given a 16-byte child root `node` to sign at hypertree position `(layer, tree, leaf)` (`layer in 0..6`):

1. **Direct 6-bit decoding (`decode_wots_c`):** Given the 16-byte truncated digest `H_l = ShortHash(...)`, let `lo = u128_le(H_l)`. `H_l` is **valid** if and only if all three conditions hold:
   - `(lo & 3) == 0` (`WOTS_Z = 2` LSB-first zero bits),
   - for every `i in 0..21`, the 6-bit field `digits[i] = (lo >> (2 + 6 * i)) & 63` satisfies `digits[i] < 60`, and
   - `digits[0] + digits[1] + ... + digits[20] == 679` (`WOTS_SUM = 679`).
   Notice `2 + 21 * 6 = 128` bits — every single bit of `H_l[0..16]` is bound with zero division, zero `u128` arithmetic, zero coding lookup tables, and zero stack buffers. Because `sum(digits) == 679` is constant, valid digit vectors form a strict antichain in `{0..=59}^{21}`, so forging by forward derivation from the same openings (absent other collision or chain-preimage events) requires matching the exact 128-bit prefix `H'_l[0..16] == H_l[0..16]` (`2^{-128}` per fresh raw query in the ROM).
2. **Deterministic `u24` counter grinding (`ONE_TIME_MSG`):** Find the smallest `ctr_l in 0..=16,777,215` (`0..2^24`) such that
   ```text
   H_l = Keyed(K_pub, tweak(ONE_TIME_MSG, layer, tree, leaf, 0, 0) || node || u32_le(ctr_l))
   ```
   is valid under `decode_wots_c`. The number of valid 128-bit prefixes is exact:
   $$|\mathcal{L}_{679}(21, 60)| = 83{,}261{,}328{,}062{,}314{,}682{,}436{,}358{,}950{,}675{,}433{,}803,$$
   giving acceptance probability $p_{\text{wots}} = |\mathcal{L}_{679}(21, 60)| / 2^{128} \approx 1 / 4{,}086.920$ per trial (mean `4,086.92` trials/layer; if all `2^{24}` values fail, the signer MUST fail closed without wrapping; exhaustion probability $(1 - p_{\text{wots}})^{2^{24}} \approx 2^{-5,923}$). On the wire, `ctr_l` is encoded as its 3 little-endian bytes `u32_le(ctr_l)[0..3]`. Verifier decodes `ctr_l = u32_le(b0, b1, b2, 0)`, computes `H_l`, runs `decode_wots_c(H_l)`, and MUST reject if invalid.
   Verification performs an **exact constant `21 * 59 - 679 = 560` chain steps per layer** (saving `60` compressions per layer — `360` total — over the midpoint `S = 619`).

### 11.2 Hypertree Walk and Wire Format (`3,990` Bytes)

Starting with `addr = leaf_addr` and `node = upors_root`:

- For `layer in 0..6`:
  - `h_l = 13` if `layer == 5` else `7`.
  - `leaf = addr & ((1 << h_l) - 1)`; `tree = addr >> h_l` (at `layer == 5`, `tree == 0`).
  - Grind `ctr_l` and decode `digits = decode_wots_c(H_l)` for `node`.
  - Sign `node` via §9 with `(layer, tree, leaf, n_chains = 21, steps = 59)` and append its `h_l`-node Merkle authentication path (`112 B` for layers `0..5`, `208 B` for layer `5`).
  - Set `node = tree_root` and `addr = tree`.
- Verification succeeds iff all `ctr_ft`, canonical Octopus padding, and `ctr_0..5` checks pass AND the reconstructed layer-5 root equals `id[16..32]` in constant time.

Wire layout of a `BLINCS-48-X` `Imprint` (`3,990` bytes):

```text
0..16        salt e (16 B)
16..32       randomizer R (16 B)
32..1188     U-PORS (1,156 B): ctr_ft (4 B) || 9 x 3 x 16 B chains (432 B) || 45 x 16 B Octopus sibs + zero pad (720 B)
1188..1639   Layer 0 (451 B): ctr_0 (3 B) || 21 x 16 B WOTS+C (336 B) || 7 x 16 B auth path (112 B)
1639..2090   Layer 1 (451 B): ctr_1 (3 B) || 21 x 16 B WOTS+C (336 B) || 7 x 16 B auth path (112 B)
2090..2541   Layer 2 (451 B): ctr_2 (3 B) || 21 x 16 B WOTS+C (336 B) || 7 x 16 B auth path (112 B)
2541..2992   Layer 3 (451 B): ctr_3 (3 B) || 21 x 16 B WOTS+C (336 B) || 7 x 16 B auth path (112 B)
2992..3443   Layer 4 (451 B): ctr_4 (3 B) || 21 x 16 B WOTS+C (336 B) || 7 x 16 B auth path (112 B)
3443..3990   Layer 5 (547 B): ctr_5 (3 B) || 21 x 16 B WOTS+C (336 B) || 13 x 16 B auth path (208 B)
```

---

## 12. Startup Self-Test (Recommended for Every Implementation)

Every production or library implementation of BLINCS — especially implementations using optimized assembly, SIMD/vector hashing, custom compilers, or cross-compiled targets — is **strongly recommended** to execute a **quick, fail-closed startup self-test** once per process before accepting or generating imprints (following Ferguson–Schneier–Kohno, `pycryptopp`, and `blake3-servil-core::initialize()`):

1. **Initialize the underlying BLAKE3 implementation's own self-test** (for example `blake3_servil_core::initialize()`).
2. **Positive verification KAT (~62 µs):** Verify `test_vectors/reference-imprint-1.bin` (`ctx = b"BLINCS-48-X reference vector v1"`, `M = b"hello, BLINCS"`), exercising `Derive`, `Keyed`, context framing, `FEW_SELECT`, `FEW_CODE`, `hex_unrank`, Octopus verification, canonical padding checks, `ONE_TIME_MSG`, `WOTS+C` 6-bit decoding, all 6 hypertree layers, and constant-time root comparison.
3. **Negative verification KATs (~125 µs):** Flip one bit in the imprint and confirm rejection; pass a different context (`b""`) and confirm rejection.
4. **Fail closed:** Refuse to proceed on any mismatch.

See [`reference/src/lib.rs`](reference/src/lib.rs) for a concrete implementation of `self_test()`.

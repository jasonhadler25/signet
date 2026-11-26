# BLINCS specification (`BLINCS-128-7x5`, draft)

*Status: pre-1.0 design under active development (0.1.0, formats and context strings may still change before 1.0). Written by an AI assistant at the direction of this repository's owner; no independent cryptographic review or security audit has been performed. Builds on BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn) and SPHINCS / SPHINCS+ / FIPS 205 SLH-DSA (Bernstein, Hopwood, Hülsing, Kölbl, Lange, Niederhagen, Papachristodoulou, Rijneveld, Schneider, Schwabe, Wilcox-O'Hearn, and the NIST SLH-DSA team). Thanks to [Project 11](https://research.projecteleven.com/) — especially **Conor Deegan**, **Alessandro Baiocchi**, **Matteo Vena**, and **Matteo Vicari** — for direct review feedback, benchmarks, and constrained-device design inspiration (full credits in [`README.md`](README.md#credits-and-thanks)).*

**BLINCS** is a stateless hash-based signature algorithm based on BLAKE3 and SPHINCS; **Signet** (this repository) is a Rust implementation of the **`BLINCS-128-7x5`** suite. `BLINCS-128-7x5` uses **WOTS+** (nibbles, `w = 16`) and byte-aligned **FORS** (`20` trees of `256` leaves — one digest byte per tree) on a uniform 7-layer hypertree (`7×5`, total height `35`) with **zero counter grinding**, a **suite-separated key schedule**, a **bounded length-framed application context (`0..=255` bytes)**, and **single-pass salted content hashing** (BLINCS-specific nibble/tweak encodings and BLAKE3 instantiation; not FIPS 205 interoperable or validated).

An imprint is **7,392 bytes** (`9,856` bytes Base64 — smaller than `SLH-DSA-128s`'s `7,856` bytes), a `SignetId` is **32 bytes**, and a `Signet` derives from a **32-byte seed** (holding a 1 KiB top tree in memory). Because there is zero counter grinding, signing performs a constant number of BLAKE3 compressions (`p99 = mean = max`, ~3.6 s uncached on a 60 MHz Ledger ST33 Secure Element, `1.25 ms` warm / `1.42 ms` cold on 1 Apple M6 core). Its design target is **128-bit classical security** (128-bit root) at up to **$2^{32}$ imprints** per signet (4,294,967,296: ten imprints a second for 13.6 years), with an estimated single-query FORS cover exponent of **134.5 bits** at $q = 2^{32}$, degrading gradually past the budget (`128.8` bits at $2^{33}$, `122.4` bits at $2^{34}$, `114.9` bits at $2^{35}$, `106.2` bits at $2^{36}$).

Messages are hashed in a single salted keyed-BLAKE3 pass under a fresh per-imprint salt `e` derived from the signet and per-imprint randomness before reading the message. Pass the original message bytes or stream directly to Signet so the entire input is covered by the salted pass at full BLAKE3 streaming speed without relying on unsalted collision resistance.

All fixed-width integers are unsigned and encoded in little-endian byte order. Ranges written `a..b` are half-open `[a, b)` and `a..=b` are closed `[a, b]`. Concatenation is written `||`, byte slicing `x[a..b]` takes bytes `a` through `b - 1`, and `x[..n]` takes the first `n` bytes. Maximum message length is $2^{64} - 1$ bytes; maximum application context length is `255` bytes.

## Hash primitive

BLINCS uses two 32-byte modes of BLAKE3:

- `Keyed(K, M)`: BLAKE3 keyed hash with 32-byte key `K` over byte string `M` (32-byte output).
- `Derive(ctx, M)`: BLAKE3 key derivation with UTF-8 context string `ctx` over input `M` (32-byte output).

## Suite identity and parameters

Suite identifier: **`BLINCS-128-7x5`**.

| Symbol | Value | Meaning |
|---|---:|---|
| `N` | 16 | Byte length of truncated tree, chain, salt, and randomizer values (`h_msg`, `D`, and derived keys are 32 bytes) |
| `LAYERS` | 7 | Uniform layers of the hypertree (`d`) |
| `TREE_HEIGHT` | 5 | Height of every hypertree layer `0..7` ($2^5 = 32$ leaves per tree; total `HYPER_BITS = 7 * 5 = 35`) |
| `W` | 16 | WOTS+ Winternitz parameter (`CHAIN_STEPS = 15`, 4-bit nibbles in `0..=15`) |
| `MSG_CHAINS` | 32 | WOTS+ message chains (`128 / 4 = 32` nibbles) |
| `CSUM_CHAINS` | 3 | WOTS+ checksum chains (`max checksum = 32 * 15 = 480 < 16^3`) |
| `CHAINS` | 35 | Total WOTS+ chains per one-time signature (`32 + 3`) |
| `FORS_HEIGHT` | 8 | Height of each FORS tree ($2^8 = 256$ leaves per tree — one byte per index) |
| `FORS_TREES` | 20 | Number of independent FORS trees (`k`; `20 * 8 = 160` bits = `D[0..20]`) |
| `MAX_CONTEXT_LEN` | 255 | Maximum byte length of the framed application context `ctx` |

Derived lengths:

- `FORS_LEN = FORS_TREES * (1 + FORS_HEIGHT) * N = 2,880` bytes.
- `LAYER_LEN = (CHAINS + TREE_HEIGHT) * N = 640` bytes (identical on all 7 layers).
- `IMPRINT_LEN = 2 * N + FORS_LEN + LAYERS * LAYER_LEN = 7,392` bytes.

## Key-derivation contexts

Every derived 32-byte key uses a distinct UTF-8 context string. All algorithm key-derivation contexts bind the suite name `BLINCS-128-7x5`, ensuring separate suites never share derived keys:

| Name | Context string |
|---|---|
| `SECRET_VALUES` | `"BLINCS-128-7x5 2026-11-25 secret values"` |
| `CONTENT_SALT` | `"BLINCS-128-7x5 2026-11-25 content salt"` |
| `RANDOMIZER` | `"BLINCS-128-7x5 2026-11-25 randomizer"` |
| `PUBLIC_SEED` | `"BLINCS-128-7x5 2026-11-25 public seed"` |
| `PUBLIC_HASH` | `"BLINCS-128-7x5 2026-11-25 public hash"` |
| `CONTENT` | `"BLINCS-128-7x5 2026-11-25 content"` |
| `GENERATE_SIGNET` | `"Signet BLINCS-128-7x5 2026-11-25 generate signet"` |
| `MIX` | `"Signet 2026-11-25 randomness: mix"` |
| `NEXT_SEED` | `"Signet 2026-11-25 randomness: next seed"` |
| `RUN_KEY` | `"Signet 2026-11-25 randomness: key of this run"` |
| `KEYGEN_KEY` | `"Signet 2026-11-25 randomness: keygen key"` |

## Tweaks

Every tree, chain, and message-binding hash is domain-separated by a 16-byte tweak:

```text
tweak(kind, layer, tree, leaf, a, b) =
    kind  (u8,  1 byte)
 || layer (u8,  1 byte)
 || tree  (u48, 6 bytes LE)
 || leaf  (u16, 2 bytes LE)
 || a     (u16, 2 bytes LE)
 || b     (u32, 4 bytes LE)
```

Unused fields are zero. The nine kinds are:

| Value | Name | Key | Data appended after tweak | Output bytes used |
|---:|---|---|---|---|
| 1 | `CHAIN_SECRET` | `K_sec` | *(empty)* | 16 |
| 2 | `CHAIN` | `K_pub` | current 16-byte chain value | 16 |
| 3 | `ONE_TIME_KEY` | `K_pub` | 35 chain ends (`560` bytes) | 16 |
| 4 | `NODE` | `K_pub` | `left (16) \|\| right (16)` | 16 |
| 5 | `FEW_SECRET` | `K_sec` | *(empty)* | 16 |
| 6 | `FEW_LEAF` | `K_pub` | 16-byte leaf secret | 16 |
| 7 | `FEW_NODE` | `K_pub` | `left (16) \|\| right (16)` | 16 |
| 8 | `FEW_ROOT` | `K_pub` | 16 × 20 FORS tree roots (`320` bytes) | 16 |
| 9 | `MESSAGE` | `K_pub` | `R (16) \|\| root (16) \|\| short (48) \|\| u8(len(ctx)) \|\| ctx` | 32 |

Define `ShortHash(K, T, data) = Keyed(K, T || data)[..16]`.

## Signet and SignetId

A `Signet` is derived from a 32-byte `seed`:

```text
K_sec   = Derive(SECRET_VALUES, seed)
K_salt  = Derive(CONTENT_SALT,  seed)
K_R     = Derive(RANDOMIZER,    seed)
pk_seed = Derive(PUBLIC_SEED,   seed)[..16]
K_pub   = Derive(PUBLIC_HASH,   pk_seed)
root    = top hypertree root at layer = 6, tree = 0 (height 5, 32 leaves)
```

The 32-byte signet identifier (`SignetId`) is `id = pk_seed || root`. A verifier derives from `id`:

```text
K_pub     = Derive(PUBLIC_HASH, id[..16])
root      = id[16..32]
K_content = Derive(CONTENT,     id)
```

## Framed application context and content hashing

Every imprint binds a caller-chosen application context `ctx` of `0..=255` bytes, framed unambiguously as:

```text
framed_ctx = u8(len(ctx)) || ctx                  # 1..=256 bytes
```

When imprinting with a 32-byte per-imprint draw `draw`:

```text
e = Keyed(K_salt, draw)[..16]                     # 16-byte per-imprint content salt
```

Given the 16-byte content salt `e`, application context `ctx`, and message `M` (any length in `0..2^64`):

```text
K_msg = Keyed(K_content, e || framed_ctx)         # 32-byte per-imprint, per-context message key (public once e, ctx are known)
h_msg = Keyed(K_msg, M)                           # 32-byte keyed BLAKE3 hash of M (single pass)
short = e || h_msg                                # 48 bytes
```

BLAKE3 commits to message length under its standard hash assumptions, and `K_msg` is derived from `id` (via `K_content`), the fresh per-imprint salt `e`, and the length-framed `ctx`.

## Message digest and index extraction

The signer computes the deterministic per-imprint randomizer and 32-byte digest `D`:

```text
R = Keyed(K_R, short || framed_ctx)[..16]
D = Keyed(K_pub, tweak(MESSAGE, 0, 0, 0, 0, 0) || R || root || short || framed_ctx)
```

From `D` (32 bytes):

- **FORS leaf indices** `indices[0..20]`: byte-aligned — for `t in 0..20`, `indices[t] = D[t]` (each in `0..256`, zero bit-unpacking).
- **Hypertree leaf address** `leaf_addr`: low 35 bits of `u64_le(D[20..28])`, i.e., `u64_le(D[20..28]) & ((1 << 35) - 1)` (the remaining high bits of `D[24..32]` are unused).

## Few-time signatures (FORS)

At hypertree address `leaf_addr` (`0..2^35`), FORS consists of `FORS_TREES = 20` independent binary Merkle trees, each of height `FORS_HEIGHT = 8` (`256` leaves):

- For tree `t in 0..20` and leaf `i in 0..256`:
  - `secret[t][i] = ShortHash(K_sec, tweak(FEW_SECRET, 0, leaf_addr, t, 0, i), empty)`
  - `leaf[t][i]   = ShortHash(K_pub, tweak(FEW_LEAF,   0, leaf_addr, t, 0, i), secret[t][i])`
- Internal node at height `level in 1..=8`, index `p in 0..(256 >> level)`:
  - `node = ShortHash(K_pub, tweak(FEW_NODE, 0, leaf_addr, t, level, p), left || right)`
- The 20 tree roots `root[0..20]` are compressed into the 16-byte FORS root:
  - `fors_root = ShortHash(K_pub, tweak(FEW_ROOT, 0, leaf_addr, 0, 0, 0), root[0] || ... || root[19])`

The FORS section of the imprint (`2,880` bytes) is the concatenation for `t = 0..20` of:
`secret[t][indices[t]]` (16 bytes) followed by its 8 authentication-path siblings from leaf level `0` up to level `7` (`128` bytes). On verification, at each level `h in 0..8`, if bit `h` of `indices[t]` is `0`, `cur` is the left child and `auth[h]` is the right child; otherwise `auth[h]` is left and `cur` is right, hashed with `tweak(FEW_NODE, 0, leaf_addr, t, h + 1, indices[t] >> (h + 1))`.

## One-time signatures (WOTS+)

Given a 16-byte message `node` to sign at `(layer, tree, leaf)`:

- **Digits `digits(node)`** (`35` nibbles in `0..=15`):
  - For `i in 0..16`: `d[2*i] = node[i] & 0x0f`, `d[2*i + 1] = node[i] >> 4`.
  - Checksum `csum = sum_{j=0..32} (15 - d[j])` (in `0..=480`).
  - `d[32] = csum & 0x0f`, `d[33] = (csum >> 4) & 0x0f`, `d[34] = (csum >> 8) & 0x0f`.
- **Chain `c in 0..35`:**
  - Start value: `x_0 = ShortHash(K_sec, tweak(CHAIN_SECRET, layer, tree, leaf, c, 0), empty)`.
  - Step `s -> s + 1` (for `s in 0..15`): `x_{s+1} = ShortHash(K_pub, tweak(CHAIN, layer, tree, leaf, c, s), x_s)`.
  - Signature value for chain `c`: `x_{d[c]}`. Verifier completes steps `s = d[c]..15` to recover `x_15`.
- **One-time verifying key (Merkle leaf):**
  - `leaf_hash = ShortHash(K_pub, tweak(ONE_TIME_KEY, layer, tree, leaf, 0, 0), x_15[0] || ... || x_15[34])`.

## Hypertree and imprint layout

The hypertree has `7` uniform layers (`layer = 0, 1, 2, 3, 4, 5, 6`), each of height `TREE_HEIGHT = 5` (`32` leaves per tree):

- Starting with `addr = leaf_addr` and `node = fors_root`:
  - For `layer = 0..7`:
    - `leaf = addr & 0x1f` (`5` low bits)
    - `tree = addr >> 5` (at `layer = 6`, `tree == 0`)
    - Sign `node` with WOTS+ at `(layer, tree, leaf)` (`35 * 16 = 560` bytes) and append the `5` Merkle authentication-path siblings from leaf level `0` up to level `4` (`80` bytes), using `tweak(NODE, layer, tree, 0, level, p)` for `level in 1..=5`.
    - On verification, at each `level in 1..=5`, if bit `level - 1` of `leaf` is `0`, `cur` is the left child and `auth[level - 1]` is right; otherwise `auth[level - 1]` is left and `cur` is right, hashed with `tweak(NODE, layer, tree, 0, level, leaf >> level)`.
    - Set `node = tree_root` and `addr = tree`.
- Verification succeeds iff the reconstructed layer-6 root equals `id[16..32]` in constant time.

Wire layout of an `Imprint` (`7,392` bytes):

```text
0..16        salt e (16 B)
16..32       randomizer R (16 B)
32..2912     FORS: 20 trees x (16 B secret + 8 x 16 B auth path) = 2,880 B
2912..3552   Layer 0: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
3552..4192   Layer 1: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
4192..4832   Layer 2: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
4832..5472   Layer 3: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
5472..6112   Layer 4: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
6112..6752   Layer 5: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
6752..7392   Layer 6: 35 x 16 B WOTS+ + 5 x 16 B auth path = 640 B
```

## Signer randomness (Signet local host policy)

The BLINCS wire format does not depend on how the signer chooses `draw`; the scheme below is Signet's local host policy for keeping `draw` non-repeating across restarts without file locking (`flock`).

State lives in a single private regular file on a trusted local filesystem (created once with `Randomness::create`, mode `0600` on Unix) holding **exact 32 raw bytes**:

1. **State mixing (`mix_pool` and `expand_pool`):**
   Given optional prior 32-byte state `prior` (`None` on `create`, `Some(prior)` on `initialize`), 32 bytes `system` from OS cryptographic randomness (`getrandom(2)` / `getentropy`), 4-byte little-endian process ID `pid`, and opaque `clock` bytes from the monotonic clock:
   ```text
   prefix     = 0x00 (on create)  or  0x20 || prior (on initialize)
   material   = prefix || system || u32_le(pid) || clock
   pool       = Derive(MIX,        material)
   next_seed  = Derive(NEXT_SEED,  pool)          # 32 bytes atomically renamed onto the state file
   run_key    = Derive(RUN_KEY,    pool)          # in-memory key for per-imprint draws
   keygen_key = Derive(KEYGEN_KEY, pool)          # in-memory key for Signet::generate
   ```
   Splitting `next_seed` from `run_key`/`keygen_key` preserves forward secrecy on disk: reading the persisted file after a run does not reveal that run's draws.
2. **Lock-free atomic state rotation (`Randomness::initialize`):**
   Check that the path is a private (`0600`) regular non-symlink file and read its exact 32 bytes (failing closed without modifying anything on missing paths, symlinks, directories, group/world-accessible permissions, or wrong lengths). Compute `pool`, write all 32 bytes of `next_seed` to a fresh `0600` sibling temp file, and atomically publish it onto the state path via POSIX `rename` (with no locks and no torn reads). `create` syncs the temp file, publishes it via no-replace `hard_link` (never overwriting an existing path), and syncs the parent directory; `initialize` omits `fsync` for low startup latency (best-effort across power loss).
3. **Per-imprint draw and signet generation:**
   Each `draw` or `generate` reserves the current 64-bit counter `n` (starting at `0`) and increments it, panicking before `u64::MAX` overflow:
   - Imprint draw: `draw = Keyed(run_key, u64_le(n))`.
   - New signet generation (`Signet::generate`): `seed = Derive(GENERATE_SIGNET, Keyed(keygen_key, u64_le(n)) || os_getrandom_32)`.
4. **Fork and VM snapshots:** in multithreaded POSIX processes, call `exec()` before initializing Signet rather than calling `initialize` directly after `fork()`. After restoring a live VM snapshot, ensure genuinely fresh unshared OS entropy before initializing.

## Security target, model, and limits

- **Design target:** 128-bit classical security at up to $q = 2^{32}$ imprints per signet (single-query FORS leaf-cover exponent under ideal hashes: **134.5 bits** at $2^{32}$, **128.8 bits** at $2^{33}$, **122.4 bits** at $2^{34}$, **114.9 bits** at $2^{35}$, **106.2 bits** at $2^{36}$; verified by `python3 tools/optimize.py --check`). These are single-key ideal-hash cover estimates, not a complete multi-user or quantum proof of BLINCS.
- **Unenforced budget:** Signet does not count imprints across runs or across copies of a seed. Do not imprint more than $2^{32}$ things with one signet.
- **Memory retention:** `Signet` retains its 32-byte seed, derived keys, and 1 KiB top tree; signing allocates a transient local `SignWorkspace` (~475 KiB for cross-tree FORS batching; ~110 KiB for `from_seed`) freed on return. Neither Signet nor `blake3-servil-core` wipes secret key memory on drop. Verification uses only local stack buffers (zero heap allocation in Signet's code; standalone `#![no_std]` crate `crates/signet-verify` links with zero allocator).

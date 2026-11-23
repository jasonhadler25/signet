# BLINCS specification (draft)

*Status: provisional design under active development (0.1.0, pre-1.0 formats and context strings may still change). Written by an AI assistant at the direction of this repository's owner; no independent cryptographic review or security audit has been performed.*

BLINCS is a stateless hash-based signature scheme built on BLAKE3. A signature is 3,988 bytes, a verifying key is 32 bytes, and a signing key is a 32-byte seed. Its parameters give at least 128 bits of security up to $2^{33}$ signatures (8,589,934,592: ten signatures a second for 27 years) under the SPHINCS+ hypertree and PORS+FP cover-probability model.

Messages are hashed in 256 KiB chunks under a salt the signer picks after seeing the first chunk, reading each chunk twice. Signing and verifying take the message itself — as bytes or a stream — with no pre-hash entry point. Pre-hashing a message before signing makes users vulnerable to collision attacks on the pre-hash; feeding the message or stream to BLINCS relies on second-preimage resistance and hashes at BLAKE3 speed.

All fixed-width integers are unsigned and encoded in little-endian byte order. Concatenation is written `||`, byte slicing `x[a..b]` takes bytes `a` through `b - 1`, and `x[..n]` takes the first `n` bytes.

## Hash primitive

BLINCS uses the three 32-byte modes of BLAKE3:

- `Keyed(K, M)`: BLAKE3 keyed hash with 32-byte key `K` over byte string `M` (32-byte output).
- `Derive(ctx, M)`: BLAKE3 key derivation with UTF-8 context string `ctx` over input `M` (32-byte output).

## Parameters

| Symbol | Value | Meaning |
|---|---:|---|
| `N` | 16 | Byte length of every internal hash value, node, salt, and randomizer |
| `LAYERS` | 4 | Layers of the hypertree (`d`) |
| `TREE_HEIGHT` | 9 | Height of each hypertree tree (`h / d`; total height `HYPER_BITS = 36`, $2^9 = 512$ leaves per tree) |
| `CHAINS` | 24 | WOTS+C chains per one-time signature (`v`) |
| `CHAIN_STEPS` | 31 | Maximum steps per chain (chain length $w = 32$, digits in `0..=31`, 5 bits per digit) |
| `ZERO_BITS` | 8 | Low bits of a WOTS+C message digest required to be zero (`g`) |
| `DIGIT_SUM` | 372 | Required sum of the 24 five-bit WOTS+C digits (`S`; verifier performs `24 * 31 - 372 = 372` chain steps) |
| `FEW_HEIGHT` | 15 | Height of each PORS+FP tree ($2^{15} = 32{,}768$ leaves) |
| `OPENED` | 11 | Distinct leaves opened in a PORS+FP signature (`k`) |
| `AUTH_NODES` | 103 | Maximum authentication nodes in a PORS+FP merged set (`m`) |
| `THRESHOLD_BITS` | 6 | Low bits of a PORS+FP pick digest required to be zero (`g_f`) |
| `CHUNK` | 262,144 | Content chunk size in bytes (256 KiB) |

Derived lengths:

- `FEW_LEN = 4 + N * (OPENED + AUTH_NODES) = 1,828` bytes.
- `LAYER_LEN = 4 + N * (CHAINS + TREE_HEIGHT) = 532` bytes.
- `SIGNATURE_LEN = 2 * N + FEW_LEN + LAYERS * LAYER_LEN = 3,988` bytes.

## Key-derivation contexts

Every derived 32-byte key uses a distinct UTF-8 context string:

| Name | Context string |
|---|---|
| `SECRET_VALUES` | `"BLINCS 2026-11-23 signing key: secret values"` |
| `CONTENT_SALT` | `"BLINCS 2026-11-23 signing key: content salt"` |
| `RANDOMIZER` | `"BLINCS 2026-11-23 signing key: randomizer"` |
| `PUBLIC_SEED` | `"BLINCS 2026-11-23 signing key: public seed"` |
| `PUBLIC_HASH` | `"BLINCS 2026-11-23 public hash"` |
| `CONTENT` | `"BLINCS 2026-11-23 content"` |
| `MIX` | `"BLINCS 2026-11-23 randomness: mix"` |
| `NEXT_SEED` | `"BLINCS 2026-11-23 randomness: seed kept in the file"` |
| `RUN_KEY` | `"BLINCS 2026-11-23 randomness: key of this run"` |

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

Unused fields are zero. The ten kinds are:

| Value | Name | Key | Data appended after tweak | Output bytes used |
|---:|---|---|---|---|
| 1 | `CHAIN_SECRET` | `K_sec` | *(empty)* | 16 |
| 2 | `CHAIN` | `K_pub` | current 16-byte chain value | 16 |
| 3 | `ONE_TIME_KEY` | `K_pub` | 24 chain ends (`384` bytes) | 16 |
| 4 | `ONE_TIME_MESSAGE` | `K_pub` | `node (16) \|\| counter (u32)` | 16 |
| 5 | `NODE` | `K_pub` | `left (16) \|\| right (16)` | 16 |
| 6 | `FEW_SECRET` | `K_sec` | *(empty)* | 16 |
| 7 | `FEW_LEAF` | `K_pub` | 16-byte leaf secret | 16 |
| 8 | `FEW_NODE` | `K_pub` | `left (16) \|\| right (16)` | 16 |
| 9 | `MESSAGE` | `K_pub` | `R (16) \|\| root (16) \|\| short (56)` | 32 |
| 10 | `PICK` | `K_pub` | `D (32) \|\| counter (u32)` | 32 |

Define `ShortHash(K, T, data) = Keyed(K, T || data)[..16]`.

## Keys

A signing key is a 32-byte `seed` supplied by the caller. From `seed`:

```text
K_sec   = Derive(SECRET_VALUES, seed)
K_salt  = Derive(CONTENT_SALT,  seed)
K_R     = Derive(RANDOMIZER,    seed)
pk_seed = Derive(PUBLIC_SEED,   seed)[..16]
K_pub   = Derive(PUBLIC_HASH,   pk_seed)
root    = top hypertree root at layer = LAYERS - 1, tree = 0
```

The 32-byte verifying key is `vk = pk_seed || root`. A verifier derives from `vk`:

```text
K_pub     = Derive(PUBLIC_HASH, vk[..16])
root      = vk[16..32]
K_content = Derive(CONTENT,     vk)
```

## Content

A message `M` of byte length `len` is split into chunks `M_0, M_1, ..., M_{c-1}` of `CHUNK` (262,144) bytes, with the final chunk taking the remaining `1..=CHUNK` bytes. An empty message (`len = 0`) has one empty chunk `M_0 = ""`.

Given a 16-byte content salt `e`:

```text
x_{-1} = 0^32   (32 zero bytes)
for i in 0..c:
    chunk_key_i  = Keyed(K_content, e || u64_le(i) || x_{i-1})
    chunk_salt_i = Keyed(chunk_key_i, M_i)        # first read of chunk i
    x_i          = Keyed(chunk_salt_i, M_i)       # second read of chunk i
short = e || x_{c-1} || u64_le(len)               # 56 bytes
```

When signing with a 32-byte per-signature draw `draw`:

```text
K_e = Keyed(K_salt, draw)
e   = Keyed(K_e, M_0)[..16]
```

## One-time signatures (WOTS+C)

At hypertree position `(layer, tree, leaf)` (`0 <= layer < 4`, `0 <= leaf < 512`):

- Chain `i` (`0 <= i < 24`) starts at:
  `start_i = ShortHash(K_sec, tweak(CHAIN_SECRET, layer, tree, leaf, i, 0), "")`.
- Advancing a chain value `v` from step `s` to step `t` (`0 <= s <= t <= 31`):
  for `step` in `s..t`: `v = ShortHash(K_pub, tweak(CHAIN, layer, tree, leaf, i, step), v)`.
- The leaf's one-time verifying key compresses all 24 chain ends (`step = 31`):
  `pk_leaf = ShortHash(K_pub, tweak(ONE_TIME_KEY, layer, tree, leaf, 0, 0), end_0 || ... || end_23)`.
- The tree over `pk_0, ..., pk_511` combines siblings at `height = 1..=9`, `index = 0..2^(9 - height)`:
  `node(height, index) = ShortHash(K_pub, tweak(NODE, layer, tree, 0, height, index), left || right)`.

To encode a 16-byte `node` with a 32-bit `counter`:

```text
digest = u128_le(ShortHash(K_pub, tweak(ONE_TIME_MESSAGE, layer, tree, leaf, 0, 0), node || u32_le(counter)))
```

`counter` is valid for `(layer, tree, leaf, node)` if and only if:

1. `digest & 0xFF == 0` (the low 8 bits are zero), and
2. taking the 24 five-bit digits `d_i = (digest >> (8 + 5 * i)) & 31` for `i = 0..24`, their sum equals `372`.

The signer finds the smallest `counter` in `0..=u32::MAX` that passes both checks, and outputs `counter` together with each chain advanced `d_i` steps from `start_i` and the 9 sibling nodes along `leaf`'s authentication path (bottom level `height = 0` first).

The verifier checks both conditions for `counter`, advances each signature chain value from `d_i` to `31`, compresses the 24 ends to `pk_leaf`, and climbs the 9 authentication-path nodes (putting the running value on the left when `(leaf >> height) & 1 == 0`, on the right otherwise) to obtain the tree root.

## Few-time signatures (PORS+FP)

Given `short` (56 bytes):

- The signer computes `R = Keyed(K_R, short)[..16]`.
- Signer and verifier both compute the 32-byte (256-bit) message digest:
  `D = Keyed(K_pub, tweak(MESSAGE, 0, 0, 0, 0, 0) || R || root || short)`.
  *(Keeping `D` at 256 bits prevents multi-target collisions across up to $2^{33}$ signed digests.)*

To test a 32-bit `counter`:

```text
g = u256_le(Keyed(K_pub, tweak(PICK, 0, 0, 0, 0, 0) || D || u32_le(counter)))
```

1. The low `THRESHOLD_BITS = 6` bits of `g` must be zero: `g & 63 == 0`.
2. `position = (g >> 6) & ((1 << 36) - 1)` selects the hypertree bottom-layer leaf:
   `tree = position >> 9` (`0..2^27`), `leaf = position & 511` (`0..512`).
3. For `j = 0..11`, extract 15-bit leaf index `raw_j = (g >> (42 + 15 * j)) & 0x7FFF`. Sort them ascending into `indices[0..11]`.
4. All 11 indices must be distinct (`indices[j] < indices[j + 1]` for `j = 0..10`).
5. The merged authentication set `merged_set(indices)` must have at most `AUTH_NODES = 103` nodes.

### Merged authentication set

For sorted distinct `indices` in a perfect binary tree of height `FEW_HEIGHT = 15`:

- Set `known = indices`.
- For `height = 0..15`:
  - Walk `known` left to right with index `i`:
    - If `known[i]` is even and `i + 1 < len(known)` and `known[i + 1] == known[i] + 1`, both children of `known[i] >> 1` are known; advance `i += 2`.
    - Otherwise, record `(height, known[i] ^ 1)` as the next required authentication node; advance `i += 1`.
    - Append `known[i] >> 1` to `parents`.
  - Set `known = parents`.

The recorded `(height, index)` pairs, in that order (bottom level first, left to right within each level), are the merged authentication set.

### Few-time tree

At bottom-layer `(tree, leaf)`:

- Leaf secret `i` (`0 <= i < 32,768`):
  `s_i = ShortHash(K_sec, tweak(FEW_SECRET, 0, tree, leaf, 0, i), "")`.
- Leaf hash `i`:
  `L_i = ShortHash(K_pub, tweak(FEW_LEAF, 0, tree, leaf, 0, i), s_i)`.
- Internal node at `height = 1..=15`, `index = 0..2^(15 - height)`:
  `node(height, index) = ShortHash(K_pub, tweak(FEW_NODE, 0, tree, leaf, height, index), left || right)`.

The signer finds the smallest valid `counter`, builds the tree, and emits `counter`, the 11 secrets `s_{indices[0]}, ..., s_{indices[10]}` in ascending order of `indices`, the `u <= 103` nodes of `merged_set(indices)` in order, and `103 - u` sixteen-byte zero blocks.

The verifier checks all five conditions on `counter`, verifies that the trailing `103 - u` authentication slots are all zero bytes, hashes the 11 secrets into leaves `L_{indices[j]}`, and folds them with the `u` authentication nodes in the same bottom-up left-to-right order to recover the few-time tree root.

## Hypertree and signature layout

Starting from `node` = few-time tree root and `(tree, leaf) = (position >> 9, position & 511)`, for `layer = 0, 1, 2, 3`:

- The signer produces the WOTS+C signature on `node` at `(layer, tree, leaf)` and the 9-node authentication path in tree `(layer, tree)`.
- `node` becomes the root of tree `(layer, tree)`; then `leaf = tree & 511`, `tree = tree >> 9`.

After `layer = 3`, `node` must equal `vk.root` (verified by both signer and verifier).

A signature is 3,988 bytes:

```text
Offset   Length  Field
     0       16  e                  content salt
    16       16  R                  randomizer
    32        4  fts_counter        u32 LE
    36      176  fts_secrets        11 x 16 bytes, for sorted indices[0..11]
   212     1648  fts_auth           103 x 16 bytes (merged set, then zero blocks)
  1860      532  layer 0            u32 counter || 24 x 16 chain values || 9 x 16 path nodes
  2392      532  layer 1            same
  2924      532  layer 2            same
  3456      532  layer 3            same
  Total: 3988 bytes
```

## Signer randomness

The signer needs one fresh 32-byte `draw` per signature without making a system call or waiting on storage on each signature.

A persistent state file is exactly 48 bytes:

```text
Offset  Length  Field
     0       8  magic   ASCII "BLINCSr1"
     8       8  count   u64 LE (starts at 0 on creation; incremented on each initialize)
    16      32  seed    32 bytes
```

- **Creation (`create`)**: creates a new file (refusing to overwrite an existing file), writes `BLINCSr1 || u64_le(0) || os_bytes(32)` where `os_bytes` comes from `/dev/urandom`, and syncs the file and its parent directory once.
- **Startup (`initialize`)**: opens an existing state file, takes an exclusive advisory lock, checks exact length 48 and magic `BLINCSr1`, reads `(count, seed)`, checks `new_count = count + 1` does not overflow, reads 32 bytes from `/dev/urandom` and a single reading of the system's monotonic clock, and computes:
  ```text
  pool      = Derive(MIX,       seed || u64_le(new_count) || os_bytes || clock_bytes)
  next_seed = Derive(NEXT_SEED, pool)
  run_key   = Derive(RUN_KEY,   pool)
  ```
  It overwrites bytes `8..48` (`u64_le(new_count) || next_seed`) in place without calling `fsync`, releases the lock, and keeps `(run_key, sig_count = 0)` in memory.
- **Per signature (`draw`)**: atomically fetches and increments `sig_count` (stopping the program if it would overflow `u64::MAX`) and returns `Keyed(run_key, u64_le(n))`.

The signing key itself is supplied by the caller and is mixed into `e = Keyed(Keyed(K_salt, draw), M_0)[..16]` on every signature. Even if the state file, `/dev/urandom`, and the monotonic clock are all rolled back together so `draw` repeats:

- The signing key is never exposed, and WOTS+C / PORS+FP leaf selection stays unpredictable (`R` is keyed by `K_R` over `short`).
- Single-chunk messages ($\le$ 256 KiB) still rely on second-preimage resistance (`e` depends on `M_0` under secret `K_salt`).
- For multi-chunk messages ($>$ 256 KiB), an attacker who probes a 256 KiB prefix `M_0` and then forces a state reset learns `e` and `chunk_key_1` before submitting a second message with the same `M_0`, reducing chunk 1+ to known-key collision resistance of the two-pass function `Keyed(Keyed(k, m), m)` (still 128 bits generically over its 256-bit output).

## Security assumptions and limits

- BLAKE3 in keyed and key-derivation modes behaves as a PRF and target-collision-resistant hash at 128-bit security.
- A signing key should make at most $2^{33}$ signatures (at $2^{33}$, the PORS+FP cover-probability bound gives 128.4 bits; at $2^{34}$, 124.5 bits; at $2^{36}$, 114.8 bits).
- Signing time depends on how many counter tries the public digest needs (expected 21,642 for `PICK` and 29,209 per hypertree layer for `ONE_TIME_MESSAGE`). Those counters depend on public inputs (`D`, subtree roots), not secret chain values.
- The library does not wipe secret keys from memory on drop (its dependency `blake3-servil-core` does not wipe intermediate state either).

# BLINCS specification (draft)

*Status: pre-1.0 design under active development (0.1.0, formats and context strings may still change before 1.0). Written by an AI assistant at the direction of this repository's owner; no independent cryptographic review or security audit has been performed. Builds on BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn) and SPHINCS / SPHINCS+ / FIPS 205 SLH-DSA (Bernstein, Hopwood, Hülsing, Kölbl, Lange, Niederhagen, Papachristodoulou, Rijneveld, Schneider, Schwabe, Wilcox-O'Hearn, and the NIST SLH-DSA team). Thanks to [Project 11](https://research.projecteleven.com/) — especially **Conor Deegan**, **Alessandro Baiocchi**, **Matteo Vena**, and **Matteo Vicari** — for direct review feedback on this specification, benchmarks, and irregular-hypertree/caching ideas (full credits in [`README.md`](README.md#credits-and-thanks)).*

BLINCS is a stateless hash-based signature scheme built on BLAKE3, combining textbook FIPS 205 **WOTS+** (nibbles, `w = 16`) and **FORS** (`16` trees of `1,024` leaves) on a 4-layer hypertree (`12 + 3×7`, total height `33`) with **zero counter grinding** and single-pass salted content hashing. A signature is **5,616 bytes** (`7,488` bytes Base64 — fitting cleanly under default Apache/nginx 8 KiB HTTP headers), a verifying key is **32 bytes**, and a signing key is a **32-byte seed**. Its parameters target **133.2 bits** of classical security at up to **$2^{32}$ signatures** per signing key (4,294,967,296: ten signatures a second for 13.6 years) under the SPHINCS+ / FIPS 205 FORS cover-probability model, degrading gracefully past the budget (`126.8` bits at $2^{33}$, `119.3` bits at $2^{34}$).

Messages are hashed in a single salted keyed-BLAKE3 pass under a fresh per-signature salt `e` derived from the signer's key and per-signature randomness. Signing and verifying take the message itself — as bytes or a stream — with no pre-hash entry point. Pre-hashing a message before signing makes users vulnerable to collision attacks on the pre-hash; feeding the message or stream directly to BLINCS avoids that exposure and runs at full BLAKE3 speed.

All fixed-width integers are unsigned and encoded in little-endian byte order. Ranges written `a..b` are half-open `[a, b)` and `a..=b` are closed `[a, b]`. Concatenation is written `||`, byte slicing `x[a..b]` takes bytes `a` through `b - 1`, and `x[..n]` takes the first `n` bytes. Maximum message length is $2^{64} - 1$ bytes.

## Hash primitive

BLINCS uses two 32-byte modes of BLAKE3:

- `Keyed(K, M)`: BLAKE3 keyed hash with 32-byte key `K` over byte string `M` (32-byte output).
- `Derive(ctx, M)`: BLAKE3 key derivation with UTF-8 context string `ctx` over input `M` (32-byte output).

## Parameters

| Symbol | Value | Meaning |
|---|---:|---|
| `N` | 16 | Byte length of truncated tree, chain, salt, and randomizer values (`h_msg`, `D`, and derived keys are 32 bytes) |
| `LAYERS` | 4 | Layers of the hypertree (`d`) |
| `LOWER_HEIGHT` | 7 | Height of lower hypertree layers `0, 1, 2` ($2^7 = 128$ leaves per tree) |
| `TOP_HEIGHT` | 12 | Height of top hypertree layer `3` ($2^{12} = 4{,}096$ leaves; total `HYPER_BITS = 12 + 3 * 7 = 33`) |
| `W` | 16 | WOTS+ Winternitz parameter (`CHAIN_STEPS = 15`, 4-bit nibbles in `0..=15`) |
| `MSG_CHAINS` | 32 | WOTS+ message chains (`128 / 4 = 32` nibbles) |
| `CSUM_CHAINS` | 3 | WOTS+ checksum chains (`max checksum = 32 * 15 = 480 < 16^3`) |
| `CHAINS` | 35 | Total WOTS+ chains per one-time signature (`32 + 3`) |
| `FORS_HEIGHT` | 10 | Height of each FORS tree ($2^{10} = 1{,}024$ leaves per tree) |
| `FORS_TREES` | 16 | Number of independent FORS trees (`k`; `16 * 10 = 160` bits) |

Derived lengths:

- `FORS_LEN = FORS_TREES * (1 + FORS_HEIGHT) * N = 2,816` bytes.
- `LOWER_LAYER_LEN = (CHAINS + LOWER_HEIGHT) * N = 672` bytes.
- `TOP_LAYER_LEN = (CHAINS + TOP_HEIGHT) * N = 752` bytes.
- `SIGNATURE_LEN = 2 * N + FORS_LEN + 3 * LOWER_LAYER_LEN + TOP_LAYER_LEN = 5,616` bytes.

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
| 8 | `FEW_ROOT` | `K_pub` | 16 FORS tree roots (`256` bytes) | 16 |
| 9 | `MESSAGE` | `K_pub` | `R (16) \|\| root (16) \|\| short (48)` | 32 |

Define `ShortHash(K, T, data) = Keyed(K, T || data)[..16]`.

## Keys

A signing key is a 32-byte `seed` supplied by the caller. From `seed`:

```text
K_sec   = Derive(SECRET_VALUES, seed)
K_salt  = Derive(CONTENT_SALT,  seed)
K_R     = Derive(RANDOMIZER,    seed)
pk_seed = Derive(PUBLIC_SEED,   seed)[..16]
K_pub   = Derive(PUBLIC_HASH,   pk_seed)
root    = top hypertree root at layer = 3, tree = 0 (height 12, 4,096 leaves)
```

The 32-byte verifying key is `vk = pk_seed || root`. A verifier derives from `vk`:

```text
K_pub     = Derive(PUBLIC_HASH, vk[..16])
root      = vk[16..32]
K_content = Derive(CONTENT,     vk)
```

## Content

When signing with a 32-byte per-signature draw `draw`:

```text
e = Keyed(K_salt, draw)[..16]                     # 16-byte per-signature content salt
```

Given the 16-byte content salt `e` and message `M` (any length in `0..2^64`):

```text
K_msg = Keyed(K_content, e)                       # 32-byte per-signature message key
h_msg = Keyed(K_msg, M)                           # 32-byte keyed BLAKE3 hash of M (single pass)
short = e || h_msg                                # 48 bytes
```

Because BLAKE3 authenticates exact message length internally, `Keyed(K_msg, M)` is length-authenticated and prefix-free across all message lengths in a single streaming pass with no chunking layer.

## Message digest and index extraction

Given `short` (48 bytes):

- The signer computes `R = Keyed(K_R, short)[..16]`.
- Signer and verifier both compute the 32-byte (256-bit) message digest:
  `D = Keyed(K_pub, tweak(MESSAGE, 0, 0, 0, 0, 0) || R || root || short)`.
  *(Keeping `D` at 256 bits prevents multi-target collisions across up to $2^{32}$ signed digests.)*
- Extract the 16 FORS leaf indices and 33-bit hypertree leaf address directly from `D` (no counter grinding):
  - `fors_bits = u160_le(D[0..20])`; for `t = 0..16`, `idx[t] = (fors_bits >> (10 * t)) & 0x3FF` (`0..1024`).
  - `leaf_addr = u64_le(D[20..28]) & ((1 << 33) - 1)` (`0..2^33`).

## Few-time signatures (FORS)

At hypertree bottom-layer leaf address `leaf_addr` (`0 <= leaf_addr < 2^33`), for each tree `t` in `0..16`:

- Leaf secret `i` (`0 <= i < 1024`):
  `s_{t,i} = ShortHash(K_sec, tweak(FEW_SECRET, 0, leaf_addr, t, 0, i), "")`.
- Leaf hash `i`:
  `L_{t,i} = ShortHash(K_pub, tweak(FEW_LEAF, 0, leaf_addr, t, 0, i), s_{t,i})`.
- Internal node at `height = 1..=10`, `index = 0..2^(10 - height)`:
  `node(t, height, index) = ShortHash(K_pub, tweak(FEW_NODE, 0, leaf_addr, t, height, index), left || right)`.
- The FORS root compresses all 16 tree roots (`height = 10`, `index = 0`):
  `fors_root = ShortHash(K_pub, tweak(FEW_ROOT, 0, leaf_addr, 0, 0, 0), root_0 || ... || root_15)`.

For each `t = 0..16`, the signer emits `s_{t, idx[t]}` followed by the 10 sibling nodes along `idx[t]`'s authentication path (bottom level `height = 0` first). The verifier hashes each secret to `L_{t, idx[t]}`, climbs the 10 authentication nodes (putting the running value on the left when `(idx[t] >> height) & 1 == 0`, on the right otherwise) to obtain `root_t`, and compresses `root_0 || ... || root_15` to `fors_root`.

## One-time signatures (WOTS+)

At hypertree position `(layer, tree, leaf)` (`height = 7` for `layer in 0..3`, `height = 12` for `layer = 3`):

- Chain `c` (`0 <= c < 35`) starts at:
  `start_c = ShortHash(K_sec, tweak(CHAIN_SECRET, layer, tree, leaf, c, 0), "")`.
- Advancing a chain value `v` from step `s` to step `t` (`0 <= s <= t <= 15`):
  for `step` in `s..t`: `v = ShortHash(K_pub, tweak(CHAIN, layer, tree, leaf, c, step), v)`.
- The leaf's one-time verifying key compresses all 35 chain ends (`step = 15`):
  `pk_leaf = ShortHash(K_pub, tweak(ONE_TIME_KEY, layer, tree, leaf, 0, 0), end_0 || ... || end_34)`.
- The tree over `pk_0, ..., pk_{2^height - 1}` combines siblings at `level = 1..=height`, `index = 0..2^(height - level)`:
  `node(level, index) = ShortHash(K_pub, tweak(NODE, layer, tree, 0, level, index), left || right)`.

To encode a 16-byte `node` into 35 nibble digits `d[0..35]` (each in `0..=15`):

```text
for i in 0..16:
    d[2 * i]     = node[i] & 0x0F
    d[2 * i + 1] = node[i] >> 4
csum = sum_{j=0}^{31} (15 - d[j])            # in 0..=480
d[32] =  csum       & 0x0F
d[33] = (csum >> 4) & 0x0F
d[34] = (csum >> 8) & 0x0F
```

The signer advances each chain `c` from `0` to `d[c]` and emits the 35 chain values followed by the `height` sibling nodes along `leaf`'s authentication path (bottom level `0` first). The verifier advances each signature chain value from `d[c]` to `15`, compresses the 35 ends to `pk_leaf`, and climbs the `height` authentication nodes to obtain the tree root.

## Hypertree and signature layout

Starting from `node = fors_root` and `addr = leaf_addr`, for `layer = 0, 1, 2, 3`:

- Let `height = 12` if `layer == 3`, else `7`.
- Let `leaf = addr & ((1 << height) - 1)` and `tree = addr >> height`.
- The signer produces the WOTS+ signature on `node` at `(layer, tree, leaf)` and the `height`-node authentication path in tree `(layer, tree)`.
- `node` becomes the root of tree `(layer, tree)`; then `addr = tree`.

After `layer = 3`, `node` must equal `vk.root` (verified in constant time by both signer and verifier).

A signature is 5,616 bytes:

```text
Offset   Length  Field
     0       16  e                  content salt
    16       16  R                  randomizer
    32     2816  fors               16 trees x (16 B secret || 10 x 16 B auth path)
  2848      672  layer 0 (h=7)      35 x 16 B WOTS+ values ||  7 x 16 B auth path
  3520      672  layer 1 (h=7)      35 x 16 B WOTS+ values ||  7 x 16 B auth path
  4192      672  layer 2 (h=7)      35 x 16 B WOTS+ values ||  7 x 16 B auth path
  4864      752  layer 3 (h=12)     35 x 16 B WOTS+ values || 12 x 16 B auth path
  Total: 5616 bytes
```

## Signer randomness (local policy)

The wire format and verification rules above depend only on `e`, not on how the signer chose `draw`. The Rust crate implements the following local randomness policy so signing needs no per-signature disk write or clock read.

A persistent state file is exactly 48 bytes:

```text
Offset  Length  Field
     0       8  magic   ASCII "BLINCSr1"
     8       8  count   u64 LE (starts at 0 on creation; incremented on each initialize)
    16      32  seed    32 bytes
```

- **Creation (`create`)**: creates a new file (refusing to overwrite an existing file; mode `0600` on Unix, subject to umask), writes `BLINCSr1 || u64_le(0) || os_bytes(32)` where `os_bytes` comes from `/dev/urandom`, and syncs the file and its parent directory once. Provision the file before starting signers; do not race `create` against `initialize`.
- **Startup (`initialize`)**: opens an existing state file in a private local directory owned by the signer, takes an exclusive advisory lock (`flock`), checks exact length 48 and magic `BLINCSr1`, reads `(count, seed)`, checks `new_count = count + 1` does not overflow, reads 32 bytes from `/dev/urandom` and opaque local diversification bytes `clock_bytes` from the system's monotonic clock (`Instant::hash` in Rust; not a portable time encoding), and computes:
  ```text
  pool      = Derive(MIX,       seed || u64_le(new_count) || os_bytes || clock_bytes)
  next_seed = Derive(NEXT_SEED, pool)
  run_key   = Derive(RUN_KEY,   pool)
  ```
  It overwrites bytes `8..48` (`u64_le(new_count) || next_seed`) in place without calling `fsync`, releases the lock, and keeps `(run_key, sig_count = 0)` in memory.
- **Per signature (`draw`)**: atomically fetches and increments `sig_count` (`0..u64::MAX`, panicking if exhausted so it never wraps) and returns `Keyed(run_key, u64_le(n))`.
- **Fork and live snapshots**: `Randomness` ensures distinct draws within one process instance. After `fork()` or restoring a live process or VM snapshot, call `initialize` again so cloned images do not repeat `(run_key, sig_count)`.
- **Path trust boundary**: `initialize` follows symlinks and relies on cooperating writers using compatible advisory locks on a local filesystem. Keep the state file in a private trusted directory.

Even if the state file, `/dev/urandom`, and the monotonic clock are all rolled back together so `draw` repeats identically:

- The signing key is never leaked, and `R = Keyed(K_R, e || h_msg)[..16]` still prevents WOTS+ reuse or FORS leaf steering on distinct messages; only content hashing downgrades from second-preimage resistance to 128-bit known-key collision resistance of single-pass 256-bit keyed BLAKE3 `Keyed(K_msg, M)`.

## Security target, model, and limits

- **FORS cover-probability bound (FIPS 205 / SPHINCS+ model, classical ROM):** over $q$ signatures with hypertree height $h = 33$, $k = 16$ FORS trees, and $t = 2^{10} = 1{,}024$ leaves per tree, the probability that a single adversary query lands on a hypertree leaf hit $r$ times and finds all $k$ selected leaves already revealed is:
  $$P(q) = \sum_{r=0}^{q} \binom{q}{r} 2^{-hr} \left(1 - 2^{-h}\right)^{q-r} \left(1 - (1 - 2^{-a})^r\right)^k.$$
  Evaluating $-\log_2 P(q)$ gives **133.2 bits** at $q = 2^{32}$, **126.8 bits** at $2^{33}$, **119.3 bits** at $2^{34}$, and **110.5 bits** at $2^{35}$. This follows the textbook FIPS 205 (SLH-DSA) WOTS+ and FORS security structure; a complete concrete proof accounting for every hash term, multi-key targets, quantum queries, and the BLAKE3 tweakable-hash instantiation has not been independently audited.
- **Zero counter grinding & deterministic work:** signing performs the exact same tree and chain work on every signature, with no counter search, no rejection sampling, and no tail-latency spikes.
- **Operational signing budget:** the $2^{32}$ per-signing-key budget is an operational requirement not enforced by the library (the state-file counter counts startups, and `Randomness` counts draws in one instance, not total signatures across copies of a seed).
- **Memory retention:** `SigningKey` retains its 32-byte seed and derived keys, and each worker thread keeps reusable scratch buffers that retain intermediate leaf secrets for the thread's lifetime. Neither BLINCS nor `blake3-servil` wipes secret key memory on drop. Streaming readers use a fresh local zero-initialized 64 KiB stack buffer (for streams $\le 64$ KiB) or a fresh per-call `Pipeline` (for streams $> 64$ KiB) with no shared cross-caller buffer pool.
- **Self-check on signing:** in Rust, `SigningKey::sign` / `sign_reader` runs `VerifyingKey::verify_short` over the assembled signature before returning it, independently recomputing the FORS and hypertree paths against `vk.root` (it does not re-read external streams).

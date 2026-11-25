# BLINCS specification (draft)

*Status: pre-1.0 design under active development (0.1.0, formats and context strings may still change before 1.0). Written by an AI assistant at the direction of this repository's owner; no independent cryptographic review or security audit has been performed. Builds on BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn) and SPHINCS / SPHINCS+ / FIPS 205 SLH-DSA (Bernstein, Hopwood, Hülsing, Kölbl, Lange, Niederhagen, Papachristodoulou, Rijneveld, Schneider, Schwabe, Wilcox-O'Hearn, and the NIST SLH-DSA team). Thanks to [Project 11](https://research.projecteleven.com/) — especially **Conor Deegan**, **Alessandro Baiocchi**, **Matteo Vena**, and **Matteo Vicari** — for direct review feedback, benchmarks, and constrained-device design inspiration (full credits in [`README.md`](README.md#credits-and-thanks)).*

BLINCS is a stateless hash-based signature scheme based on BLAKE3 and SPHINCS, using a **WOTS+** (nibbles, `w = 16`) and **FORS** (`13` trees of `2,048` leaves) structure on a uniform 5-layer hypertree (`5×7`, total height `35`) with **zero counter grinding** and single-pass salted content hashing (BLINCS-specific nibble/tweak encodings and BLAKE3 instantiation; not FIPS 205 interoperable or validated). An imprint is **5,888 bytes** (`7,852` bytes Base64 — fitting under default Apache/nginx 8 KiB HTTP headers), a `SignetId` is **32 bytes**, and a `Signet` derives from a **32-byte seed** (holding a 4 KiB top tree in memory). Its design target is **128-bit classical security** (128-bit root) at up to **$2^{32}$ imprints** per signet (4,294,967,296: ten imprints a second for 13.6 years), with an estimated single-query FORS cover exponent of **132.5 bits** at $q = 2^{32}$, degrading gradually past the budget (`128.5` bits at $2^{33}$, `123.8` bits at $2^{34}$, `118.3` bits at $2^{35}$, `111.9` bits at $2^{36}$).

Messages are hashed in a single salted keyed-BLAKE3 pass under a fresh per-imprint salt `e` derived from the signet and per-imprint randomness before reading the message. Pass the original message bytes or stream directly to BLINCS so the entire input is covered by the salted pass at full BLAKE3 streaming speed without relying on unsalted collision resistance.

All fixed-width integers are unsigned and encoded in little-endian byte order. Ranges written `a..b` are half-open `[a, b)` and `a..=b` are closed `[a, b]`. Concatenation is written `||`, byte slicing `x[a..b]` takes bytes `a` through `b - 1`, and `x[..n]` takes the first `n` bytes. Maximum message length is $2^{64} - 1$ bytes.

## Hash primitive

BLINCS uses two 32-byte modes of BLAKE3:

- `Keyed(K, M)`: BLAKE3 keyed hash with 32-byte key `K` over byte string `M` (32-byte output).
- `Derive(ctx, M)`: BLAKE3 key derivation with UTF-8 context string `ctx` over input `M` (32-byte output).

## Parameters

| Symbol | Value | Meaning |
|---|---:|---|
| `N` | 16 | Byte length of truncated tree, chain, salt, and randomizer values (`h_msg`, `D`, and derived keys are 32 bytes) |
| `LAYERS` | 5 | Uniform layers of the hypertree (`d`) |
| `TREE_HEIGHT` | 7 | Height of every hypertree layer `0..5` ($2^7 = 128$ leaves per tree; total `HYPER_BITS = 5 * 7 = 35`) |
| `W` | 16 | WOTS+ Winternitz parameter (`CHAIN_STEPS = 15`, 4-bit nibbles in `0..=15`) |
| `MSG_CHAINS` | 32 | WOTS+ message chains (`128 / 4 = 32` nibbles) |
| `CSUM_CHAINS` | 3 | WOTS+ checksum chains (`max checksum = 32 * 15 = 480 < 16^3`) |
| `CHAINS` | 35 | Total WOTS+ chains per one-time signature (`32 + 3`) |
| `FORS_HEIGHT` | 11 | Height of each FORS tree ($2^{11} = 2{,}048$ leaves per tree) |
| `FORS_TREES` | 13 | Number of independent FORS trees (`k`; `13 * 11 = 143` bits) |

Derived lengths:

- `FORS_LEN = FORS_TREES * (1 + FORS_HEIGHT) * N = 2,496` bytes.
- `LAYER_LEN = (CHAINS + TREE_HEIGHT) * N = 672` bytes (identical on all 5 layers).
- `IMPRINT_LEN = 2 * N + FORS_LEN + LAYERS * LAYER_LEN = 5,888` bytes.

## Key-derivation contexts

Every derived 32-byte key uses a distinct UTF-8 context string:

| Name | Context string |
|---|---|
| `SECRET_VALUES` | `"BLINCS 2026-11-25 signet: secret values"` |
| `CONTENT_SALT` | `"BLINCS 2026-11-25 signet: content salt"` |
| `RANDOMIZER` | `"BLINCS 2026-11-25 signet: randomizer"` |
| `PUBLIC_SEED` | `"BLINCS 2026-11-25 signet: public seed"` |
| `GENERATE_SIGNET` | `"BLINCS 2026-11-25 signet: generate"` |
| `PUBLIC_HASH` | `"BLINCS 2026-11-25 public hash"` |
| `CONTENT` | `"BLINCS 2026-11-25 content"` |
| `MIX` | `"BLINCS 2026-11-25 randomness: mix"` |
| `FILE_ID` | `"BLINCS 2026-11-25 randomness: file id"` |
| `NEXT_SEED` | `"BLINCS 2026-11-25 randomness: next seed"` |
| `RUN_KEY` | `"BLINCS 2026-11-25 randomness: key of this run"` |
| `KEYGEN_KEY` | `"BLINCS 2026-11-25 randomness: keygen key"` |

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
| 8 | `FEW_ROOT` | `K_pub` | 16 × 13 FORS tree roots (`208` bytes) | 16 |
| 9 | `MESSAGE` | `K_pub` | `R (16) \|\| root (16) \|\| short (48)` | 32 |

Define `ShortHash(K, T, data) = Keyed(K, T || data)[..16]`.

## Signet and SignetId

A `Signet` is derived from a 32-byte `seed`:

```text
K_sec   = Derive(SECRET_VALUES, seed)
K_salt  = Derive(CONTENT_SALT,  seed)
K_R     = Derive(RANDOMIZER,    seed)
pk_seed = Derive(PUBLIC_SEED,   seed)[..16]
K_pub   = Derive(PUBLIC_HASH,   pk_seed)
root    = top hypertree root at layer = 4, tree = 0 (height 7, 128 leaves)
```

The 32-byte signet identifier (`SignetId`) is `id = pk_seed || root`. A verifier derives from `id`:

```text
K_pub     = Derive(PUBLIC_HASH, id[..16])
root      = id[16..32]
K_content = Derive(CONTENT,     id)
```

## Content

When imprinting with a 32-byte per-imprint draw `draw`:

```text
e = Keyed(K_salt, draw)[..16]                     # 16-byte per-imprint content salt
```

Given the 16-byte content salt `e` and message `M` (any length in `0..2^64`):

```text
K_msg = Keyed(K_content, e)                       # 32-byte per-imprint message key (public once e is known)
h_msg = Keyed(K_msg, M)                           # 32-byte keyed BLAKE3 hash of M (single pass)
short = e || h_msg                                # 48 bytes
```

BLAKE3 commits to message length under its standard hash assumptions, and `K_msg` is derived from both `id` (via `K_content`) and the fresh per-imprint salt `e`.

## Message digest and index extraction

The signer computes the deterministic per-imprint randomizer and 32-byte digest `D`:

```text
R = Keyed(K_R, short)[..16]
D = Keyed(K_pub, tweak(MESSAGE, 0, 0, 0, 0, 0) || R || root || short)
```

From `D` (32 bytes):

- **FORS leaf indices** `indices[0..13]`: view `D[0..18]` as a 144-bit little-endian unsigned integer; for `t in 0..13`, `indices[t] = (u144(D[0..18]) >> (11 * t)) & 0x7ff` (each in `0..2048`; bit 143 and bytes `D[18..20]` are unused).
- **Hypertree leaf address** `leaf_addr`: low 35 bits of `u64_le(D[20..28])`, i.e., `u64_le(D[20..28]) & ((1 << 35) - 1)` (the remaining high bits of `D[24..32]` are unused).

## Few-time signatures (FORS)

At hypertree address `leaf_addr` (`0..2^35`), FORS consists of `FORS_TREES = 13` independent binary Merkle trees, each of height `FORS_HEIGHT = 11` (`2,048` leaves):

- For tree `t in 0..13` and leaf `i in 0..2048`:
  - `secret[t][i] = ShortHash(K_sec, tweak(FEW_SECRET, 0, leaf_addr, t, 0, i), empty)`
  - `leaf[t][i]   = ShortHash(K_pub, tweak(FEW_LEAF,   0, leaf_addr, t, 0, i), secret[t][i])`
- Internal node at height `level in 1..=11`, index `p in 0..(2048 >> level)`:
  - `node = ShortHash(K_pub, tweak(FEW_NODE, 0, leaf_addr, t, level, p), left || right)`
- The 13 tree roots `root[0..13]` are compressed into the 16-byte FORS root:
  - `fors_root = ShortHash(K_pub, tweak(FEW_ROOT, 0, leaf_addr, 0, 0, 0), root[0] || ... || root[12])`

The FORS section of the imprint (`2,496` bytes) is the concatenation for `t = 0..13` of:
`secret[t][indices[t]]` (16 bytes) followed by its 11 authentication-path siblings from leaf level `0` up to level `10` (`176` bytes). On verification, at each level `h in 0..11`, if bit `h` of `indices[t]` is `0`, `cur` is the left child and `auth[h]` is the right child; otherwise `auth[h]` is left and `cur` is right, hashed with `tweak(FEW_NODE, 0, leaf_addr, t, h + 1, indices[t] >> (h + 1))`.

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

The hypertree has `5` uniform layers (`layer = 0, 1, 2, 3, 4`), each of height `TREE_HEIGHT = 7` (`128` leaves per tree):

- Starting with `addr = leaf_addr` and `node = fors_root`:
  - For `layer = 0..5`:
    - `leaf = addr & 0x7f` (`7` low bits)
    - `tree = addr >> 7` (at `layer = 4`, `tree == 0`)
    - Sign `node` with WOTS+ at `(layer, tree, leaf)` (`35 * 16 = 560` bytes) and append the `7` Merkle authentication-path siblings from leaf level `0` up to level `6` (`112` bytes), using `tweak(NODE, layer, tree, 0, level, p)` for `level in 1..=7`.
    - On verification, at each `level in 1..=7`, if bit `level - 1` of `leaf` is `0`, `cur` is the left child and `auth[level - 1]` is right; otherwise `auth[level - 1]` is left and `cur` is right, hashed with `tweak(NODE, layer, tree, 0, level, leaf >> level)`.
    - Set `node = tree_root` and `addr = tree`.
- Verification succeeds iff the reconstructed layer-4 root equals `id[16..32]` in constant time.

Wire layout of an `Imprint` (`5,888` bytes):

```text
0..16        salt e (16 B)
16..32       randomizer R (16 B)
32..2528     FORS: 13 trees x (16 B secret + 11 x 16 B auth path) = 2,496 B
2528..3200   Layer 0: 35 x 16 B WOTS+ + 7 x 16 B auth path = 672 B
3200..3872   Layer 1: 35 x 16 B WOTS+ + 7 x 16 B auth path = 672 B
3872..4544   Layer 2: 35 x 16 B WOTS+ + 7 x 16 B auth path = 672 B
4544..5216   Layer 3: 35 x 16 B WOTS+ + 7 x 16 B auth path = 672 B
5216..5888   Layer 4: 35 x 16 B WOTS+ + 7 x 16 B auth path = 672 B
```

## Signer randomness (local policy)

The wire format does not depend on how the signer chooses `draw`; the scheme below is BLINCS's local host policy for keeping `draw` non-repeating across restarts without file locking (`flock`).

State lives in a private directory (created once with `Randomness::create`, `0700` on Unix) containing one or more regular files named `blincs-r2-<32 lowercase hex chars>`, each holding `0..=32` raw bytes:

1. **State mixing (`mix_pool` and `expand_pool`):**
   Given sorted seed file contents `s_0, ..., s_{m-1}` (each `len <= 32`), 32 bytes `system` from OS cryptographic randomness (`getrandom(2)` / `getentropy`), and opaque `clock` bytes from the monotonic clock:
   ```text
   material   = (u8(len(s_0)) || s_0) || ... || (u8(len(s_{m-1})) || s_{m-1}) || 0xff || system || clock
   pool       = Derive(MIX,        material)
   file_id    = Derive(FILE_ID,    pool)[..16]    # filename only; reveals zero bits of secrets below
   next_seed  = Derive(NEXT_SEED,  pool)          # 32 bytes written inside blincs-r2-<hex(file_id)>
   run_key    = Derive(RUN_KEY,    pool)          # in-memory key for per-imprint draws
   keygen_key = Derive(KEYGEN_KEY, pool)          # in-memory key for Signet::generate
   ```
2. **Lock-free directory update (`Randomness::initialize`):**
   Read all `blincs-r2-<32hex>` regular files in the directory (rejecting unexpected entries, symlinks, files `> 32` bytes, or an empty directory without modifying anything). Compute `pool`, and create `blincs-r2-<hex(file_id)>` with `O_CREAT | O_EXCL` (`0600`) writing `next_seed` (no `fsync`). If `AlreadyExists` occurs, advance `pool = Derive(MIX, pool)` and retry. After writing the new file, unlink the old filenames that were read (ignoring `NotFound`).
3. **Per-imprint draw and signet generation:**
   Each `draw` or `generate` increments an in-memory 64-bit counter `n` (panicking before overflow):
   - Imprint draw: `draw = Keyed(run_key, u64_le(n))`.
   - New signet generation (`Signet::generate`): `seed = Derive(GENERATE_SIGNET, Keyed(keygen_key, u64_le(n)) || os_getrandom_32)`.
4. **Fork and live VM snapshots:** after `fork()` (without `exec()`) or restoring a live VM snapshot, call `Randomness::initialize` again so cloned processes or images do not repeat `(run_key, n)`.

## Security target, model, and limits

- **Design target:** 128-bit classical security at up to $q = 2^{32}$ imprints per signet (single-query FORS leaf-cover exponent under ideal hashes: **132.5 bits** at $2^{32}$, **128.5 bits** at $2^{33}$, **123.8 bits** at $2^{34}$, **118.3 bits** at $2^{35}$, **111.9 bits** at $2^{36}$; verified by `python3 tools/optimize.py --check`). These are single-key ideal-hash cover estimates, not a complete multi-user or quantum proof of BLINCS.
- **Unenforced budget:** BLINCS does not count imprints across runs or across copies of a seed. Do not imprint more than $2^{32}$ things with one signet.
- **Memory retention:** `Signet` retains its 32-byte seed, derived keys, and 4 KiB top tree; signing allocates a transient local `SignWorkspace` freed on return. Neither BLINCS nor `blake3-servil-core` wipes secret key memory on drop. Verification uses only local stack buffers (zero heap allocation). Streaming readers use a fresh local zero-initialized 16 KiB stack buffer, zeroing each slice before calling `Read::read`.

use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience, initialize};

/// Permanent suite identifier for this BLINCS parameter set (`7×5`, `U-FORS(3, 10, 16, 64, 5, 15)`, 2³² budget).
pub const SUITE_NAME: &str = "BLINCS-128-7x5";
/// Byte length of a [`crate::Signet`] secret seed (`32` bytes).
pub const SEED_LEN: usize = 32;
/// Byte length of a [`crate::SignetId`] wire encoding (`32` bytes: `public_seed || top_root`).
pub const SIGNET_ID_LEN: usize = 32;
/// Maximum byte length of a [`crate::Context`] application domain tag (`255` bytes).
pub const MAX_CONTEXT_LEN: usize = 255;

pub(crate) const N: usize = 16;
pub(crate) const LAYERS: usize = 7;
pub(crate) const TREE_HEIGHT: usize = 5;
pub(crate) const TREE_LEAVES: usize = 1 << TREE_HEIGHT;

pub(crate) const W: usize = 16;
pub(crate) const CHAIN_STEPS: u8 = 15;
pub(crate) const MSG_CHAINS: usize = 2 * N;
pub(crate) const CSUM_CHAINS: usize = 3;
pub(crate) const CHAINS: usize = MSG_CHAINS + CSUM_CHAINS;

pub(crate) const UFORS_TREES: usize = 15;
pub(crate) const UFORS_CHAINS: usize = 3;
pub(crate) const UFORS_W: usize = 10;
pub(crate) const UFORS_STEPS: u8 = 9;
pub(crate) const UFORS_SUM: usize = 16;
pub(crate) const UFORS_CODE_BITS: usize = 6;
pub(crate) const UFORS_LAYER_BASE: u8 = 0x80;
pub(crate) const UFORS_TOTAL_LEAVES: usize = UFORS_TREES * TREE_LEAVES;
pub(crate) const UFORS_TOTAL_CHAINS: usize = UFORS_TOTAL_LEAVES * UFORS_CHAINS;
pub(crate) const HYPER_BITS: usize = LAYERS * TREE_HEIGHT;

pub(crate) const SHORT_LEN: usize = N + 32;
pub(crate) const UFORS_TREE_LEN: usize = (UFORS_CHAINS + TREE_HEIGHT) * N;
pub(crate) const UFORS_LEN: usize = UFORS_TREES * UFORS_TREE_LEN;
pub(crate) const LAYER_LEN: usize = (CHAINS + TREE_HEIGHT) * N;
/// Byte length of a BLINCS-128-7x5 [`crate::Imprint`] (`6,432` bytes).
pub const IMPRINT_LEN: usize = 2 * N + UFORS_LEN + LAYERS * LAYER_LEN;

const _: () = {
    assert!(W == (CHAIN_STEPS as usize) + 1 && CHAINS == 35 && MSG_CHAINS * 4 == N * 8);
    assert!(UFORS_W == (UFORS_STEPS as usize) + 1 && UFORS_CHAINS == 3 && UFORS_SUM == 16 && 16 + UFORS_CHAINS * N == 64);
    assert!(UFORS_TREES * (TREE_HEIGHT + UFORS_CODE_BITS) + HYPER_BITS == 200 && HYPER_BITS == 35 && HYPER_BITS < 48);
    assert!(LAYERS <= (UFORS_LAYER_BASE as usize) && (UFORS_LAYER_BASE as usize) + UFORS_TREES < 256);
    assert!(UFORS_TOTAL_LEAVES == 480 && UFORS_TOTAL_CHAINS == 1440 && UFORS_LEN == 1920 && LAYER_LEN == 640);
    assert!(IMPRINT_LEN == 6432 && 2 * N + UFORS_LEN + 7 * LAYER_LEN == IMPRINT_LEN && UFORS_CODE.len() == 64);
};

/// Canonical 64-entry upper-layer constant-sum extreme-variance code in `{0..=9}^3` with sum `16` (`SPEC.md`).
pub(crate) const UFORS_CODE: [[u8; UFORS_CHAINS]; 1 << UFORS_CODE_BITS] = [
    [0, 7, 9],
    [0, 8, 8],
    [0, 9, 7],
    [1, 6, 9],
    [1, 7, 8],
    [1, 8, 7],
    [1, 9, 6],
    [2, 5, 9],
    [2, 6, 8],
    [2, 7, 7],
    [2, 8, 6],
    [2, 9, 5],
    [3, 4, 9],
    [3, 5, 8],
    [3, 6, 7],
    [3, 7, 6],
    [3, 8, 5],
    [3, 9, 4],
    [4, 3, 9],
    [4, 4, 8],
    [4, 5, 7],
    [4, 7, 5],
    [4, 8, 4],
    [4, 9, 3],
    [5, 2, 9],
    [5, 3, 8],
    [5, 4, 7],
    [5, 7, 4],
    [5, 8, 3],
    [5, 9, 2],
    [6, 1, 9],
    [6, 2, 8],
    [6, 3, 7],
    [6, 6, 4],
    [6, 7, 3],
    [6, 8, 2],
    [6, 9, 1],
    [7, 0, 9],
    [7, 1, 8],
    [7, 2, 7],
    [7, 3, 6],
    [7, 4, 5],
    [7, 5, 4],
    [7, 6, 3],
    [7, 7, 2],
    [7, 8, 1],
    [7, 9, 0],
    [8, 0, 8],
    [8, 1, 7],
    [8, 2, 6],
    [8, 3, 5],
    [8, 4, 4],
    [8, 5, 3],
    [8, 6, 2],
    [8, 7, 1],
    [8, 8, 0],
    [9, 0, 7],
    [9, 1, 6],
    [9, 2, 5],
    [9, 3, 4],
    [9, 4, 3],
    [9, 5, 2],
    [9, 6, 1],
    [9, 7, 0],
];

// Key-derivation contexts (SPEC.md, "Key-derivation contexts").
// Algorithm contexts bind SUITE_NAME ("BLINCS-128-7x5") so suites never share derived keys.
pub(crate) const CTX_SECRET_VALUES: &str = "BLINCS-128-7x5 2026-11-26 secret values";
pub(crate) const CTX_CONTENT_SALT: &str = "BLINCS-128-7x5 2026-11-26 content salt";
pub(crate) const CTX_RANDOMIZER: &str = "BLINCS-128-7x5 2026-11-26 randomizer";
pub(crate) const CTX_PUBLIC_SEED: &str = "BLINCS-128-7x5 2026-11-26 public seed";
pub(crate) const CTX_PUBLIC_HASH: &str = "BLINCS-128-7x5 2026-11-26 public hash";
pub(crate) const CTX_CONTENT: &str = "BLINCS-128-7x5 2026-11-26 content";
pub(crate) const CTX_GENERATE_SIGNET: &str = "Signet BLINCS-128-7x5 2026-11-26 generate signet";
pub(crate) const CTX_MIX: &str = "Signet 2026-11-26 randomness: mix";
pub(crate) const CTX_NEXT_SEED: &str = "Signet 2026-11-26 randomness: next seed";
pub(crate) const CTX_RUN_KEY: &str = "Signet 2026-11-26 randomness: key of this run";
pub(crate) const CTX_KEYGEN_KEY: &str = "Signet 2026-11-26 randomness: keygen key";

#[inline]
pub(crate) fn ensure_init() {
    initialize();
}

#[inline]
pub(crate) fn keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *convenience::hash_with(Mode::Keyed(key), data).as_bytes()
}

#[inline]
pub(crate) fn derive_key(context: &str, material: &[u8]) -> [u8; 32] {
    *convenience::hash_with(Mode::DeriveKey(context), material).as_bytes()
}

#[inline]
pub(crate) fn first_n(full: &[u8; 32]) -> [u8; N] {
    full[..N].try_into().unwrap()
}

#[inline]
pub(crate) fn pack_tagged(dst: &mut [u8; 32], t: [u8; 16], val: &[u8]) {
    dst[..16].copy_from_slice(&t);
    dst[16..32].copy_from_slice(val);
}

#[inline]
pub(crate) fn pack_pair(dst: &mut [u8; 48], t: [u8; 16], left: &[u8], right: &[u8]) {
    dst[..16].copy_from_slice(&t);
    dst[16..32].copy_from_slice(left);
    dst[32..48].copy_from_slice(right);
}

/// Extract `width` bits (`1..=57`) starting at LSB-first bit offset `bit_off` from `d`.
#[inline]
pub(crate) fn read_bits(d: &[u8; 32], bit_off: usize, width: usize) -> u64 {
    assert!((1..=57).contains(&width) && bit_off + width <= 256);
    let byte_off = bit_off / 8;
    let shift = bit_off % 8;
    let mut raw = [0u8; 8];
    let avail = (32 - byte_off).min(8);
    raw[..avail].copy_from_slice(&d[byte_off..byte_off + avail]);
    (u64::from_le_bytes(raw) >> shift) & ((1u64 << width) - 1)
}

fn tree_hasher(key: &[u8; 32], use_sme2: bool) -> TreeHasher {
    if use_sme2 { TreeHasher::new(Mode::Keyed(key)) } else { TreeHasher::new(Mode::Keyed(key)).on_this_core() }
}

/// Separate newtypes for secret (`K_sec`) vs. public (`K_pub`) tree keys prevent cross-role mixups.
///
/// `SecretKey` exposes only narrow secret-domain `ChainSecret` batch derivations and never hands
/// out a raw `TreeHasher`, so public-tweak callers cannot misuse it.
#[derive(Clone, Copy)]
pub(crate) struct SecretKey([u8; 32]);

impl SecretKey {
    pub(crate) fn derive(seed: &[u8; SEED_LEN]) -> Self {
        Self(derive_key(CTX_SECRET_VALUES, seed))
    }

    /// Derive all `TREE_LEAVES * CHAINS` (1,120) WOTS+ start values for hypertree `(layer, tree)`.
    pub(crate) fn derive_wots_tree_starts(&self, layer: Layer, tree: u64, b16: &mut [[u8; 16]], out: &mut [[u8; 32]]) {
        assert!(tree < layer.trees());
        let layer_u8 = layer.as_u8();
        let total = TREE_LEAVES * CHAINS;
        for i in 0..TREE_LEAVES {
            let leaf = u16::try_from(i).unwrap();
            for c in 0..CHAINS {
                b16[i * CHAINS + c] = tweak(TweakKind::ChainSecret, layer_u8, tree, leaf, u16::try_from(c).unwrap(), 0);
            }
        }
        tree_hasher(&self.0, true).hash_many(&b16[..total], &mut out[..total]);
    }

    /// Derive the `CHAINS` (35) WOTS+ start values for one hypertree leaf `(layer, tree, leaf)`.
    pub(crate) fn derive_wots_leaf_starts(&self, layer: Layer, tree: u64, leaf: u16) -> [[u8; N]; CHAINS] {
        assert!(tree < layer.trees() && usize::from(leaf) < TREE_LEAVES);
        let layer_u8 = layer.as_u8();
        let mut b16 = [[0u8; 16]; CHAINS];
        let mut hashes = [[0u8; 32]; CHAINS];
        for (c, slot) in b16.iter_mut().enumerate() {
            *slot = tweak(TweakKind::ChainSecret, layer_u8, tree, leaf, u16::try_from(c).unwrap(), 0);
        }
        tree_hasher(&self.0, false).hash_many(&b16[..], &mut hashes[..]);
        core::array::from_fn(|c| first_n(&hashes[c]))
    }

    /// Derive all `UFORS_TOTAL_CHAINS` (`15 * 32 * 3 = 1,440`) U-FORS chain starts under `leaf_addr`.
    pub(crate) fn derive_ufors_starts(&self, leaf_addr: LeafAddr, b16: &mut [[u8; 16]], out: &mut [[u8; 32]]) {
        assert!(b16.len() >= UFORS_TOTAL_CHAINS && out.len() >= UFORS_TOTAL_CHAINS);
        let tree = leaf_addr.as_u64();
        let mut slot = 0usize;
        for t in 0..UFORS_TREES {
            let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
            for leaf in 0..TREE_LEAVES {
                let leaf_u16 = u16::try_from(leaf).unwrap();
                for c in 0..UFORS_CHAINS {
                    b16[slot] = tweak(TweakKind::ChainSecret, layer_u8, tree, leaf_u16, u16::try_from(c).unwrap(), 0);
                    slot += 1;
                }
            }
        }
        tree_hasher(&self.0, true).hash_many(&b16[..UFORS_TOTAL_CHAINS], &mut out[..UFORS_TOTAL_CHAINS]);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicKey([u8; 32]);

impl PublicKey {
    pub(crate) fn from_seed(public_seed: &[u8; N]) -> Self {
        Self(derive_key(CTX_PUBLIC_HASH, public_seed))
    }

    pub(crate) fn hasher(&self, use_sme2: bool) -> TreeHasher {
        tree_hasher(&self.0, use_sme2)
    }

    pub(crate) fn keyed(&self, data: &[u8]) -> [u8; 32] {
        keyed(&self.0, data)
    }
}

/// Six unified tweak domain tags (SPEC.md, "Tweaks").
#[repr(u8)]
#[derive(Clone, Copy)]
pub(crate) enum TweakKind {
    ChainSecret = 1,
    Chain = 2,
    OneTimeKey = 3,
    Node = 4,
    FewRoot = 5,
    Message = 6,
}

/// Uniform hypertree layer (`0..7`), each of height `TREE_HEIGHT = 5` (`32` leaves).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L5 = 5,
    L6 = 6,
}

impl Layer {
    pub(crate) const ALL: [Self; LAYERS] = [Self::L0, Self::L1, Self::L2, Self::L3, Self::L4, Self::L5, Self::L6];
    pub(crate) const LOWER: [Self; LAYERS - 1] = [Self::L0, Self::L1, Self::L2, Self::L3, Self::L4, Self::L5];
    pub(crate) const TOP: Self = Self::L6;

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Number of trees at this layer (`2^30`, `2^25`, `2^20`, `2^15`, `2^10`, `2^5`, `1` for layers 0..=6).
    pub(crate) const fn trees(self) -> u64 {
        1u64 << (HYPER_BITS - (self.index() + 1) * TREE_HEIGHT)
    }

    pub(crate) const fn sig_offset(self) -> usize {
        2 * N + UFORS_LEN + self.index() * LAYER_LEN
    }
}

/// Validated 35-bit hypertree leaf address (`< 2^35`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeafAddr(u64);

impl LeafAddr {
    pub(crate) fn from_digest_word(word: u64) -> Self {
        Self(word & ((1u64 << HYPER_BITS) - 1))
    }

    pub(crate) fn as_u64(self) -> u64 {
        self.0
    }

    /// Decompose this 35-bit address into `(tree, leaf)` for each of the 7 uniform hypertree layers.
    pub(crate) fn split_layers(self) -> [(u64, u16); LAYERS] {
        let mut out = [(0u64, 0u16); LAYERS];
        let mut addr = self.0;
        let mask = (1u64 << TREE_HEIGHT) - 1;
        for layer in Layer::ALL {
            let leaf = u16::try_from(addr & mask).unwrap();
            addr >>= TREE_HEIGHT;
            out[layer.index()] = (addr, leaf);
        }
        out
    }
}

/// 16-byte domain-separation tweak (SPEC.md, "Tweaks").
#[inline]
pub(crate) fn tweak(kind: TweakKind, layer: u8, tree: u64, leaf: u16, a: u16, b: u32) -> [u8; 16] {
    assert!(tree < (1u64 << 48), "tree index exceeds 48 bits");
    let mut t = [0u8; 16];
    t[0] = kind as u8;
    t[1] = layer;
    t[2..8].copy_from_slice(&tree.to_le_bytes()[..6]);
    t[8..10].copy_from_slice(&leaf.to_le_bytes());
    t[10..12].copy_from_slice(&a.to_le_bytes());
    t[12..16].copy_from_slice(&b.to_le_bytes());
    t
}

#[cfg(test)]
pub(crate) fn short_hash(key: &PublicKey, t: [u8; 16], data: &[u8]) -> [u8; N] {
    let mut buf = [0u8; 64];
    assert!(16 + data.len() <= buf.len());
    buf[..16].copy_from_slice(&t);
    buf[16..16 + data.len()].copy_from_slice(data);
    first_n(&key.keyed(&buf[..16 + data.len()]))
}

use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience, initialize};

/// Byte length of a [`crate::Signet`] secret seed (`32` bytes).
pub const SEED_LEN: usize = 32;
/// Byte length of a [`crate::SignetId`] wire encoding (`32` bytes: `public_seed || top_root`).
pub const SIGNET_ID_LEN: usize = 32;

pub(crate) const N: usize = 16;
pub(crate) const LAYERS: usize = 7;
pub(crate) const TREE_HEIGHT: usize = 5;
pub(crate) const TREE_LEAVES: usize = 1 << TREE_HEIGHT;

pub(crate) const W: usize = 16;
pub(crate) const CHAIN_STEPS: u8 = 15;
pub(crate) const MSG_CHAINS: usize = 2 * N;
pub(crate) const CSUM_CHAINS: usize = 3;
pub(crate) const CHAINS: usize = MSG_CHAINS + CSUM_CHAINS;

pub(crate) const FORS_HEIGHT: usize = 8;
pub(crate) const FORS_LEAVES: usize = 1 << FORS_HEIGHT;
pub(crate) const FORS_TREES: usize = 20;
pub(crate) const HYPER_BITS: usize = LAYERS * TREE_HEIGHT;

pub(crate) const SHORT_LEN: usize = N + 32;
pub(crate) const FORS_LEN: usize = FORS_TREES * (1 + FORS_HEIGHT) * N;
pub(crate) const LAYER_LEN: usize = (CHAINS + TREE_HEIGHT) * N;
/// Byte length of a BLINCS [`crate::Imprint`] (`7,392` bytes).
pub const IMPRINT_LEN: usize = 2 * N + FORS_LEN + LAYERS * LAYER_LEN;

const _: () = {
    assert!(W == (CHAIN_STEPS as usize) + 1 && CHAINS == 35 && MSG_CHAINS * 4 == N * 8);
    assert!(FORS_TREES * FORS_HEIGHT == 160 && HYPER_BITS == 35 && HYPER_BITS < 48);
    assert!(IMPRINT_LEN == 7392 && 2 * N + FORS_LEN + 7 * LAYER_LEN == IMPRINT_LEN);
};

// Key-derivation contexts (SPEC.md, "Key-derivation contexts").
pub(crate) const CTX_SECRET_VALUES: &str = "BLINCS 2026-11-25 signet: secret values";
pub(crate) const CTX_CONTENT_SALT: &str = "BLINCS 2026-11-25 signet: content salt";
pub(crate) const CTX_RANDOMIZER: &str = "BLINCS 2026-11-25 signet: randomizer";
pub(crate) const CTX_PUBLIC_SEED: &str = "BLINCS 2026-11-25 signet: public seed";
pub(crate) const CTX_GENERATE_SIGNET: &str = "BLINCS 2026-11-25 signet: generate";
pub(crate) const CTX_PUBLIC_HASH: &str = "BLINCS 2026-11-25 public hash";
pub(crate) const CTX_CONTENT: &str = "BLINCS 2026-11-25 content";
pub(crate) const CTX_MIX: &str = "BLINCS 2026-11-25 randomness: mix";
pub(crate) const CTX_FILE_ID: &str = "BLINCS 2026-11-25 randomness: file id";
pub(crate) const CTX_NEXT_SEED: &str = "BLINCS 2026-11-25 randomness: next seed";
pub(crate) const CTX_RUN_KEY: &str = "BLINCS 2026-11-25 randomness: key of this run";
pub(crate) const CTX_KEYGEN_KEY: &str = "BLINCS 2026-11-25 randomness: keygen key";

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

fn tree_hasher(key: &[u8; 32], use_sme2: bool) -> TreeHasher {
    if use_sme2 { TreeHasher::new(Mode::Keyed(key)) } else { TreeHasher::new(Mode::Keyed(key)).on_this_core() }
}

/// Separate newtypes for secret (`K_sec`) vs. public (`K_pub`) tree keys prevent cross-role mixups.
#[derive(Clone, Copy)]
pub(crate) struct SecretKey([u8; 32]);

impl SecretKey {
    pub(crate) fn derive(seed: &[u8; SEED_LEN]) -> Self {
        Self(derive_key(CTX_SECRET_VALUES, seed))
    }

    pub(crate) fn hasher(&self, use_sme2: bool) -> TreeHasher {
        tree_hasher(&self.0, use_sme2)
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

/// Tweak domain tag (SPEC.md, "Tweaks").
#[repr(u8)]
#[derive(Clone, Copy)]
pub(crate) enum TweakKind {
    ChainSecret = 1,
    Chain = 2,
    OneTimeKey = 3,
    Node = 4,
    FewSecret = 5,
    FewLeaf = 6,
    FewNode = 7,
    FewRoot = 8,
    Message = 9,
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
        2 * N + FORS_LEN + self.index() * LAYER_LEN
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

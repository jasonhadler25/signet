use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience, initialize};

pub const SEED_LEN: usize = 32;
pub const SIGNET_ID_LEN: usize = 32;

pub(crate) const N: usize = 16;
pub(crate) const LAYERS: usize = 4;
pub(crate) const LOWER_HEIGHT: usize = 7;
pub(crate) const LOWER_LEAVES: usize = 1 << LOWER_HEIGHT;
pub(crate) const TOP_HEIGHT: usize = 12;
pub(crate) const TOP_LEAVES: usize = 1 << TOP_HEIGHT;

pub(crate) const W: usize = 16;
pub(crate) const CHAIN_STEPS: u8 = 15;
pub(crate) const MSG_CHAINS: usize = 2 * N;
pub(crate) const CSUM_CHAINS: usize = 3;
pub(crate) const CHAINS: usize = MSG_CHAINS + CSUM_CHAINS;

pub(crate) const FORS_HEIGHT: usize = 10;
pub(crate) const FORS_LEAVES: usize = 1 << FORS_HEIGHT;
pub(crate) const FORS_TREES: usize = 16;
pub(crate) const HYPER_BITS: usize = TOP_HEIGHT + (LAYERS - 1) * LOWER_HEIGHT;

pub(crate) const SHORT_LEN: usize = N + 32;
pub(crate) const FORS_LEN: usize = FORS_TREES * (1 + FORS_HEIGHT) * N;
pub(crate) const LOWER_LAYER_LEN: usize = (CHAINS + LOWER_HEIGHT) * N;
pub(crate) const TOP_LAYER_LEN: usize = (CHAINS + TOP_HEIGHT) * N;
pub const IMPRINT_LEN: usize = 2 * N + FORS_LEN + (LAYERS - 1) * LOWER_LAYER_LEN + TOP_LAYER_LEN;

const _: () = {
    assert!(W == (CHAIN_STEPS as usize) + 1 && CHAINS == 35 && MSG_CHAINS * 4 == N * 8);
    assert!(FORS_TREES * FORS_HEIGHT == 160 && HYPER_BITS == 33 && HYPER_BITS < 48);
    assert!(FORS_TREES * FORS_HEIGHT + HYPER_BITS <= 256);
    assert!(IMPRINT_LEN == 5616 && 2 * N + FORS_LEN + 3 * LOWER_LAYER_LEN + TOP_LAYER_LEN == IMPRINT_LEN);
};

// Key-derivation contexts (SPEC.md, "Key-derivation contexts").
pub(crate) const CTX_SECRET_VALUES: &str = "BLINCS 2026-11-24 signet: secret values";
pub(crate) const CTX_CONTENT_SALT: &str = "BLINCS 2026-11-24 signet: content salt";
pub(crate) const CTX_RANDOMIZER: &str = "BLINCS 2026-11-24 signet: randomizer";
pub(crate) const CTX_PUBLIC_SEED: &str = "BLINCS 2026-11-24 signet: public seed";
pub(crate) const CTX_PUBLIC_HASH: &str = "BLINCS 2026-11-24 public hash";
pub(crate) const CTX_CONTENT: &str = "BLINCS 2026-11-24 content";
pub(crate) const CTX_MIX: &str = "BLINCS 2026-11-24 randomness: mix";
pub(crate) const CTX_NEXT_SEED: &str = "BLINCS 2026-11-24 randomness: seed kept in the file";
pub(crate) const CTX_RUN_KEY: &str = "BLINCS 2026-11-24 randomness: key of this run";

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

/// Hypertree layer (`0..4`), single source of truth for height, leaf count, and signature slice layout.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

impl Layer {
    pub(crate) const ALL: [Self; LAYERS] = [Self::L0, Self::L1, Self::L2, Self::L3];
    pub(crate) const LOWER: [Self; LAYERS - 1] = [Self::L0, Self::L1, Self::L2];
    pub(crate) const TOP: Self = Self::L3;

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    pub(crate) const fn height(self) -> usize {
        if matches!(self, Self::L3) { TOP_HEIGHT } else { LOWER_HEIGHT }
    }

    pub(crate) const fn leaves(self) -> usize {
        if matches!(self, Self::L3) { TOP_LEAVES } else { LOWER_LEAVES }
    }

    /// Number of trees at this layer (`2^26`, `2^19`, `2^12`, `1` for layers 0..=3).
    pub(crate) const fn trees(self) -> u64 {
        match self {
            Self::L0 => 1u64 << (HYPER_BITS - LOWER_HEIGHT),
            Self::L1 => 1u64 << (HYPER_BITS - 2 * LOWER_HEIGHT),
            Self::L2 => 1u64 << (HYPER_BITS - 3 * LOWER_HEIGHT),
            Self::L3 => 1,
        }
    }

    pub(crate) const fn sig_len(self) -> usize {
        if matches!(self, Self::L3) { TOP_LAYER_LEN } else { LOWER_LAYER_LEN }
    }

    pub(crate) const fn sig_offset(self) -> usize {
        2 * N + FORS_LEN + self.index() * LOWER_LAYER_LEN
    }
}

/// Validated 33-bit hypertree leaf address (`< 2^33`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeafAddr(u64);

impl LeafAddr {
    pub(crate) fn from_digest_word(word: u64) -> Self {
        Self(word & ((1u64 << HYPER_BITS) - 1))
    }

    pub(crate) fn as_u64(self) -> u64 {
        self.0
    }

    /// Decompose this 33-bit address into `(tree, leaf)` for each of the 4 hypertree layers.
    pub(crate) fn split_layers(self) -> [(u64, u16); LAYERS] {
        let mut out = [(0u64, 0u16); LAYERS];
        let mut addr = self.0;
        for layer in Layer::ALL {
            let h = layer.height();
            let leaf = u16::try_from(addr & ((1u64 << h) - 1)).unwrap();
            addr >>= h;
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

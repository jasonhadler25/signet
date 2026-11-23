use blake3_servil::throughput::TreeHasher;
use blake3_servil::{Mode, convenience, initialize_multithreaded};

pub const SEED_LEN: usize = 32;
pub const VERIFYING_KEY_LEN: usize = 32;

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
pub const SIGNATURE_LEN: usize = 2 * N + FORS_LEN + (LAYERS - 1) * LOWER_LAYER_LEN + TOP_LAYER_LEN;

const _: () = {
    assert!(W == (CHAIN_STEPS as usize) + 1);
    assert!(SIGNATURE_LEN == 5616);
    assert!(CHAINS == 35);
    assert!(MSG_CHAINS * 4 == N * 8);
    assert!(FORS_TREES * FORS_HEIGHT == 160);
    assert!(HYPER_BITS == 33);
    assert!(HYPER_BITS < 48);
    assert!(FORS_TREES * FORS_HEIGHT + HYPER_BITS <= 256);
    assert!(2 * N + FORS_LEN + 3 * LOWER_LAYER_LEN + TOP_LAYER_LEN == SIGNATURE_LEN);
};

// Key-derivation contexts (SPEC.md, "Key-derivation contexts").
const CTX_SECRET_VALUES: &str = "BLINCS 2026-11-23 signing key: secret values";
const CTX_CONTENT_SALT: &str = "BLINCS 2026-11-23 signing key: content salt";
const CTX_RANDOMIZER: &str = "BLINCS 2026-11-23 signing key: randomizer";
const CTX_PUBLIC_SEED: &str = "BLINCS 2026-11-23 signing key: public seed";
const CTX_PUBLIC_HASH: &str = "BLINCS 2026-11-23 public hash";
const CTX_CONTENT: &str = "BLINCS 2026-11-23 content";
pub(crate) const CTX_MIX: &str = "BLINCS 2026-11-23 randomness: mix";
pub(crate) const CTX_NEXT_SEED: &str = "BLINCS 2026-11-23 randomness: seed kept in the file";
pub(crate) const CTX_RUN_KEY: &str = "BLINCS 2026-11-23 randomness: key of this run";

/// Ensure `blake3-servil` kernels and worker pool are initialized and the calling thread is prepared.
#[inline]
pub(crate) fn ensure_init() {
    initialize_multithreaded(None);
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
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

/// Domain-separated 32-byte key for deriving leaf and chain secrets (`K_sec`).
#[derive(Clone, Copy)]
pub(crate) struct SecretKey([u8; 32]);

impl SecretKey {
    pub(crate) fn derive(seed: &[u8; SEED_LEN]) -> Self {
        Self(derive_key(CTX_SECRET_VALUES, seed))
    }

    pub(crate) fn tree_hasher(&self, use_sme2: bool) -> TreeHasher {
        if use_sme2 { TreeHasher::new(Mode::Keyed(&self.0)) } else { TreeHasher::new(Mode::Keyed(&self.0)).on_this_core() }
    }
}

/// Domain-separated 32-byte public tree/chain/message hash key (`K_pub`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicKey([u8; 32]);

impl PublicKey {
    pub(crate) fn derive_seed_and_key(seed: &[u8; SEED_LEN]) -> ([u8; N], Self) {
        let public_seed = first_n(&derive_key(CTX_PUBLIC_SEED, seed));
        (public_seed, Self::from_public_seed(&public_seed))
    }

    pub(crate) fn from_public_seed(public_seed: &[u8; N]) -> Self {
        Self(derive_key(CTX_PUBLIC_HASH, public_seed))
    }

    pub(crate) fn tree_hasher(&self, use_sme2: bool) -> TreeHasher {
        if use_sme2 { TreeHasher::new(Mode::Keyed(&self.0)) } else { TreeHasher::new(Mode::Keyed(&self.0)).on_this_core() }
    }

    pub(crate) fn keyed(&self, data: &[u8]) -> [u8; 32] {
        keyed(&self.0, data)
    }
}

/// Domain-separated 32-byte key for binding content hashes to a verifying key (`K_content`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContentKey([u8; 32]);

impl ContentKey {
    pub(crate) fn from_vk_bytes(vk_bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {
        Self(derive_key(CTX_CONTENT, vk_bytes))
    }

    pub(crate) fn message_key(&self, salt: &[u8; N]) -> MessageKey {
        MessageKey(keyed(&self.0, salt))
    }
}

/// Single-use per-signature message key `K_msg = Keyed(K_content, e)`.
#[derive(Clone, Copy)]
pub(crate) struct MessageKey([u8; 32]);

impl MessageKey {
    pub(crate) fn mode(&self) -> Mode<'_> {
        Mode::Keyed(&self.0)
    }
}

/// Domain-separated 32-byte key for deriving per-signature content salts (`K_salt`).
#[derive(Clone, Copy)]
pub(crate) struct SaltKey([u8; 32]);

impl SaltKey {
    pub(crate) fn derive(seed: &[u8; SEED_LEN]) -> Self {
        Self(derive_key(CTX_CONTENT_SALT, seed))
    }

    pub(crate) fn derive_salt(&self, draw: &[u8; 32]) -> [u8; N] {
        first_n(&keyed(&self.0, draw))
    }
}

/// Domain-separated 32-byte key for deriving per-signature randomizers (`K_R`).
#[derive(Clone, Copy)]
pub(crate) struct RandomizerKey([u8; 32]);

impl RandomizerKey {
    pub(crate) fn derive(seed: &[u8; SEED_LEN]) -> Self {
        Self(derive_key(CTX_RANDOMIZER, seed))
    }

    pub(crate) fn derive_randomizer(&self, short: &[u8; SHORT_LEN]) -> [u8; N] {
        first_n(&keyed(&self.0, short))
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

/// Hypertree layer (`0..4`), carrying its height, leaf count, and signature slice layout.
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

    #[inline]
    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    #[inline]
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub(crate) const fn height(self) -> usize {
        match self {
            Self::L3 => TOP_HEIGHT,
            Self::L0 | Self::L1 | Self::L2 => LOWER_HEIGHT,
        }
    }

    #[inline]
    pub(crate) const fn leaves(self) -> usize {
        match self {
            Self::L3 => TOP_LEAVES,
            Self::L0 | Self::L1 | Self::L2 => LOWER_LEAVES,
        }
    }

    #[inline]
    pub(crate) const fn sig_len(self) -> usize {
        match self {
            Self::L3 => TOP_LAYER_LEN,
            Self::L0 | Self::L1 | Self::L2 => LOWER_LAYER_LEN,
        }
    }

    #[inline]
    pub(crate) const fn sig_offset(self) -> usize {
        2 * N + FORS_LEN + self.index() * LOWER_LAYER_LEN
    }
}

/// 48-bit hypertree/FORS tree coordinate (`< 2^48`), matching the 6-byte LE field in `tweak`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeIndex(u64);

impl TreeIndex {
    pub(crate) const ZERO: Self = Self(0);

    #[cfg(test)]
    #[inline]
    pub(crate) fn new(value: u64) -> Self {
        assert!(value < (1u64 << 48), "tree index exceeds 48 bits");
        Self(value)
    }

    #[inline]
    pub(crate) fn to_le_6(self) -> [u8; 6] {
        let b = self.0.to_le_bytes();
        [b[0], b[1], b[2], b[3], b[4], b[5]]
    }
}

/// 33-bit hypertree leaf address (`< 2^33`), guaranteed to fit inside `TreeIndex`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeafAddr(u64);

impl LeafAddr {
    #[inline]
    pub(crate) fn from_digest_word(word: u64) -> Self {
        Self(word & ((1u64 << HYPER_BITS) - 1))
    }

    #[inline]
    pub(crate) fn as_tree(self) -> TreeIndex {
        TreeIndex(self.0)
    }

    /// Decompose this 33-bit address into `(tree, leaf)` for each of the 4 hypertree layers.
    #[inline]
    pub(crate) fn split_layers(self) -> [(TreeIndex, u16); LAYERS] {
        let mut out = [(TreeIndex::ZERO, 0u16); LAYERS];
        let mut addr = self.0;
        for layer in Layer::ALL {
            let h = layer.height();
            let leaf = u16::try_from(addr & ((1u64 << h) - 1)).unwrap();
            addr >>= h;
            out[layer.index()] = (TreeIndex(addr), leaf);
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn as_u64(self) -> u64 {
        self.0
    }
}

/// Validated 10-bit FORS leaf index (`0..1024`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForsIndex(u16);

impl ForsIndex {
    #[inline]
    pub(crate) fn from_bits(bits: u64) -> Self {
        Self(u16::try_from(bits & 0x3ff).unwrap())
    }

    #[inline]
    pub(crate) fn as_usize(self) -> usize {
        usize::from(self.0)
    }

    #[inline]
    pub(crate) fn as_u32(self) -> u32 {
        u32::from(self.0)
    }

    #[cfg(test)]
    pub(crate) fn as_u16(self) -> u16 {
        self.0
    }
}

/// 16-byte domain-separation tweak (SPEC.md, "Tweaks").
#[inline]
pub(crate) fn tweak(kind: TweakKind, layer: u8, tree: TreeIndex, leaf: u16, a: u16, b: u32) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[0] = kind as u8;
    t[1] = layer;
    t[2..8].copy_from_slice(&tree.to_le_6());
    t[8..10].copy_from_slice(&leaf.to_le_bytes());
    t[10..12].copy_from_slice(&a.to_le_bytes());
    t[12..16].copy_from_slice(&b.to_le_bytes());
    t
}

#[cfg(test)]
#[inline]
pub(crate) fn short_hash(key: &PublicKey, t: [u8; 16], data: &[u8]) -> [u8; N] {
    let mut buf = [0u8; 64];
    assert!(16 + data.len() <= buf.len());
    buf[..16].copy_from_slice(&t);
    buf[16..16 + data.len()].copy_from_slice(data);
    first_n(&key.keyed(&buf[..16 + data.len()]))
}

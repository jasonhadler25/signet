use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience, initialize};

/// Permanent suite identifier for this BLINCS parameter set (`12+7+7+7` `S-WOTS+Z` + `U-PORS`, 2³² budget).
pub const SUITE_NAME: &str = "BLINCS-128-A2";
/// Byte length of a [`crate::Signet`] secret seed (`32` bytes).
pub const SEED_LEN: usize = 32;
/// Byte length of a [`crate::SignetId`] wire encoding (`32` bytes: `public_seed || top_root`).
pub const SIGNET_ID_LEN: usize = 32;
/// Maximum byte length of a [`crate::Context`] application domain tag (`255` bytes).
pub const MAX_CONTEXT_LEN: usize = 255;

pub(crate) const N: usize = 16;

// Hypertree: 12 + 7 + 7 + 7 = 33 bits across 4 layers (d = 4).
pub(crate) const LAYERS: usize = 4;
pub(crate) const LOW_HEIGHT: usize = 7;
pub(crate) const LOW_LEAVES: usize = 1 << LOW_HEIGHT;
pub(crate) const TOP_HEIGHT: usize = 12;
pub(crate) const TOP_LEAVES: usize = 1 << TOP_HEIGHT;
pub(crate) const HYPER_BITS: usize = 3 * LOW_HEIGHT + TOP_HEIGHT;

// S-WOTS+Z(n = 24, w = 40, S = 468, z = 8, deterministic u16 counter).
pub(crate) const WOTS_N: usize = 24;
pub(crate) const WOTS_W: usize = 40;
pub(crate) const WOTS_STEPS: u8 = 39;
pub(crate) const WOTS_SUM: usize = 468;
pub(crate) const WOTS_CTR_LEN: usize = 2;
pub(crate) const WOTS_PK_IN_LEN: usize = 16 + WOTS_N * N;

// U-PORS(n = 3, w = 24, S = 42, C = 376, A = 10, k = 10, m_max = 44, u32 counter).
pub(crate) const UPORS_HEIGHT: usize = 10;
pub(crate) const UPORS_LEAVES: usize = 1 << UPORS_HEIGHT;
pub(crate) const UPORS_N: usize = 3;
pub(crate) const UPORS_W: usize = 24;
pub(crate) const UPORS_STEPS: u8 = 23;
pub(crate) const UPORS_SUM: usize = 42;
pub(crate) const UPORS_C: usize = 376;
pub(crate) const UPORS_K: usize = 10;
pub(crate) const UPORS_M_MAX: usize = 44;
pub(crate) const UPORS_CTR_LEN: usize = 4;
pub(crate) const UPORS_LAYER_U8: u8 = 0x80;
pub(crate) const UPORS_SELECT_MAX_DRAWS: usize = 22;

pub(crate) const SHORT_LEN: usize = N + 32;
pub(crate) const UPORS_LEN: usize = UPORS_CTR_LEN + (UPORS_K * UPORS_N + UPORS_M_MAX) * N;
pub(crate) const LOW_LAYER_LEN: usize = WOTS_CTR_LEN + (WOTS_N + LOW_HEIGHT) * N;
pub(crate) const TOP_LAYER_LEN: usize = WOTS_CTR_LEN + (WOTS_N + TOP_HEIGHT) * N;
/// Byte length of a `BLINCS-128-A2` [`crate::Imprint`] (`3,292` bytes).
pub const IMPRINT_LEN: usize = 2 * N + UPORS_LEN + 3 * LOW_LAYER_LEN + TOP_LAYER_LEN;

const _: () = {
    assert!(HYPER_BITS == 33 && HYPER_BITS < 48);
    assert!(LOW_LEAVES == 128 && TOP_LEAVES == 4096 && UPORS_LEAVES == 1024);
    assert!(WOTS_W == (WOTS_STEPS as usize) + 1 && WOTS_SUM * 2 == WOTS_N * (WOTS_STEPS as usize) && WOTS_PK_IN_LEN == 400);
    assert!(UPORS_W == (UPORS_STEPS as usize) + 1 && 16 + UPORS_N * N == 64);
    assert!(UPORS_SELECT_MAX_DRAWS * UPORS_HEIGHT + HYPER_BITS == 253);
    assert!(LAYERS <= (UPORS_LAYER_U8 as usize));
    assert!(UPORS_LEN == 1188 && LOW_LAYER_LEN == 498 && TOP_LAYER_LEN == 578);
    assert!(IMPRINT_LEN == 3292);
};

// Key-derivation contexts (SPEC.md, "Key-derivation contexts").
// Algorithm contexts bind SUITE_NAME ("BLINCS-128-A2") so suites never share derived keys.
pub(crate) const CTX_SECRET_VALUES: &str = "BLINCS-128-A2 2026-11-26 secret values";
pub(crate) const CTX_CONTENT_SALT: &str = "BLINCS-128-A2 2026-11-26 content salt";
pub(crate) const CTX_RANDOMIZER: &str = "BLINCS-128-A2 2026-11-26 randomizer";
pub(crate) const CTX_PUBLIC_SEED: &str = "BLINCS-128-A2 2026-11-26 public seed";
pub(crate) const CTX_PUBLIC_HASH: &str = "BLINCS-128-A2 2026-11-26 public hash";
pub(crate) const CTX_CONTENT: &str = "BLINCS-128-A2 2026-11-26 content";
pub(crate) const CTX_GENERATE_SIGNET: &str = "Signet BLINCS-128-A2 2026-11-26 generate signet";
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

    /// Derive `out.len()` consecutive secret chain starts via register-only `hash_counter_range`
    /// (word 3 = `b` = linear slot `leaf_idx * chains + chain_idx`).
    pub(crate) fn derive_chain_starts(&self, layer: u8, tree: u64, start_slot: u32, use_sme2: bool, out: &mut [[u8; 32]]) {
        assert!(tree < (1u64 << 48));
        let tmpl = tweak(TweakKind::ChainSecret, layer, tree, 0, 0, 0);
        tree_hasher(&self.0, use_sme2).hash_counter_range(&tmpl, 3, start_slot, out);
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

/// Hypertree layer index (`0..=3`, with layer 3 being the cached height-12 top tree).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            _ => LOW_HEIGHT,
        }
    }

    #[inline]
    pub(crate) const fn layer_len(self) -> usize {
        match self {
            Self::L3 => TOP_LAYER_LEN,
            _ => LOW_LAYER_LEN,
        }
    }

    #[inline]
    pub(crate) const fn sig_offset(self) -> usize {
        2 * N + UPORS_LEN + self.index() * LOW_LAYER_LEN
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn trees(self) -> u64 {
        match self {
            Self::L0 => 1u64 << 26,
            Self::L1 => 1u64 << 19,
            Self::L2 => 1u64 << 12,
            Self::L3 => 1,
        }
    }
}

/// 33-bit hypertree leaf address (`0 .. 2^33`), guaranteed to fit inside a 48-bit tweak `tree` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LeafAddr(u64);

impl LeafAddr {
    #[inline]
    pub(crate) const fn from_word(word: u64) -> Self {
        Self(word & ((1u64 << HYPER_BITS) - 1))
    }

    #[inline]
    pub(crate) const fn as_u64(self) -> u64 {
        self.0
    }

    /// Split `leaf_addr` into `(tree, leaf)` for each of the 4 hypertree layers (`7, 7, 7, 12` bits).
    #[inline]
    pub(crate) fn split_layers(self) -> [(u64, u16); LAYERS] {
        let a = self.0;
        let l0 = u16::try_from(a & 0x7f).unwrap();
        let t0 = a >> LOW_HEIGHT;
        let l1 = u16::try_from(t0 & 0x7f).unwrap();
        let t1 = t0 >> LOW_HEIGHT;
        let l2 = u16::try_from(t1 & 0x7f).unwrap();
        let t2 = t1 >> LOW_HEIGHT;
        let l3 = u16::try_from(t2 & 0xfff).unwrap();
        [(t0, l0), (t1, l1), (t2, l2), (0, l3)]
    }
}

/// Every distinct hash role inside BLINCS carries its own tag byte in byte 0 of the 16-byte tweak.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TweakKind {
    ChainSecret = 1,
    Chain = 2,
    OneTimeKey = 3,
    Node = 4,
    OneTimeMsg = 5,
    Message = 6,
    FewSelect = 7,
    FewCode = 8,
}

/// Domain separation for every hash in the tree (SPEC.md, "Tweaks").
///
/// Layout: `kind(1) || layer(1) || tree(6 LE) || leaf(2 LE) || a(2 LE) || b(4 LE)` = 16 bytes.
pub(crate) fn tweak(kind: TweakKind, layer: u8, tree: u64, leaf: u16, a: u16, b: u32) -> [u8; 16] {
    assert!(tree < (1u64 << 48), "tree index exceeds 48-bit tweak field");
    let mut t = [0u8; 16];
    t[0] = kind as u8;
    t[1] = layer;
    t[2..8].copy_from_slice(&tree.to_le_bytes()[..6]);
    t[8..10].copy_from_slice(&leaf.to_le_bytes());
    t[10..12].copy_from_slice(&a.to_le_bytes());
    t[12..16].copy_from_slice(&b.to_le_bytes());
    t
}

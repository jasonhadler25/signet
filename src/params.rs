use blake3_servil_core::{Mode, convenience};

pub const SEED_LEN: usize = 32;
pub const VERIFYING_KEY_LEN: usize = 32;
pub const CHUNK_LEN: usize = 256 * 1024;

pub(crate) const N: usize = 16;
pub(crate) const LAYERS: usize = 4;
pub(crate) const TREE_HEIGHT: usize = 9;
pub(crate) const TREE_LEAVES: usize = 1 << TREE_HEIGHT;
pub(crate) const TOP_NODES: usize = 2 * TREE_LEAVES;

pub(crate) const CHAINS: usize = 24;
pub(crate) const CHAIN_STEPS: u32 = 31;
pub(crate) const ZERO_BITS: u32 = 8;
pub(crate) const DIGIT_SUM: u32 = 372;

pub(crate) const FEW_HEIGHT: usize = 15;
pub(crate) const FEW_LEAVES: usize = 1 << FEW_HEIGHT;
pub(crate) const OPENED: usize = 11;
pub(crate) const AUTH_NODES: usize = 103;
pub(crate) const THRESHOLD_BITS: usize = 6;
pub(crate) const HYPER_BITS: usize = LAYERS * TREE_HEIGHT;

pub(crate) const SHORT_LEN: usize = N + 32 + 8;
pub(crate) const FEW_LEN: usize = 4 + N * (OPENED + AUTH_NODES);
pub(crate) const LAYER_LEN: usize = 4 + N * (CHAINS + TREE_HEIGHT);
pub const SIGNATURE_LEN: usize = 2 * N + FEW_LEN + LAYERS * LAYER_LEN;

const _: () = {
    assert!(SIGNATURE_LEN == 3988);
    assert!(CHUNK_LEN.is_multiple_of(64));
    assert!(ZERO_BITS as usize + 5 * CHAINS == 128);
    assert!(THRESHOLD_BITS + HYPER_BITS + OPENED * FEW_HEIGHT <= 256);
};

// Key-derivation contexts (SPEC.md, "Key-derivation contexts").
pub(crate) const CTX_SECRET_VALUES: &str = "BLINCS 2026-11-23 signing key: secret values";
pub(crate) const CTX_CONTENT_SALT: &str = "BLINCS 2026-11-23 signing key: content salt";
pub(crate) const CTX_RANDOMIZER: &str = "BLINCS 2026-11-23 signing key: randomizer";
pub(crate) const CTX_PUBLIC_SEED: &str = "BLINCS 2026-11-23 signing key: public seed";
pub(crate) const CTX_PUBLIC_HASH: &str = "BLINCS 2026-11-23 public hash";
pub(crate) const CTX_CONTENT: &str = "BLINCS 2026-11-23 content";
pub(crate) const CTX_MIX: &str = "BLINCS 2026-11-23 randomness: mix";
pub(crate) const CTX_NEXT_SEED: &str = "BLINCS 2026-11-23 randomness: seed kept in the file";
pub(crate) const CTX_RUN_KEY: &str = "BLINCS 2026-11-23 randomness: key of this run";

// Tweak kinds (SPEC.md, "Tweaks").
pub(crate) const KIND_CHAIN_SECRET: u8 = 1;
pub(crate) const KIND_CHAIN: u8 = 2;
pub(crate) const KIND_ONE_TIME_KEY: u8 = 3;
pub(crate) const KIND_ONE_TIME_MESSAGE: u8 = 4;
pub(crate) const KIND_NODE: u8 = 5;
pub(crate) const KIND_FEW_SECRET: u8 = 6;
pub(crate) const KIND_FEW_LEAF: u8 = 7;
pub(crate) const KIND_FEW_NODE: u8 = 8;
pub(crate) const KIND_MESSAGE: u8 = 9;
pub(crate) const KIND_PICK: u8 = 10;

/// 16-byte domain-separation tweak (SPEC.md, "Tweaks").
#[inline]
pub(crate) fn tweak(kind: u8, layer: u8, tree: u64, leaf: u16, a: u16, b: u32) -> [u8; 16] {
    debug_assert!(tree < (1u64 << 48));
    let mut t = [0u8; 16];
    let tb = tree.to_le_bytes();
    t[0] = kind;
    t[1] = layer;
    t[2..8].copy_from_slice(&tb[..6]);
    t[8..10].copy_from_slice(&leaf.to_le_bytes());
    t[10..12].copy_from_slice(&a.to_le_bytes());
    t[12..16].copy_from_slice(&b.to_le_bytes());
    t
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

#[inline]
pub(crate) fn short_hash(key: &[u8; 32], t: [u8; 16], data: &[u8]) -> [u8; N] {
    let mut buf = [0u8; 64];
    debug_assert!(16 + data.len() <= buf.len());
    buf[..16].copy_from_slice(&t);
    buf[16..16 + data.len()].copy_from_slice(data);
    first_n(&keyed(key, &buf[..16 + data.len()]))
}

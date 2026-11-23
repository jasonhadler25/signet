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
pub(crate) const CHAIN_STEPS: u32 = (W - 1) as u32;
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
    assert!(SIGNATURE_LEN == 5616);
    assert!(CHAINS == 35);
    assert!(MSG_CHAINS * 4 == N * 8);
    assert!(FORS_TREES * FORS_HEIGHT == 160);
    assert!(HYPER_BITS == 33);
    assert!(FORS_TREES * FORS_HEIGHT + HYPER_BITS <= 256);
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
pub(crate) const KIND_NODE: u8 = 4;
pub(crate) const KIND_FEW_SECRET: u8 = 5;
pub(crate) const KIND_FEW_LEAF: u8 = 6;
pub(crate) const KIND_FEW_NODE: u8 = 7;
pub(crate) const KIND_FEW_ROOT: u8 = 8;
pub(crate) const KIND_MESSAGE: u8 = 9;

/// Ensure `blake3-servil` kernels and worker pool are initialized and the calling thread is prepared.
#[inline]
pub(crate) fn ensure_init() {
    initialize_multithreaded(None);
}

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

#[cfg(test)]
#[inline]
pub(crate) fn short_hash(key: &[u8; 32], t: [u8; 16], data: &[u8]) -> [u8; N] {
    let mut buf = [0u8; 64];
    debug_assert!(16 + data.len() <= buf.len());
    buf[..16].copy_from_slice(&t);
    buf[16..16 + data.len()].copy_from_slice(data);
    first_n(&keyed(key, &buf[..16 + data.len()]))
}

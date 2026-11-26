//! Standalone `#![no_std]`, zero-allocation verifier for **`BLINCS-128-7x5`** signatures.
//!
//! **Pre-1.0 experimental software (unsupported):** wire formats, context strings, and APIs may
//! change before 1.0, and no independent human cryptographic audit has been performed.
//!
//! This crate verifies [`ImprintRef`] signatures against an expected [`SignetId`] and bounded
//! application [`Context`] using pure-Rust BLAKE3 (`blake3` with `default-features = false`,
//! `features = ["pure"]`). It requires neither `std` nor `alloc` and contains zero `unsafe` code.
//!
//! Both one-shot slice verification ([`SignetId::verify`]) and incremental streaming verification
//! ([`SignetId::verifier`] -> [`Verifier::update`] -> [`Verifier::finalize`]) are provided.

#![no_std]
#![forbid(unsafe_code)]

use core::array::TryFromSliceError;
use core::error::Error;
use core::fmt;

/// Permanent suite identifier for this BLINCS parameter set (`7×5`, `FORS(8, 20)`, 2³² budget).
pub const SUITE_NAME: &str = "BLINCS-128-7x5";
/// Byte length of a [`SignetId`] wire encoding (`32` bytes: `public_seed || top_root`).
pub const SIGNET_ID_LEN: usize = 32;
/// Byte length of a `BLINCS-128-7x5` signature (`7,392` bytes).
pub const IMPRINT_LEN: usize = 7392;
/// Maximum byte length of a [`Context`] application domain tag (`255` bytes).
pub const MAX_CONTEXT_LEN: usize = 255;

const N: usize = 16;
const LAYERS: usize = 7;
const TREE_HEIGHT: usize = 5;
const CHAIN_STEPS: u8 = 15;
const MSG_CHAINS: usize = 2 * N;
const CSUM_CHAINS: usize = 3;
const CHAINS: usize = MSG_CHAINS + CSUM_CHAINS;
const FORS_HEIGHT: usize = 8;
const FORS_TREES: usize = 20;
const HYPER_BITS: usize = LAYERS * TREE_HEIGHT;
const SHORT_LEN: usize = N + 32;
const FORS_LEN: usize = FORS_TREES * (1 + FORS_HEIGHT) * N;
const LAYER_LEN: usize = (CHAINS + TREE_HEIGHT) * N;
const MSG_DIGEST_INPUT_MAX_LEN: usize = 16 + N + N + SHORT_LEN + 1 + MAX_CONTEXT_LEN;

const _: () = {
    assert!(CHAINS == 35 && MSG_CHAINS * 4 == N * 8);
    assert!(FORS_TREES * FORS_HEIGHT == 160 && HYPER_BITS == 35);
    assert!(2 * N + FORS_LEN + LAYERS * LAYER_LEN == IMPRINT_LEN);
    assert!(MSG_DIGEST_INPUT_MAX_LEN == 352);
};

// Public verifier key-derivation contexts (SPEC.md, "Key-derivation contexts").
const CTX_PUBLIC_HASH: &str = "BLINCS-128-7x5 2026-11-25 public hash";
const CTX_CONTENT: &str = "BLINCS-128-7x5 2026-11-25 content";

#[derive(Clone, Copy)]
#[repr(u8)]
enum TweakKind {
    Chain = 2,
    OneTimeKey = 3,
    Node = 4,
    FewLeaf = 6,
    FewNode = 7,
    FewRoot = 8,
    Message = 9,
}

#[inline]
fn first_n(full: &[u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

#[inline]
fn keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

#[inline]
fn keyed_n(key: &[u8; 32], data: &[u8]) -> [u8; N] {
    first_n(&keyed(key, data))
}

#[inline]
fn tweak(kind: TweakKind, layer: u8, tree: u64, leaf: u16, idx: u16, step: u32) -> [u8; 16] {
    assert!(tree < (1u64 << 48), "tree index exceeds 48-bit wire field");
    let mut out = [0u8; 16];
    out[0] = kind as u8;
    out[1] = layer;
    out[2..8].copy_from_slice(&tree.to_le_bytes()[..6]);
    out[8..10].copy_from_slice(&leaf.to_le_bytes());
    out[10..12].copy_from_slice(&idx.to_le_bytes());
    out[12..16].copy_from_slice(&step.to_le_bytes());
    out
}

/// Returned by [`Context::try_new`] when a context slice exceeds [`MAX_CONTEXT_LEN`] (`255`) bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextTooLong {
    /// Byte length of the rejected slice.
    pub len: usize,
}

impl fmt::Display for ContextTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BLINCS context length {} exceeds maximum {MAX_CONTEXT_LEN} bytes", self.len)
    }
}

impl Error for ContextTooLong {}

/// Bounded application domain-separation label (`0..=255` bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Context<'a>(&'a [u8]);

impl<'a> Context<'a> {
    /// Empty (`0`-byte) application context.
    pub const EMPTY: Self = Self(b"");

    /// Wrap a compile-time or pre-validated slice (`<= 255` bytes). Panics if `bytes.len() > 255`.
    pub const fn new(bytes: &'a [u8]) -> Self {
        assert!(bytes.len() <= MAX_CONTEXT_LEN, "BLINCS context exceeds 255 bytes");
        Self(bytes)
    }

    /// Fallibly wrap a runtime slice (`<= 255` bytes).
    pub fn try_new(bytes: &'a [u8]) -> Result<Self, ContextTooLong> {
        if bytes.len() > MAX_CONTEXT_LEN {
            return Err(ContextTooLong { len: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// Borrow the raw context bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    fn write_framed(&self, dst: &mut [u8]) -> usize {
        let len = self.0.len();
        dst[0] = u8::try_from(len).unwrap();
        dst[1..1 + len].copy_from_slice(self.0);
        1 + len
    }
}

/// Returned by [`SignetId::verify`] when an imprint does not verify against the expected
/// [`SignetId`], [`Context`], and message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidImprint;

impl fmt::Display for InvalidImprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid BLINCS imprint")
    }
}

impl Error for InvalidImprint {}

/// Returned by [`Verifier::update`] when the cumulative streamed message length exceeds `u64::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageTooLong;

impl fmt::Display for MessageTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("streamed message length exceeds u64::MAX bytes")
    }
}

impl Error for MessageTooLong {}

/// Returned by [`Verifier::finalize`] when streaming verification fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamVerifyError {
    /// The imprint did not verify against the expected [`SignetId`], [`Context`], and streamed bytes.
    InvalidImprint,
    /// Cumulative streamed input length exceeded `u64::MAX` bytes during [`Verifier::update`].
    MessageTooLong,
}

impl fmt::Display for StreamVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidImprint => f.write_str("invalid BLINCS imprint"),
            Self::MessageTooLong => f.write_str("streamed message length exceeds u64::MAX bytes"),
        }
    }
}

impl Error for StreamVerifyError {}

/// Zero-copy borrowed reference to a `7,392`-byte `BLINCS-128-7x5` imprint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ImprintRef<'a>(&'a [u8; IMPRINT_LEN]);

impl<'a> ImprintRef<'a> {
    /// Wrap a fixed-length `7,392`-byte imprint reference without copying.
    pub const fn from_bytes(bytes: &'a [u8; IMPRINT_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the underlying `7,392`-byte slice reference.
    pub const fn as_bytes(self) -> &'a [u8; IMPRINT_LEN] {
        self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for ImprintRef<'a> {
    type Error = TryFromSliceError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let arr: &'a [u8; IMPRINT_LEN] = bytes.try_into()?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for ImprintRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImprintRef({IMPRINT_LEN} bytes)")
    }
}

/// Identifies a Signet (`32` bytes: `public_seed || top_root`) and verifies its imprints.
///
/// The caller must supply the **expected** `SignetId` for the publisher or authority they rely on;
/// accepting a `SignetId` sent alongside an untrusted message proves only internal consistency.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignetId {
    bytes: [u8; SIGNET_ID_LEN],
    pub_key: [u8; 32],
    content_key: [u8; 32],
}

impl SignetId {
    /// Construct a [`SignetId`] from its `32`-byte wire encoding (`public_seed || top_root`).
    pub fn from_bytes(bytes: &[u8; SIGNET_ID_LEN]) -> Self {
        let pub_key = blake3::derive_key(CTX_PUBLIC_HASH, &bytes[..N]);
        let content_key = blake3::derive_key(CTX_CONTENT, bytes);
        Self { bytes: *bytes, pub_key, content_key }
    }

    /// Return the `32`-byte wire encoding (`public_seed || top_root`).
    pub const fn as_bytes(&self) -> &[u8; SIGNET_ID_LEN] {
        &self.bytes
    }

    fn root(&self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[N..SIGNET_ID_LEN]);
        out
    }

    fn derive_msg_key(&self, salt: &[u8; N], ctx: Context<'_>) -> [u8; 32] {
        let mut buf = [0u8; N + 1 + MAX_CONTEXT_LEN];
        buf[..N].copy_from_slice(salt);
        let ctx_len = ctx.write_framed(&mut buf[N..]);
        keyed(&self.content_key, &buf[..N + ctx_len])
    }

    /// Verify a `7,392`-byte imprint over `message` under `ctx` in one pass (zero heap allocations).
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, ctx: Context<'_>, message: &[u8], sig: ImprintRef<'_>) -> Result<(), InvalidImprint> {
        let salt = read_n(sig.as_bytes(), 0);
        let msg_key = self.derive_msg_key(&salt, ctx);
        let msg_hash = keyed(&msg_key, message);
        let short = pack_short(&salt, &msg_hash);
        self.verify_short(ctx, &short, sig)
    }

    /// Begin incremental streaming verification over arbitrarily chunked input under `ctx`.
    ///
    /// Binds `self`, `ctx`, and `sig` for the lifetime of the [`Verifier`]. The message is not
    /// authenticated until [`Verifier::finalize`] returns `Ok(())`.
    pub fn verifier<'a>(&'a self, ctx: Context<'a>, sig: ImprintRef<'a>) -> Verifier<'a> {
        let salt = read_n(sig.as_bytes(), 0);
        let msg_key = self.derive_msg_key(&salt, ctx);
        Verifier { id: self, ctx, sig, salt, hasher: blake3::Hasher::new_keyed(&msg_key), total_bytes: 0, overflowed: false }
    }

    fn verify_short(&self, ctx: Context<'_>, short: &[u8; SHORT_LEN], sig: ImprintRef<'_>) -> Result<(), InvalidImprint> {
        let raw = sig.as_bytes();
        let salt = read_n(raw, 0);
        let mut expected_salt = [0u8; N];
        expected_salt.copy_from_slice(&short[..N]);
        if !constant_time_eq::constant_time_eq_16(&salt, &expected_salt) {
            return Err(InvalidImprint);
        }

        let randomizer = read_n(raw, N);
        let root = self.root();
        let digest = compute_message_digest(&self.pub_key, &randomizer, &root, short, ctx);
        let (fors_indices, leaf_addr) = parse_digest(&digest);

        let fors_slice = &raw[2 * N..2 * N + FORS_LEN];
        let mut node = verify_fors(&self.pub_key, leaf_addr, &fors_indices, fors_slice);

        let mut offset = 2 * N + FORS_LEN;
        for layer in 0..LAYERS {
            let tree = leaf_addr >> ((layer + 1) * TREE_HEIGHT);
            let leaf = u16::try_from((leaf_addr >> (layer * TREE_HEIGHT)) & ((1u64 << TREE_HEIGHT) - 1)).unwrap();
            let wots_sig = &raw[offset..offset + CHAINS * N];
            let auth = &raw[offset + CHAINS * N..offset + LAYER_LEN];
            offset += LAYER_LEN;

            let layer_u8 = u8::try_from(layer).unwrap();
            let pk = wots_pk_from_sig(&self.pub_key, layer_u8, tree, leaf, &node, wots_sig);
            node = verify_merkle_path(&self.pub_key, layer_u8, tree, leaf, pk, auth);
        }
        assert_eq!(offset, IMPRINT_LEN);

        if constant_time_eq::constant_time_eq_16(&node, &root) { Ok(()) } else { Err(InvalidImprint) }
    }
}

impl TryFrom<&[u8]> for SignetId {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: &[u8; SIGNET_ID_LEN] = bytes.try_into()?;
        Ok(Self::from_bytes(arr))
    }
}

impl fmt::Debug for SignetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignetId(")?;
        for b in &self.bytes {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Incremental streaming verifier produced by [`SignetId::verifier`].
///
/// Tracks cumulative input length in `u64`. If [`Verifier::update`] ever reports
/// [`MessageTooLong`], the verifier is permanently poisoned so [`Verifier::finalize`] can never
/// approve a truncated prefix even if the caller ignored the `update` error.
#[must_use = "the message is not authenticated until finalize succeeds"]
pub struct Verifier<'a> {
    id: &'a SignetId,
    ctx: Context<'a>,
    sig: ImprintRef<'a>,
    salt: [u8; N],
    hasher: blake3::Hasher,
    total_bytes: u64,
    overflowed: bool,
}

impl<'a> Verifier<'a> {
    /// Feed the next slice of message bytes into the streaming verifier.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), MessageTooLong> {
        if self.overflowed {
            return Err(MessageTooLong);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let Ok(len_u64) = u64::try_from(bytes.len()) else {
            self.overflowed = true;
            return Err(MessageTooLong);
        };
        let Some(next) = self.total_bytes.checked_add(len_u64) else {
            self.overflowed = true;
            return Err(MessageTooLong);
        };
        self.total_bytes = next;
        self.hasher.update(bytes);
        Ok(())
    }

    /// Finish hashing the streamed bytes and verify the bound imprint.
    #[must_use = "verification result must be checked"]
    pub fn finalize(self) -> Result<(), StreamVerifyError> {
        if self.overflowed {
            return Err(StreamVerifyError::MessageTooLong);
        }
        let msg_hash = *self.hasher.finalize().as_bytes();
        let short = pack_short(&self.salt, &msg_hash);
        self.id.verify_short(self.ctx, &short, self.sig).map_err(|_| StreamVerifyError::InvalidImprint)
    }

    #[cfg(test)]
    fn with_total_bytes(mut self, total: u64) -> Self {
        self.total_bytes = total;
        self
    }
}

#[inline]
fn read_n(slice: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&slice[offset..offset + N]);
    out
}

#[inline]
fn pack_short(salt: &[u8; N], msg_hash: &[u8; 32]) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..].copy_from_slice(msg_hash);
    short
}

fn compute_message_digest(pub_key: &[u8; 32], randomizer: &[u8; N], root: &[u8; N], short: &[u8; SHORT_LEN], ctx: Context<'_>) -> [u8; 32] {
    let mut input = [0u8; MSG_DIGEST_INPUT_MAX_LEN];
    input[..16].copy_from_slice(&tweak(TweakKind::Message, 0, 0, 0, 0, 0));
    input[16..16 + N].copy_from_slice(randomizer);
    input[16 + N..16 + 2 * N].copy_from_slice(root);
    input[16 + 2 * N..16 + 2 * N + SHORT_LEN].copy_from_slice(short);
    let len_off = 16 + 2 * N + SHORT_LEN;
    let ctx_len = ctx.write_framed(&mut input[len_off..]);
    keyed(pub_key, &input[..len_off + ctx_len])
}

fn parse_digest(digest: &[u8; 32]) -> ([u8; FORS_TREES], u64) {
    let mut indices = [0u8; FORS_TREES];
    indices.copy_from_slice(&digest[..FORS_TREES]);
    let mut word = [0u8; 8];
    word.copy_from_slice(&digest[FORS_TREES..FORS_TREES + 8]);
    let leaf_addr = u64::from_le_bytes(word) & ((1u64 << HYPER_BITS) - 1);
    (indices, leaf_addr)
}

fn wots_digits(message: &[u8; N]) -> [u8; CHAINS] {
    let mut out = [0u8; CHAINS];
    let mut csum: u16 = 0;
    for (i, &byte) in message.iter().enumerate() {
        let lo = byte & 0x0f;
        let hi = byte >> 4;
        out[2 * i] = lo;
        out[2 * i + 1] = hi;
        csum += u16::from(CHAIN_STEPS - lo) + u16::from(CHAIN_STEPS - hi);
    }
    for j in 0..CSUM_CHAINS {
        out[MSG_CHAINS + j] = u8::try_from((csum >> (4 * j)) & 0x0f).unwrap();
    }
    out
}

fn wots_pk_from_sig(pub_key: &[u8; 32], layer: u8, tree: u64, leaf: u16, msg: &[u8; N], sig: &[u8]) -> [u8; N] {
    let digits = wots_digits(msg);
    let mut pk_in = [0u8; 16 + CHAINS * N];
    pk_in[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer, tree, leaf, 0, 0));

    let mut step_in = [0u8; 16 + N];
    for (chain, &d) in digits.iter().enumerate() {
        let mut cur = read_n(sig, chain * N);
        let chain_u16 = u16::try_from(chain).unwrap();
        for step in d..CHAIN_STEPS {
            step_in[..16].copy_from_slice(&tweak(TweakKind::Chain, layer, tree, leaf, chain_u16, u32::from(step)));
            step_in[16..].copy_from_slice(&cur);
            cur = keyed_n(pub_key, &step_in);
        }
        pk_in[16 + chain * N..16 + (chain + 1) * N].copy_from_slice(&cur);
    }
    keyed_n(pub_key, &pk_in)
}

fn verify_merkle_path(pub_key: &[u8; 32], layer: u8, tree: u64, leaf: u16, mut node: [u8; N], auth: &[u8]) -> [u8; N] {
    let mut idx = u32::from(leaf);
    let mut pair_in = [0u8; 16 + 2 * N];
    for level in 0..TREE_HEIGHT {
        let sib = read_n(auth, level * N);
        let parent = idx >> 1;
        let level_u16 = u16::try_from(level + 1).unwrap();
        pair_in[..16].copy_from_slice(&tweak(TweakKind::Node, layer, tree, 0, level_u16, parent));
        if idx & 1 == 0 {
            pair_in[16..16 + N].copy_from_slice(&node);
            pair_in[16 + N..].copy_from_slice(&sib);
        } else {
            pair_in[16..16 + N].copy_from_slice(&sib);
            pair_in[16 + N..].copy_from_slice(&node);
        }
        node = keyed_n(pub_key, &pair_in);
        idx = parent;
    }
    node
}

fn verify_fors(pub_key: &[u8; 32], leaf_addr: u64, indices: &[u8; FORS_TREES], sig: &[u8]) -> [u8; N] {
    let mut root_in = [0u8; 16 + FORS_TREES * N];
    root_in[..16].copy_from_slice(&tweak(TweakKind::FewRoot, 0, leaf_addr, 0, 0, 0));

    let mut leaf_in = [0u8; 16 + N];
    let mut pair_in = [0u8; 16 + 2 * N];
    let tree_stride = (1 + FORS_HEIGHT) * N;

    for (t, &idx_u8) in indices.iter().enumerate() {
        let t_u16 = u16::try_from(t).unwrap();
        let base = t * tree_stride;
        let mut idx = u32::from(idx_u8);

        leaf_in[..16].copy_from_slice(&tweak(TweakKind::FewLeaf, 0, leaf_addr, t_u16, 0, idx));
        leaf_in[16..].copy_from_slice(&sig[base..base + N]);
        let mut node = keyed_n(pub_key, &leaf_in);

        for level in 0..FORS_HEIGHT {
            let sib = read_n(sig, base + (1 + level) * N);
            let parent = idx >> 1;
            let level_u16 = u16::try_from(level + 1).unwrap();
            pair_in[..16].copy_from_slice(&tweak(TweakKind::FewNode, 0, leaf_addr, t_u16, level_u16, parent));
            if idx & 1 == 0 {
                pair_in[16..16 + N].copy_from_slice(&node);
                pair_in[16 + N..].copy_from_slice(&sib);
            } else {
                pair_in[16..16 + N].copy_from_slice(&sib);
                pair_in[16 + N..].copy_from_slice(&node);
            }
            node = keyed_n(pub_key, &pair_in);
            idx = parent;
        }
        root_in[16 + t * N..16 + (t + 1) * N].copy_from_slice(&node);
    }
    keyed_n(pub_key, &root_in)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sticky_overflow_poisons_verifier_forever() {
        let id = SignetId::from_bytes(&[0x11u8; SIGNET_ID_LEN]);
        let sig_bytes = [0u8; IMPRINT_LEN];
        let sig = ImprintRef::from_bytes(&sig_bytes);

        let mut v = id.verifier(Context::EMPTY, sig).with_total_bytes(u64::MAX - 2);
        assert_eq!(v.update(b""), Ok(()));
        assert_eq!(v.update(b"ab"), Ok(()));
        assert_eq!(v.update(b"c"), Err(MessageTooLong));
        // Even an empty update or ignoring the earlier error stays poisoned!
        assert_eq!(v.update(b""), Err(MessageTooLong));
        assert_eq!(v.finalize(), Err(StreamVerifyError::MessageTooLong));
    }
}

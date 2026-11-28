//! Standalone `#![no_std]`, zero-allocation, zero-table verifier for **`BLINCS-48-X`** signatures (`3,990` bytes).
//!
//! **Pre-1.0 experimental software (unsupported):** wire formats, context strings, and APIs may
//! change before 1.0, and no independent human cryptographic audit has been performed.
//!
//! This crate verifies [`ImprintRef`] signatures against an expected [`SignetId`] and bounded
//! application [`Context`] using pure-Rust BLAKE3 (`blake3` with `default-features = false`,
//! `features = ["pure"]`), zero static coding lookup tables (closed-form `U-PORS` hexagon
//! unranking and direct 6-bit `WOTS+C` decoding), zero `std`, zero `alloc`, and zero `unsafe`.
//! (The `< 1 KiB` Cortex-M33 stack watermark in `DESIGN.md` / `BENCHMARKS.md` refers to a
//! specialized single-block QEMU harness; this crate holds a full streaming `blake3::Hasher` and
//! fixed stack scratch buffers with zero heap allocation.)
//!
//! Both one-shot slice verification ([`SignetId::verify`]) and incremental streaming verification
//! ([`SignetId::verifier`] -> [`Verifier::update`] -> [`Verifier::finalize`]) are provided.

#![no_std]
#![forbid(unsafe_code)]

use core::array::TryFromSliceError;
use core::error::Error;
use core::fmt;

/// Permanent suite identifier for this BLINCS parameter set (`13+7+7+7+7+7` `WOTS+C` + `U-PORS`, 2⁴⁸ budget).
pub const SUITE_NAME: &str = "BLINCS-48-X";
/// Byte length of a [`SignetId`] wire encoding (`32` bytes: `public_seed || top_root`).
pub const SIGNET_ID_LEN: usize = 32;
/// Byte length of a `BLINCS-48-X` signature (`3,990` bytes).
pub const IMPRINT_LEN: usize = 3990;
/// Maximum byte length of a [`Context`] application domain tag (`255` bytes).
pub const MAX_CONTEXT_LEN: usize = 255;

const N: usize = 16;
const LAYERS: usize = 6;
const LOW_HEIGHT: usize = 7;
const TOP_HEIGHT: usize = 13;
const HYPER_BITS: usize = 5 * LOW_HEIGHT + TOP_HEIGHT;

const WOTS_N: usize = 21;
const WOTS_W: usize = 60;
const WOTS_STEPS: u8 = 59;
const WOTS_SUM: usize = 679;
const WOTS_CTR_LEN: usize = 3;
const WOTS_PK_IN_LEN: usize = 16 + WOTS_N * N;

const UPORS_HEIGHT: usize = 11;
const UPORS_N: usize = 3;
const UPORS_STEPS: u8 = 23;
const UPORS_SUM: usize = 42;
const UPORS_C: usize = 376;
const UPORS_K: usize = 9;
const UPORS_M_MAX: usize = 45;
const UPORS_CTR_LEN: usize = 4;
const UPORS_LAYER_U8: u8 = 0x80;
const UPORS_SELECT_MAX_DRAWS: usize = 18;

const SHORT_LEN: usize = N + 32;
const UPORS_LEN: usize = UPORS_CTR_LEN + (UPORS_K * UPORS_N + UPORS_M_MAX) * N;
const LOW_LAYER_LEN: usize = WOTS_CTR_LEN + (WOTS_N + LOW_HEIGHT) * N;
const TOP_LAYER_LEN: usize = WOTS_CTR_LEN + (WOTS_N + TOP_HEIGHT) * N;
const MSG_DIGEST_INPUT_MAX_LEN: usize = 16 + N + N + SHORT_LEN + 1 + MAX_CONTEXT_LEN;

const _: () = {
    assert!(HYPER_BITS == 48 && WOTS_PK_IN_LEN == 352);
    assert!(UPORS_LEN == 1156 && LOW_LAYER_LEN == 451 && TOP_LAYER_LEN == 547);
    assert!(2 * N + UPORS_LEN + 5 * LOW_LAYER_LEN + TOP_LAYER_LEN == IMPRINT_LEN);
    assert!(MSG_DIGEST_INPUT_MAX_LEN == 352);
};

// Public verifier key-derivation contexts (SPEC.md, "Key-derivation contexts").
const CTX_PUBLIC_HASH: &str = "BLINCS-48-X 2026-11-26 public hash";
const CTX_CONTENT: &str = "BLINCS-48-X 2026-11-26 content";

#[derive(Clone, Copy)]
#[repr(u8)]
enum TweakKind {
    Chain = 2,
    OneTimeKey = 3,
    Node = 4,
    OneTimeMsg = 5,
    Message = 6,
    FewSelect = 7,
    FewCode = 8,
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
fn tweak(kind: TweakKind, layer: u8, tree: u64, leaf: u16, a: u16, b: u32) -> [u8; 16] {
    assert!(tree < (1u64 << 48), "tree index exceeds 48-bit wire field");
    let mut out = [0u8; 16];
    out[0] = kind as u8;
    out[1] = layer;
    out[2..8].copy_from_slice(&tree.to_le_bytes()[..6]);
    out[8..10].copy_from_slice(&leaf.to_le_bytes());
    out[10..12].copy_from_slice(&a.to_le_bytes());
    out[12..16].copy_from_slice(&b.to_le_bytes());
    out
}

#[inline]
fn read_bits(d: &[u8; 32], bit_off: usize, width: usize) -> u64 {
    assert!((1..=57).contains(&width) && bit_off + width <= 256);
    let byte_off = bit_off / 8;
    let shift = bit_off % 8;
    let mut raw = [0u8; 8];
    let avail = (32 - byte_off).min(8);
    raw[..avail].copy_from_slice(&d[byte_off..byte_off + avail]);
    (u64::from_le_bytes(raw) >> shift) & ((1u64 << width) - 1)
}

/// Zero-table closed-form hexagon unranker mapping `idx in 0..376` to `(a, b, c)` in `{0..=23}^3` summing to `42`.
fn hex_unrank(mut idx: u16) -> [u8; UPORS_N] {
    assert!(usize::from(idx) < UPORS_C);
    let w1 = usize::from(UPORS_STEPS);
    let a_lo = UPORS_SUM.saturating_sub(2 * w1);
    let a_hi = UPORS_SUM.min(w1);
    for a in a_lo..=a_hi {
        let rem = UPORS_SUM - a;
        let b_lo = rem.saturating_sub(w1);
        let b_hi = rem.min(w1);
        let len = u16::try_from(b_hi - b_lo + 1).unwrap();
        if idx < len {
            let b = b_lo + usize::from(idx);
            let c = rem - b;
            return [u8::try_from(a).unwrap(), u8::try_from(b).unwrap(), u8::try_from(c).unwrap()];
        }
        idx -= len;
    }
    unreachable!()
}

/// Direct 6-bit `WOTS+C(n = 21, w = 60, z = 2, S = 679)` decoder (`2 + 21 * 6 = 128` bits exact,
/// zero static tables, zero `u128` DP, zero heap, `< 64 B` stack!).
fn decode_wots_c(digest: &[u8; 32]) -> Option<[u8; WOTS_N]> {
    let lo = u128::from_le_bytes(digest[..16].try_into().unwrap());
    if (lo & 3) != 0 {
        return None;
    }
    let mut digits = [0u8; WOTS_N];
    let mut sum = 0usize;
    for (i, slot) in digits.iter_mut().enumerate() {
        let d = u8::try_from((lo >> (2 + 6 * i)) & 63).unwrap();
        if usize::from(d) >= WOTS_W {
            return None;
        }
        *slot = d;
        sum += usize::from(d);
    }
    if sum == WOTS_SUM { Some(digits) } else { None }
}

fn count_octopus_sibs(sorted_leaves: &[u16; UPORS_K]) -> usize {
    let mut cur = *sorted_leaves;
    let mut len = UPORS_K;
    let mut sibs = 0usize;
    for _ in 0..UPORS_HEIGHT {
        let mut out_len = 0usize;
        let mut i = 0usize;
        while i < len {
            let x = cur[i];
            if i + 1 < len && (x ^ 1) == cur[i + 1] {
                cur[out_len] = x >> 1;
                out_len += 1;
                i += 2;
            } else {
                sibs += 1;
                cur[out_len] = x >> 1;
                out_len += 1;
                i += 1;
            }
        }
        len = out_len;
    }
    sibs
}

fn parse_select_digest(d: &[u8; 32]) -> Option<(u64, [u16; UPORS_K], usize)> {
    let mut leaves = [0u16; UPORS_K];
    let mut found = 0usize;
    for i in 0..UPORS_SELECT_MAX_DRAWS {
        let x = u16::try_from(read_bits(d, i * UPORS_HEIGHT, UPORS_HEIGHT)).unwrap();
        if !leaves[..found].contains(&x) {
            leaves[found] = x;
            found += 1;
            if found == UPORS_K {
                break;
            }
        }
    }
    if found < UPORS_K {
        return None;
    }
    for i in 1..UPORS_K {
        let key = leaves[i];
        let mut j = i;
        while j > 0 && leaves[j - 1] > key {
            leaves[j] = leaves[j - 1];
            j -= 1;
        }
        leaves[j] = key;
    }
    let sibs = count_octopus_sibs(&leaves);
    if sibs > UPORS_M_MAX {
        return None;
    }
    let leaf_addr = read_bits(d, UPORS_SELECT_MAX_DRAWS * UPORS_HEIGHT, HYPER_BITS);
    Some((leaf_addr, leaves, sibs))
}

fn extract_upors_codewords(k_pub: &[u8; 32], h_sel: &[u8; 32]) -> Option<[[u8; UPORS_N]; UPORS_K]> {
    let mut msg = [0u8; 48];
    msg[16..48].copy_from_slice(h_sel);

    let mut out = [[0u8; UPORS_N]; UPORS_K];
    let mut got = 0usize;
    for block_idx in 0..=u16::MAX {
        msg[..16].copy_from_slice(&tweak(TweakKind::FewCode, UPORS_LAYER_U8, 0, 0, block_idx, 0));
        let blk = keyed(k_pub, &msg);
        for j in 0..28usize {
            let v = u16::try_from(read_bits(&blk, j * 9, 9)).unwrap();
            if usize::from(v) < UPORS_C {
                out[got] = hex_unrank(v);
                got += 1;
                if got == UPORS_K {
                    return Some(out);
                }
            }
        }
    }
    None
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

/// Returned by [`Verifier::finalize`] when streaming verification fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamVerifyError {
    /// Cumulative streamed message length exceeded `u64::MAX`.
    MessageTooLong,
    /// The imprint is not valid for the expected [`SignetId`], [`Context`], and streamed bytes.
    InvalidImprint,
}

impl fmt::Display for StreamVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLong => f.write_str("streamed message length exceeds u64::MAX bytes"),
            Self::InvalidImprint => f.write_str("invalid BLINCS imprint"),
        }
    }
}

impl Error for StreamVerifyError {}

/// Zero-copy borrowed reference to a 3,990-byte `BLINCS-48-X` signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ImprintRef<'a>(&'a [u8; IMPRINT_LEN]);

impl<'a> ImprintRef<'a> {
    /// Borrow a fixed-length 3,990-byte imprint array.
    pub const fn from_bytes(bytes: &'a [u8; IMPRINT_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 3,990-byte imprint array.
    pub const fn as_bytes(&self) -> &'a [u8; IMPRINT_LEN] {
        self.0
    }

    fn salt(&self) -> &'a [u8; N] {
        self.0[..N].try_into().unwrap()
    }

    fn randomizer(&self) -> &'a [u8; N] {
        self.0[N..2 * N].try_into().unwrap()
    }

    fn upors(&self) -> &'a [u8; UPORS_LEN] {
        self.0[2 * N..2 * N + UPORS_LEN].try_into().unwrap()
    }

    fn layer(&self, layer: usize) -> &'a [u8] {
        let off = 2 * N + UPORS_LEN + layer * LOW_LAYER_LEN;
        let len = if layer == LAYERS - 1 { TOP_LAYER_LEN } else { LOW_LAYER_LEN };
        &self.0[off..off + len]
    }
}

impl<'a> TryFrom<&'a [u8]> for ImprintRef<'a> {
    type Error = TryFromSliceError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self(slice.try_into()?))
    }
}

impl fmt::Debug for ImprintRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImprintRef({SUITE_NAME}, {IMPRINT_LEN} bytes)")
    }
}

/// A publisher's self-certifying 32-byte `BLINCS-48-X` identifier and verifying key (`public_seed || top_root`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignetId([u8; SIGNET_ID_LEN]);

impl SignetId {
    /// Construct a `SignetId` from its 32-byte wire encoding (`public_seed || top_root`).
    pub const fn from_bytes(bytes: &[u8; SIGNET_ID_LEN]) -> Self {
        Self(*bytes)
    }

    /// Borrow the raw 32-byte wire encoding.
    pub const fn as_bytes(&self) -> &[u8; SIGNET_ID_LEN] {
        &self.0
    }

    fn public_seed(&self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.0[..N]);
        out
    }

    fn root(&self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.0[N..]);
        out
    }

    fn derive_msg_key(&self, salt: &[u8; N], ctx: Context<'_>) -> [u8; 32] {
        let content_key = blake3::derive_key(CTX_CONTENT, &self.0);
        let mut buf = [0u8; N + 1 + MAX_CONTEXT_LEN];
        buf[..N].copy_from_slice(salt);
        let ctx_len = ctx.write_framed(&mut buf[N..]);
        keyed(&content_key, &buf[..N + ctx_len])
    }

    /// Verify a 3,990-byte imprint against `ctx` and an in-memory `message` slice (zero allocation).
    #[must_use = "imprint verification result must be checked"]
    pub fn verify(&self, ctx: Context<'_>, message: &[u8], imprint: ImprintRef<'_>) -> Result<(), InvalidImprint> {
        let mut v = self.verifier(ctx, imprint);
        v.update(message).map_err(|_| InvalidImprint)?;
        v.finalize().map_err(|_| InvalidImprint)
    }

    /// Begin incremental, streaming verification of `imprint` under `ctx` (zero allocation).
    pub fn verifier<'a>(&self, ctx: Context<'a>, imprint: ImprintRef<'a>) -> Verifier<'a> {
        let msg_key = self.derive_msg_key(imprint.salt(), ctx);
        Verifier { id: *self, ctx, imprint, hasher: blake3::Hasher::new_keyed(&msg_key), total_bytes: 0, overflowed: false }
    }

    fn verify_with_hash(&self, ctx: Context<'_>, message_hash: &[u8; 32], imprint: ImprintRef<'_>) -> Result<(), InvalidImprint> {
        let k_pub = blake3::derive_key(CTX_PUBLIC_HASH, &self.public_seed());
        let root = self.root();

        let mut short = [0u8; SHORT_LEN];
        short[..N].copy_from_slice(imprint.salt());
        short[N..].copy_from_slice(message_hash);

        let mut msg_buf = [0u8; MSG_DIGEST_INPUT_MAX_LEN];
        msg_buf[..16].copy_from_slice(&tweak(TweakKind::Message, 0, 0, 0, 0, 0));
        msg_buf[16..32].copy_from_slice(imprint.randomizer());
        msg_buf[32..48].copy_from_slice(&root);
        msg_buf[48..96].copy_from_slice(&short);
        let ctx_len = ctx.write_framed(&mut msg_buf[96..]);
        let d_seed = keyed(&k_pub, &msg_buf[..96 + ctx_len]);

        let upors_slice = imprint.upors();
        let ctr_ft = u32::from_le_bytes(upors_slice[..UPORS_CTR_LEN].try_into().unwrap());
        let mut sel_msg = [0u8; 52];
        sel_msg[..16].copy_from_slice(&tweak(TweakKind::FewSelect, UPORS_LAYER_U8, 0, 0, 0, 0));
        sel_msg[16..48].copy_from_slice(&d_seed);
        sel_msg[48..52].copy_from_slice(&ctr_ft.to_le_bytes());
        let d_sel = keyed(&k_pub, &sel_msg);
        let (leaf_addr, leaves, sibs) = parse_select_digest(&d_sel).ok_or(InvalidImprint)?;
        let codewords = extract_upors_codewords(&k_pub, &d_sel).ok_or(InvalidImprint)?;
        let mut node = upors_verify(&k_pub, leaf_addr, &leaves, sibs, &codewords, upors_slice).ok_or(InvalidImprint)?;

        let mut addr = leaf_addr;
        for layer in 0..LAYERS {
            let h_l = if layer == LAYERS - 1 { TOP_HEIGHT } else { LOW_HEIGHT };
            let leaf = u16::try_from(addr & ((1u64 << h_l) - 1)).unwrap();
            let tree = addr >> h_l;
            addr = tree;
            node = verify_layer(&k_pub, u8::try_from(layer).unwrap(), h_l, tree, leaf, &node, imprint.layer(layer)).ok_or(InvalidImprint)?;
        }

        if constant_time_eq::constant_time_eq_16(&node, &root) { Ok(()) } else { Err(InvalidImprint) }
    }
}

impl TryFrom<&[u8]> for SignetId {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(slice.try_into()?))
    }
}

impl fmt::Debug for SignetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignetId(")?;
        for &b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// Streaming single-pass `#![no_std]` verifier returned by [`SignetId::verifier`].
#[must_use = "imprint verification is not complete until finalize() succeeds"]
pub struct Verifier<'a> {
    id: SignetId,
    ctx: Context<'a>,
    imprint: ImprintRef<'a>,
    hasher: blake3::Hasher,
    total_bytes: u64,
    overflowed: bool,
}

impl fmt::Debug for Verifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier").field("id", &self.id).field("total_bytes", &self.total_bytes).field("overflowed", &self.overflowed).finish()
    }
}

impl Verifier<'_> {
    /// Feed the next message chunk into the salted BLAKE3 stream.
    ///
    /// Fails closed with [`StreamVerifyError::MessageTooLong`] if the cumulative byte length exceeds `u64::MAX`,
    /// poisoning subsequent calls to [`Verifier::update`] and [`Verifier::finalize`].
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), StreamVerifyError> {
        if self.overflowed {
            return Err(StreamVerifyError::MessageTooLong);
        }
        let Ok(n) = u64::try_from(bytes.len()) else {
            self.overflowed = true;
            return Err(StreamVerifyError::MessageTooLong);
        };
        let Some(total) = self.total_bytes.checked_add(n) else {
            self.overflowed = true;
            return Err(StreamVerifyError::MessageTooLong);
        };
        self.total_bytes = total;
        self.hasher.update(bytes);
        Ok(())
    }

    /// Finish streaming and verify the imprint against the expected [`SignetId`], [`Context`], and streamed bytes.
    #[must_use = "imprint verification result must be checked"]
    pub fn finalize(self) -> Result<(), StreamVerifyError> {
        if self.overflowed {
            return Err(StreamVerifyError::MessageTooLong);
        }
        let message_hash = *self.hasher.finalize().as_bytes();
        self.id.verify_with_hash(self.ctx, &message_hash, self.imprint).map_err(|_| StreamVerifyError::InvalidImprint)
    }
}

fn upors_verify(
    k_pub: &[u8; 32],
    tree: u64,
    leaves: &[u16; UPORS_K],
    expected_sibs: usize,
    codewords: &[[u8; UPORS_N]; UPORS_K],
    sig: &[u8; UPORS_LEN],
) -> Option<[u8; N]> {
    let chains_off = UPORS_CTR_LEN;
    let octo_off = UPORS_CTR_LEN + UPORS_K * UPORS_N * N;

    let mut cur_val = [[0u8; N]; UPORS_K];
    let mut step_buf = [0u8; 32];
    let mut leaf_buf = [0u8; 64];
    for t in 0..UPORS_K {
        let leaf = leaves[t];
        leaf_buf[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, UPORS_LAYER_U8, tree, leaf, 0, 0));
        for c in 0..UPORS_N {
            let off = chains_off + (t * UPORS_N + c) * N;
            let mut val: [u8; N] = sig[off..off + N].try_into().unwrap();
            let c_u16 = u16::try_from(c).unwrap();
            for step in codewords[t][c]..UPORS_STEPS {
                step_buf[..16].copy_from_slice(&tweak(TweakKind::Chain, UPORS_LAYER_U8, tree, leaf, c_u16, u32::from(step)));
                step_buf[16..32].copy_from_slice(&val);
                val = keyed_n(k_pub, &step_buf);
            }
            leaf_buf[16 + c * N..16 + (c + 1) * N].copy_from_slice(&val);
        }
        cur_val[t] = keyed_n(k_pub, &leaf_buf);
    }

    let mut cur_idx = *leaves;
    let mut cur_len = UPORS_K;
    let mut sib_cursor = 0usize;
    let mut pair_buf = [0u8; 48];
    for level in 1..=UPORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let mut next_len = 0usize;
        let mut i = 0usize;
        while i < cur_len {
            let x = cur_idx[i];
            let p = x >> 1;
            pair_buf[..16].copy_from_slice(&tweak(TweakKind::Node, UPORS_LAYER_U8, tree, 0, level_u16, u32::from(p)));
            if i + 1 < cur_len && (x ^ 1) == cur_idx[i + 1] {
                pair_buf[16..32].copy_from_slice(&cur_val[i]);
                pair_buf[32..48].copy_from_slice(&cur_val[i + 1]);
                i += 2;
            } else {
                let off = octo_off + sib_cursor * N;
                let sib = &sig[off..off + N];
                sib_cursor += 1;
                if (x & 1) == 0 {
                    pair_buf[16..32].copy_from_slice(&cur_val[i]);
                    pair_buf[32..48].copy_from_slice(sib);
                } else {
                    pair_buf[16..32].copy_from_slice(sib);
                    pair_buf[32..48].copy_from_slice(&cur_val[i]);
                }
                i += 1;
            }
            cur_val[next_len] = keyed_n(k_pub, &pair_buf);
            cur_idx[next_len] = p;
            next_len += 1;
        }
        cur_len = next_len;
    }
    assert_eq!(sib_cursor, expected_sibs);

    let pad = &sig[octo_off + sib_cursor * N..octo_off + UPORS_M_MAX * N];
    let zeros = [0u8; UPORS_M_MAX * N];
    if !constant_time_eq::constant_time_eq(pad, &zeros[..pad.len()]) {
        return None;
    }
    Some(cur_val[0])
}

fn verify_layer(k_pub: &[u8; 32], layer: u8, height: usize, tree: u64, leaf: u16, child_root: &[u8; N], layer_sig: &[u8]) -> Option<[u8; N]> {
    let ctr = u32::from_le_bytes([layer_sig[0], layer_sig[1], layer_sig[2], 0]);
    let mut msg = [0u8; 36];
    msg[..16].copy_from_slice(&tweak(TweakKind::OneTimeMsg, layer, tree, leaf, 0, 0));
    msg[16..32].copy_from_slice(child_root);
    msg[32..36].copy_from_slice(&ctr.to_le_bytes());
    let h = keyed(k_pub, &msg);
    let digits = decode_wots_c(&h)?;

    let chains_off = WOTS_CTR_LEN;
    let auth_off = WOTS_CTR_LEN + WOTS_N * N;
    let mut pk_buf = [0u8; WOTS_PK_IN_LEN];
    pk_buf[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer, tree, leaf, 0, 0));
    let mut step_buf = [0u8; 32];
    for c in 0..WOTS_N {
        let off = chains_off + c * N;
        let mut val: [u8; N] = layer_sig[off..off + N].try_into().unwrap();
        let c_u16 = u16::try_from(c).unwrap();
        for step in digits[c]..WOTS_STEPS {
            step_buf[..16].copy_from_slice(&tweak(TweakKind::Chain, layer, tree, leaf, c_u16, u32::from(step)));
            step_buf[16..32].copy_from_slice(&val);
            val = keyed_n(k_pub, &step_buf);
        }
        pk_buf[16 + c * N..16 + (c + 1) * N].copy_from_slice(&val);
    }

    let mut node = keyed_n(k_pub, &pk_buf);
    let mut idx = usize::from(leaf);
    let mut pair_buf = [0u8; 48];
    for level in 0..height {
        let sib = &layer_sig[auth_off + level * N..auth_off + (level + 1) * N];
        pair_buf[..16].copy_from_slice(&tweak(TweakKind::Node, layer, tree, 0, u16::try_from(level + 1).unwrap(), u32::try_from(idx >> 1).unwrap()));
        if (idx & 1) == 0 {
            pair_buf[16..32].copy_from_slice(&node);
            pair_buf[32..48].copy_from_slice(sib);
        } else {
            pair_buf[16..32].copy_from_slice(sib);
            pair_buf[32..48].copy_from_slice(&node);
        }
        node = keyed_n(k_pub, &pair_buf);
        idx >>= 1;
    }
    Some(node)
}

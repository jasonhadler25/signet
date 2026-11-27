//! Signet — a Rust implementation of the **BLINCS** (`BLINCS-128-A2`) stateless hash-based
//! post-quantum signature algorithm, based on BLAKE3 and SPHINCS.
//!
//! **Pre-1.0 experimental software (unsupported):** formats, context strings, and APIs may change
//! incompatibly before 1.0, and no independent human cryptographic audit has been performed.
//!
//! Designed for post-quantum use with a 128-bit classical security target at up to 2³² imprints
//! per signet (do not imprint more than 2³² things with one signet; see `SPEC.md` for bounds).
//! Runs strictly on the calling thread (`blake3-servil-core`; no background worker threads) with
//! a `12+7+7+7` `S-WOTS+Z` hypertree (`128 KiB` cached top tree) and zero-ROM single-tree
//! `U-PORS` Octopus few-time signatures (`3,292`-byte imprints).
//! Supported platforms: Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`).
//! Because a cryptographic key is a transferable bearer authority rather than a person's handwritten
//! signature, this API calls the secret a [`Signet`], its 32-byte self-certifying identifier a
//! [`SignetId`] (which names which signet you mean and verifies its imprints), and the 3,292-byte
//! proof an [`Imprint`]. Pass a domain-separating [`Context`] and the original message bytes or
//! stream directly: BLINCS hashes the input in a single salted keyed-BLAKE3 pass under a fresh
//! per-imprint salt.
//!
//! ```no_run
//! use signet::{Context, Randomness, Signet, SignetId, VerifyError};
//!
//! const RELEASE_CTX: Context<'static> = Context::new(b"example.org release manifest v1");
//!
//! Randomness::create("/path/to/signet.salt")?;
//! let randomness = Randomness::initialize("/path/to/signet.salt")?;
//! let publisher = Signet::generate(&randomness)?;
//! let expected_publisher: SignetId = publisher.id();
//!
//! let imprint = publisher.imprint(&randomness, RELEASE_CTX, b"hello, BLINCS");
//! expected_publisher.verify(RELEASE_CTX, b"hello, BLINCS", &imprint)?;
//!
//! // Streaming or structured messages push bytes into a `Sink` (which implements `std::io::Write`):
//! let streamed = publisher.imprint_with(&randomness, RELEASE_CTX, |sink| {
//!     sink.update(b"hello, ");
//!     sink.update(b"BLINCS");
//!     Ok::<(), std::io::Error>(())
//! })?;
//! expected_publisher.verify_with(RELEASE_CTX, &streamed, |sink| {
//!     std::io::copy(&mut &b"hello, BLINCS"[..], sink)?;
//!     Ok::<(), std::io::Error>(())
//! })?;
//!
//! // A valid imprint from a different signet or a different context must be rejected.
//! let other = Signet::generate(&randomness)?;
//! let other_imprint = other.imprint(&randomness, RELEASE_CTX, b"hello, BLINCS");
//! assert!(expected_publisher.verify(RELEASE_CTX, b"hello, BLINCS", &other_imprint).is_err());
//! assert!(expected_publisher.verify(Context::new(b"other-protocol"), b"hello, BLINCS", &imprint).is_err());
//! # Ok::<(), VerifyError>(())
//! ```

#![forbid(unsafe_code)]

mod coding;
mod content;
mod few_time;
mod one_time;
mod params;
mod randomness;

#[cfg(test)]
mod test;

pub use content::Sink;
pub use params::{IMPRINT_LEN, MAX_CONTEXT_LEN, SEED_LEN, SIGNET_ID_LEN, SUITE_NAME};
pub use randomness::Randomness;

use content::{content_from_slice, content_with};
use few_time::{extract_upors_codewords, upors_verify, verify_upors_selection};
use one_time::{build_top_tree, sign_superwave, verify_layer};
use params::{
    CTX_CONTENT, CTX_CONTENT_SALT, CTX_GENERATE_SIGNET, CTX_PUBLIC_SEED, CTX_RANDOMIZER, Layer, N, PublicKey, SHORT_LEN, SecretKey, TweakKind, UPORS_CTR_LEN,
    UPORS_LEN, derive_key, ensure_init, first_n, keyed, tweak,
};
use randomness::read_os_randomness;
use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt;
use std::io;

/// Error returned when a [`Context`] exceeds [`MAX_CONTEXT_LEN`] (`255`) bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextTooLong {
    /// Actual byte length supplied by the caller.
    pub len: usize,
}

impl fmt::Display for ContextTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BLINCS application context length {} exceeds maximum {MAX_CONTEXT_LEN} bytes", self.len)
    }
}

impl Error for ContextTooLong {}

/// Bounded application domain-separation context (`0..=255` bytes) bound into every imprint.
///
/// Using a distinct `Context` per protocol or message purpose prevents cross-protocol replay
/// under the same [`SignetId`]. Construct static contexts at compile time with [`Context::new`],
/// or validate runtime byte slices with [`Context::try_new`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Context<'a>(&'a [u8]);

impl<'a> Context<'a> {
    /// Empty application context (`b""`). Prefer a non-empty protocol-specific label.
    pub const EMPTY: Self = Self(b"");

    /// Construct a `Context` from a byte slice of at most [`MAX_CONTEXT_LEN`] (`255`) bytes.
    ///
    /// Panics if `bytes.len() > MAX_CONTEXT_LEN` (fails at compile time when used in a `const`).
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        assert!(bytes.len() <= MAX_CONTEXT_LEN, "BLINCS application context exceeds 255 bytes");
        Self(bytes)
    }

    /// Validate a runtime byte slice as a `Context` (`<= 255` bytes).
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

    /// Write the length-prefixed frame `u8(len) || bytes` into `dst` and return bytes written (`1 + len`).
    pub(crate) fn write_framed(&self, dst: &mut [u8]) -> usize {
        let len = self.0.len();
        dst[0] = u8::try_from(len).unwrap();
        dst[1..1 + len].copy_from_slice(self.0);
        1 + len
    }
}

impl<'a> TryFrom<&'a [u8]> for Context<'a> {
    type Error = ContextTooLong;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

/// Imprint verification failed: the imprint is not valid for this [`SignetId`], [`Context`], and message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidImprint;

impl fmt::Display for InvalidImprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid BLINCS imprint")
    }
}

impl Error for InvalidImprint {}

/// Error returned by [`SignetId::verify_with`], distinguishing producer failure from an invalid imprint.
#[derive(Debug)]
pub enum VerifyError<E = io::Error> {
    /// Producing the message bytes failed.
    Source(E),
    /// The imprint is not valid for this [`SignetId`], [`Context`], and message.
    Invalid,
}

impl<E: fmt::Display> fmt::Display for VerifyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(e) => write!(f, "failed to produce message bytes: {e}"),
            Self::Invalid => f.write_str("invalid BLINCS imprint"),
        }
    }
}

impl<E: Error + 'static> Error for VerifyError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(e) => Some(e),
            Self::Invalid => None,
        }
    }
}

impl From<io::Error> for VerifyError<io::Error> {
    fn from(err: io::Error) -> Self {
        Self::Source(err)
    }
}

impl<E> From<InvalidImprint> for VerifyError<E> {
    fn from(_: InvalidImprint) -> Self {
        Self::Invalid
    }
}

fn ct_eq_n(a: &[u8; N], b: &[u8; N]) -> bool {
    constant_time_eq::constant_time_eq_16(a, b)
}

fn fmt_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

const RANDOMIZER_INPUT_MAX_LEN: usize = SHORT_LEN + 1 + MAX_CONTEXT_LEN;
const MSG_DIGEST_INPUT_MAX_LEN: usize = 16 + N + N + SHORT_LEN + 1 + MAX_CONTEXT_LEN;
const _: () = assert!(RANDOMIZER_INPUT_MAX_LEN == 304 && MSG_DIGEST_INPUT_MAX_LEN == 352);

pub(crate) fn compute_randomizer(randomizer_key: &[u8; 32], short: &[u8; SHORT_LEN], ctx: Context<'_>) -> [u8; N] {
    let mut buf = [0u8; RANDOMIZER_INPUT_MAX_LEN];
    buf[..SHORT_LEN].copy_from_slice(short);
    let ctx_len = ctx.write_framed(&mut buf[SHORT_LEN..]);
    first_n(&keyed(randomizer_key, &buf[..SHORT_LEN + ctx_len]))
}

pub(crate) fn compute_message_digest(public_key: &PublicKey, randomizer: &[u8; N], root: &[u8; N], short: &[u8; SHORT_LEN], ctx: Context<'_>) -> [u8; 32] {
    let mut buf = [0u8; MSG_DIGEST_INPUT_MAX_LEN];
    buf[..16].copy_from_slice(&tweak(TweakKind::Message, 0, 0, 0, 0, 0));
    buf[16..32].copy_from_slice(randomizer);
    buf[32..48].copy_from_slice(root);
    buf[48..96].copy_from_slice(short);
    let ctx_len = ctx.write_framed(&mut buf[96..]);
    public_key.keyed(&buf[..96 + ctx_len])
}

/// A 3,292-byte `BLINCS-128-A2` imprint (proof produced by pressing a [`Signet`] onto a context and message).
#[derive(Clone, PartialEq, Eq)]
pub struct Imprint([u8; IMPRINT_LEN]);

impl Imprint {
    /// Wrap a raw 3,292-byte imprint array.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; IMPRINT_LEN]) -> Self {
        Self(*bytes)
    }

    /// Borrow the raw 3,292 imprint bytes.
    pub fn as_bytes(&self) -> &[u8; IMPRINT_LEN] {
        &self.0
    }

    fn salt(&self) -> &[u8; N] {
        self.0[..N].try_into().unwrap()
    }

    fn randomizer(&self) -> &[u8; N] {
        self.0[N..2 * N].try_into().unwrap()
    }

    fn upors(&self) -> &[u8; UPORS_LEN] {
        self.0[2 * N..2 * N + UPORS_LEN].try_into().unwrap()
    }

    fn layer(&self, layer: Layer) -> &[u8] {
        let off = layer.sig_offset();
        &self.0[off..off + layer.layer_len()]
    }
}

impl TryFrom<&[u8]> for Imprint {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(slice.try_into()?))
    }
}

impl fmt::Debug for Imprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Imprint({SUITE_NAME}, {IMPRINT_LEN} bytes, salt=")?;
        fmt_hex(f, self.salt())?;
        f.write_str(")")
    }
}

/// A publisher's self-certifying 32-byte identifier and its complete `BLINCS-128-A2` verifying key (`public_seed || top_root`).
///
/// Receiving a `SignetId` does not authenticate the sender: obtain the expected `SignetId` from a
/// pinned or authenticated channel and call `expected_publisher.verify(ctx, message, &imprint)?`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignetId {
    bytes: [u8; SIGNET_ID_LEN],
    public_key: PublicKey,
    content_key: [u8; 32],
}

impl TryFrom<&[u8]> for SignetId {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(slice.try_into()?))
    }
}

impl fmt::Debug for SignetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignetId(")?;
        fmt_hex(f, &self.bytes)?;
        f.write_str(")")
    }
}

impl SignetId {
    /// Construct a signet identifier from its 32-byte wire encoding (`public_seed || top_root`).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SIGNET_ID_LEN]) -> Self {
        ensure_init();
        let public_key = PublicKey::from_seed(bytes[..N].try_into().unwrap());
        let content_key = derive_key(CTX_CONTENT, bytes);
        Self { bytes: *bytes, public_key, content_key }
    }

    /// The 32-byte wire encoding of this signet identifier.
    pub fn as_bytes(&self) -> &[u8; SIGNET_ID_LEN] {
        &self.bytes
    }

    fn root(&self) -> &[u8; N] {
        self.bytes[N..].try_into().unwrap()
    }

    /// Verify that `imprint` was made by this signet for `ctx` and an in-memory `message` slice (zero heap allocation).
    ///
    /// Fails closed: returns `Ok(())` only if the imprint is valid. Verify against an expected
    /// [`SignetId`] obtained from a pinned or authenticated channel.
    #[must_use = "imprint verification result must be checked"]
    pub fn verify(&self, ctx: Context<'_>, message: &[u8], imprint: &Imprint) -> Result<(), InvalidImprint> {
        let short = content_from_slice(&self.content_key, imprint.salt(), ctx, message);
        self.verify_short(ctx, &short, imprint)
    }

    /// Verify that `imprint` was made by this signet for `ctx` and bytes streamed into [`Sink`]
    /// by `produce` in one salted pass (zero heap allocation).
    ///
    /// Fails closed: returns `Ok(())` only if `produce` succeeds without overflow and the imprint
    /// is valid. For any `std::io::Read` source, call `std::io::copy(&mut reader, sink)` inside
    /// `produce`. Verify against an expected [`SignetId`] obtained from a pinned or authenticated
    /// channel.
    #[must_use = "imprint verification result must be checked"]
    pub fn verify_with<E>(&self, ctx: Context<'_>, imprint: &Imprint, produce: impl FnOnce(&mut Sink) -> Result<(), E>) -> Result<(), VerifyError<E>> {
        let Some(short) = content_with(&self.content_key, imprint.salt(), ctx, produce).map_err(VerifyError::Source)? else {
            return Err(VerifyError::Invalid);
        };
        self.verify_short(ctx, &short, imprint)?;
        Ok(())
    }

    pub(crate) fn verify_short(&self, ctx: Context<'_>, short: &[u8; SHORT_LEN], imprint: &Imprint) -> Result<(), InvalidImprint> {
        if !ct_eq_n(imprint.salt(), short[..N].try_into().unwrap()) {
            return Err(InvalidImprint);
        }
        let d_seed = compute_message_digest(&self.public_key, imprint.randomizer(), self.root(), short, ctx);
        let public = self.public_key.hasher(false);
        let upors_slice = imprint.upors();
        let ctr_ft = u32::from_le_bytes(upors_slice[..UPORS_CTR_LEN].try_into().unwrap());
        let sel = verify_upors_selection(&public, &d_seed, ctr_ft).ok_or(InvalidImprint)?;
        let codewords = extract_upors_codewords(&self.public_key, &d_seed, ctr_ft);
        let mut node = upors_verify(&public, &sel, &codewords, upors_slice).ok_or(InvalidImprint)?;
        let coords = sel.leaf_addr.split_layers();
        for layer in Layer::ALL {
            let (tree, leaf) = coords[layer.index()];
            node = verify_layer(&public, layer, tree, leaf, &node, imprint.layer(layer)).ok_or(InvalidImprint)?;
        }
        if ct_eq_n(&node, self.root()) { Ok(()) } else { Err(InvalidImprint) }
    }
}

/// A `BLINCS-128-A2` signet (bearer authority derived from a 32-byte seed, caching the `128 KiB` height-12 top hypertree in memory).
pub struct Signet {
    seed: [u8; SEED_LEN],
    secret_key: SecretKey,
    salt_key: [u8; 32],
    randomizer_key: [u8; 32],
    id: SignetId,
    top_tree: Box<[[u8; N]]>,
}

impl fmt::Debug for Signet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signet({:?})", self.id)
    }
}

/// Pure key-generation seed combiner (`SPEC.md`, "Key-derivation contexts").
pub(crate) fn generate_seed(local: &[u8; 32], os: &[u8; 32]) -> [u8; SEED_LEN] {
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(local);
    material[32..].copy_from_slice(os);
    derive_key(CTX_GENERATE_SIGNET, &material)
}

impl Signet {
    /// Generate a fresh signet by mixing a domain-separated draw from `randomness` with fresh OS
    /// randomness (`getrandom`). Persist [`Signet::seed`] securely if you need to reload this signet.
    pub fn generate(randomness: &Randomness) -> io::Result<Self> {
        let seed = generate_seed(&randomness.draw_for_keygen(), &read_os_randomness()?);
        Ok(Self::from_seed(&seed))
    }

    /// Derive a signet from a persisted 32-byte `seed`, building and caching the `128 KiB`
    /// height-12 top hypertree on the calling thread.
    ///
    /// Performs no entropy check on `seed`. For creating new signets, use [`Signet::generate`].
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        ensure_init();
        let secret_key = SecretKey::derive(seed);
        let salt_key = derive_key(CTX_CONTENT_SALT, seed);
        let randomizer_key = derive_key(CTX_RANDOMIZER, seed);
        let public_seed = first_n(&derive_key(CTX_PUBLIC_SEED, seed));
        let public_key = PublicKey::from_seed(&public_seed);

        let top_tree = build_top_tree(&secret_key, &public_key);

        let mut id_bytes = [0u8; SIGNET_ID_LEN];
        id_bytes[..N].copy_from_slice(&public_seed);
        id_bytes[N..].copy_from_slice(&top_tree[1]);
        Self { seed: *seed, secret_key, salt_key, randomizer_key, id: SignetId::from_bytes(&id_bytes), top_tree }
    }

    /// The 32-byte seed from which this signet was derived.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The 32-byte identifier of this signet.
    pub fn id(&self) -> SignetId {
        self.id
    }

    fn finish_imprint(&self, ctx: Context<'_>, short: &[u8; SHORT_LEN]) -> Imprint {
        let salt: &[u8; N] = short[..N].try_into().unwrap();
        let randomizer = compute_randomizer(&self.randomizer_key, short, ctx);
        let d_seed = compute_message_digest(&self.id.public_key, &randomizer, self.id.root(), short, ctx);
        let sig = sign_superwave(&self.secret_key, &self.id.public_key, salt, &randomizer, &d_seed, &self.top_tree);
        let imprint = Imprint(sig);
        assert!(self.id.verify_short(ctx, short, &imprint).is_ok(), "internal error: generated imprint failed self-verification");
        imprint
    }

    pub(crate) fn imprint_with_draw(&self, draw: &[u8; 32], ctx: Context<'_>, message: &[u8]) -> Imprint {
        ensure_init();
        let salt = first_n(&keyed(&self.salt_key, draw));
        let short = content_from_slice(&self.id.content_key, &salt, ctx, message);
        self.finish_imprint(ctx, &short)
    }

    pub(crate) fn imprint_with_draw_stream<E>(
        &self,
        draw: &[u8; 32],
        ctx: Context<'_>,
        produce: impl FnOnce(&mut Sink) -> Result<(), E>,
    ) -> Result<Imprint, E> {
        ensure_init();
        let salt = first_n(&keyed(&self.salt_key, draw));
        let short = content_with(&self.id.content_key, &salt, ctx, produce)?.expect("stream length exceeds u64::MAX");
        Ok(self.finish_imprint(ctx, &short))
    }

    /// Imprint an in-memory `message` under `ctx`, drawing fresh per-imprint randomness from `randomness`.
    ///
    /// Self-verifies the finished imprint against `short` before returning. Do not imprint more
    /// than 2³² things with one signet.
    #[must_use]
    pub fn imprint(&self, randomness: &Randomness, ctx: Context<'_>, message: &[u8]) -> Imprint {
        let draw = randomness.draw();
        self.imprint_with_draw(&draw, ctx, message)
    }

    /// Imprint bytes streamed into [`Sink`] by `produce` under `ctx` in one salted pass, drawing
    /// fresh per-imprint randomness from `randomness`.
    ///
    /// Signet chooses the fresh salt and initializes keyed BLAKE3 before invoking `produce`; if
    /// `produce` returns `Err(e)`, imprinting aborts and returns `Err(e)`. For any `std::io::Read`
    /// source, call `std::io::copy(&mut reader, sink)` inside `produce`. Self-verifies the
    /// finished imprint against `short` before returning. Do not imprint more than 2³² things with
    /// one signet.
    pub fn imprint_with<E>(&self, randomness: &Randomness, ctx: Context<'_>, produce: impl FnOnce(&mut Sink) -> Result<(), E>) -> Result<Imprint, E> {
        let draw = randomness.draw();
        self.imprint_with_draw_stream(&draw, ctx, produce)
    }
}

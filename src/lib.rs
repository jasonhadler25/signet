//! BLINCS: stateless hash-based signatures on BLAKE3.
//!
//! A signature is 3,988 bytes, a verifying key is 32 bytes, and a signing key is a 32-byte seed.
//! Messages are hashed in 256 KiB chunks under a per-signature salt, reading each chunk twice; passing the
//! message or stream directly to BLINCS relies on second-preimage resistance rather than collision
//! resistance, and hashes at BLAKE3 speed.
//!
//! ```
//! use blincs::{Randomness, SigningKey, VerifyingKey};
//!
//! let dir = std::env::temp_dir().join(format!("blincs-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&dir).unwrap();
//! let state = dir.join("state.bin");
//! let _ = std::fs::remove_file(&state);
//!
//! Randomness::create(&state).unwrap();
//! let rng = Randomness::initialize(&state).unwrap();
//!
//! let seed = [42u8; blincs::SEED_LEN];
//! let signing_key = SigningKey::from_seed(&seed);
//! let verifying_key = VerifyingKey::from_bytes(signing_key.verifying_key().as_bytes());
//!
//! let signature = signing_key.sign(&rng, b"hello, BLINCS");
//! assert!(verifying_key.verify(b"hello, BLINCS", &signature));
//! assert!(!verifying_key.verify(b"other message", &signature));
//! # let _ = std::fs::remove_dir_all(&dir);
//! ```

#![forbid(unsafe_code)]

mod content;
mod few_time;
mod one_time;
mod params;
mod randomness;
mod workspace;

pub use params::{CHUNK_LEN, SEED_LEN, SIGNATURE_LEN, VERIFYING_KEY_LEN};
pub use randomness::Randomness;

use content::{content_from_reader, content_from_slice, derive_salt_slice};
use few_time::{few_time_sign, few_time_verify};
use one_time::{Pos, build_tree, sign_layer, sign_top_layer, verify_layer};
use params::{
    CTX_CONTENT, CTX_CONTENT_SALT, CTX_PUBLIC_HASH, CTX_PUBLIC_SEED, CTX_RANDOMIZER, CTX_SECRET_VALUES, FEW_LEN, KIND_MESSAGE, LAYER_LEN, LAYERS, N, SHORT_LEN,
    TOP_NODES, TREE_HEIGHT, derive_key, first_n, keyed, tweak,
};
use std::array::TryFromSliceError;
use std::fmt;
use std::io::{self, Read};
use workspace::{SignWorkspace, with_sign_workspace, with_verify_workspace};

/// A 3,988-byte BLINCS signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    bytes: Box<[u8; SIGNATURE_LEN]>,
}

impl Signature {
    /// Wrap a 3,988-byte array as a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
        Self { bytes: Box::new(*bytes) }
    }

    /// Borrow the 3,988 signature bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: &[u8; SIGNATURE_LEN] = slice.try_into()?;
        Ok(Self::from_bytes(arr))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({SIGNATURE_LEN} bytes, salt=")?;
        for b in &self.bytes[..N] {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A 32-byte BLINCS verifying key (`public_seed || top_root`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; VERIFYING_KEY_LEN],
    public: [u8; 32],
    content_key: [u8; 32],
}

impl VerifyingKey {
    /// Load a verifying key from its 32-byte representation.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {
        blake3_servil_core::initialize();
        let public = derive_key(CTX_PUBLIC_HASH, &bytes[..N]);
        let content_key = derive_key(CTX_CONTENT, bytes);
        Self { bytes: *bytes, public, content_key }
    }

    /// Borrow the 32 verifying-key bytes.
    pub fn as_bytes(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.bytes
    }

    fn root(&self) -> &[u8] {
        &self.bytes[N..]
    }

    fn message_digest(&self, randomizer: &[u8; N], short: &[u8; SHORT_LEN]) -> [u8; 32] {
        let mut input = [0u8; 16 + N + N + SHORT_LEN];
        input[..16].copy_from_slice(&tweak(KIND_MESSAGE, 0, 0, 0, 0, 0));
        input[16..16 + N].copy_from_slice(randomizer);
        input[16 + N..16 + 2 * N].copy_from_slice(self.root());
        input[16 + 2 * N..].copy_from_slice(short);
        keyed(&self.public, &input)
    }

    pub(crate) fn verify_short(&self, short: &[u8; SHORT_LEN], signature: &Signature) -> bool {
        let sig = signature.as_bytes();
        let randomizer: [u8; N] = sig[N..2 * N].try_into().unwrap();
        let digest = self.message_digest(&randomizer, short);
        with_verify_workspace(|ws| {
            let Some((mut tree, mut leaf, mut node)) = few_time_verify(&self.public, &digest, &sig[2 * N..2 * N + FEW_LEN], ws) else {
                return false;
            };
            let mut at = 2 * N + FEW_LEN;
            for layer in 0..LAYERS {
                let pos = Pos { layer: layer as u8, tree, leaf };
                let Some(next) = verify_layer(&self.public, pos, &node, &sig[at..at + LAYER_LEN], ws) else {
                    return false;
                };
                node = next;
                leaf = (tree & ((1u64 << TREE_HEIGHT) - 1)) as u16;
                tree >>= TREE_HEIGHT;
                at += LAYER_LEN;
            }
            node == self.root()
        })
    }

    /// Verify `signature` over an in-memory `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let salt: [u8; N] = signature.as_bytes()[..N].try_into().unwrap();
        let short = content_from_slice(&self.content_key, &salt, message);
        self.verify_short(&short, signature)
    }

    /// Verify `signature` over a streaming `reader`, hashing in 256 KiB chunks.
    pub fn verify_reader(&self, reader: impl Read, signature: &Signature) -> io::Result<bool> {
        let salt: [u8; N] = signature.as_bytes()[..N].try_into().unwrap();
        let (_, short) = with_verify_workspace(|ws| content_from_reader(&self.content_key, Ok(salt), reader, ws.chunk_buf()))?;
        Ok(self.verify_short(&short, signature))
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifyingKey(")?;
        for b in &self.bytes {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A BLINCS signing key derived from a caller-supplied 32-byte seed.
///
/// The top hypertree tree (16 KiB) is computed once on load and kept inside the key, so each signature
/// builds three hypertree trees instead of four.
pub struct SigningKey {
    seed: [u8; SEED_LEN],
    secret: [u8; 32],
    salt_key: [u8; 32],
    randomizer_key: [u8; 32],
    verifying_key: VerifyingKey,
    top: Box<[[u8; N]; TOP_NODES]>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({:?})", self.verifying_key)
    }
}

impl SigningKey {
    /// Construct a signing key from a caller-supplied 32-byte `seed`.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        blake3_servil_core::initialize();
        let secret = derive_key(CTX_SECRET_VALUES, seed);
        let salt_key = derive_key(CTX_CONTENT_SALT, seed);
        let randomizer_key = derive_key(CTX_RANDOMIZER, seed);
        let public_seed = first_n(&derive_key(CTX_PUBLIC_SEED, seed));
        let public = derive_key(CTX_PUBLIC_HASH, &public_seed);
        let mut top = Box::new([[0u8; N]; TOP_NODES]);
        let root = with_sign_workspace(|ws| build_tree(&secret, &public, (LAYERS - 1) as u8, 0, Some(&mut top), None, ws));
        let mut vk_bytes = [0u8; VERIFYING_KEY_LEN];
        vk_bytes[..N].copy_from_slice(&public_seed);
        vk_bytes[N..].copy_from_slice(&root);
        let verifying_key = VerifyingKey::from_bytes(&vk_bytes);
        Self { seed: *seed, secret, salt_key, randomizer_key, verifying_key, top }
    }

    /// Borrow the 32-byte seed this signing key was derived from.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The 32-byte verifying key matching this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    fn finish_signature(&self, salt: &[u8; N], short: &[u8; SHORT_LEN], ws: &mut SignWorkspace) -> Signature {
        let randomizer = first_n(&keyed(&self.randomizer_key, short));
        let digest = self.verifying_key.message_digest(&randomizer, short);

        let mut bytes = Box::new([0u8; SIGNATURE_LEN]);
        bytes[..N].copy_from_slice(salt);
        bytes[N..2 * N].copy_from_slice(&randomizer);

        let (mut tree, mut leaf, mut node) = few_time_sign(&self.secret, &self.verifying_key.public, &digest, &mut bytes[2 * N..2 * N + FEW_LEN], ws);

        let mut at = 2 * N + FEW_LEN;
        for layer in 0..LAYERS {
            let pos = Pos { layer: layer as u8, tree, leaf };
            let part = &mut bytes[at..at + LAYER_LEN];
            node = if layer == LAYERS - 1 {
                sign_top_layer(&self.secret, &self.verifying_key.public, pos, &node, &self.top, part, ws)
            } else {
                sign_layer(&self.secret, &self.verifying_key.public, pos, &node, part, ws)
            };
            leaf = (tree & ((1u64 << TREE_HEIGHT) - 1)) as u16;
            tree >>= TREE_HEIGHT;
            at += LAYER_LEN;
        }
        assert_eq!(node, self.verifying_key.root(), "computed hypertree root differs from verifying key");
        let sig = Signature { bytes };
        assert!(self.verifying_key.verify_short(short, &sig), "produced signature failed self-verification");
        sig
    }

    pub(crate) fn sign_with_draw(&self, draw: &[u8; 32], message: &[u8]) -> Signature {
        let first_chunk = &message[..message.len().min(CHUNK_LEN)];
        let salt = derive_salt_slice(&self.salt_key, draw, first_chunk);
        let short = content_from_slice(&self.verifying_key.content_key, &salt, message);
        with_sign_workspace(|ws| self.finish_signature(&salt, &short, ws))
    }

    pub(crate) fn sign_reader_with_draw(&self, draw: &[u8; 32], reader: impl Read) -> io::Result<Signature> {
        with_sign_workspace(|ws| {
            let (salt, short) = content_from_reader(&self.verifying_key.content_key, Err((&self.salt_key, draw)), reader, &mut ws.chunk)?;
            Ok(self.finish_signature(&salt, &short, ws))
        })
    }

    /// Sign an in-memory `message`, drawing fresh per-signature randomness from `randomness`.
    pub fn sign(&self, randomness: &Randomness, message: &[u8]) -> Signature {
        let draw = randomness.draw();
        self.sign_with_draw(&draw, message)
    }

    /// Sign a streaming `reader` in 256 KiB chunks, drawing fresh per-signature randomness from `randomness`.
    pub fn sign_reader(&self, randomness: &Randomness, reader: impl Read) -> io::Result<Signature> {
        let draw = randomness.draw();
        self.sign_reader_with_draw(&draw, reader)
    }
}

#[cfg(test)]
mod test;

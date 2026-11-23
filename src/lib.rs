//! BLINCS — stateless hash-based signatures on BLAKE3.
//!
//! A signature is 5,616 bytes, a verifying key is 32 bytes, and a signing key is a 32-byte seed.
//! Messages are hashed in a single salted keyed-BLAKE3 pass under a fresh per-signature salt; passing
//! the message or stream directly to BLINCS relies on second-preimage resistance rather than collision
//! resistance, and hashes across all CPU cores at full BLAKE3 speed.
//!
//! ```no_run
//! use blincs::{Randomness, SigningKey, VerifyingKey};
//!
//! Randomness::create("/path/to/blincs.state")?;
//! let randomness = Randomness::initialize("/path/to/blincs.state")?;
//! let sk = SigningKey::from_seed(&[0x42; 32]);
//! let vk: VerifyingKey = sk.verifying_key();
//!
//! let sig = sk.sign(&randomness, b"hello, BLINCS");
//! assert!(vk.verify(b"hello, BLINCS", &sig));
//! # Ok::<(), std::io::Error>(())
//! ```

#![forbid(unsafe_code)]

mod content;
mod few_time;
mod one_time;
mod params;
mod pool;
mod randomness;
mod workspace;

#[cfg(test)]
mod test;

pub use params::{SEED_LEN, SIGNATURE_LEN, VERIFYING_KEY_LEN};
pub use randomness::Randomness;

use content::{content_from_reader, content_from_slice};
use few_time::{fors_root, fors_verify, parse_digest};
use one_time::{KeyPair, Pos, build_merkle_heap, verify_layer, write_layer_signature};
use params::{ContentKey, FORS_LEN, FORS_TREES, Layer, N, PublicKey, RandomizerKey, SHORT_LEN, SaltKey, SecretKey, TreeIndex, TweakKind, ensure_init, tweak};
use pool::{build_top_leaves_parallel, run_sign_wave};
use std::array::TryFromSliceError;
use std::fmt;
use std::hint::black_box;
use std::io::{self, Read};
use workspace::{with_caller_scratch, with_verify_workspace};

fn ct_eq_n(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    black_box(diff) == 0
}

/// A 5,616-byte BLINCS signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wrap a raw 5,616-byte signature array.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
        Self(*bytes)
    }

    /// Borrow the raw 5,616 signature bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    fn salt(&self) -> &[u8; N] {
        self.0[..N].try_into().unwrap()
    }

    fn randomizer(&self) -> &[u8; N] {
        self.0[N..2 * N].try_into().unwrap()
    }

    fn fors(&self) -> &[u8; FORS_LEN] {
        self.0[2 * N..2 * N + FORS_LEN].try_into().unwrap()
    }

    fn layer(&self, layer: Layer) -> &[u8] {
        let off = layer.sig_offset();
        &self.0[off..off + layer.sig_len()]
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(slice.try_into()?))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({SIGNATURE_LEN} bytes, salt=")?;
        for &b in self.salt() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A 32-byte BLINCS verifying key (`public_seed || top_root`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; VERIFYING_KEY_LEN],
    public_key: PublicKey,
    content_key: ContentKey,
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: &[u8; VERIFYING_KEY_LEN] = slice.try_into()?;
        Ok(Self::from_bytes(arr))
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifyingKey(")?;
        for &b in &self.bytes {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl VerifyingKey {
    /// Construct a verifying key from its 32-byte wire encoding (`public_seed || top_root`).
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {
        ensure_init();
        let public_seed: &[u8; N] = bytes[..N].try_into().unwrap();
        let public_key = PublicKey::from_public_seed(public_seed);
        let content_key = ContentKey::from_vk_bytes(bytes);
        Self { bytes: *bytes, public_key, content_key }
    }

    /// The 32-byte wire encoding of this verifying key.
    pub fn as_bytes(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.bytes
    }

    fn root(&self) -> &[u8; N] {
        self.bytes[N..].try_into().unwrap()
    }

    /// Verify `signature` over an in-memory `message` slice.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let short = content_from_slice(&self.content_key, signature.salt(), message);
        self.verify_short(&short, signature)
    }

    /// Verify `signature` over a streaming `reader` in one salted pass.
    pub fn verify_reader(&self, reader: impl Read, signature: &Signature) -> io::Result<bool> {
        let short = content_from_reader(&self.content_key, signature.salt(), reader)?;
        Ok(self.verify_short(&short, signature))
    }

    fn verify_short(&self, short: &[u8; SHORT_LEN], signature: &Signature) -> bool {
        let mut msg_in = [0u8; 16 + N + N + SHORT_LEN];
        msg_in[..16].copy_from_slice(&tweak(TweakKind::Message, 0, TreeIndex::ZERO, 0, 0, 0));
        msg_in[16..32].copy_from_slice(signature.randomizer());
        msg_in[32..48].copy_from_slice(self.root());
        msg_in[48..].copy_from_slice(short);

        let public = self.public_key.tree_hasher(false);
        let digest = *public.hash(&msg_in).as_bytes();
        let (fors_indices, leaf_addr) = parse_digest(&digest);
        let coords = leaf_addr.split_layers();

        with_verify_workspace(|ws| {
            let mut node = fors_verify(&public, leaf_addr, &fors_indices, signature.fors(), ws);
            for layer in Layer::ALL {
                let (tree, leaf) = coords[layer.index()];
                node = verify_layer(&public, Pos::new(layer, tree, leaf), &node, signature.layer(layer), ws);
            }
            ct_eq_n(&node, self.root())
        })
    }
}

/// A BLINCS signing key derived from a 32-byte seed, holding the 128 KiB top hypertree in memory.
pub struct SigningKey {
    seed: [u8; SEED_LEN],
    secret_key: SecretKey,
    salt_key: SaltKey,
    randomizer_key: RandomizerKey,
    verifying_key: VerifyingKey,
    top_tree: Vec<[u8; N]>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({:?})", self.verifying_key)
    }
}

impl SigningKey {
    /// Derive a signing key from a 32-byte `seed`, building the 128 KiB top hypertree across all CPU cores.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        ensure_init();
        let secret_key = SecretKey::derive(seed);
        let salt_key = SaltKey::derive(seed);
        let randomizer_key = RandomizerKey::derive(seed);
        let (public_seed, public_key) = PublicKey::derive_seed_and_key(seed);

        let top_leaves = build_top_leaves_parallel(&secret_key, &public_key);
        let top_tree = with_caller_scratch(|ws| build_merkle_heap(&public_key, Layer::TOP, TreeIndex::ZERO, &top_leaves, ws));

        let mut vk_bytes = [0u8; VERIFYING_KEY_LEN];
        vk_bytes[..N].copy_from_slice(&public_seed);
        vk_bytes[N..].copy_from_slice(&top_tree[1]);
        let content_key = ContentKey::from_vk_bytes(&vk_bytes);
        let verifying_key = VerifyingKey { bytes: vk_bytes, public_key, content_key };
        Self { seed: *seed, secret_key, salt_key, randomizer_key, verifying_key, top_tree }
    }

    /// The 32-byte seed from which this signing key was derived.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The 32-byte verifying key corresponding to this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    fn finish_signature(&self, salt: &[u8; N], short: &[u8; SHORT_LEN]) -> Signature {
        let mut sig = [0u8; SIGNATURE_LEN];
        let randomizer = self.randomizer_key.derive_randomizer(short);
        sig[..N].copy_from_slice(salt);
        sig[N..2 * N].copy_from_slice(&randomizer);

        let mut msg_in = [0u8; 16 + N + N + SHORT_LEN];
        msg_in[..16].copy_from_slice(&tweak(TweakKind::Message, 0, TreeIndex::ZERO, 0, 0, 0));
        msg_in[16..32].copy_from_slice(&randomizer);
        msg_in[32..48].copy_from_slice(self.verifying_key.root());
        msg_in[48..].copy_from_slice(short);
        let digest = self.verifying_key.public_key.keyed(&msg_in);
        let (fors_indices, leaf_addr) = parse_digest(&digest);
        let coords = leaf_addr.split_layers();
        let lower_trees = [coords[0].0, coords[1].0, coords[2].0];

        // One parallel wave builds all 3 lower XMSS leaf sets (384 WOTS+ leaves) and all 16 FORS trees.
        let (lower_leaves, fors_trees) = run_sign_wave(&self.secret_key, &self.verifying_key.public_key, leaf_addr, lower_trees, fors_indices);

        // Pack FORS signature and compute FORS root.
        let mut at = 2 * N;
        let mut fors_roots = [[0u8; N]; FORS_TREES];
        for (t, tree) in fors_trees.iter().enumerate() {
            sig[at..at + N].copy_from_slice(&tree.secret);
            at += N;
            for sib in &tree.auth {
                sig[at..at + N].copy_from_slice(sib);
                at += N;
            }
            fors_roots[t] = tree.root;
        }
        let pub_h = self.verifying_key.public_key.tree_hasher(false);
        let mut node = fors_root(&pub_h, leaf_addr, &fors_roots);

        // Finish the 3 lower Merkle heaps (128 leaves each) and sign all 4 hypertree layers.
        let keys = KeyPair { secret: &self.secret_key, public: &self.verifying_key.public_key };
        with_caller_scratch(|ws| {
            for layer in Layer::LOWER {
                let l = layer.index();
                let (tree, leaf) = coords[l];
                let off = layer.sig_offset();
                let heap = build_merkle_heap(&self.verifying_key.public_key, layer, tree, &lower_leaves[l], ws);
                write_layer_signature(keys, Pos::new(layer, tree, leaf), &node, &heap, ws, &mut sig[off..off + layer.sig_len()]);
                node = heap[1];
            }
            let top = Layer::TOP;
            let (top_tree_idx, top_leaf) = coords[top.index()];
            let off = top.sig_offset();
            write_layer_signature(keys, Pos::new(top, top_tree_idx, top_leaf), &node, &self.top_tree, ws, &mut sig[off..off + top.sig_len()]);
        });
        let signature = Signature(sig);
        assert!(self.verifying_key.verify_short(short, &signature), "internal error: generated signature failed self-verification");
        signature
    }

    pub(crate) fn sign_with_draw(&self, draw: &[u8; 32], message: &[u8]) -> Signature {
        let salt = self.salt_key.derive_salt(draw);
        let short = content_from_slice(&self.verifying_key.content_key, &salt, message);
        self.finish_signature(&salt, &short)
    }

    pub(crate) fn sign_reader_with_draw(&self, draw: &[u8; 32], reader: impl Read) -> io::Result<Signature> {
        let salt = self.salt_key.derive_salt(draw);
        let short = content_from_reader(&self.verifying_key.content_key, &salt, reader)?;
        Ok(self.finish_signature(&salt, &short))
    }

    /// Sign an in-memory `message`, drawing fresh per-signature randomness from `randomness`.
    pub fn sign(&self, randomness: &Randomness, message: &[u8]) -> Signature {
        let draw = randomness.draw();
        self.sign_with_draw(&draw, message)
    }

    /// Sign a streaming `reader` in one salted pass, drawing fresh per-signature randomness from `randomness`.
    pub fn sign_reader(&self, randomness: &Randomness, reader: impl Read) -> io::Result<Signature> {
        let draw = randomness.draw();
        self.sign_reader_with_draw(&draw, reader)
    }
}

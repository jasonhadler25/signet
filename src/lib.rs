//! BLINCS — stateless post-quantum digital signatures built on BLAKE3.
//!
//! A signature is 5,616 bytes, a verifying key is 32 bytes, and a signing key is a 32-byte seed.
//! Messages are hashed in a single salted keyed-BLAKE3 pass under a fresh per-signature salt; passing
//! the message or stream directly to BLINCS avoids pre-hash collision exposure and hashes across all
//! CPU cores at full BLAKE3 speed.
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

#[cfg(test)]
mod test;

pub use params::{SEED_LEN, SIGNATURE_LEN, VERIFYING_KEY_LEN};
pub use randomness::Randomness;

use content::{content_from_reader, content_from_slice};
use few_time::{ForsTreeOut, build_fors_tree, fors_root, fors_verify, parse_digest};
use one_time::{Pos, build_merkle_heap, build_wots_leaves_chunk, verify_layer, write_layer_signature};
use params::{
    CTX_CONTENT, CTX_CONTENT_SALT, CTX_PUBLIC_SEED, CTX_RANDOMIZER, FORS_LEN, FORS_TREES, LAYERS, LOWER_LEAVES, Layer, N, PublicKey, SHORT_LEN, SecretKey,
    TOP_LEAVES, TweakKind, derive_key, ensure_init, first_n, keyed, tweak,
};
use pool::{WOTS_CHUNK_LEAVES, parallel_collect, with_caller_scratch, with_verify_workspace};
use std::array::TryFromSliceError;
use std::fmt;
use std::hint::black_box;
use std::io::{self, Read};

const TOP_CHUNKS: usize = TOP_LEAVES / WOTS_CHUNK_LEAVES;
const SIGN_WOTS_CHUNK: usize = 8;
const LOWER_CHUNKS_PER_LAYER: usize = LOWER_LEAVES / SIGN_WOTS_CHUNK;
const LOWER_WOTS_TASKS: usize = (LAYERS - 1) * LOWER_CHUNKS_PER_LAYER;
const SIGN_TOTAL_TASKS: usize = LOWER_WOTS_TASKS + FORS_TREES;

const _: () = {
    assert!(TOP_LEAVES.is_multiple_of(WOTS_CHUNK_LEAVES) && LOWER_LEAVES.is_multiple_of(SIGN_WOTS_CHUNK));
};

fn ct_eq_n(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    black_box(diff) == 0
}

fn fmt_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

fn msg_digest_input(randomizer: &[u8; N], root: &[u8; N], short: &[u8; SHORT_LEN]) -> [u8; 16 + N + N + SHORT_LEN] {
    let mut buf = [0u8; 16 + N + N + SHORT_LEN];
    buf[..16].copy_from_slice(&tweak(TweakKind::Message, 0, 0, 0, 0, 0));
    buf[16..32].copy_from_slice(randomizer);
    buf[32..48].copy_from_slice(root);
    buf[48..].copy_from_slice(short);
    buf
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
        fmt_hex(f, self.salt())?;
        f.write_str(")")
    }
}

/// A 32-byte BLINCS verifying key (`public_seed || top_root`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; VERIFYING_KEY_LEN],
    public_key: PublicKey,
    content_key: [u8; 32],
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(slice.try_into()?))
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifyingKey(")?;
        fmt_hex(f, &self.bytes)?;
        f.write_str(")")
    }
}

impl VerifyingKey {
    /// Construct a verifying key from its 32-byte wire encoding (`public_seed || top_root`).
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {
        ensure_init();
        let public_key = PublicKey::from_seed(bytes[..N].try_into().unwrap());
        let content_key = derive_key(CTX_CONTENT, bytes);
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
        if !ct_eq_n(signature.salt(), short[..N].try_into().unwrap()) {
            return false;
        }
        let msg_in = msg_digest_input(signature.randomizer(), self.root(), short);
        let public = self.public_key.hasher(false);
        let (fors_indices, leaf_addr) = parse_digest(public.hash(&msg_in).as_bytes());
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
    salt_key: [u8; 32],
    randomizer_key: [u8; 32],
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
        let salt_key = derive_key(CTX_CONTENT_SALT, seed);
        let randomizer_key = derive_key(CTX_RANDOMIZER, seed);
        let public_seed = first_n(&derive_key(CTX_PUBLIC_SEED, seed));
        let public_key = PublicKey::from_seed(&public_seed);

        let chunks = parallel_collect(TOP_CHUNKS, move |id, sme2, ws| {
            let mut buf = [[0u8; N]; WOTS_CHUNK_LEAVES];
            let leaf = u16::try_from(id * WOTS_CHUNK_LEAVES).unwrap();
            build_wots_leaves_chunk(&secret_key, &public_key, Pos::new(Layer::TOP, 0, leaf), sme2, ws, &mut buf);
            buf
        });
        let top_leaves: Vec<[u8; N]> = chunks.into_iter().flatten().collect();
        let top_tree = with_caller_scratch(|ws| build_merkle_heap(&public_key, Layer::TOP, 0, &top_leaves, ws));

        let mut vk_bytes = [0u8; VERIFYING_KEY_LEN];
        vk_bytes[..N].copy_from_slice(&public_seed);
        vk_bytes[N..].copy_from_slice(&top_tree[1]);
        Self { seed: *seed, secret_key, salt_key, randomizer_key, verifying_key: VerifyingKey::from_bytes(&vk_bytes), top_tree }
    }

    /// The 32-byte seed from which this signing key was derived.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The 32-byte verifying key corresponding to this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    fn finish_signature(&self, short: &[u8; SHORT_LEN]) -> Signature {
        enum WaveOut {
            Wots([[u8; N]; SIGN_WOTS_CHUNK]),
            Fors(ForsTreeOut),
        }

        let mut sig = [0u8; SIGNATURE_LEN];
        let randomizer = first_n(&keyed(&self.randomizer_key, short));
        sig[..N].copy_from_slice(&short[..N]);
        sig[N..2 * N].copy_from_slice(&randomizer);

        let msg_in = msg_digest_input(&randomizer, self.verifying_key.root(), short);
        let (fors_indices, leaf_addr) = parse_digest(&self.verifying_key.public_key.keyed(&msg_in));
        let coords = leaf_addr.split_layers();
        let (sec, pubk) = (self.secret_key, self.verifying_key.public_key);

        // One parallel wave builds all 3 lower XMSS leaf sets (384 WOTS+ leaves) and all 16 FORS trees.
        let results = parallel_collect(SIGN_TOTAL_TASKS, move |id, sme2, ws| {
            if id < LOWER_WOTS_TASKS {
                let layer = Layer::LOWER[id / LOWER_CHUNKS_PER_LAYER];
                let leaf = u16::try_from((id % LOWER_CHUNKS_PER_LAYER) * SIGN_WOTS_CHUNK).unwrap();
                let mut buf = [[0u8; N]; SIGN_WOTS_CHUNK];
                build_wots_leaves_chunk(&sec, &pubk, Pos::new(layer, coords[layer.index()].0, leaf), sme2, ws, &mut buf);
                WaveOut::Wots(buf)
            } else {
                let t = id - LOWER_WOTS_TASKS;
                WaveOut::Fors(build_fors_tree(&sec, &pubk, leaf_addr, u16::try_from(t).unwrap(), fors_indices[t], sme2, ws))
            }
        });

        // Pack FORS signature and compute FORS root.
        let mut at = 2 * N;
        let mut fors_roots = [[0u8; N]; FORS_TREES];
        for (t, item) in results[LOWER_WOTS_TASKS..].iter().enumerate() {
            let WaveOut::Fors(tree) = item else { unreachable!() };
            sig[at..at + N].copy_from_slice(&tree.secret);
            at += N;
            for sib in &tree.auth {
                sig[at..at + N].copy_from_slice(sib);
                at += N;
            }
            fors_roots[t] = tree.root;
        }
        let mut node = fors_root(&pubk.hasher(false), leaf_addr, &fors_roots);

        // Build the 3 lower Merkle heaps and sign all 4 hypertree layers.
        with_caller_scratch(|ws| {
            for layer in Layer::LOWER {
                let l = layer.index();
                let mut leaves = [[0u8; N]; LOWER_LEAVES];
                for chunk in 0..LOWER_CHUNKS_PER_LAYER {
                    let WaveOut::Wots(data) = &results[l * LOWER_CHUNKS_PER_LAYER + chunk] else { unreachable!() };
                    leaves[chunk * SIGN_WOTS_CHUNK..(chunk + 1) * SIGN_WOTS_CHUNK].copy_from_slice(data);
                }
                let (tree, leaf) = coords[l];
                let off = layer.sig_offset();
                let heap = build_merkle_heap(&pubk, layer, tree, &leaves, ws);
                write_layer_signature(&sec, &pubk, Pos::new(layer, tree, leaf), &node, &heap, ws, &mut sig[off..off + layer.sig_len()]);
                node = heap[1];
            }
            let (top_tree_idx, top_leaf) = coords[Layer::TOP.index()];
            let off = Layer::TOP.sig_offset();
            write_layer_signature(
                &sec,
                &pubk,
                Pos::new(Layer::TOP, top_tree_idx, top_leaf),
                &node,
                &self.top_tree,
                ws,
                &mut sig[off..off + Layer::TOP.sig_len()],
            );
        });

        let signature = Signature(sig);
        assert!(self.verifying_key.verify_short(short, &signature), "internal error: generated signature failed self-verification");
        signature
    }

    pub(crate) fn sign_with_draw(&self, draw: &[u8; 32], message: &[u8]) -> Signature {
        ensure_init();
        let salt = first_n(&keyed(&self.salt_key, draw));
        let short = content_from_slice(&self.verifying_key.content_key, &salt, message);
        self.finish_signature(&short)
    }

    pub(crate) fn sign_reader_with_draw(&self, draw: &[u8; 32], reader: impl Read) -> io::Result<Signature> {
        ensure_init();
        let salt = first_n(&keyed(&self.salt_key, draw));
        let short = content_from_reader(&self.verifying_key.content_key, &salt, reader)?;
        Ok(self.finish_signature(&short))
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

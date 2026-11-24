//! BLINCS — stateless hash-based digital signatures based on BLAKE3 and SPHINCS.
//!
//! **Pre-1.0 experimental software (unsupported):** formats, context strings, and APIs may change
//! incompatibly before 1.0, and no independent human cryptographic audit has been performed.
//!
//! Designed for post-quantum use with a 128-bit classical security target (see `SPEC.md` for bounds).
//! Because a cryptographic key is a transferable bearer authority rather than a person's handwritten
//! signature, this API calls the secret a [`Signet`], its 32-byte public identifier a [`SignetId`]
//! (which names which signet you mean and verifies its imprints), and the 5,616-byte proof an
//! [`Imprint`]. Pass message bytes or a stream directly: BLINCS hashes the input in a single
//! salted keyed-BLAKE3 pass under a fresh per-imprint salt.
//!
//! ```no_run
//! use blincs::{Randomness, Signet, SignetId};
//!
//! Randomness::create("/path/to/blincs.state")?;
//! let randomness = Randomness::initialize("/path/to/blincs.state")?;
//! let signet = Signet::from_seed(&[0x42; 32]); // example only; use OS randomness in real code
//! let id: SignetId = signet.id();
//!
//! let imprint = signet.imprint(&randomness, b"hello, BLINCS");
//! assert!(id.verify(b"hello, BLINCS", &imprint));
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

pub use params::{IMPRINT_LEN, SEED_LEN, SIGNET_ID_LEN};
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

/// A 5,616-byte BLINCS imprint (proof produced by pressing a [`Signet`] onto a message).
#[derive(Clone, PartialEq, Eq)]
pub struct Imprint([u8; IMPRINT_LEN]);

impl Imprint {
    /// Wrap a raw 5,616-byte imprint array.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; IMPRINT_LEN]) -> Self {
        Self(*bytes)
    }

    /// Borrow the raw 5,616 imprint bytes.
    pub fn as_bytes(&self) -> &[u8; IMPRINT_LEN] {
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

impl TryFrom<&[u8]> for Imprint {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(slice.try_into()?))
    }
}

impl fmt::Debug for Imprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Imprint({IMPRINT_LEN} bytes, salt=")?;
        fmt_hex(f, self.salt())?;
        f.write_str(")")
    }
}

/// A 32-byte BLINCS signet identifier (`public_seed || top_root`).
///
/// A `SignetId` names which [`Signet`] you mean and lets anyone verify whether an [`Imprint`]
/// came from that signet.
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

    /// Verify that `imprint` was made by this signet over an in-memory `message` slice.
    #[must_use = "imprint verification result must be checked"]
    pub fn verify(&self, message: &[u8], imprint: &Imprint) -> bool {
        let short = content_from_slice(&self.content_key, imprint.salt(), message);
        self.verify_short(&short, imprint)
    }

    /// Verify that `imprint` was made by this signet over a streaming `reader` in one salted pass.
    #[must_use = "imprint verification result must be checked"]
    pub fn verify_reader(&self, reader: impl Read, imprint: &Imprint) -> io::Result<bool> {
        let short = content_from_reader(&self.content_key, imprint.salt(), reader)?;
        Ok(self.verify_short(&short, imprint))
    }

    fn verify_short(&self, short: &[u8; SHORT_LEN], imprint: &Imprint) -> bool {
        if !ct_eq_n(imprint.salt(), short[..N].try_into().unwrap()) {
            return false;
        }
        let msg_in = msg_digest_input(imprint.randomizer(), self.root(), short);
        let public = self.public_key.hasher(false);
        let (fors_indices, leaf_addr) = parse_digest(public.hash(&msg_in).as_bytes());
        let coords = leaf_addr.split_layers();

        with_verify_workspace(|ws| {
            let mut node = fors_verify(&public, leaf_addr, &fors_indices, imprint.fors(), ws);
            for layer in Layer::ALL {
                let (tree, leaf) = coords[layer.index()];
                node = verify_layer(&public, Pos::new(layer, tree, leaf), &node, imprint.layer(layer), ws);
            }
            ct_eq_n(&node, self.root())
        })
    }
}

/// A BLINCS signet (bearer authority derived from a 32-byte seed, holding the 128 KiB top hypertree in memory).
pub struct Signet {
    seed: [u8; SEED_LEN],
    secret_key: SecretKey,
    salt_key: [u8; 32],
    randomizer_key: [u8; 32],
    id: SignetId,
    top_tree: Vec<[u8; N]>,
}

impl fmt::Debug for Signet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signet({:?})", self.id)
    }
}

impl Signet {
    /// Derive a signet from a 32-byte `seed`, building the 128 KiB top hypertree across all CPU cores.
    #[must_use]
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

    fn finish_imprint(&self, short: &[u8; SHORT_LEN]) -> Imprint {
        enum WaveOut {
            Wots([[u8; N]; SIGN_WOTS_CHUNK]),
            Fors(ForsTreeOut),
        }

        let mut sig = [0u8; IMPRINT_LEN];
        let randomizer = first_n(&keyed(&self.randomizer_key, short));
        sig[..N].copy_from_slice(&short[..N]);
        sig[N..2 * N].copy_from_slice(&randomizer);

        let msg_in = msg_digest_input(&randomizer, self.id.root(), short);
        let (fors_indices, leaf_addr) = parse_digest(&self.id.public_key.keyed(&msg_in));
        let coords = leaf_addr.split_layers();
        let (sec, pubk) = (self.secret_key, self.id.public_key);

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

        // Pack FORS imprint and compute FORS root.
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

        // Build the 3 lower Merkle heaps and imprint all 4 hypertree layers.
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
            assert_eq!(top_tree_idx, 0);
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

        let imprint = Imprint(sig);
        assert!(self.id.verify_short(short, &imprint), "internal error: generated imprint failed self-verification");
        imprint
    }

    pub(crate) fn imprint_with_draw(&self, draw: &[u8; 32], message: &[u8]) -> Imprint {
        ensure_init();
        let salt = first_n(&keyed(&self.salt_key, draw));
        let short = content_from_slice(&self.id.content_key, &salt, message);
        self.finish_imprint(&short)
    }

    pub(crate) fn imprint_reader_with_draw(&self, draw: &[u8; 32], reader: impl Read) -> io::Result<Imprint> {
        ensure_init();
        let salt = first_n(&keyed(&self.salt_key, draw));
        let short = content_from_reader(&self.id.content_key, &salt, reader)?;
        Ok(self.finish_imprint(&short))
    }

    /// Imprint an in-memory `message`, drawing fresh per-imprint randomness from `randomness`.
    #[must_use]
    pub fn imprint(&self, randomness: &Randomness, message: &[u8]) -> Imprint {
        let draw = randomness.draw();
        self.imprint_with_draw(&draw, message)
    }

    /// Imprint a streaming `reader` in one salted pass, drawing fresh per-imprint randomness from `randomness`.
    pub fn imprint_reader(&self, randomness: &Randomness, reader: impl Read) -> io::Result<Imprint> {
        let draw = randomness.draw();
        self.imprint_reader_with_draw(&draw, reader)
    }
}

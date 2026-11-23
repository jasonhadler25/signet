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

use blake3_servil::throughput::{TreeHasher, update_multithreaded};
use blake3_servil::{Mode, convenience};
use content::{content_from_reader, content_from_slice, derive_salt};
use few_time::{fors_root, fors_verify, parse_digest};
use one_time::{KeyPair, Pos, build_merkle_heap, verify_layer, write_layer_signature};
use params::{
    CTX_CONTENT, CTX_CONTENT_SALT, CTX_PUBLIC_HASH, CTX_PUBLIC_SEED, CTX_RANDOMIZER, CTX_SECRET_VALUES, CTX_TOP_CACHE, FORS_LEN, FORS_TREES, KIND_MESSAGE,
    LAYERS, LOWER_HEIGHT, LOWER_LAYER_LEN, N, SHORT_LEN, TOP_HEIGHT, TOP_LAYER_LEN, TOP_NODES, derive_key, ensure_init, first_n, keyed, tweak,
};
use pool::{build_top_leaves_parallel, run_sign_wave};
use std::array::TryFromSliceError;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use workspace::{with_caller_scratch, with_verify_workspace};

const TOP_CACHE_MAGIC: &[u8; 16] = b"BLINCS-TOP-V1\0\0\0";
const TOP_CACHE_HEADER_LEN: usize = 16 + 32;
const TOP_CACHE_NODES_BYTES: usize = (TOP_NODES - 1) * N;
const TOP_CACHE_LEN: usize = TOP_CACHE_HEADER_LEN + TOP_CACHE_NODES_BYTES;

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn ct_eq_n(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn mac_top_nodes(cache_key: &[u8; 32], nodes_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = convenience::Hasher::new(Mode::Keyed(cache_key), Some(nodes_bytes.len() as u64));
    update_multithreaded(&mut hasher, nodes_bytes);
    *hasher.finalize().as_bytes()
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
        for &b in &self.0[..N] {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A 32-byte BLINCS verifying key (`public_seed || top_root`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; VERIFYING_KEY_LEN],
    public_key: [u8; 32],
    content_key: [u8; 32],
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
        let public_key = derive_key(CTX_PUBLIC_HASH, &bytes[..N]);
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
        let salt: [u8; N] = signature.as_bytes()[..N].try_into().unwrap();
        let short = content_from_slice(&self.content_key, &salt, message);
        self.verify_short(&short, signature)
    }

    /// Verify `signature` over a streaming `reader` in one salted pass.
    pub fn verify_reader(&self, reader: impl Read, signature: &Signature) -> io::Result<bool> {
        let salt: [u8; N] = signature.as_bytes()[..N].try_into().unwrap();
        let short = content_from_reader(&self.content_key, &salt, reader)?;
        Ok(self.verify_short(&short, signature))
    }

    fn verify_short(&self, short: &[u8; SHORT_LEN], signature: &Signature) -> bool {
        let sig = signature.as_bytes();
        let randomizer = &sig[N..2 * N];
        let mut msg_in = [0u8; 16 + N + N + SHORT_LEN];
        msg_in[..16].copy_from_slice(&tweak(KIND_MESSAGE, 0, 0, 0, 0, 0));
        msg_in[16..32].copy_from_slice(randomizer);
        msg_in[32..48].copy_from_slice(self.root());
        msg_in[48..].copy_from_slice(short);

        let public = TreeHasher::new(Mode::Keyed(&self.public_key)).on_this_core();
        let digest = *public.hash(&msg_in).as_bytes();
        let (fors_indices, leaf_addr) = parse_digest(&digest);

        with_verify_workspace(|ws| {
            let mut at = 2 * N;
            let mut node = fors_verify(&public, leaf_addr, &fors_indices, &sig[at..at + FORS_LEN], ws);
            at += FORS_LEN;

            let mut addr = leaf_addr;
            for layer in 0..LAYERS {
                let (height, layer_len) = if layer + 1 == LAYERS { (TOP_HEIGHT, TOP_LAYER_LEN) } else { (LOWER_HEIGHT, LOWER_LAYER_LEN) };
                let leaf = (addr & ((1u64 << height) - 1)) as u16;
                let tree = addr >> height;
                node = verify_layer(&public, Pos { layer: layer as u8, tree, leaf }, height, &node, &sig[at..at + layer_len], ws);
                at += layer_len;
                addr = tree;
            }
            debug_assert_eq!(at, SIGNATURE_LEN);
            ct_eq_n(&node, self.root())
        })
    }
}

/// A BLINCS signing key derived from a 32-byte seed, caching the 1 MiB top hypertree in memory.
pub struct SigningKey {
    seed: [u8; SEED_LEN],
    secret_key: [u8; 32],
    salt_key: [u8; 32],
    randomizer_key: [u8; 32],
    cache_key: [u8; 32],
    verifying_key: VerifyingKey,
    top_tree: Vec<[u8; N]>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({:?})", self.verifying_key)
    }
}

struct Subkeys {
    secret_key: [u8; 32],
    salt_key: [u8; 32],
    randomizer_key: [u8; 32],
    cache_key: [u8; 32],
    public_seed: [u8; N],
    public_key: [u8; 32],
}

impl SigningKey {
    fn derive_subkeys(seed: &[u8; SEED_LEN]) -> Subkeys {
        let secret_key = derive_key(CTX_SECRET_VALUES, seed);
        let salt_key = derive_key(CTX_CONTENT_SALT, seed);
        let randomizer_key = derive_key(CTX_RANDOMIZER, seed);
        let cache_key = derive_key(CTX_TOP_CACHE, seed);
        let public_seed = first_n(&derive_key(CTX_PUBLIC_SEED, seed));
        let public_key = derive_key(CTX_PUBLIC_HASH, &public_seed);
        Subkeys { secret_key, salt_key, randomizer_key, cache_key, public_seed, public_key }
    }

    fn assemble(seed: &[u8; SEED_LEN], sub: Subkeys, top_tree: Vec<[u8; N]>) -> Self {
        let mut vk_bytes = [0u8; VERIFYING_KEY_LEN];
        vk_bytes[..N].copy_from_slice(&sub.public_seed);
        vk_bytes[N..].copy_from_slice(&top_tree[1]);
        let content_key = derive_key(CTX_CONTENT, &vk_bytes);
        let verifying_key = VerifyingKey { bytes: vk_bytes, public_key: sub.public_key, content_key };
        Self {
            seed: *seed,
            secret_key: sub.secret_key,
            salt_key: sub.salt_key,
            randomizer_key: sub.randomizer_key,
            cache_key: sub.cache_key,
            verifying_key,
            top_tree,
        }
    }

    /// Derive a signing key from a 32-byte `seed`, building the 1 MiB top hypertree across all CPU cores.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        ensure_init();
        let sub = Self::derive_subkeys(seed);
        let top_leaves = build_top_leaves_parallel(&sub.secret_key, &sub.public_key);
        let top_tree = with_caller_scratch(|ws| build_merkle_heap(&sub.public_key, (LAYERS - 1) as u8, 0, TOP_HEIGHT, &top_leaves, ws));
        Self::assemble(seed, sub, top_tree)
    }

    /// The 32-byte seed from which this signing key was derived.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Write an authenticated 1 MiB stateless top-tree cache file atomically to `path`.
    ///
    /// Losing this file never threatens security; it is purely deterministic from the 32-byte seed
    /// and can always be regenerated by [`SigningKey::from_seed`].
    pub fn save_top_tree_cache(&self, path: impl AsRef<Path>) -> io::Result<()> {
        ensure_init();
        let path = path.as_ref();
        let mut nodes_bytes = Vec::with_capacity(TOP_CACHE_NODES_BYTES);
        for node in &self.top_tree[1..TOP_NODES] {
            nodes_bytes.extend_from_slice(node);
        }
        let mac = mac_top_nodes(&self.cache_key, &nodes_bytes);

        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let parent = path.parent().unwrap_or(Path::new("."));
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("blincs-top-cache");
        let tmp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path)?;
        let write_res = (|| -> io::Result<()> {
            file.write_all(TOP_CACHE_MAGIC)?;
            file.write_all(&mac)?;
            file.write_all(&nodes_bytes)?;
            file.sync_all()
        })();
        if let Err(e) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        Ok(())
    }

    /// Load a signing key from `seed` and an authenticated top-tree cache file created by
    /// [`SigningKey::save_top_tree_cache`], avoiding the cold top-tree rebuild.
    ///
    /// Returns [`ErrorKind::InvalidData`] if the cache file is truncated, has trailing bytes,
    /// does not match `seed`, or fails its keyed BLAKE3 MAC check.
    pub fn from_seed_with_cache(seed: &[u8; SEED_LEN], path: impl AsRef<Path>) -> io::Result<Self> {
        ensure_init();
        let sub = Self::derive_subkeys(seed);

        let file = File::open(path.as_ref())?;
        let mut raw = Vec::with_capacity(TOP_CACHE_LEN + 1);
        file.take((TOP_CACHE_LEN + 1) as u64).read_to_end(&mut raw)?;
        if raw.len() != TOP_CACHE_LEN || &raw[..16] != TOP_CACHE_MAGIC {
            return Err(io::Error::new(ErrorKind::InvalidData, "not a valid BLINCS top-tree cache file"));
        }
        let stored_mac: [u8; 32] = raw[16..TOP_CACHE_HEADER_LEN].try_into().unwrap();
        let nodes_bytes = &raw[TOP_CACHE_HEADER_LEN..];
        let expected_mac = mac_top_nodes(&sub.cache_key, nodes_bytes);
        if !ct_eq_32(&stored_mac, &expected_mac) {
            return Err(io::Error::new(ErrorKind::InvalidData, "BLINCS top-tree cache authentication failed"));
        }

        let mut top_tree = vec![[0u8; N]; TOP_NODES];
        for (dst, src) in top_tree[1..TOP_NODES].iter_mut().zip(nodes_bytes.as_chunks::<N>().0) {
            *dst = *src;
        }
        Ok(Self::assemble(seed, sub, top_tree))
    }

    /// The 32-byte verifying key corresponding to this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    fn finish_signature(&self, salt: &[u8; N], short: &[u8; SHORT_LEN]) -> Signature {
        let mut sig = [0u8; SIGNATURE_LEN];
        let randomizer = first_n(&keyed(&self.randomizer_key, short));
        sig[..N].copy_from_slice(salt);
        sig[N..2 * N].copy_from_slice(&randomizer);

        let mut msg_in = [0u8; 16 + N + N + SHORT_LEN];
        msg_in[..16].copy_from_slice(&tweak(KIND_MESSAGE, 0, 0, 0, 0, 0));
        msg_in[16..32].copy_from_slice(&randomizer);
        msg_in[32..48].copy_from_slice(self.verifying_key.root());
        msg_in[48..].copy_from_slice(short);
        let digest = keyed(&self.verifying_key.public_key, &msg_in);
        let (fors_indices, leaf_addr) = parse_digest(&digest);

        // One parallel wave builds all 3 lower XMSS leaf sets (192 WOTS+ leaves) and all 16 FORS trees.
        let (lower_leaves, fors_trees) = run_sign_wave(&self.secret_key, &self.verifying_key.public_key, leaf_addr, fors_indices);

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
        let pub_h = TreeHasher::new(Mode::Keyed(&self.verifying_key.public_key)).on_this_core();
        let mut node = fors_root(&pub_h, leaf_addr, &fors_roots);

        // Finish the 3 tiny 64-leaf lower Merkle heaps and sign all 4 hypertree layers.
        let keys = KeyPair { secret: &self.secret_key, public: &self.verifying_key.public_key };
        with_caller_scratch(|ws| {
            let mut addr = leaf_addr;
            for (layer, leaves) in lower_leaves.iter().enumerate() {
                let leaf = (addr & ((1u64 << LOWER_HEIGHT) - 1)) as u16;
                let tree = addr >> LOWER_HEIGHT;
                let heap = build_merkle_heap(&self.verifying_key.public_key, layer as u8, tree, LOWER_HEIGHT, leaves, ws);
                write_layer_signature(keys, Pos { layer: layer as u8, tree, leaf }, LOWER_HEIGHT, &node, &heap, ws, &mut sig[at..at + LOWER_LAYER_LEN]);
                node = heap[1];
                at += LOWER_LAYER_LEN;
                addr = tree;
            }
            let top_leaf = (addr & ((1u64 << TOP_HEIGHT) - 1)) as u16;
            write_layer_signature(
                keys,
                Pos { layer: (LAYERS - 1) as u8, tree: 0, leaf: top_leaf },
                TOP_HEIGHT,
                &node,
                &self.top_tree,
                ws,
                &mut sig[at..at + TOP_LAYER_LEN],
            );
            debug_assert_eq!(at + TOP_LAYER_LEN, SIGNATURE_LEN);
        });
        let signature = Signature(sig);
        assert!(self.verifying_key.verify_short(short, &signature), "internal error: generated signature failed self-verification");
        signature
    }

    pub(crate) fn sign_with_draw(&self, draw: &[u8; 32], message: &[u8]) -> Signature {
        let salt = derive_salt(&self.salt_key, draw);
        let short = content_from_slice(&self.verifying_key.content_key, &salt, message);
        self.finish_signature(&salt, &short)
    }

    pub(crate) fn sign_reader_with_draw(&self, draw: &[u8; 32], reader: impl Read) -> io::Result<Signature> {
        let salt = derive_salt(&self.salt_key, draw);
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

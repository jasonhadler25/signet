use crate::params::{FORS_HEIGHT, FORS_LEAVES, FORS_LEN, FORS_TREES, ForsIndex, LeafAddr, N, PublicKey, SecretKey, TweakKind, first_n, tweak};
use crate::workspace::{VerifyWorkspace, WorkerScratch};
use blake3_servil::throughput::{Prepared, TreeHasher};

/// Unpack the 16 ten-bit FORS leaf indices (`digest[0..20]`) and 33-bit hypertree leaf address
/// (`digest[20..28]`, low 33 bits) directly from the 32-byte message digest `D`.
#[inline]
pub(crate) fn parse_digest(digest: &[u8; 32]) -> ([ForsIndex; FORS_TREES], LeafAddr) {
    let mut indices = [ForsIndex::from_bits(0); FORS_TREES];
    for group in 0..4 {
        let b = &digest[group * 5..group * 5 + 5];
        let bits = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], 0, 0, 0]);
        for j in 0..4 {
            indices[group * 4 + j] = ForsIndex::from_bits(bits >> (10 * j));
        }
    }
    let leaf_addr = LeafAddr::from_digest_word(u64::from_le_bytes(digest[20..28].try_into().unwrap()));
    (indices, leaf_addr)
}

/// Output of building one FORS tree during signing: secret value, authentication path, and tree root.
#[derive(Clone, Copy)]
pub(crate) struct ForsTreeOut {
    pub secret: [u8; N],
    pub auth: [[u8; N]; FORS_HEIGHT],
    pub root: [u8; N],
}

impl Default for ForsTreeOut {
    fn default() -> Self {
        Self { secret: [0u8; N], auth: [[0u8; N]; FORS_HEIGHT], root: [0u8; N] }
    }
}

/// Build one FORS tree `tree_idx` (0..16, 1,024 leaves) for `leaf_addr` and extract the signature slice
/// for `chosen_leaf`.
pub(crate) fn build_fors_tree(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    leaf_addr: LeafAddr,
    tree_idx: u16,
    chosen_leaf: ForsIndex,
    use_sme2: bool,
    ws: &mut WorkerScratch,
) -> ForsTreeOut {
    assert!(usize::from(tree_idx) < FORS_TREES);
    let tree = leaf_addr.as_tree();
    let sec_h = secret_key.tree_hasher(use_sme2);
    let pub_h = public_key.tree_hasher(use_sme2);

    for i in 0..FORS_LEAVES {
        let leaf_u32 = u32::try_from(i).unwrap();
        ws.b16.message_mut(i).copy_from_slice(&tweak(TweakKind::FewSecret, 0, tree, tree_idx, 0, leaf_u32));
    }
    sec_h.hash_many(&ws.b16.part(0..FORS_LEAVES), &mut ws.out[..FORS_LEAVES]);
    let chosen_secret = first_n(&ws.out[chosen_leaf.as_usize()]);

    for i in 0..FORS_LEAVES {
        let leaf_u32 = u32::try_from(i).unwrap();
        let m = ws.b32.message_mut(i);
        m[..16].copy_from_slice(&tweak(TweakKind::FewLeaf, 0, tree, tree_idx, 0, leaf_u32));
        m[16..32].copy_from_slice(&ws.out[i][..N]);
    }
    pub_h.hash_many(&ws.b32.part(0..FORS_LEAVES), &mut ws.out[..FORS_LEAVES]);

    let mut level_nodes = [[0u8; N]; FORS_LEAVES];
    for i in 0..FORS_LEAVES {
        level_nodes[i] = first_n(&ws.out[i]);
    }

    let mut auth = [[0u8; N]; FORS_HEIGHT];
    let mut cur_idx = chosen_leaf.as_usize();
    let mut count = FORS_LEAVES;
    for level in 1..=FORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        auth[level - 1] = level_nodes[cur_idx ^ 1];
        let parents = count / 2;
        for p in 0..parents {
            let p_u32 = u32::try_from(p).unwrap();
            let m = ws.b48.message_mut(p);
            m[..16].copy_from_slice(&tweak(TweakKind::FewNode, 0, tree, tree_idx, level_u16, p_u32));
            m[16..32].copy_from_slice(&level_nodes[2 * p]);
            m[32..48].copy_from_slice(&level_nodes[2 * p + 1]);
        }
        pub_h.hash_many(&ws.b48.part(0..parents), &mut ws.out[..parents]);
        for p in 0..parents {
            level_nodes[p] = first_n(&ws.out[p]);
        }
        cur_idx >>= 1;
        count = parents;
    }

    ForsTreeOut { secret: chosen_secret, auth, root: level_nodes[0] }
}

/// Compress the 16 FORS tree roots into the 16-byte FORS root signed by hypertree layer 0.
pub(crate) fn fors_root(public: &TreeHasher, leaf_addr: LeafAddr, roots: &[[u8; N]; FORS_TREES]) -> [u8; N] {
    let mut input = [0u8; 16 + N * FORS_TREES];
    input[..16].copy_from_slice(&tweak(TweakKind::FewRoot, 0, leaf_addr.as_tree(), 0, 0, 0));
    for t in 0..FORS_TREES {
        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);
    }
    first_n(public.hash(&input).as_bytes())
}

/// Verify a FORS signature and return its reconstructed 16-byte FORS root (batching all 16 trees per level).
pub(crate) fn fors_verify(
    public: &TreeHasher,
    leaf_addr: LeafAddr,
    indices: &[ForsIndex; FORS_TREES],
    sig: &[u8; FORS_LEN],
    ws: &mut VerifyWorkspace,
) -> [u8; N] {
    let tree = leaf_addr.as_tree();
    let tree_stride = (1 + FORS_HEIGHT) * N;

    for t in 0..FORS_TREES {
        let t_u16 = u16::try_from(t).unwrap();
        let m = ws.b32.message_mut(t);
        m[..16].copy_from_slice(&tweak(TweakKind::FewLeaf, 0, tree, t_u16, 0, indices[t].as_u32()));
        m[16..32].copy_from_slice(&sig[t * tree_stride..t * tree_stride + N]);
    }
    public.hash_many(&ws.b32.part(0..FORS_TREES), &mut ws.out[..FORS_TREES]);

    let mut cur = [[0u8; N]; FORS_TREES];
    let mut idx = [0u32; FORS_TREES];
    for t in 0..FORS_TREES {
        cur[t] = first_n(&ws.out[t]);
        idx[t] = indices[t].as_u32();
    }

    for level in 1..=FORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        for t in 0..FORS_TREES {
            let t_u16 = u16::try_from(t).unwrap();
            let sib = &sig[t * tree_stride + level * N..t * tree_stride + (level + 1) * N];
            let m = ws.b48.message_mut(t);
            m[..16].copy_from_slice(&tweak(TweakKind::FewNode, 0, tree, t_u16, level_u16, idx[t] >> 1));
            if idx[t] & 1 == 0 {
                m[16..32].copy_from_slice(&cur[t]);
                m[32..48].copy_from_slice(sib);
            } else {
                m[16..32].copy_from_slice(sib);
                m[32..48].copy_from_slice(&cur[t]);
            }
        }
        public.hash_many(&ws.b48.part(0..FORS_TREES), &mut ws.out[..FORS_TREES]);
        for t in 0..FORS_TREES {
            cur[t] = first_n(&ws.out[t]);
            idx[t] >>= 1;
        }
    }

    fors_root(public, leaf_addr, &cur)
}

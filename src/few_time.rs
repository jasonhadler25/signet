use crate::one_time::SignWorkspace;
use crate::params::{FORS_HEIGHT, FORS_LEAVES, FORS_LEN, FORS_TREES, LeafAddr, N, PublicKey, SecretKey, TweakKind, first_n, pack_pair, pack_tagged, tweak};
use blake3_servil_core::throughput::TreeHasher;

/// Unpack the 16 ten-bit FORS leaf indices (`digest[0..20]`) and 33-bit hypertree leaf address
/// (`digest[20..28]`, low 33 bits) directly from the 32-byte message digest `D`.
pub(crate) fn parse_digest(digest: &[u8; 32]) -> ([u16; FORS_TREES], LeafAddr) {
    let mut indices = [0u16; FORS_TREES];
    for group in 0..4 {
        let b = &digest[group * 5..group * 5 + 5];
        let bits = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], 0, 0, 0]);
        for j in 0..4 {
            indices[group * 4 + j] = u16::try_from((bits >> (10 * j)) & 0x3ff).unwrap();
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

/// Build one FORS tree `tree_idx` (0..16, 1,024 leaves) for `leaf_addr` and extract `chosen_leaf`'s path.
pub(crate) fn build_fors_tree(
    secret: &SecretKey,
    public: &PublicKey,
    leaf_addr: LeafAddr,
    tree_idx: u16,
    chosen_leaf: u16,
    ws: &mut SignWorkspace,
) -> ForsTreeOut {
    assert!(usize::from(tree_idx) < FORS_TREES && usize::from(chosen_leaf) < FORS_LEAVES);
    let tree = leaf_addr.as_u64();
    let (sec_h, pub_h) = (secret.hasher(true), public.hasher(true));

    let secret_template = tweak(TweakKind::FewSecret, 0, tree, tree_idx, 0, 0);
    sec_h.hash_counter_range(&secret_template, 3, 0, &mut ws.out[..FORS_LEAVES]);
    let chosen_secret = first_n(&ws.out[usize::from(chosen_leaf)]);

    for i in 0..FORS_LEAVES {
        pack_tagged(&mut ws.b32[i], tweak(TweakKind::FewLeaf, 0, tree, tree_idx, 0, u32::try_from(i).unwrap()), &ws.out[i][..N]);
    }
    pub_h.hash_many(&ws.b32[..FORS_LEAVES], &mut ws.out[..FORS_LEAVES]);

    let mut nodes: [[u8; N]; FORS_LEAVES] = core::array::from_fn(|i| first_n(&ws.out[i]));
    let mut auth = [[0u8; N]; FORS_HEIGHT];
    let (mut cur_idx, mut count) = (usize::from(chosen_leaf), FORS_LEAVES);

    for level in 1..=FORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        auth[level - 1] = nodes[cur_idx ^ 1];
        let parents = count / 2;
        for p in 0..parents {
            pack_pair(&mut ws.b48[p], tweak(TweakKind::FewNode, 0, tree, tree_idx, level_u16, u32::try_from(p).unwrap()), &nodes[2 * p], &nodes[2 * p + 1]);
        }
        pub_h.hash_many(&ws.b48[..parents], &mut ws.out[..parents]);
        for p in 0..parents {
            nodes[p] = first_n(&ws.out[p]);
        }
        (cur_idx, count) = (cur_idx >> 1, parents);
    }

    ForsTreeOut { secret: chosen_secret, auth, root: nodes[0] }
}

/// Compress the 16 FORS tree roots into the 16-byte FORS root signed by hypertree layer 0.
pub(crate) fn fors_root(public: &TreeHasher, leaf_addr: LeafAddr, roots: &[[u8; N]; FORS_TREES]) -> [u8; N] {
    let mut input = [0u8; 16 + N * FORS_TREES];
    input[..16].copy_from_slice(&tweak(TweakKind::FewRoot, 0, leaf_addr.as_u64(), 0, 0, 0));
    for t in 0..FORS_TREES {
        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);
    }
    first_n(public.hash(&input).as_bytes())
}

/// Verify a FORS signature and return its reconstructed 16-byte FORS root (batching all 16 trees per level).
pub(crate) fn fors_verify(public: &TreeHasher, leaf_addr: LeafAddr, indices: &[u16; FORS_TREES], sig: &[u8; FORS_LEN]) -> [u8; N] {
    let tree = leaf_addr.as_u64();
    let stride = (1 + FORS_HEIGHT) * N;
    let mut b32 = [[0u8; 32]; FORS_TREES];
    let mut b48 = [[0u8; 48]; FORS_TREES];
    let mut out = [[0u8; 32]; FORS_TREES];

    for t in 0..FORS_TREES {
        pack_tagged(&mut b32[t], tweak(TweakKind::FewLeaf, 0, tree, u16::try_from(t).unwrap(), 0, u32::from(indices[t])), &sig[t * stride..t * stride + N]);
    }
    public.hash_many(&b32[..], &mut out[..]);

    let mut cur: [[u8; N]; FORS_TREES] = core::array::from_fn(|t| first_n(&out[t]));
    let mut idx: [u32; FORS_TREES] = core::array::from_fn(|t| u32::from(indices[t]));

    for level in 1..=FORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        for t in 0..FORS_TREES {
            let sib = &sig[t * stride + level * N..t * stride + (level + 1) * N];
            let (left, right) = if idx[t] & 1 == 0 { (&cur[t][..], sib) } else { (sib, &cur[t][..]) };
            pack_pair(&mut b48[t], tweak(TweakKind::FewNode, 0, tree, u16::try_from(t).unwrap(), level_u16, idx[t] >> 1), left, right);
        }
        public.hash_many(&b48[..], &mut out[..]);
        for t in 0..FORS_TREES {
            cur[t] = first_n(&out[t]);
            idx[t] >>= 1;
        }
    }

    fors_root(public, leaf_addr, &cur)
}

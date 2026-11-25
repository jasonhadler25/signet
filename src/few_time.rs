use crate::one_time::SignWorkspace;
use crate::params::{
    FORS_HEIGHT, FORS_LEAVES, FORS_LEN, FORS_TOTAL_LEAVES, FORS_TREES, LeafAddr, N, PublicKey, SecretKey, TweakKind, first_n, pack_pair, pack_tagged, tweak,
};
use blake3_servil_core::throughput::TreeHasher;

/// Extract the 20 byte-aligned FORS leaf indices (`digest[0..20]`, one byte per tree) and 35-bit
/// hypertree leaf address (`digest[20..28]`, low 35 bits) directly from the 32-byte digest `D`.
pub(crate) fn parse_digest(digest: &[u8; 32]) -> ([u8; FORS_TREES], LeafAddr) {
    let mut indices = [0u8; FORS_TREES];
    indices.copy_from_slice(&digest[..FORS_TREES]);
    let leaf_addr = LeafAddr::from_digest_word(u64::from_le_bytes(digest[20..28].try_into().unwrap()));
    (indices, leaf_addr)
}

/// Build all 20 FORS trees (256 leaves each) in lockstep, batching leaves and Merkle levels across
/// all 20 trees so SIMD/SME2 stays saturated, writing secrets and authentication paths into `out_sig`
/// and returning the 16-byte FORS root.
pub(crate) fn build_all_fors(
    secret: &SecretKey,
    public: &PublicKey,
    leaf_addr: LeafAddr,
    indices: &[u8; FORS_TREES],
    ws: &mut SignWorkspace,
    out_sig: &mut [u8; FORS_LEN],
) -> [u8; N] {
    let tree = leaf_addr.as_u64();
    let stride = (1 + FORS_HEIGHT) * N;
    let (sec_h, pub_h) = (secret.hasher(true), public.hasher(true));

    for (t, &chosen) in indices.iter().enumerate() {
        let base = t * FORS_LEAVES;
        let tree_u16 = u16::try_from(t).unwrap();
        let secret_template = tweak(TweakKind::FewSecret, 0, tree, tree_u16, 0, 0);
        sec_h.hash_counter_range(&secret_template, 3, 0, &mut ws.out[base..base + FORS_LEAVES]);
        out_sig[t * stride..t * stride + N].copy_from_slice(&ws.out[base + usize::from(chosen)][..N]);

        for i in 0..FORS_LEAVES {
            pack_tagged(&mut ws.b32[base + i], tweak(TweakKind::FewLeaf, 0, tree, tree_u16, 0, u32::try_from(i).unwrap()), &ws.out[base + i][..N]);
        }
    }

    pub_h.hash_many(&ws.b32[..FORS_TOTAL_LEAVES], &mut ws.out[..FORS_TOTAL_LEAVES]);
    for i in 0..FORS_TOTAL_LEAVES {
        ws.fors_nodes[i] = first_n(&ws.out[i]);
    }

    let mut cur_idx: [usize; FORS_TREES] = core::array::from_fn(|t| usize::from(indices[t]));
    let mut width = FORS_LEAVES;
    for level in 1..=FORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let parents = width / 2;
        let total_parents = FORS_TREES * parents;
        for t in 0..FORS_TREES {
            let tree_u16 = u16::try_from(t).unwrap();
            let base = t * width;
            out_sig[t * stride + level * N..t * stride + (level + 1) * N].copy_from_slice(&ws.fors_nodes[base + (cur_idx[t] ^ 1)]);
            let p_base = t * parents;
            for p in 0..parents {
                pack_pair(
                    &mut ws.b48[p_base + p],
                    tweak(TweakKind::FewNode, 0, tree, tree_u16, level_u16, u32::try_from(p).unwrap()),
                    &ws.fors_nodes[base + 2 * p],
                    &ws.fors_nodes[base + 2 * p + 1],
                );
            }
            cur_idx[t] >>= 1;
        }
        pub_h.hash_many(&ws.b48[..total_parents], &mut ws.out[..total_parents]);
        for i in 0..total_parents {
            ws.fors_nodes[i] = first_n(&ws.out[i]);
        }
        width = parents;
    }

    let roots: &[[u8; N]; FORS_TREES] = ws.fors_nodes[..FORS_TREES].try_into().unwrap();
    fors_root(&public.hasher(false), leaf_addr, roots)
}

/// Compress the 20 FORS tree roots into the 16-byte FORS root signed by hypertree layer 0.
pub(crate) fn fors_root(public: &TreeHasher, leaf_addr: LeafAddr, roots: &[[u8; N]; FORS_TREES]) -> [u8; N] {
    let mut input = [0u8; 16 + N * FORS_TREES];
    input[..16].copy_from_slice(&tweak(TweakKind::FewRoot, 0, leaf_addr.as_u64(), 0, 0, 0));
    for t in 0..FORS_TREES {
        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);
    }
    first_n(public.hash(&input).as_bytes())
}

/// Verify a FORS signature and return its reconstructed 16-byte FORS root (batching all 20 trees per level).
pub(crate) fn fors_verify(public: &TreeHasher, leaf_addr: LeafAddr, indices: &[u8; FORS_TREES], sig: &[u8; FORS_LEN]) -> [u8; N] {
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

use crate::params::{
    FORS_HEIGHT, FORS_LEAVES, FORS_LEN, FORS_TREES, HYPER_BITS, KIND_FEW_LEAF, KIND_FEW_NODE, KIND_FEW_ROOT, KIND_FEW_SECRET, N, first_n, tweak,
};
use crate::workspace::{VerifyWorkspace, WorkerScratch};
use blake3_servil::Mode;
use blake3_servil::throughput::{Prepared, TreeHasher};

/// Unpack the 16 ten-bit FORS leaf indices (`digest[0..20]`) and 33-bit hypertree leaf address
/// (`digest[20..28]`, low 33 bits) directly from the 32-byte message digest `D`.
#[inline]
pub(crate) fn parse_digest(digest: &[u8; 32]) -> ([u16; FORS_TREES], u64) {
    let mut indices = [0u16; FORS_TREES];
    for group in 0..4 {
        let b = &digest[group * 5..group * 5 + 5];
        let bits = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], 0, 0, 0]);
        for j in 0..4 {
            indices[group * 4 + j] = ((bits >> (10 * j)) & 0x3ff) as u16;
        }
    }
    let leaf_addr = u64::from_le_bytes(digest[20..28].try_into().unwrap()) & ((1u64 << HYPER_BITS) - 1);
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
    secret_key: &[u8; 32],
    public_key: &[u8; 32],
    leaf_addr: u64,
    tree_idx: u16,
    chosen_leaf: u16,
    use_sme2: bool,
    ws: &mut WorkerScratch,
) -> ForsTreeOut {
    debug_assert!((tree_idx as usize) < FORS_TREES && (chosen_leaf as usize) < FORS_LEAVES);
    let sec_h = if use_sme2 { TreeHasher::new(Mode::Keyed(secret_key)) } else { TreeHasher::new(Mode::Keyed(secret_key)).on_this_core() };
    let pub_h = if use_sme2 { TreeHasher::new(Mode::Keyed(public_key)) } else { TreeHasher::new(Mode::Keyed(public_key)).on_this_core() };

    for i in 0..FORS_LEAVES {
        ws.b16.message_mut(i).copy_from_slice(&tweak(KIND_FEW_SECRET, 0, leaf_addr, tree_idx, 0, i as u32));
    }
    sec_h.hash_many(&ws.b16.part(0..FORS_LEAVES), &mut ws.out[..FORS_LEAVES]);
    let chosen_secret = first_n(&ws.out[chosen_leaf as usize]);

    for i in 0..FORS_LEAVES {
        let m = ws.b32.message_mut(i);
        m[..16].copy_from_slice(&tweak(KIND_FEW_LEAF, 0, leaf_addr, tree_idx, 0, i as u32));
        m[16..32].copy_from_slice(&ws.out[i][..N]);
    }
    pub_h.hash_many(&ws.b32.part(0..FORS_LEAVES), &mut ws.out[..FORS_LEAVES]);

    let mut level_nodes = [[0u8; N]; FORS_LEAVES];
    for i in 0..FORS_LEAVES {
        level_nodes[i] = first_n(&ws.out[i]);
    }

    let mut auth = [[0u8; N]; FORS_HEIGHT];
    let mut cur_idx = chosen_leaf as usize;
    let mut count = FORS_LEAVES;
    for level in 1..=FORS_HEIGHT {
        auth[level - 1] = level_nodes[cur_idx ^ 1];
        let parents = count / 2;
        for p in 0..parents {
            let m = ws.b48.message_mut(p);
            m[..16].copy_from_slice(&tweak(KIND_FEW_NODE, 0, leaf_addr, tree_idx, level as u16, p as u32));
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

/// Compress the 16 FORS tree roots into the 16-byte FORS public key signed by hypertree layer 0.
pub(crate) fn fors_root(public: &TreeHasher, leaf_addr: u64, roots: &[[u8; N]; FORS_TREES]) -> [u8; N] {
    let mut input = [0u8; 16 + N * FORS_TREES];
    input[..16].copy_from_slice(&tweak(KIND_FEW_ROOT, 0, leaf_addr, 0, 0, 0));
    for t in 0..FORS_TREES {
        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);
    }
    first_n(public.hash(&input).as_bytes())
}

/// Verify a FORS signature and return its reconstructed 16-byte FORS root (batching all 16 trees per level).
pub(crate) fn fors_verify(public: &TreeHasher, leaf_addr: u64, indices: &[u16; FORS_TREES], sig: &[u8], ws: &mut VerifyWorkspace) -> [u8; N] {
    debug_assert_eq!(sig.len(), FORS_LEN);
    let tree_stride = (1 + FORS_HEIGHT) * N;

    for t in 0..FORS_TREES {
        let m = ws.b32.message_mut(t);
        m[..16].copy_from_slice(&tweak(KIND_FEW_LEAF, 0, leaf_addr, t as u16, 0, indices[t] as u32));
        m[16..32].copy_from_slice(&sig[t * tree_stride..t * tree_stride + N]);
    }
    public.hash_many(&ws.b32.part(0..FORS_TREES), &mut ws.out[..FORS_TREES]);

    let mut cur = [[0u8; N]; FORS_TREES];
    let mut idx = [0u32; FORS_TREES];
    for t in 0..FORS_TREES {
        cur[t] = first_n(&ws.out[t]);
        idx[t] = indices[t] as u32;
    }

    for level in 1..=FORS_HEIGHT {
        for t in 0..FORS_TREES {
            let sib = &sig[t * tree_stride + level * N..t * tree_stride + (level + 1) * N];
            let m = ws.b48.message_mut(t);
            m[..16].copy_from_slice(&tweak(KIND_FEW_NODE, 0, leaf_addr, t as u16, level as u16, idx[t] >> 1));
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

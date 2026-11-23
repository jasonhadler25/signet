use crate::params::{CHAIN_STEPS, CHAINS, Layer, MSG_CHAINS, N, PublicKey, SecretKey, TreeIndex, TweakKind, first_n, tweak};
use crate::workspace::{VerifyWorkspace, WOTS_CHUNK_LEAVES, WorkerScratch};
use blake3_servil::throughput::{Batch, Prepared, TreeHasher};

/// Checked position of a one-time signature in the hypertree (`leaf < layer.leaves()`).
#[derive(Clone, Copy)]
pub(crate) struct Pos {
    layer: Layer,
    tree: TreeIndex,
    leaf: u16,
}

impl Pos {
    #[inline]
    pub(crate) fn new(layer: Layer, tree: TreeIndex, leaf: u16) -> Self {
        assert!(usize::from(leaf) < layer.leaves());
        Self { layer, tree, leaf }
    }

    #[inline]
    pub(crate) fn layer(self) -> Layer {
        self.layer
    }
}

/// Convert a 16-byte message/root into 35 WOTS+ nibble digits (32 message nibbles + 3 checksum nibbles,
/// little-endian nibble order; SPEC.md, "One-time signatures").
#[inline]
pub(crate) fn digits(node: &[u8; N]) -> [u8; CHAINS] {
    let mut out = [0u8; CHAINS];
    let mut csum = 0u16;
    for (i, &byte) in node.iter().enumerate() {
        let lo = byte & 0x0f;
        let hi = byte >> 4;
        out[2 * i] = lo;
        out[2 * i + 1] = hi;
        csum += u16::from(CHAIN_STEPS - lo) + u16::from(CHAIN_STEPS - hi);
    }
    out[MSG_CHAINS] = u8::try_from(csum & 0x0f).unwrap();
    out[MSG_CHAINS + 1] = u8::try_from((csum >> 4) & 0x0f).unwrap();
    out[MSG_CHAINS + 2] = u8::try_from((csum >> 8) & 0x0f).unwrap();
    out
}

/// Advance each of 35 chains in place from `starts[c]` to `ends[c]`, batching active chains at each step.
pub(crate) fn advance_chains(
    public: &TreeHasher,
    pos: Pos,
    values: &mut [[u8; N]; CHAINS],
    starts: &[u8; CHAINS],
    ends: &[u8; CHAINS],
    b32: &mut Batch<'_>,
    out: &mut [[u8; 32]],
) {
    let mut order = [(0u8, 0u8); CHAINS];
    for c in 0..CHAINS {
        assert!(starts[c] <= ends[c] && ends[c] <= CHAIN_STEPS);
        order[c] = (ends[c] - starts[c], u8::try_from(c).unwrap());
    }
    order.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));

    let mut active = CHAINS;
    while active > 0 && order[active - 1].0 == 0 {
        active -= 1;
    }
    let layer = pos.layer.as_u8();
    for (slot, &(_, c)) in order[..active].iter().enumerate() {
        let idx = usize::from(c);
        let m = b32.message_mut(slot);
        m[..16].copy_from_slice(&tweak(TweakKind::Chain, layer, pos.tree, pos.leaf, u16::from(c), u32::from(starts[idx])));
        m[16..32].copy_from_slice(&values[idx]);
    }
    for step in 1..=CHAIN_STEPS {
        if active == 0 {
            break;
        }
        public.hash_many(&b32.part(0..active), &mut out[..active]);
        while active > 0 && order[active - 1].0 == step {
            active -= 1;
            values[usize::from(order[active].1)].copy_from_slice(&out[active][..N]);
        }
        for (slot, &(_, c)) in order[..active].iter().enumerate() {
            let idx = usize::from(c);
            let m = b32.message_mut(slot);
            m[12..16].copy_from_slice(&u32::from(starts[idx] + step).to_le_bytes());
            m[16..32].copy_from_slice(&out[slot][..N]);
        }
    }
}

/// Secret and public hash keys passed together to one-time tree helpers.
#[derive(Clone, Copy)]
pub(crate) struct KeyPair<'a> {
    pub secret: &'a SecretKey,
    pub public: &'a PublicKey,
}

/// Build `out_leaves.len()` consecutive WOTS+ verifying-key leaves starting at `pos.leaf`.
pub(crate) fn build_wots_leaves_chunk(keys: KeyPair<'_>, pos: Pos, use_sme2: bool, ws: &mut WorkerScratch, out_leaves: &mut [[u8; N]]) {
    let count = out_leaves.len();
    assert!(count > 0 && count <= WOTS_CHUNK_LEAVES && usize::from(pos.leaf) + count <= pos.layer.leaves());
    let total = count * CHAINS;
    let layer = pos.layer.as_u8();

    let sec_h = keys.secret.tree_hasher(use_sme2);
    let pub_h = keys.public.tree_hasher(use_sme2);

    for i in 0..count {
        let leaf = pos.leaf + u16::try_from(i).unwrap();
        for c in 0..CHAINS {
            let c_u16 = u16::try_from(c).unwrap();
            ws.b16.message_mut(i * CHAINS + c).copy_from_slice(&tweak(TweakKind::ChainSecret, layer, pos.tree, leaf, c_u16, 0));
        }
    }
    sec_h.hash_many(&ws.b16.part(0..total), &mut ws.out[..total]);

    for i in 0..count {
        let leaf = pos.leaf + u16::try_from(i).unwrap();
        for c in 0..CHAINS {
            let c_u16 = u16::try_from(c).unwrap();
            let slot = i * CHAINS + c;
            let m = ws.b32.message_mut(slot);
            m[..16].copy_from_slice(&tweak(TweakKind::Chain, layer, pos.tree, leaf, c_u16, 0));
            m[16..32].copy_from_slice(&ws.out[slot][..N]);
        }
    }
    pub_h.hash_many(&ws.b32.part(0..total), &mut ws.out[..total]);
    for step in 1..CHAIN_STEPS {
        let next = u32::from(step).to_le_bytes();
        for slot in 0..total {
            let m = ws.b32.message_mut(slot);
            m[12..16].copy_from_slice(&next);
            m[16..32].copy_from_slice(&ws.out[slot][..N]);
        }
        pub_h.hash_many(&ws.b32.part(0..total), &mut ws.out[..total]);
    }

    for i in 0..count {
        let leaf = pos.leaf + u16::try_from(i).unwrap();
        let m = ws.b_pk.message_mut(i);
        m[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer, pos.tree, leaf, 0, 0));
        for c in 0..CHAINS {
            m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&ws.out[i * CHAINS + c][..N]);
        }
    }
    pub_h.hash_many(&ws.b_pk.part(0..count), &mut ws.out[..count]);
    for i in 0..count {
        out_leaves[i] = first_n(&ws.out[i]);
    }
}

/// Build the 1-indexed binary Merkle heap (`2 * layer.leaves()` nodes; index `1` is the root) from `leaves`.
pub(crate) fn build_merkle_heap(public_key: &PublicKey, layer: Layer, tree: TreeIndex, leaves: &[[u8; N]], ws: &mut WorkerScratch) -> Vec<[u8; N]> {
    let n_leaves = layer.leaves();
    assert_eq!(leaves.len(), n_leaves);
    let mut nodes = vec![[0u8; N]; 2 * n_leaves];
    nodes[n_leaves..].copy_from_slice(leaves);

    let pub_h = public_key.tree_hasher(true);
    let layer_u8 = layer.as_u8();
    let mut level_start = n_leaves;
    let mut count = n_leaves;
    for level in 1..=layer.height() {
        let level_u16 = u16::try_from(level).unwrap();
        let parents = count / 2;
        let parent_start = level_start / 2;
        let chunk = parents.min(ws.b48.len());
        assert_eq!(parents % chunk, 0);
        let mut offset = 0usize;
        while offset < parents {
            for j in 0..chunk {
                let idx = offset + j;
                let idx_u32 = u32::try_from(idx).unwrap();
                let m = ws.b48.message_mut(j);
                m[..16].copy_from_slice(&tweak(TweakKind::Node, layer_u8, tree, 0, level_u16, idx_u32));
                m[16..32].copy_from_slice(&nodes[level_start + 2 * idx]);
                m[32..48].copy_from_slice(&nodes[level_start + 2 * idx + 1]);
            }
            pub_h.hash_many(&ws.b48.part(0..chunk), &mut ws.out[..chunk]);
            for j in 0..chunk {
                nodes[parent_start + offset + j] = first_n(&ws.out[j]);
            }
            offset += chunk;
        }
        level_start = parent_start;
        count = parents;
    }
    nodes
}

/// Write a WOTS+ signature (35 chains) and authentication path (`pos.layer().height()` nodes) into `out`.
pub(crate) fn write_layer_signature(keys: KeyPair<'_>, pos: Pos, node: &[u8; N], tree_nodes: &[[u8; N]], ws: &mut WorkerScratch, out: &mut [u8]) {
    let layer = pos.layer();
    let height = layer.height();
    assert_eq!(out.len(), layer.sig_len());
    assert_eq!(tree_nodes.len(), 2 * layer.leaves());
    let d = digits(node);

    let sec_h = keys.secret.tree_hasher(false);
    let pub_h = keys.public.tree_hasher(false);
    let layer_u8 = layer.as_u8();

    for c in 0..CHAINS {
        let c_u16 = u16::try_from(c).unwrap();
        ws.b16.message_mut(c).copy_from_slice(&tweak(TweakKind::ChainSecret, layer_u8, pos.tree, pos.leaf, c_u16, 0));
    }
    sec_h.hash_many(&ws.b16.part(0..CHAINS), &mut ws.out[..CHAINS]);
    let mut values = [[0u8; N]; CHAINS];
    for c in 0..CHAINS {
        values[c] = first_n(&ws.out[c]);
    }
    advance_chains(&pub_h, pos, &mut values, &[0u8; CHAINS], &d, &mut ws.b32, &mut ws.out);

    for c in 0..CHAINS {
        out[c * N..(c + 1) * N].copy_from_slice(&values[c]);
    }
    let mut cursor = layer.leaves() + usize::from(pos.leaf);
    let auth_off = CHAINS * N;
    for level in 0..height {
        out[auth_off + level * N..auth_off + (level + 1) * N].copy_from_slice(&tree_nodes[cursor ^ 1]);
        cursor >>= 1;
    }
}

/// Verify one hypertree layer signature and return its reconstructed Merkle root.
pub(crate) fn verify_layer(public: &TreeHasher, pos: Pos, node: &[u8; N], layer_sig: &[u8], ws: &mut VerifyWorkspace) -> [u8; N] {
    let layer = pos.layer();
    let height = layer.height();
    assert_eq!(layer_sig.len(), layer.sig_len());
    let d = digits(node);
    let mut values = [[0u8; N]; CHAINS];
    for c in 0..CHAINS {
        values[c].copy_from_slice(&layer_sig[c * N..(c + 1) * N]);
    }
    advance_chains(public, pos, &mut values, &d, &[CHAIN_STEPS; CHAINS], &mut ws.b32, &mut ws.out);

    let layer_u8 = layer.as_u8();
    let mut pk_in = [0u8; 16 + N * CHAINS];
    pk_in[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, pos.tree, pos.leaf, 0, 0));
    for c in 0..CHAINS {
        pk_in[16 + c * N..16 + (c + 1) * N].copy_from_slice(&values[c]);
    }
    let mut cur = first_n(public.hash(&pk_in).as_bytes());

    let auth_off = CHAINS * N;
    let mut index = u32::from(pos.leaf);
    let mut pair = [0u8; 48];
    for level in 1..=height {
        let level_u16 = u16::try_from(level).unwrap();
        let sib = &layer_sig[auth_off + (level - 1) * N..auth_off + level * N];
        pair[..16].copy_from_slice(&tweak(TweakKind::Node, layer_u8, pos.tree, 0, level_u16, index >> 1));
        if index & 1 == 0 {
            pair[16..32].copy_from_slice(&cur);
            pair[32..48].copy_from_slice(sib);
        } else {
            pair[16..32].copy_from_slice(sib);
            pair[32..48].copy_from_slice(&cur);
        }
        cur = first_n(public.hash(&pair).as_bytes());
        index >>= 1;
    }
    cur
}

#[cfg(test)]
pub(crate) fn lower_tree_len_check() -> usize {
    assert_eq!(Layer::L0.leaves(), 1 << Layer::L0.height());
    assert_eq!(Layer::TOP.leaves(), 1 << Layer::TOP.height());
    2 * Layer::TOP.leaves()
}

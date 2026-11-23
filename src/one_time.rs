use crate::params::{
    CHAIN_STEPS, CHAINS, KIND_CHAIN, KIND_CHAIN_SECRET, KIND_NODE, KIND_ONE_TIME_KEY, LOWER_LAYER_LEN, MSG_CHAINS, N, TOP_HEIGHT, TOP_LAYER_LEN, first_n, tweak,
};
use crate::workspace::{VerifyWorkspace, WOTS_CHUNK_LEAVES, WorkerScratch};
use blake3_servil::Mode;
use blake3_servil::throughput::{Batch, Prepared, TreeHasher};

/// Position of a one-time signature in the hypertree.
#[derive(Clone, Copy)]
pub(crate) struct Pos {
    pub layer: u8,
    pub tree: u64,
    pub leaf: u16,
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
        csum += (CHAIN_STEPS as u16 - lo as u16) + (CHAIN_STEPS as u16 - hi as u16);
    }
    out[MSG_CHAINS] = (csum & 0x0f) as u8;
    out[MSG_CHAINS + 1] = ((csum >> 4) & 0x0f) as u8;
    out[MSG_CHAINS + 2] = ((csum >> 8) & 0x0f) as u8;
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
    let mut order = [(0u8, 0usize); CHAINS];
    for c in 0..CHAINS {
        assert!(starts[c] <= ends[c] && ends[c] as u32 <= CHAIN_STEPS);
        order[c] = (ends[c] - starts[c], c);
    }
    order.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));

    let mut active = CHAINS;
    while active > 0 && order[active - 1].0 == 0 {
        active -= 1;
    }
    for (slot, &(_, c)) in order[..active].iter().enumerate() {
        let m = b32.message_mut(slot);
        m[..16].copy_from_slice(&tweak(KIND_CHAIN, pos.layer, pos.tree, pos.leaf, c as u16, starts[c] as u32));
        m[16..32].copy_from_slice(&values[c]);
    }
    for step in 1..=(CHAIN_STEPS as u8) {
        if active == 0 {
            break;
        }
        public.hash_many(&b32.part(0..active), &mut out[..active]);
        for (slot, &(rem, c)) in order[..active].iter().enumerate() {
            if step < rem {
                let m = b32.message_mut(slot);
                m[12..16].copy_from_slice(&((starts[c] + step) as u32).to_le_bytes());
                m[16..32].copy_from_slice(&out[slot][..N]);
            } else {
                values[c].copy_from_slice(&out[slot][..N]);
            }
        }
        while active > 0 && order[active - 1].0 <= step {
            active -= 1;
        }
    }
}

/// Secret and public hash keys passed together to one-time tree helpers.
#[derive(Clone, Copy)]
pub(crate) struct KeyPair<'a> {
    pub secret: &'a [u8; 32],
    pub public: &'a [u8; 32],
}

/// Build `out_leaves.len()` consecutive WOTS+ public-key leaves starting at `start_leaf`.
pub(crate) fn build_wots_leaves_chunk(keys: KeyPair<'_>, pos: Pos, use_sme2: bool, ws: &mut WorkerScratch, out_leaves: &mut [[u8; N]]) {
    let count = out_leaves.len();
    assert!(count > 0 && count <= WOTS_CHUNK_LEAVES);
    let total = count * CHAINS;

    let sec_h = if use_sme2 { TreeHasher::new(Mode::Keyed(keys.secret)) } else { TreeHasher::new(Mode::Keyed(keys.secret)).on_this_core() };
    let pub_h = if use_sme2 { TreeHasher::new(Mode::Keyed(keys.public)) } else { TreeHasher::new(Mode::Keyed(keys.public)).on_this_core() };

    for i in 0..count {
        let leaf = pos.leaf + i as u16;
        for c in 0..CHAINS {
            ws.b16.message_mut(i * CHAINS + c).copy_from_slice(&tweak(KIND_CHAIN_SECRET, pos.layer, pos.tree, leaf, c as u16, 0));
        }
    }
    sec_h.hash_many(&ws.b16.part(0..total), &mut ws.out[..total]);

    for i in 0..count {
        let leaf = pos.leaf + i as u16;
        for c in 0..CHAINS {
            let slot = i * CHAINS + c;
            let m = ws.b32.message_mut(slot);
            m[..16].copy_from_slice(&tweak(KIND_CHAIN, pos.layer, pos.tree, leaf, c as u16, 0));
            m[16..32].copy_from_slice(&ws.out[slot][..N]);
        }
    }
    for step in 0..CHAIN_STEPS {
        pub_h.hash_many(&ws.b32.part(0..total), &mut ws.out[..total]);
        if step + 1 < CHAIN_STEPS {
            let next = (step + 1).to_le_bytes();
            for slot in 0..total {
                let m = ws.b32.message_mut(slot);
                m[12..16].copy_from_slice(&next);
                m[16..32].copy_from_slice(&ws.out[slot][..N]);
            }
        }
    }

    for i in 0..count {
        let leaf = pos.leaf + i as u16;
        let m = ws.b_pk.message_mut(i);
        m[..16].copy_from_slice(&tweak(KIND_ONE_TIME_KEY, pos.layer, pos.tree, leaf, 0, 0));
        for c in 0..CHAINS {
            m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&ws.out[i * CHAINS + c][..N]);
        }
    }
    pub_h.hash_many(&ws.b_pk.part(0..count), &mut ws.out[..count]);
    for i in 0..count {
        out_leaves[i] = first_n(&ws.out[i]);
    }
}

/// Build the 1-indexed binary Merkle heap (`2 * leaves.len()` nodes; index `1` is the root) from `leaves`.
pub(crate) fn build_merkle_heap(public_key: &[u8; 32], layer: u8, tree: u64, height: usize, leaves: &[[u8; N]], ws: &mut WorkerScratch) -> Vec<[u8; N]> {
    let n_leaves = 1usize << height;
    assert_eq!(leaves.len(), n_leaves);
    let mut nodes = vec![[0u8; N]; 2 * n_leaves];
    nodes[n_leaves..].copy_from_slice(leaves);

    let pub_h = TreeHasher::new(Mode::Keyed(public_key));
    let mut level_start = n_leaves;
    let mut count = n_leaves;
    for level in 1..=height {
        let parents = count / 2;
        let parent_start = level_start / 2;
        let mut offset = 0usize;
        while offset < parents {
            let chunk = (parents - offset).min(ws.b48.len());
            for j in 0..chunk {
                let idx = offset + j;
                let m = ws.b48.message_mut(j);
                m[..16].copy_from_slice(&tweak(KIND_NODE, layer, tree, 0, level as u16, idx as u32));
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

/// Write a WOTS+ signature (35 chains) and authentication path (`height` nodes) for `pos` into `out`.
pub(crate) fn write_layer_signature(
    keys: KeyPair<'_>,
    pos: Pos,
    height: usize,
    node: &[u8; N],
    tree_nodes: &[[u8; N]],
    ws: &mut WorkerScratch,
    out: &mut [u8],
) {
    let expected_len = if height == TOP_HEIGHT { TOP_LAYER_LEN } else { LOWER_LAYER_LEN };
    assert_eq!(out.len(), expected_len);
    assert_eq!(tree_nodes.len(), 2usize << height);
    let d = digits(node);

    let sec_h = TreeHasher::new(Mode::Keyed(keys.secret)).on_this_core();
    let pub_h = TreeHasher::new(Mode::Keyed(keys.public)).on_this_core();

    for c in 0..CHAINS {
        ws.b16.message_mut(c).copy_from_slice(&tweak(KIND_CHAIN_SECRET, pos.layer, pos.tree, pos.leaf, c as u16, 0));
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
    let mut cursor = (1usize << height) + pos.leaf as usize;
    let auth_off = CHAINS * N;
    for level in 0..height {
        out[auth_off + level * N..auth_off + (level + 1) * N].copy_from_slice(&tree_nodes[cursor ^ 1]);
        cursor >>= 1;
    }
}

/// Verify one hypertree layer signature and return its reconstructed Merkle root.
pub(crate) fn verify_layer(public: &TreeHasher, pos: Pos, height: usize, node: &[u8; N], layer_sig: &[u8], ws: &mut VerifyWorkspace) -> [u8; N] {
    debug_assert_eq!(layer_sig.len(), (CHAINS + height) * N);
    let d = digits(node);
    let mut values = [[0u8; N]; CHAINS];
    for c in 0..CHAINS {
        values[c].copy_from_slice(&layer_sig[c * N..(c + 1) * N]);
    }
    advance_chains(public, pos, &mut values, &d, &[CHAIN_STEPS as u8; CHAINS], &mut ws.b32, &mut ws.out);

    let mut pk_in = [0u8; 16 + N * CHAINS];
    pk_in[..16].copy_from_slice(&tweak(KIND_ONE_TIME_KEY, pos.layer, pos.tree, pos.leaf, 0, 0));
    for c in 0..CHAINS {
        pk_in[16 + c * N..16 + (c + 1) * N].copy_from_slice(&values[c]);
    }
    let mut cur = first_n(public.hash(&pk_in).as_bytes());

    let auth_off = CHAINS * N;
    let mut index = pos.leaf as u32;
    let mut pair = [0u8; 48];
    for level in 1..=height {
        let sib = &layer_sig[auth_off + (level - 1) * N..auth_off + level * N];
        pair[..16].copy_from_slice(&tweak(KIND_NODE, pos.layer, pos.tree, 0, level as u16, index >> 1));
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
    assert_eq!(crate::params::LOWER_LEAVES, 1 << crate::params::LOWER_HEIGHT);
    assert_eq!(crate::params::TOP_NODES, 2 << TOP_HEIGHT);
    crate::params::TOP_NODES
}

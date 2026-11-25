use crate::params::{
    CHAIN_STEPS, CHAINS, FORS_LEAVES, LAYER_LEN, Layer, MSG_CHAINS, N, PublicKey, SecretKey, TREE_HEIGHT, TREE_LEAVES, TweakKind, first_n, pack_pair,
    pack_tagged, tweak,
};
use blake3_servil_core::throughput::{Batch, Prepared, TreeHasher};

const WOTS_BATCH_SLOTS: usize = TREE_LEAVES * CHAINS;
const MERKLE_BATCH_SLOTS: usize = FORS_LEAVES / 2;

const _: () = {
    assert!(WOTS_BATCH_SLOTS == 1120 && WOTS_BATCH_SLOTS >= FORS_LEAVES && MERKLE_BATCH_SLOTS == 128);
};

/// Transient heap workspace owned by a single `Signet::from_seed` or `Signet::imprint` call.
pub(crate) struct SignWorkspace {
    pub b16: Vec<[u8; 16]>,
    pub b32: Vec<[u8; 32]>,
    pub b48: Vec<[u8; 48]>,
    pub b_pk: Batch<'static>,
    pub out: Vec<[u8; 32]>,
}

impl SignWorkspace {
    pub(crate) fn new() -> Self {
        Self {
            b16: vec![[0u8; 16]; WOTS_BATCH_SLOTS],
            b32: vec![[0u8; 32]; WOTS_BATCH_SLOTS],
            b48: vec![[0u8; 48]; MERKLE_BATCH_SLOTS],
            b_pk: Batch::new(16 + N * CHAINS, TREE_LEAVES),
            out: vec![[0u8; 32]; WOTS_BATCH_SLOTS],
        }
    }
}

/// Checked position of a one-time signature in the hypertree (`tree < layer.trees()` and `leaf < TREE_LEAVES`).
#[derive(Clone, Copy)]
pub(crate) struct Pos {
    layer: Layer,
    tree: u64,
    leaf: u16,
}

impl Pos {
    pub(crate) fn new(layer: Layer, tree: u64, leaf: u16) -> Self {
        assert!(tree < layer.trees() && usize::from(leaf) < TREE_LEAVES);
        Self { layer, tree, leaf }
    }
}

/// Convert a 16-byte node into 35 WOTS+ nibble digits (32 message nibbles + 3 checksum nibbles,
/// little-endian nibble order; SPEC.md, "One-time signatures").
pub(crate) fn digits(node: &[u8; N]) -> [u8; CHAINS] {
    let mut out = [0u8; CHAINS];
    let mut csum = 0u16;
    for (i, &byte) in node.iter().enumerate() {
        let (lo, hi) = (byte & 0x0f, byte >> 4);
        out[2 * i] = lo;
        out[2 * i + 1] = hi;
        csum += u16::from(CHAIN_STEPS - lo) + u16::from(CHAIN_STEPS - hi);
    }
    out[MSG_CHAINS] = u8::try_from(csum & 0x0f).unwrap();
    out[MSG_CHAINS + 1] = u8::try_from((csum >> 4) & 0x0f).unwrap();
    out[MSG_CHAINS + 2] = u8::try_from((csum >> 8) & 0x0f).unwrap();
    out
}

/// Advance each of 35 chains in place from `starts[c]` to `ends[c]`, batching active chains per step.
pub(crate) fn advance_chains(public: &TreeHasher, pos: Pos, values: &mut [[u8; N]; CHAINS], starts: &[u8; CHAINS], ends: &[u8; CHAINS]) {
    let mut order: [(u8, u8); CHAINS] = core::array::from_fn(|c| {
        assert!(starts[c] <= ends[c] && ends[c] <= CHAIN_STEPS);
        (ends[c] - starts[c], u8::try_from(c).unwrap())
    });
    order.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));

    let mut active = CHAINS;
    while active > 0 && order[active - 1].0 == 0 {
        active -= 1;
    }
    let mut b32 = [[0u8; 32]; CHAINS];
    let mut out = [[0u8; 32]; CHAINS];
    let layer = pos.layer.as_u8();
    for (slot, &(_, c)) in order[..active].iter().enumerate() {
        let idx = usize::from(c);
        pack_tagged(&mut b32[slot], tweak(TweakKind::Chain, layer, pos.tree, pos.leaf, u16::from(c), u32::from(starts[idx])), &values[idx]);
    }
    for step in 1..=CHAIN_STEPS {
        if active == 0 {
            break;
        }
        public.hash_many(&b32[..active], &mut out[..active]);
        while active > 0 && order[active - 1].0 == step {
            active -= 1;
            values[usize::from(order[active].1)].copy_from_slice(&out[active][..N]);
        }
        for (slot, &(_, c)) in order[..active].iter().enumerate() {
            let idx = usize::from(c);
            let m = &mut b32[slot];
            m[12..16].copy_from_slice(&u32::from(starts[idx] + step).to_le_bytes());
            m[16..32].copy_from_slice(&out[slot][..N]);
        }
    }
}

/// Build all `TREE_LEAVES` (32) WOTS+ verifying-key leaves for `(layer, tree)` and its 1-indexed
/// binary Merkle heap (`2 * TREE_LEAVES` nodes; index `1` is the root).
pub(crate) fn build_tree_heap(secret: &SecretKey, public: &PublicKey, layer: Layer, tree: u64, ws: &mut SignWorkspace) -> [[u8; N]; 2 * TREE_LEAVES] {
    assert!(tree < layer.trees());
    let layer_u8 = layer.as_u8();
    let (sec_h, pub_h) = (secret.hasher(true), public.hasher(true));

    for i in 0..TREE_LEAVES {
        let leaf = u16::try_from(i).unwrap();
        for c in 0..CHAINS {
            ws.b16[i * CHAINS + c] = tweak(TweakKind::ChainSecret, layer_u8, tree, leaf, u16::try_from(c).unwrap(), 0);
        }
    }
    sec_h.hash_many(&ws.b16[..WOTS_BATCH_SLOTS], &mut ws.out[..WOTS_BATCH_SLOTS]);

    for i in 0..TREE_LEAVES {
        let leaf = u16::try_from(i).unwrap();
        for c in 0..CHAINS {
            let slot = i * CHAINS + c;
            pack_tagged(&mut ws.b32[slot], tweak(TweakKind::Chain, layer_u8, tree, leaf, u16::try_from(c).unwrap(), 0), &ws.out[slot][..N]);
        }
    }
    pub_h.hash_many(&ws.b32[..WOTS_BATCH_SLOTS], &mut ws.out[..WOTS_BATCH_SLOTS]);
    for step in 1..CHAIN_STEPS {
        let next = u32::from(step).to_le_bytes();
        for slot in 0..WOTS_BATCH_SLOTS {
            let m = &mut ws.b32[slot];
            m[12..16].copy_from_slice(&next);
            m[16..32].copy_from_slice(&ws.out[slot][..N]);
        }
        pub_h.hash_many(&ws.b32[..WOTS_BATCH_SLOTS], &mut ws.out[..WOTS_BATCH_SLOTS]);
    }

    for i in 0..TREE_LEAVES {
        let leaf = u16::try_from(i).unwrap();
        let m = ws.b_pk.message_mut(i);
        m[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, leaf, 0, 0));
        for c in 0..CHAINS {
            m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&ws.out[i * CHAINS + c][..N]);
        }
    }
    pub_h.hash_many(&ws.b_pk.part(0..TREE_LEAVES), &mut ws.out[..TREE_LEAVES]);

    let mut nodes = [[0u8; N]; 2 * TREE_LEAVES];
    for i in 0..TREE_LEAVES {
        nodes[TREE_LEAVES + i] = first_n(&ws.out[i]);
    }

    let (mut level_start, mut count) = (TREE_LEAVES, TREE_LEAVES);
    for level in 1..=TREE_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let (parents, parent_start) = (count / 2, level_start / 2);
        for (j, slot) in ws.b48[..parents].iter_mut().enumerate() {
            pack_pair(
                slot,
                tweak(TweakKind::Node, layer_u8, tree, 0, level_u16, u32::try_from(j).unwrap()),
                &nodes[level_start + 2 * j],
                &nodes[level_start + 2 * j + 1],
            );
        }
        pub_h.hash_many(&ws.b48[..parents], &mut ws.out[..parents]);
        for j in 0..parents {
            nodes[parent_start + j] = first_n(&ws.out[j]);
        }
        (level_start, count) = (parent_start, parents);
    }
    nodes
}

/// Write a WOTS+ signature (35 chains) and authentication path (`TREE_HEIGHT` nodes) into `out`.
pub(crate) fn write_layer_signature(secret: &SecretKey, public: &PublicKey, pos: Pos, node: &[u8; N], tree_nodes: &[[u8; N]; 2 * TREE_LEAVES], out: &mut [u8]) {
    assert_eq!(out.len(), LAYER_LEN);

    let (sec_h, pub_h) = (secret.hasher(false), public.hasher(false));
    let layer_u8 = pos.layer.as_u8();
    let mut b16 = [[0u8; 16]; CHAINS];
    let mut hashes = [[0u8; 32]; CHAINS];
    for (c, slot) in b16.iter_mut().enumerate() {
        *slot = tweak(TweakKind::ChainSecret, layer_u8, pos.tree, pos.leaf, u16::try_from(c).unwrap(), 0);
    }
    sec_h.hash_many(&b16[..], &mut hashes[..]);
    let mut values: [[u8; N]; CHAINS] = core::array::from_fn(|c| first_n(&hashes[c]));
    advance_chains(&pub_h, pos, &mut values, &[0u8; CHAINS], &digits(node));

    for c in 0..CHAINS {
        out[c * N..(c + 1) * N].copy_from_slice(&values[c]);
    }
    let mut cursor = TREE_LEAVES + usize::from(pos.leaf);
    let auth_off = CHAINS * N;
    for level in 0..TREE_HEIGHT {
        out[auth_off + level * N..auth_off + (level + 1) * N].copy_from_slice(&tree_nodes[cursor ^ 1]);
        cursor >>= 1;
    }
}

/// Verify one hypertree layer signature and return its reconstructed Merkle root.
pub(crate) fn verify_layer(public: &TreeHasher, pos: Pos, node: &[u8; N], layer_sig: &[u8]) -> [u8; N] {
    assert_eq!(layer_sig.len(), LAYER_LEN);

    let mut values: [[u8; N]; CHAINS] = core::array::from_fn(|c| layer_sig[c * N..(c + 1) * N].try_into().unwrap());
    advance_chains(public, pos, &mut values, &digits(node), &[CHAIN_STEPS; CHAINS]);

    let layer_u8 = pos.layer.as_u8();
    let mut pk_in = [0u8; 16 + N * CHAINS];
    pk_in[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, pos.tree, pos.leaf, 0, 0));
    for c in 0..CHAINS {
        pk_in[16 + c * N..16 + (c + 1) * N].copy_from_slice(&values[c]);
    }
    let mut cur = first_n(public.hash(&pk_in).as_bytes());

    let auth_off = CHAINS * N;
    let mut index = u32::from(pos.leaf);
    let mut pair = [0u8; 48];
    for level in 1..=TREE_HEIGHT {
        let sib = &layer_sig[auth_off + (level - 1) * N..auth_off + level * N];
        let (left, right) = if index & 1 == 0 { (&cur[..], sib) } else { (sib, &cur[..]) };
        pack_pair(&mut pair, tweak(TweakKind::Node, layer_u8, pos.tree, 0, u16::try_from(level).unwrap(), index >> 1), left, right);
        cur = first_n(public.hash(&pair).as_bytes());
        index >>= 1;
    }
    cur
}

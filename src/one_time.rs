use crate::params::{
    CHAIN_STEPS, CHAINS, DIGIT_SUM, KIND_CHAIN, KIND_CHAIN_SECRET, KIND_NODE, KIND_ONE_TIME_KEY, KIND_ONE_TIME_MESSAGE, LAYER_LEN, N, TOP_NODES, TREE_HEIGHT,
    TREE_LEAVES, ZERO_BITS, first_n, keyed, short_hash, tweak,
};
use crate::workspace::{GRIND, SignWorkspace, VerifyWorkspace};
use blake3_servil_core::Mode;
use blake3_servil_core::throughput::{self, Batch, Prepared};

/// Check a 16-byte `ONE_TIME_MESSAGE` digest: low 8 bits zero and 24 five-bit digits summing to 372.
pub(crate) fn parse_digits(digest: &[u8; 32]) -> Option<[u8; CHAINS]> {
    let mut x = u128::from_le_bytes(digest[..N].try_into().unwrap());
    if (x & ((1u128 << ZERO_BITS) - 1)) != 0 {
        return None;
    }
    x >>= ZERO_BITS;
    let mut out = [0u8; CHAINS];
    let mut sum = 0u32;
    for slot in &mut out {
        let d = (x & 31) as u8;
        *slot = d;
        sum += d as u32;
        x >>= 5;
    }
    (sum == DIGIT_SUM).then_some(out)
}

/// Position of a one-time signature in the hypertree.
#[derive(Clone, Copy)]
pub(crate) struct Pos {
    pub layer: u8,
    pub tree: u64,
    pub leaf: u16,
}

/// Evaluate `ONE_TIME_MESSAGE` for one `(pos, node, counter)`.
pub(crate) fn digits(public: &[u8; 32], pos: Pos, node: &[u8; N], counter: u32) -> Option<[u8; CHAINS]> {
    let mut input = [0u8; 36];
    input[..16].copy_from_slice(&tweak(KIND_ONE_TIME_MESSAGE, pos.layer, pos.tree, pos.leaf, 0, 0));
    input[16..32].copy_from_slice(node);
    input[32..36].copy_from_slice(&counter.to_le_bytes());
    parse_digits(&keyed(public, &input))
}

/// Find the smallest `counter` in `0..=u32::MAX` that passes `ONE_TIME_MESSAGE`.
fn search_wots(public: &[u8; 32], pos: Pos, node: &[u8; N], ws: &mut SignWorkspace) -> (u32, [u8; CHAINS]) {
    let t = tweak(KIND_ONE_TIME_MESSAGE, pos.layer, pos.tree, pos.leaf, 0, 0);
    for i in 0..GRIND {
        let m = ws.b_wmsg.message_mut(i);
        m[..16].copy_from_slice(&t);
        m[16..32].copy_from_slice(node);
    }
    let mut base = 0u64;
    loop {
        let count = (u32::MAX as u64 + 1 - base).min(GRIND as u64) as usize;
        assert!(count > 0, "one-time counter search exhausted 2^32 tries");
        for i in 0..count {
            ws.b_wmsg.message_mut(i)[32..36].copy_from_slice(&((base + i as u64) as u32).to_le_bytes());
        }
        throughput::hash_many(Mode::Keyed(public), &ws.b_wmsg.part(0..count), &mut ws.out[..count]);
        for (i, digest) in ws.out.iter().enumerate().take(count) {
            if let Some(d) = parse_digits(digest) {
                return ((base + i as u64) as u32, d);
            }
        }
        base += count as u64;
    }
}

/// Advance each of 24 chains in place from `starts[c]` to `ends[c]`, batching active chains at each step.
/// Shared by layer-3 signing (using the cached top tree) and by signature verification.
pub(crate) fn advance_chains(
    public: &[u8; 32],
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
    let mut step = 0u8;
    while active > 0 {
        throughput::hash_many(Mode::Keyed(public), &b32.part(0..active), &mut out[..active]);
        step += 1;
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

/// Build one 512-leaf hypertree tree, returning its root.
/// When `top_out` is `Some`, writes all 1,023 nodes into 1-indexed heap layout (`nodes[1]` = root).
/// When `sign_out` is `Some`, simultaneously harvests the 24 signature chain values and 9 path siblings
/// for `(target_leaf, digits)` into `sig_part` (`LAYER_LEN` bytes, after the 4-byte counter).
pub(crate) fn build_tree(
    secret: &[u8; 32],
    public: &[u8; 32],
    layer: u8,
    tree: u64,
    mut top_out: Option<&mut [[u8; N]; TOP_NODES]>,
    mut sign_out: Option<(u16, &[u8; CHAINS], &mut [u8])>,
    ws: &mut SignWorkspace,
) -> [u8; N] {
    let total_chains = TREE_LEAVES * CHAINS;
    for leaf in 0..TREE_LEAVES {
        for c in 0..CHAINS {
            ws.b16.message_mut(leaf * CHAINS + c).copy_from_slice(&tweak(KIND_CHAIN_SECRET, layer, tree, leaf as u16, c as u16, 0));
        }
    }
    throughput::hash_many(Mode::Keyed(secret), &ws.b16.part(0..total_chains), &mut ws.out[..total_chains]);

    if let Some((target_leaf, target_digits, ref mut sig_part)) = sign_out {
        let base = target_leaf as usize * CHAINS;
        for c in 0..CHAINS {
            if target_digits[c] == 0 {
                sig_part[4 + N * c..4 + N * (c + 1)].copy_from_slice(&ws.out[base + c][..N]);
            }
        }
    }

    for leaf in 0..TREE_LEAVES {
        for c in 0..CHAINS {
            let j = leaf * CHAINS + c;
            let m = ws.b32.message_mut(j);
            m[..16].copy_from_slice(&tweak(KIND_CHAIN, layer, tree, leaf as u16, c as u16, 0));
            m[16..32].copy_from_slice(&ws.out[j][..N]);
        }
    }
    for step in 0..CHAIN_STEPS {
        throughput::hash_many(Mode::Keyed(public), &ws.b32.part(0..total_chains), &mut ws.out[..total_chains]);
        if let Some((target_leaf, target_digits, ref mut sig_part)) = sign_out {
            let base = target_leaf as usize * CHAINS;
            for c in 0..CHAINS {
                if target_digits[c] as u32 == step + 1 {
                    sig_part[4 + N * c..4 + N * (c + 1)].copy_from_slice(&ws.out[base + c][..N]);
                }
            }
        }
        if step + 1 < CHAIN_STEPS {
            let next_bytes = (step + 1).to_le_bytes();
            for j in 0..total_chains {
                let m = ws.b32.message_mut(j);
                m[12..16].copy_from_slice(&next_bytes);
                m[16..32].copy_from_slice(&ws.out[j][..N]);
            }
        }
    }

    for leaf in 0..TREE_LEAVES {
        let m = ws.b400.message_mut(leaf);
        m[..16].copy_from_slice(&tweak(KIND_ONE_TIME_KEY, layer, tree, leaf as u16, 0, 0));
        for c in 0..CHAINS {
            m[16 + N * c..16 + N * (c + 1)].copy_from_slice(&ws.out[leaf * CHAINS + c][..N]);
        }
    }
    throughput::hash_many(Mode::Keyed(public), &ws.b400, &mut ws.out[..TREE_LEAVES]);

    for height in 0..TREE_HEIGHT {
        let count = TREE_LEAVES >> height;
        if let Some(ref mut top) = top_out {
            for i in 0..count {
                top[count + i].copy_from_slice(&ws.out[i][..N]);
            }
        }
        if let Some((target_leaf, _, ref mut sig_part)) = sign_out {
            let sib = ((target_leaf as usize) >> height) ^ 1;
            let at = 4 + N * CHAINS + N * height;
            sig_part[at..at + N].copy_from_slice(&ws.out[sib][..N]);
        }
        let parents = count / 2;
        for i in 0..parents {
            let m = ws.b48.message_mut(i);
            m[..16].copy_from_slice(&tweak(KIND_NODE, layer, tree, 0, height as u16 + 1, i as u32));
            m[16..32].copy_from_slice(&ws.out[2 * i][..N]);
            m[32..48].copy_from_slice(&ws.out[2 * i + 1][..N]);
        }
        throughput::hash_many(Mode::Keyed(public), &ws.b48.part(0..parents), &mut ws.out[..parents]);
    }
    let root = first_n(&ws.out[0]);
    if let Some(top) = top_out {
        top[1] = root;
    }
    root
}

/// Sign one hypertree layer by building its tree (layers 0..3). Returns the tree root.
pub(crate) fn sign_layer(secret: &[u8; 32], public: &[u8; 32], pos: Pos, node: &[u8; N], sig_part: &mut [u8], ws: &mut SignWorkspace) -> [u8; N] {
    debug_assert_eq!(sig_part.len(), LAYER_LEN);
    let (counter, d) = search_wots(public, pos, node, ws);
    sig_part[0..4].copy_from_slice(&counter.to_le_bytes());
    build_tree(secret, public, pos.layer, pos.tree, None, Some((pos.leaf, &d, sig_part)), ws)
}

/// Sign the top hypertree layer using its cached tree (no full tree rebuild). Returns the top root.
pub(crate) fn sign_top_layer(
    secret: &[u8; 32],
    public: &[u8; 32],
    pos: Pos,
    node: &[u8; N],
    top: &[[u8; N]; TOP_NODES],
    sig_part: &mut [u8],
    ws: &mut SignWorkspace,
) -> [u8; N] {
    debug_assert_eq!(sig_part.len(), LAYER_LEN);
    let (counter, d) = search_wots(public, pos, node, ws);
    sig_part[0..4].copy_from_slice(&counter.to_le_bytes());

    for c in 0..CHAINS {
        ws.b16.message_mut(c).copy_from_slice(&tweak(KIND_CHAIN_SECRET, pos.layer, 0, pos.leaf, c as u16, 0));
    }
    throughput::hash_many(Mode::Keyed(secret), &ws.b16.part(0..CHAINS), &mut ws.out[..CHAINS]);
    let mut values = [[0u8; N]; CHAINS];
    for c in 0..CHAINS {
        values[c] = first_n(&ws.out[c]);
    }
    advance_chains(public, pos, &mut values, &[0u8; CHAINS], &d, &mut ws.b32, &mut ws.out[..CHAINS]);
    for c in 0..CHAINS {
        sig_part[4 + N * c..4 + N * (c + 1)].copy_from_slice(&values[c]);
    }
    for height in 0..TREE_HEIGHT {
        let sib = (TREE_LEAVES >> height) + (((pos.leaf as usize) >> height) ^ 1);
        let at = 4 + N * CHAINS + N * height;
        sig_part[at..at + N].copy_from_slice(&top[sib]);
    }
    top[1]
}

/// Verify one hypertree layer in `sig_part` (`LAYER_LEN` bytes), returning the recovered tree root.
pub(crate) fn verify_layer(public: &[u8; 32], pos: Pos, node: &[u8; N], sig_part: &[u8], ws: &mut VerifyWorkspace) -> Option<[u8; N]> {
    debug_assert_eq!(sig_part.len(), LAYER_LEN);
    let counter = u32::from_le_bytes(sig_part[0..4].try_into().unwrap());
    let d = digits(public, pos, node, counter)?;

    let mut values = [[0u8; N]; CHAINS];
    for c in 0..CHAINS {
        values[c].copy_from_slice(&sig_part[4 + N * c..4 + N * (c + 1)]);
    }
    advance_chains(public, pos, &mut values, &d, &[CHAIN_STEPS as u8; CHAINS], &mut ws.b32, &mut ws.out);

    let mut pk_in = [0u8; 16 + N * CHAINS];
    pk_in[..16].copy_from_slice(&tweak(KIND_ONE_TIME_KEY, pos.layer, pos.tree, pos.leaf, 0, 0));
    for c in 0..CHAINS {
        pk_in[16 + N * c..16 + N * (c + 1)].copy_from_slice(&values[c]);
    }
    let mut cur = first_n(&keyed(public, &pk_in));

    let path = &sig_part[4 + N * CHAINS..];
    let mut pair = [0u8; 2 * N];
    for height in 0..TREE_HEIGHT {
        let sibling = &path[N * height..N * (height + 1)];
        let index = (pos.leaf as usize) >> height;
        if index & 1 == 0 {
            pair[..N].copy_from_slice(&cur);
            pair[N..].copy_from_slice(sibling);
        } else {
            pair[..N].copy_from_slice(sibling);
            pair[N..].copy_from_slice(&cur);
        }
        cur = short_hash(public, tweak(KIND_NODE, pos.layer, pos.tree, 0, height as u16 + 1, (index >> 1) as u32), &pair);
    }
    Some(cur)
}

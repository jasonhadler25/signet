use crate::coding::decode_wots_c;
use crate::engine::{Batch, Block, Dispatch, HashEngine, Packed};
use crate::few_time::{extract_upors_codewords, grind_upors_selection};
use crate::params::{
    IMPRINT_LEN, LAYERS, LOW_HEIGHT, LOW_LAYERS, LOW_LEAVES, Layer, N, PublicKey, SecretKey, TOP_HEIGHT, TOP_LEAVES, TweakKind, UPORS_CTR_LEN, UPORS_HEIGHT,
    UPORS_K, UPORS_LAYER_U8, UPORS_LEAVES, UPORS_M_MAX, UPORS_N, UPORS_STEPS, WOTS_CTR_LEN, WOTS_CTR_LIMIT, WOTS_N, WOTS_PK_IN_LEN, WOTS_STEPS, pack_pair,
    pack_tagged, tweak,
};

const TOP_TILE_LEAVES: usize = 2048;
const TOP_MERKLE_PARENTS: usize = TOP_LEAVES / 2;
const LOW_TOTAL_LEAVES: usize = LOW_LAYERS * LOW_LEAVES;
const LOW_MERKLE_PARENTS: usize = LOW_LAYERS * (LOW_LEAVES / 2);
const UPORS_MERKLE_PARENTS: usize = UPORS_LEAVES / 2;
const LOW_TOTAL_CHAINS: usize = LOW_TOTAL_LEAVES * WOTS_N;
const UPORS_TOTAL_CHAINS: usize = UPORS_LEAVES * UPORS_N;
const SUPER_CHAINS: usize = LOW_TOTAL_CHAINS + UPORS_TOTAL_CHAINS;

const _: () = {
    assert!(TOP_LEAVES.is_multiple_of(TOP_TILE_LEAVES));
    assert!(TOP_MERKLE_PARENTS == 4096 && LOW_MERKLE_PARENTS == 320 && UPORS_MERKLE_PARENTS == 1024);
    assert!(LOW_TOTAL_LEAVES == 640 && LOW_TOTAL_CHAINS == 13440 && UPORS_TOTAL_CHAINS == 6144 && SUPER_CHAINS == 19584);
    assert!(SUPER_CHAINS.is_multiple_of(32) && LOW_TOTAL_CHAINS.is_multiple_of(32) && UPORS_TOTAL_CHAINS.is_multiple_of(32));
};

/// Build the `256 KiB` cached height-13 top Merkle heap (`2 * 8,192` 16-byte nodes, 1-indexed)
/// using `2,048`-leaf SIMD tiling via [`HashEngine`] (zero `Drop`).
pub(crate) fn build_top_tree(secret: &SecretKey, public: &PublicKey) -> Box<[[u8; N]]> {
    let bulk = public.engine(Dispatch::Bulk);
    let tile_chains = TOP_TILE_LEAVES * WOTS_N;
    let mut b32 = Packed::<32>::new(tile_chains);
    let mut b_pk = Batch::new(WOTS_PK_IN_LEN, TOP_TILE_LEAVES);
    let mut b48 = Packed::<48>::new(TOP_MERKLE_PARENTS);
    let mut scratch = vec![[0u8; 32]; tile_chains];
    let mut chains16 = vec![[0u8; N]; tile_chains];
    let mut nodes = vec![[0u8; N]; 2 * TOP_LEAVES].into_boxed_slice();

    let layer_u8 = Layer::TOP.as_u8();
    let mut leaf_base = 0usize;
    while leaf_base < TOP_LEAVES {
        let leaf_end = leaf_base + TOP_TILE_LEAVES;
        secret.derive_chain_starts_16(layer_u8, 0, u32::try_from(leaf_base * WOTS_N).unwrap(), Dispatch::Bulk, &mut scratch, &mut chains16);

        let mut slot = 0usize;
        for l in leaf_base..leaf_end {
            let leaf_u16 = u16::try_from(l).unwrap();
            for c in 0..WOTS_N {
                pack_tagged(&mut b32[slot], tweak(TweakKind::Chain, layer_u8, 0, leaf_u16, u16::try_from(c).unwrap(), 0), &chains16[slot]);
                slot += 1;
            }
        }
        bulk.advance_chains_fixed(&mut b32, WOTS_STEPS, &mut scratch, &mut chains16);

        for rel in 0..TOP_TILE_LEAVES {
            let l = leaf_base + rel;
            let m = b_pk.message_mut(rel);
            m[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, 0, u16::try_from(l).unwrap(), 0, 0));
            let cbase = rel * WOTS_N;
            for c in 0..WOTS_N {
                m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&chains16[cbase + c]);
            }
        }
        bulk.hash_batch_n(&b_pk, &mut scratch, &mut nodes[TOP_LEAVES + leaf_base..TOP_LEAVES + leaf_end]);
        leaf_base = leaf_end;
    }

    let mut level_start = TOP_LEAVES;
    let mut count = TOP_LEAVES;
    for level in 1..=TOP_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let parents = count / 2;
        let parent_start = level_start / 2;
        for j in 0..parents {
            pack_pair(
                &mut b48[j],
                tweak(TweakKind::Node, layer_u8, 0, 0, level_u16, u32::try_from(j).unwrap()),
                &nodes[level_start + 2 * j],
                &nodes[level_start + 2 * j + 1],
            );
        }
        bulk.hash_packed_48_bulk(&b48, &mut scratch, &mut nodes[parent_start..parent_start + parents]);
        level_start = parent_start;
        count = parents;
    }
    nodes
}

/// Grind the deterministic smallest `u24` counter `ctr` (`0..2^24`) for `WOTS+C(n = 21, w = 60, z = 2, S = 679)`
/// via [`HashEngine::grind_counter`] on `OneTimeMsg` (`counter_word = 8`), reusing caller-provided
/// scratch (`scratch.len() >= 1024`).
pub(crate) fn grind_wots_msg(engine: &HashEngine, layer: Layer, tree: u64, leaf: u16, child_root: &[u8; N], scratch: &mut [[u8; 32]]) -> (u32, [u8; WOTS_N]) {
    let mut tmpl = [0u8; 36];
    tmpl[..16].copy_from_slice(&tweak(TweakKind::OneTimeMsg, layer.as_u8(), tree, leaf, 0, 0));
    tmpl[16..32].copy_from_slice(child_root);
    let (ctr, _, digits) =
        engine.grind_counter(&tmpl, 8, u64::from(WOTS_CTR_LIMIT), scratch, decode_wots_c).expect("WOTS+C u24 counter exhausted (probability 2^-5922)");
    (ctr, digits)
}

/// Verify one `WOTS+C(n = 21, w = 60, z = 2, S = 679)` `u24` counter `ctr` and return its 21
/// 6-bit digits iff `(lo & 3) == 0`, all `d_i < 60`, and `sum(d_i) == 679`.
#[inline]
pub(crate) fn verify_wots_msg(engine: &HashEngine, layer: Layer, tree: u64, leaf: u16, child_root: &[u8; N], ctr: u32) -> Option<[u8; WOTS_N]> {
    assert!(ctr < WOTS_CTR_LIMIT);
    let mut msg = [0u8; 36];
    msg[..16].copy_from_slice(&tweak(TweakKind::OneTimeMsg, layer.as_u8(), tree, leaf, 0, 0));
    msg[16..32].copy_from_slice(child_root);
    msg[32..36].copy_from_slice(&ctr.to_le_bytes());
    let h = engine.hash_short(&msg);
    decode_wots_c(&h)
}

/// Sign a `BLINCS-48-X` imprint using pure fixed-step bulk waves via [`HashEngine`] (`13,440` lower
/// hypertree chains + `6,144` `U-PORS` chains) and variable-length on-core waves for the `27`
/// active `U-PORS` and `126` active `WOTS+C` chains, keeping stack usage tiny (< 16 KiB) with zero `Drop`.
pub(crate) fn sign_superwave(secret: &SecretKey, public: &PublicKey, e: &[u8; N], r: &[u8; N], d_seed: &[u8; 32], top_tree: &[[u8; N]]) -> [u8; IMPRINT_LEN] {
    let bulk = public.engine(Dispatch::Bulk);
    let core = public.engine(Dispatch::OnCore);

    let mut b32 = Packed::<32>::new(SUPER_CHAINS);
    let mut b48 = Packed::<48>::new(UPORS_MERKLE_PARENTS);
    let mut b64 = vec![Block::ZERO; UPORS_LEAVES];
    let mut b_pk = Batch::new(WOTS_PK_IN_LEN, LOW_TOTAL_LEAVES);
    let mut scratch = vec![[0u8; 32]; SUPER_CHAINS];
    let mut chains16 = vec![[0u8; N]; SUPER_CHAINS];
    let mut upors_nodes = vec![[0u8; N]; UPORS_LEAVES];
    let mut low_nodes = vec![[0u8; N]; LOW_LAYERS * 2 * LOW_LEAVES];

    let sel = grind_upors_selection(&bulk, d_seed, &mut scratch);
    let codewords = extract_upors_codewords(&core, sel.h_sel()).expect("FewCode block_idx overflow");
    let splits = sel.leaf_addr().split_layers();

    let mut sig = [0u8; IMPRINT_LEN];
    sig[..N].copy_from_slice(e);
    sig[N..2 * N].copy_from_slice(r);
    let upors_base = 2 * N;
    sig[upors_base..upors_base + UPORS_CTR_LEN].copy_from_slice(&sel.ctr().to_le_bytes());
    let upors_chains_off = upors_base + UPORS_CTR_LEN;
    let upors_octo_off = upors_chains_off + UPORS_K * UPORS_N * N;

    // 1. Derive all 19,584 16-byte chain starts via 6 register-only `derive_chain_starts_16` calls.
    for layer in Layer::LOWER {
        let (tree, _) = splits[layer.index()];
        let off = layer.index() * LOW_LEAVES * WOTS_N;
        secret.derive_chain_starts_16(layer.as_u8(), tree, 0, Dispatch::Bulk, &mut scratch, &mut chains16[off..off + LOW_LEAVES * WOTS_N]);
    }
    let upors_tree = sel.leaf_addr().as_u64();
    secret.derive_chain_starts_16(UPORS_LAYER_U8, upors_tree, 0, Dispatch::Bulk, &mut scratch, &mut chains16[LOW_TOTAL_CHAINS..SUPER_CHAINS]);

    // 2. Pack initial step-0 `[prefix12 || 0u32 || start16]` inputs across all 19,584 slots.
    let mut slot = 0usize;
    for layer in Layer::LOWER {
        let layer_u8 = layer.as_u8();
        let (tree, _) = splits[layer.index()];
        for l in 0..LOW_LEAVES {
            let leaf_u16 = u16::try_from(l).unwrap();
            for c in 0..WOTS_N {
                pack_tagged(&mut b32[slot], tweak(TweakKind::Chain, layer_u8, tree, leaf_u16, u16::try_from(c).unwrap(), 0), &chains16[slot]);
                slot += 1;
            }
        }
    }
    for l in 0..UPORS_LEAVES {
        let leaf_u16 = u16::try_from(l).unwrap();
        for c in 0..UPORS_N {
            pack_tagged(&mut b32[slot], tweak(TweakKind::Chain, UPORS_LAYER_U8, upors_tree, leaf_u16, u16::try_from(c).unwrap(), 0), &chains16[slot]);
            slot += 1;
        }
    }
    assert_eq!(slot, SUPER_CHAINS);

    // 3. Advance the 27 active U-PORS chains independently via `advance_chains_varlen`.
    const UPORS_ACTIVE_TOTAL: usize = UPORS_K * UPORS_N;
    let mut upors_init32 = [[0u8; 32]; UPORS_ACTIVE_TOTAL];
    let mut upors_steps = [0u8; UPORS_ACTIVE_TOTAL];
    let mut upors_active = [[0u8; N]; UPORS_ACTIVE_TOTAL];
    let leaves = sel.leaves();
    for t in 0..UPORS_K {
        let base = LOW_TOTAL_CHAINS + usize::from(leaves[t]) * UPORS_N;
        for c in 0..UPORS_N {
            let idx = t * UPORS_N + c;
            upors_init32[idx] = b32[base + c];
            upors_steps[idx] = codewords[t][c];
        }
    }
    core.advance_chains_varlen::<UPORS_ACTIVE_TOTAL>(&upors_init32, &upors_steps, &mut upors_active);
    for (idx, val) in upors_active.iter().enumerate() {
        let dst = upors_chains_off + idx * N;
        sig[dst..dst + N].copy_from_slice(val);
    }

    // 4. Advance all 19,584 bulk chains to their endpoints (13,440 lower × 59; 6,144 U-PORS × 23).
    bulk.advance_chains_staged(&mut b32, LOW_TOTAL_CHAINS, UPORS_STEPS, WOTS_STEPS, &mut scratch, &mut chains16);

    // 5. Hash all 2,048 U-PORS 64-byte leaves in one batch.
    for (l, blk) in b64.iter_mut().enumerate() {
        let cbase = LOW_TOTAL_CHAINS + l * UPORS_N;
        let dst = &mut blk.0;
        dst[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, UPORS_LAYER_U8, upors_tree, u16::try_from(l).unwrap(), 0, 0));
        for c in 0..UPORS_N {
            dst[16 + c * N..16 + (c + 1) * N].copy_from_slice(&chains16[cbase + c]);
        }
    }
    bulk.hash_blocks_64_n(&b64, &mut scratch, &mut upors_nodes);

    // 6. Hash all 640 lower-hypertree 352-byte WOTS leaf hashes in one batch.
    for layer in Layer::LOWER {
        let layer_u8 = layer.as_u8();
        let (tree, _) = splits[layer.index()];
        for l in 0..LOW_LEAVES {
            let pk_idx = layer.index() * LOW_LEAVES + l;
            let m = b_pk.message_mut(pk_idx);
            m[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, u16::try_from(l).unwrap(), 0, 0));
            let cbase = pk_idx * WOTS_N;
            for c in 0..WOTS_N {
                m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&chains16[cbase + c]);
            }
        }
    }
    let mut low_leaf_out = [[0u8; N]; LOW_TOTAL_LEAVES];
    bulk.hash_batch_n(&b_pk, &mut scratch, &mut low_leaf_out);
    for layer in Layer::LOWER {
        let heap_base = layer.index() * 2 * LOW_LEAVES;
        let src_base = layer.index() * LOW_LEAVES;
        low_nodes[heap_base + LOW_LEAVES..heap_base + 2 * LOW_LEAVES].copy_from_slice(&low_leaf_out[src_base..src_base + LOW_LEAVES]);
    }

    // 7. Build U-PORS height-11 Merkle tree + extract Octopus siblings -> `upors_root`.
    let mut cur_idx = *leaves;
    let mut cur_len = UPORS_K;
    let mut sib_cursor = 0usize;
    let mut width = UPORS_LEAVES;
    for level in 1..=UPORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let mut next_len = 0usize;
        let mut i = 0usize;
        while i < cur_len {
            let x = cur_idx[i];
            if i + 1 < cur_len && (x & 1) == 0 && cur_idx[i + 1] == x + 1 {
                cur_idx[next_len] = x >> 1;
                next_len += 1;
                i += 2;
            } else {
                let off = upors_octo_off + sib_cursor * N;
                sig[off..off + N].copy_from_slice(&upors_nodes[usize::from(x ^ 1)]);
                sib_cursor += 1;
                cur_idx[next_len] = x >> 1;
                next_len += 1;
                i += 1;
            }
        }
        cur_len = next_len;

        let parents = width / 2;
        for p in 0..parents {
            pack_pair(
                &mut b48[p],
                tweak(TweakKind::Node, UPORS_LAYER_U8, upors_tree, 0, level_u16, u32::try_from(p).unwrap()),
                &upors_nodes[2 * p],
                &upors_nodes[2 * p + 1],
            );
        }
        bulk.hash_packed_48_bulk(&b48, &mut scratch, &mut upors_nodes[..parents]);
        width = parents;
    }
    assert_eq!(sib_cursor, sel.sibs());
    sig[upors_octo_off + sib_cursor * N..upors_octo_off + UPORS_M_MAX * N].fill(0);
    let upors_root = upors_nodes[0];

    // 8. Build all 5 lower Merkle heaps (L0..L4) in lockstep.
    let mut level_start = LOW_LEAVES;
    let mut count = LOW_LEAVES;
    let mut low_parent_out = [[0u8; N]; LOW_MERKLE_PARENTS];
    for level in 1..=LOW_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let parents = count / 2;
        let parent_start = level_start / 2;
        let mut pslot = 0usize;
        for layer in Layer::LOWER {
            let layer_u8 = layer.as_u8();
            let (tree, _) = splits[layer.index()];
            let heap_base = layer.index() * 2 * LOW_LEAVES;
            for j in 0..parents {
                pack_pair(
                    &mut b48[pslot],
                    tweak(TweakKind::Node, layer_u8, tree, 0, level_u16, u32::try_from(j).unwrap()),
                    &low_nodes[heap_base + level_start + 2 * j],
                    &low_nodes[heap_base + level_start + 2 * j + 1],
                );
                pslot += 1;
            }
        }
        bulk.hash_packed_48_bulk(&b48, &mut scratch, &mut low_parent_out[..pslot]);
        let mut rslot = 0usize;
        for layer in Layer::LOWER {
            let heap_base = layer.index() * 2 * LOW_LEAVES;
            low_nodes[heap_base + parent_start..heap_base + parent_start + parents].copy_from_slice(&low_parent_out[rslot..rslot + parents]);
            rslot += parents;
        }
        level_start = parent_start;
        count = parents;
    }

    // 9. Grind all 6 WOTS+C u24 counters and advance all 126 active chains via `advance_chains_varlen`.
    let child_roots =
        [upors_root, low_nodes[1], low_nodes[2 * LOW_LEAVES + 1], low_nodes[4 * LOW_LEAVES + 1], low_nodes[6 * LOW_LEAVES + 1], low_nodes[8 * LOW_LEAVES + 1]];
    const ACTIVE_TOTAL: usize = LAYERS * WOTS_N;
    let mut active_init32 = [[0u8; 32]; ACTIVE_TOTAL];
    let mut active_ends = [0u8; ACTIVE_TOTAL];
    let mut active_vals = [[0u8; N]; ACTIVE_TOTAL];
    let mut raw_scratch = [[0u8; 32]; WOTS_N];
    let mut starts16 = [[0u8; N]; WOTS_N];

    for layer in Layer::ALL {
        let li = layer.index();
        let (tree, leaf) = splits[li];
        let (ctr, digits) = grind_wots_msg(&bulk, layer, tree, leaf, &child_roots[li], &mut scratch);

        let off = layer.sig_offset();
        sig[off..off + WOTS_CTR_LEN].copy_from_slice(&ctr.to_le_bytes()[..WOTS_CTR_LEN]);

        secret.derive_chain_starts_16(layer.as_u8(), tree, u32::from(leaf) * u32::try_from(WOTS_N).unwrap(), Dispatch::OnCore, &mut raw_scratch, &mut starts16);
        for c in 0..WOTS_N {
            let idx = li * WOTS_N + c;
            pack_tagged(&mut active_init32[idx], tweak(TweakKind::Chain, layer.as_u8(), tree, leaf, u16::try_from(c).unwrap(), 0), &starts16[c]);
            active_ends[idx] = digits[c];
        }
    }
    core.advance_chains_varlen::<ACTIVE_TOTAL>(&active_init32, &active_ends, &mut active_vals);

    for layer in Layer::ALL {
        let li = layer.index();
        let off = layer.sig_offset();
        for c in 0..WOTS_N {
            sig[off + WOTS_CTR_LEN + c * N..off + WOTS_CTR_LEN + (c + 1) * N].copy_from_slice(&active_vals[li * WOTS_N + c]);
        }
        let auth_off = off + WOTS_CTR_LEN + WOTS_N * N;
        let (_, leaf) = splits[li];
        let (heap, base_leaves, height) = if layer == Layer::TOP {
            (top_tree, TOP_LEAVES, TOP_HEIGHT)
        } else {
            let heap_base = li * 2 * LOW_LEAVES;
            (&low_nodes[heap_base..heap_base + 2 * LOW_LEAVES], LOW_LEAVES, LOW_HEIGHT)
        };
        let mut cursor = base_leaves + usize::from(leaf);
        for level in 0..height {
            sig[auth_off + level * N..auth_off + (level + 1) * N].copy_from_slice(&heap[cursor ^ 1]);
            cursor >>= 1;
        }
    }
    sig
}

/// Zero-allocation stack-batched `WOTS+C` + Merkle path verifier for one hypertree layer.
/// Advances all 21 variable-length chains via [`HashEngine::advance_chains_varlen`] and climbs
/// the Merkle path via [`HashEngine::hash_short_n`].
pub(crate) fn verify_layer(engine: &HashEngine, layer: Layer, tree: u64, leaf: u16, child_root: &[u8; N], layer_sig: &[u8]) -> Option<[u8; N]> {
    let ctr = u32::from_le_bytes([layer_sig[0], layer_sig[1], layer_sig[2], 0]);
    let digits = verify_wots_msg(engine, layer, tree, leaf, child_root, ctr)?;

    let layer_u8 = layer.as_u8();
    let chains_off = WOTS_CTR_LEN;
    let auth_off = WOTS_CTR_LEN + WOTS_N * N;

    let mut init32 = [[0u8; 32]; WOTS_N];
    let mut steps = [0u8; WOTS_N];
    let mut endpoints = [[0u8; N]; WOTS_N];
    for (c, &d) in digits.iter().enumerate() {
        let src = &layer_sig[chains_off + c * N..chains_off + (c + 1) * N];
        steps[c] = WOTS_STEPS - d;
        pack_tagged(&mut init32[c], tweak(TweakKind::Chain, layer_u8, tree, leaf, u16::try_from(c).unwrap(), u32::from(d)), src);
    }
    engine.advance_chains_varlen::<WOTS_N>(&init32, &steps, &mut endpoints);

    let mut pk_buf = [0u8; WOTS_PK_IN_LEN];
    pk_buf[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, leaf, 0, 0));
    for (c, ep) in endpoints.iter().enumerate() {
        pk_buf[16 + c * N..16 + (c + 1) * N].copy_from_slice(ep);
    }

    let mut node = engine.hash_n(&pk_buf);
    let mut idx = usize::from(leaf);
    let mut buf = [0u8; 48];
    for level in 0..layer.height() {
        let sib = &layer_sig[auth_off + level * N..auth_off + (level + 1) * N];
        let tw = tweak(TweakKind::Node, layer_u8, tree, 0, u16::try_from(level + 1).unwrap(), u32::try_from(idx >> 1).unwrap());
        if (idx & 1) == 0 {
            pack_pair(&mut buf, tw, &node, sib);
        } else {
            pack_pair(&mut buf, tw, sib, &node);
        }
        node = engine.hash_short_n(&buf);
        idx >>= 1;
    }
    Some(node)
}

use crate::coding::decode_wots_c;
use crate::few_time::{extract_upors_codewords, grind_upors_selection};
use crate::params::{
    IMPRINT_LEN, LAYERS, LOW_HEIGHT, LOW_LAYERS, LOW_LEAVES, Layer, N, PublicKey, SecretKey, TOP_HEIGHT, TOP_LEAVES, TweakKind, UPORS_CTR_LEN, UPORS_HEIGHT,
    UPORS_K, UPORS_LAYER_U8, UPORS_LEAVES, UPORS_M_MAX, UPORS_N, UPORS_STEPS, WOTS_CTR_LEN, WOTS_CTR_LIMIT, WOTS_N, WOTS_PK_IN_LEN, WOTS_STEPS, first_n,
    pack_pair, pack_tagged, tweak,
};
use blake3_servil_core::throughput::{Batch, Block, Packed, Prepared, TreeHasher};

const TOP_TILE_LEAVES: usize = 2048;
const TOP_MERKLE_PARENTS: usize = TOP_LEAVES / 2;
const LOW_TOTAL_LEAVES: usize = LOW_LAYERS * LOW_LEAVES;
const UPORS_MERKLE_PARENTS: usize = UPORS_LEAVES / 2;
const LOW_TOTAL_CHAINS: usize = LOW_TOTAL_LEAVES * WOTS_N;
const UPORS_TOTAL_CHAINS: usize = UPORS_LEAVES * UPORS_N;
const SUPER_CHAINS: usize = LOW_TOTAL_CHAINS + UPORS_TOTAL_CHAINS;

const _: () = {
    assert!(TOP_LEAVES.is_multiple_of(TOP_TILE_LEAVES));
    assert!(TOP_MERKLE_PARENTS == 4096 && UPORS_MERKLE_PARENTS == 1024);
    assert!(LOW_TOTAL_LEAVES == 640 && LOW_TOTAL_CHAINS == 13440 && UPORS_TOTAL_CHAINS == 6144 && SUPER_CHAINS == 19584);
    assert!(SUPER_CHAINS.is_multiple_of(32) && LOW_TOTAL_CHAINS.is_multiple_of(32) && UPORS_TOTAL_CHAINS.is_multiple_of(32));
};

/// Build the `256 KiB` cached height-13 top Merkle heap (`2 * 8,192` 16-byte nodes, 1-indexed)
/// using `2,048`-leaf SIMD tiling (zero `Drop`).
pub(crate) fn build_top_tree(secret: &SecretKey, public: &PublicKey) -> Box<[[u8; N]]> {
    let pub_h = public.hasher(true);
    let tile_chains = TOP_TILE_LEAVES * WOTS_N;
    let mut b32 = Packed::<32>::new(tile_chains);
    let mut b_pk = Batch::new(WOTS_PK_IN_LEN, TOP_TILE_LEAVES);
    let mut b48 = Packed::<48>::new(TOP_MERKLE_PARENTS);
    let mut out = vec![[0u8; 32]; tile_chains];
    let mut nodes = vec![[0u8; N]; 2 * TOP_LEAVES].into_boxed_slice();

    let layer_u8 = Layer::TOP.as_u8();
    let mut leaf_base = 0usize;
    while leaf_base < TOP_LEAVES {
        let leaf_end = leaf_base + TOP_TILE_LEAVES;
        secret.derive_chain_starts(layer_u8, 0, u32::try_from(leaf_base * WOTS_N).unwrap(), true, &mut out[..tile_chains]);

        let mut slot = 0usize;
        for l in leaf_base..leaf_end {
            let leaf_u16 = u16::try_from(l).unwrap();
            for c in 0..WOTS_N {
                let tw = tweak(TweakKind::Chain, layer_u8, 0, leaf_u16, u16::try_from(c).unwrap(), 0);
                b32[slot][..12].copy_from_slice(&tw[..12]);
                slot += 1;
            }
        }

        for step in 0..WOTS_STEPS {
            let step_bytes = u32::from(step).to_le_bytes();
            for (m, o) in b32[..tile_chains].iter_mut().zip(out[..tile_chains].iter()) {
                m[12..16].copy_from_slice(&step_bytes);
                m[16..32].copy_from_slice(&o[..N]);
            }
            pub_h.hash_many(&b32.part(0..tile_chains), &mut out[..tile_chains]);
        }

        for rel in 0..TOP_TILE_LEAVES {
            let l = leaf_base + rel;
            let m = b_pk.message_mut(rel);
            m[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, 0, u16::try_from(l).unwrap(), 0, 0));
            let cbase = rel * WOTS_N;
            for c in 0..WOTS_N {
                m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&out[cbase + c][..N]);
            }
        }
        pub_h.hash_many(&b_pk.part(0..TOP_TILE_LEAVES), &mut out[..TOP_TILE_LEAVES]);
        for rel in 0..TOP_TILE_LEAVES {
            nodes[TOP_LEAVES + leaf_base + rel] = first_n(&out[rel]);
        }
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
        pub_h.hash_many(&b48.part(0..parents), &mut out[..parents]);
        for j in 0..parents {
            nodes[parent_start + j] = first_n(&out[j]);
        }
        level_start = parent_start;
        count = parents;
    }
    nodes
}

/// Grind the deterministic smallest `u24` counter `ctr` (`0..2^24`) for `WOTS+C(n = 21, w = 60, z = 2, S = 679)`
/// via register-only `TreeHasher::hash_counter_range` on `OneTimeMsg` (`counter_word = 8`), reusing
/// caller-provided scratch (`scratch.len() >= 1024`).
pub(crate) fn grind_wots_msg(pub_h: &TreeHasher, layer: Layer, tree: u64, leaf: u16, child_root: &[u8; N], scratch: &mut [[u8; 32]]) -> (u32, [u8; WOTS_N]) {
    let mut tmpl = [0u8; 36];
    tmpl[..16].copy_from_slice(&tweak(TweakKind::OneTimeMsg, layer.as_u8(), tree, leaf, 0, 0));
    tmpl[16..32].copy_from_slice(child_root);

    const BATCH: usize = 1024;
    const _: () = assert!((WOTS_CTR_LIMIT as usize).is_multiple_of(BATCH));
    let out = &mut scratch[..BATCH];
    for start in (0..WOTS_CTR_LIMIT).step_by(BATCH) {
        pub_h.hash_counter_range(&tmpl, 8, start, out);
        for (i, h) in out.iter().enumerate() {
            if let Some(digits) = decode_wots_c(h) {
                return (start + u32::try_from(i).unwrap(), digits);
            }
        }
    }
    panic!("WOTS+C u24 counter exhausted (probability 2^-5922)");
}

/// Verify one `WOTS+C(n = 21, w = 60, z = 2, S = 679)` `u24` counter `ctr` and return its 21
/// 6-bit digits iff `(lo & 3) == 0`, all `d_i < 60`, and `sum(d_i) == 679`.
#[inline]
pub(crate) fn verify_wots_msg(pub_h: &TreeHasher, layer: Layer, tree: u64, leaf: u16, child_root: &[u8; N], ctr: u32) -> Option<[u8; WOTS_N]> {
    assert!(ctr < WOTS_CTR_LIMIT);
    let mut msg = [0u8; 36];
    msg[..16].copy_from_slice(&tweak(TweakKind::OneTimeMsg, layer.as_u8(), tree, leaf, 0, 0));
    msg[16..32].copy_from_slice(child_root);
    msg[32..36].copy_from_slice(&ctr.to_le_bytes());
    let h = *pub_h.hash(&msg).as_bytes();
    decode_wots_c(&h)
}

/// Sign a `BLINCS-48-X` imprint using a single merged `19,584`-chain (`612 × 32`) single-threaded
/// SIMD super-wave (all five uniform height-7 lower hypertree layers + height-11 `U-PORS` tree
/// stepped in lockstep), keeping stack usage tiny (< 16 KiB) with zero `Drop` implementations.
pub(crate) fn sign_superwave(secret: &SecretKey, public: &PublicKey, e: &[u8; N], r: &[u8; N], d_seed: &[u8; 32], top_tree: &[[u8; N]]) -> [u8; IMPRINT_LEN] {
    let pub_h = public.hasher(true);

    let mut b32 = Packed::<32>::new(SUPER_CHAINS);
    let mut b48 = Packed::<48>::new(UPORS_MERKLE_PARENTS);
    let mut b64 = vec![Block::ZERO; UPORS_LEAVES];
    let mut b_pk = Batch::new(WOTS_PK_IN_LEN, LOW_TOTAL_LEAVES);
    let mut out = vec![[0u8; 32]; SUPER_CHAINS];
    let mut upors_nodes = vec![[0u8; N]; UPORS_LEAVES];
    let mut low_nodes = vec![[0u8; N]; LOW_LAYERS * 2 * LOW_LEAVES];

    let sel = grind_upors_selection(&pub_h, d_seed, &mut out);
    let codewords = extract_upors_codewords(public, &sel.h_sel).expect("FewCode block_idx overflow");
    let splits = sel.leaf_addr.split_layers();

    let mut sig = [0u8; IMPRINT_LEN];
    sig[..N].copy_from_slice(e);
    sig[N..2 * N].copy_from_slice(r);
    let upors_base = 2 * N;
    sig[upors_base..upors_base + UPORS_CTR_LEN].copy_from_slice(&sel.ctr.to_le_bytes());
    let upors_chains_off = upors_base + UPORS_CTR_LEN;
    let upors_octo_off = upors_chains_off + UPORS_K * UPORS_N * N;

    // 1. Derive all 19,584 chain starts via 6 register-only `hash_counter_range` calls.
    for layer in Layer::LOWER {
        let (tree, _) = splits[layer.index()];
        let off = layer.index() * LOW_LEAVES * WOTS_N;
        secret.derive_chain_starts(layer.as_u8(), tree, 0, true, &mut out[off..off + LOW_LEAVES * WOTS_N]);
    }
    let upors_tree = sel.leaf_addr.as_u64();
    secret.derive_chain_starts(UPORS_LAYER_U8, upors_tree, 0, true, &mut out[LOW_TOTAL_CHAINS..SUPER_CHAINS]);

    for t in 0..UPORS_K {
        let base = LOW_TOTAL_CHAINS + usize::from(sel.leaves[t]) * UPORS_N;
        for c in 0..UPORS_N {
            if codewords[t][c] == 0 {
                let dst = upors_chains_off + (t * UPORS_N + c) * N;
                sig[dst..dst + N].copy_from_slice(&out[base + c][..N]);
            }
        }
    }

    // 2. Pack invariant 12-byte tweak prefix once across all 19,584 slots.
    let mut slot = 0usize;
    for layer in Layer::LOWER {
        let layer_u8 = layer.as_u8();
        let (tree, _) = splits[layer.index()];
        for l in 0..LOW_LEAVES {
            let leaf_u16 = u16::try_from(l).unwrap();
            for c in 0..WOTS_N {
                let tw = tweak(TweakKind::Chain, layer_u8, tree, leaf_u16, u16::try_from(c).unwrap(), 0);
                b32[slot][..12].copy_from_slice(&tw[..12]);
                slot += 1;
            }
        }
    }
    for l in 0..UPORS_LEAVES {
        let leaf_u16 = u16::try_from(l).unwrap();
        for c in 0..UPORS_N {
            let tw = tweak(TweakKind::Chain, UPORS_LAYER_U8, upors_tree, leaf_u16, u16::try_from(c).unwrap(), 0);
            b32[slot][..12].copy_from_slice(&tw[..12]);
            slot += 1;
        }
    }
    assert_eq!(slot, SUPER_CHAINS);

    // 3. Steps 0..23: all 19,584 chains (L0..L4 + U-PORS) in one lockstep super-wave.
    for step in 0..UPORS_STEPS {
        let step_bytes = u32::from(step).to_le_bytes();
        for (m, o) in b32[..SUPER_CHAINS].iter_mut().zip(out[..SUPER_CHAINS].iter()) {
            m[12..16].copy_from_slice(&step_bytes);
            m[16..32].copy_from_slice(&o[..N]);
        }
        pub_h.hash_many(&b32.part(0..SUPER_CHAINS), &mut out[..SUPER_CHAINS]);

        let completed = step + 1;
        for t in 0..UPORS_K {
            let base = LOW_TOTAL_CHAINS + usize::from(sel.leaves[t]) * UPORS_N;
            for c in 0..UPORS_N {
                if codewords[t][c] == completed {
                    let dst = upors_chains_off + (t * UPORS_N + c) * N;
                    sig[dst..dst + N].copy_from_slice(&out[base + c][..N]);
                }
            }
        }
    }

    // 4. Finish U-PORS 64-byte leaves while U-PORS endpoints sit in out[13440..19584].
    for (l, blk) in b64.iter_mut().enumerate() {
        let cbase = LOW_TOTAL_CHAINS + l * UPORS_N;
        let dst = &mut blk.0;
        dst[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, UPORS_LAYER_U8, upors_tree, u16::try_from(l).unwrap(), 0, 0));
        for c in 0..UPORS_N {
            dst[16 + c * N..16 + (c + 1) * N].copy_from_slice(&out[cbase + c][..N]);
        }
    }
    let upors_out = &mut out[LOW_TOTAL_CHAINS..LOW_TOTAL_CHAINS + UPORS_LEAVES];
    pub_h.hash_many(&Batch::from_blocks(&b64[..UPORS_LEAVES], 64), upors_out);
    for (dst, src) in upors_nodes.iter_mut().zip(upors_out.iter()) {
        *dst = first_n(src);
    }

    // 5. Steps 23..59: finish the remaining 36 steps on all 13,440 lower-hypertree chains.
    for step in UPORS_STEPS..WOTS_STEPS {
        let step_bytes = u32::from(step).to_le_bytes();
        for (m, o) in b32[..LOW_TOTAL_CHAINS].iter_mut().zip(out[..LOW_TOTAL_CHAINS].iter()) {
            m[12..16].copy_from_slice(&step_bytes);
            m[16..32].copy_from_slice(&o[..N]);
        }
        pub_h.hash_many(&b32.part(0..LOW_TOTAL_CHAINS), &mut out[..LOW_TOTAL_CHAINS]);
    }

    // 6. Hash all 640 lower-hypertree 352-byte WOTS public keys in one batch.
    for layer in Layer::LOWER {
        let layer_u8 = layer.as_u8();
        let (tree, _) = splits[layer.index()];
        for l in 0..LOW_LEAVES {
            let pk_idx = layer.index() * LOW_LEAVES + l;
            let m = b_pk.message_mut(pk_idx);
            m[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, u16::try_from(l).unwrap(), 0, 0));
            let cbase = pk_idx * WOTS_N;
            for c in 0..WOTS_N {
                m[16 + c * N..16 + (c + 1) * N].copy_from_slice(&out[cbase + c][..N]);
            }
        }
    }
    pub_h.hash_many(&b_pk.part(0..LOW_TOTAL_LEAVES), &mut out[..LOW_TOTAL_LEAVES]);
    for layer in Layer::LOWER {
        let heap_base = layer.index() * 2 * LOW_LEAVES;
        for l in 0..LOW_LEAVES {
            low_nodes[heap_base + LOW_LEAVES + l] = first_n(&out[layer.index() * LOW_LEAVES + l]);
        }
    }

    // 7. Build U-PORS height-11 Merkle tree + extract Octopus siblings -> `upors_root`.
    let mut cur_idx = sel.leaves;
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
        pub_h.hash_many(&b48.part(0..parents), &mut out[..parents]);
        for p in 0..parents {
            upors_nodes[p] = first_n(&out[p]);
        }
        width = parents;
    }
    assert_eq!(sib_cursor, sel.sibs);
    sig[upors_octo_off + sib_cursor * N..upors_octo_off + UPORS_M_MAX * N].fill(0);
    let upors_root = upors_nodes[0];

    // 8. Build all 5 lower Merkle heaps (L0..L4) in lockstep.
    let mut level_start = LOW_LEAVES;
    let mut count = LOW_LEAVES;
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
        pub_h.hash_many(&b48.part(0..pslot), &mut out[..pslot]);
        let mut rslot = 0usize;
        for layer in Layer::LOWER {
            let heap_base = layer.index() * 2 * LOW_LEAVES;
            for j in 0..parents {
                low_nodes[heap_base + parent_start + j] = first_n(&out[rslot]);
                rslot += 1;
            }
        }
        level_start = parent_start;
        count = parents;
    }

    // 9. Grind all 6 WOTS+C u24 counters and advance all 126 active chains in one NEON batch.
    let child_roots =
        [upors_root, low_nodes[1], low_nodes[2 * LOW_LEAVES + 1], low_nodes[4 * LOW_LEAVES + 1], low_nodes[6 * LOW_LEAVES + 1], low_nodes[8 * LOW_LEAVES + 1]];
    const ACTIVE_TOTAL: usize = LAYERS * WOTS_N;
    let mut active_vals = [[0u8; N]; ACTIVE_TOTAL];
    let mut active_ends = [0u8; ACTIVE_TOTAL];
    let mut raw_starts = [[0u8; 32]; WOTS_N];

    for layer in Layer::ALL {
        let li = layer.index();
        let (tree, leaf) = splits[li];
        let (ctr, digits) = grind_wots_msg(&pub_h, layer, tree, leaf, &child_roots[li], &mut out);

        let off = layer.sig_offset();
        sig[off..off + WOTS_CTR_LEN].copy_from_slice(&ctr.to_le_bytes()[..WOTS_CTR_LEN]);

        secret.derive_chain_starts(layer.as_u8(), tree, u32::from(leaf) * u32::try_from(WOTS_N).unwrap(), false, &mut raw_starts);
        for c in 0..WOTS_N {
            active_vals[li * WOTS_N + c] = first_n(&raw_starts[c]);
            active_ends[li * WOTS_N + c] = digits[c];
        }
    }

    let mut order: [(u8, u8); ACTIVE_TOTAL] = core::array::from_fn(|i| (active_ends[i], u8::try_from(i).unwrap()));
    order.sort_unstable_by_key(|x| core::cmp::Reverse(x.0));
    let mut active = order.partition_point(|&(rem, _)| rem > 0);
    let mut ab32 = [[0u8; 32]; ACTIVE_TOTAL];
    let mut aout = [[0u8; 32]; ACTIVE_TOTAL];
    for (slot, &(_, idx_u8)) in order[..active].iter().enumerate() {
        let idx = usize::from(idx_u8);
        let li = idx / WOTS_N;
        let c = idx % WOTS_N;
        let (tree, leaf) = splits[li];
        pack_tagged(&mut ab32[slot], tweak(TweakKind::Chain, u8::try_from(li).unwrap(), tree, leaf, u16::try_from(c).unwrap(), 0), &active_vals[idx]);
    }
    let pub_neon = public.hasher(false);
    for step in 1..=WOTS_STEPS {
        if active == 0 {
            break;
        }
        pub_neon.hash_many(&ab32[..active], &mut aout[..active]);
        while active > 0 && order[active - 1].0 == step {
            active -= 1;
            active_vals[usize::from(order[active].1)].copy_from_slice(&aout[active][..N]);
        }
        let next_step = u32::from(step).to_le_bytes();
        for slot in 0..active {
            let m = &mut ab32[slot];
            m[12..16].copy_from_slice(&next_step);
            m[16..32].copy_from_slice(&aout[slot][..N]);
        }
    }

    for layer in Layer::ALL {
        let li = layer.index();
        let off = layer.sig_offset();
        for c in 0..WOTS_N {
            sig[off + WOTS_CTR_LEN + c * N..off + WOTS_CTR_LEN + (c + 1) * N].copy_from_slice(&active_vals[li * WOTS_N + c]);
        }
        let auth_off = off + WOTS_CTR_LEN + WOTS_N * N;
        let (_, leaf) = splits[li];
        if layer == Layer::TOP {
            let mut cursor = TOP_LEAVES + usize::from(leaf);
            for level in 0..TOP_HEIGHT {
                sig[auth_off + level * N..auth_off + (level + 1) * N].copy_from_slice(&top_tree[cursor ^ 1]);
                cursor >>= 1;
            }
        } else {
            let heap_base = li * 2 * LOW_LEAVES;
            let mut cursor = LOW_LEAVES + usize::from(leaf);
            for level in 0..LOW_HEIGHT {
                sig[auth_off + level * N..auth_off + (level + 1) * N].copy_from_slice(&low_nodes[heap_base + (cursor ^ 1)]);
                cursor >>= 1;
            }
        }
    }
    sig
}

/// Pad NEON `hash_many` batch widths to multiples of 11 (`8+3` packed kernel) when doing so avoids
/// an extra under-filled vector pass (`active` in `8..11 -> 11`, `active >= 16 -> 22`).
#[inline]
pub(crate) const fn neon_pad_width(active: usize) -> usize {
    match active {
        16.. => 22,
        8..11 => 11,
        _ => active,
    }
}

/// Zero-allocation stack-batched `WOTS+C` + Merkle path verifier for one hypertree layer.
/// Writes completed chain endpoints directly into `pk_buf`, pads NEON batches to multiples of 11
/// (`8+3` packed kernel), and routes single-lane tails to scalar `hash`.
pub(crate) fn verify_layer(pub_h: &TreeHasher, layer: Layer, tree: u64, leaf: u16, child_root: &[u8; N], layer_sig: &[u8]) -> Option<[u8; N]> {
    let ctr = u32::from_le_bytes([layer_sig[0], layer_sig[1], layer_sig[2], 0]);
    let digits = verify_wots_msg(pub_h, layer, tree, leaf, child_root, ctr)?;

    let layer_u8 = layer.as_u8();
    let chains_off = WOTS_CTR_LEN;
    let auth_off = WOTS_CTR_LEN + WOTS_N * N;

    let mut pk_buf = [0u8; WOTS_PK_IN_LEN];
    pk_buf[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, leaf, 0, 0));

    let mut order = [(0u8, 0u8); WOTS_N];
    let mut active = 0usize;
    for (c, &d) in digits.iter().enumerate() {
        let rem = WOTS_STEPS - d;
        let src = &layer_sig[chains_off + c * N..chains_off + (c + 1) * N];
        if rem == 0 {
            pk_buf[16 + c * N..16 + (c + 1) * N].copy_from_slice(src);
        } else {
            order[active] = (rem, u8::try_from(c).unwrap());
            active += 1;
        }
    }
    order[..active].sort_unstable_by_key(|x| core::cmp::Reverse(x.0));

    let mut b32 = [[0u8; 32]; 22];
    let mut out = [[0u8; 32]; 22];
    let mut slot_step = [0u32; 22];
    for (slot, &(_, c_u8)) in order[..active].iter().enumerate() {
        let c = usize::from(c_u8);
        let d = u32::from(digits[c]);
        slot_step[slot] = d;
        pack_tagged(
            &mut b32[slot],
            tweak(TweakKind::Chain, layer_u8, tree, leaf, u16::from(c_u8), d),
            &layer_sig[chains_off + c * N..chains_off + (c + 1) * N],
        );
    }
    for step in 1..=WOTS_STEPS {
        if active == 0 {
            break;
        }
        if active == 1 {
            out[0] = *pub_h.hash(&b32[0]).as_bytes();
        } else {
            let run = neon_pad_width(active);
            pub_h.hash_many(&b32[..run], &mut out[..run]);
        }
        while active > 0 && order[active - 1].0 == step {
            active -= 1;
            let c = usize::from(order[active].1);
            pk_buf[16 + c * N..16 + (c + 1) * N].copy_from_slice(&out[active][..N]);
        }
        for slot in 0..active {
            slot_step[slot] += 1;
            let m = &mut b32[slot];
            m[12..16].copy_from_slice(&slot_step[slot].to_le_bytes());
            m[16..32].copy_from_slice(&out[slot][..N]);
        }
    }

    let mut node = first_n(pub_h.hash(&pk_buf).as_bytes());
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
        node = first_n(pub_h.hash(&buf).as_bytes());
        idx >>= 1;
    }
    Some(node)
}

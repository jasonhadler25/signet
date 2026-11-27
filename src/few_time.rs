use crate::coding::hex_unrank;
use crate::params::{
    HYPER_BITS, LeafAddr, N, PublicKey, TweakKind, UPORS_C, UPORS_CTR_LEN, UPORS_HEIGHT, UPORS_K, UPORS_LAYER_U8, UPORS_LEN, UPORS_M_MAX, UPORS_N,
    UPORS_SELECT_MAX_DRAWS, UPORS_STEPS, first_n, pack_pair, pack_tagged, read_bits, tweak,
};
use blake3_servil_core::throughput::{Batch, Block, TreeHasher};
use constant_time_eq::constant_time_eq;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UporsSelection {
    pub(crate) ctr: u32,
    pub(crate) leaf_addr: LeafAddr,
    pub(crate) leaves: [u16; UPORS_K],
    pub(crate) sibs: usize,
}

/// Count exact Octopus authentication siblings for `sorted_leaves` in a height-10 binary tree.
#[inline]
pub(crate) fn count_octopus_sibs(sorted_leaves: &[u16; UPORS_K]) -> usize {
    let mut cur = *sorted_leaves;
    let mut len = UPORS_K;
    let mut sibs = 0usize;
    for _ in 0..UPORS_HEIGHT {
        let mut out_len = 0usize;
        let mut i = 0usize;
        while i < len {
            let x = cur[i];
            if i + 1 < len && (x & 1) == 0 && cur[i + 1] == x + 1 {
                cur[out_len] = x >> 1;
                out_len += 1;
                i += 2;
            } else {
                sibs += 1;
                cur[out_len] = x >> 1;
                out_len += 1;
                i += 1;
            }
        }
        len = out_len;
    }
    sibs
}

/// Parse a `FewSelect` digest into `(leaf_addr, sorted_leaves, sibs)` if 10 distinct leaves appear
/// within 22 10-bit draws and their Octopus sibling count is `<= UPORS_M_MAX` (44).
#[inline]
pub(crate) fn parse_select_digest(d: &[u8; 32]) -> Option<(LeafAddr, [u16; UPORS_K], usize)> {
    let mut leaves = [0u16; UPORS_K];
    let mut found = 0usize;

    for i in 0..UPORS_SELECT_MAX_DRAWS {
        let x = u16::try_from(read_bits(d, i * UPORS_HEIGHT, UPORS_HEIGHT)).unwrap();
        if !leaves[..found].contains(&x) {
            leaves[found] = x;
            found += 1;
            if found == UPORS_K {
                break;
            }
        }
    }
    if found != UPORS_K {
        return None;
    }
    leaves.sort_unstable();
    let sibs = count_octopus_sibs(&leaves);
    if sibs > UPORS_M_MAX {
        return None;
    }
    let leaf_addr = LeafAddr::from_word(read_bits(d, UPORS_SELECT_MAX_DRAWS * UPORS_HEIGHT, HYPER_BITS));
    Some((leaf_addr, leaves, sibs))
}

/// Grind `ctr_ft` via register-only SIMD `TreeHasher::hash_counter_range` (batches of 512).
pub(crate) fn grind_upors_selection(pub_h: &TreeHasher, d_seed: &[u8; 32]) -> UporsSelection {
    let mut tmpl = [0u8; 52];
    tmpl[..16].copy_from_slice(&tweak(TweakKind::FewSelect, UPORS_LAYER_U8, 0, 0, 0, 0));
    tmpl[16..48].copy_from_slice(d_seed);

    const BATCH: usize = 512;
    let mut out = [[0u8; 32]; BATCH];
    let mut start = 0u32;
    loop {
        pub_h.hash_counter_range(&tmpl, 12, start, &mut out);
        for (i, digest) in out.iter().enumerate() {
            if let Some((leaf_addr, leaves, sibs)) = parse_select_digest(digest) {
                return UporsSelection { ctr: start + u32::try_from(i).unwrap(), leaf_addr, leaves, sibs };
            }
        }
        start = start.checked_add(u32::try_from(BATCH).unwrap()).expect("u32 ctr_ft exhausted");
    }
}

/// Verify a single `ctr_ft` during verification (`1` compression).
#[inline]
pub(crate) fn verify_upors_selection(pub_h: &TreeHasher, d_seed: &[u8; 32], ctr: u32) -> Option<UporsSelection> {
    let mut msg = [0u8; 52];
    msg[..16].copy_from_slice(&tweak(TweakKind::FewSelect, UPORS_LAYER_U8, 0, 0, 0, 0));
    msg[16..48].copy_from_slice(d_seed);
    msg[48..52].copy_from_slice(&ctr.to_le_bytes());
    let h = *pub_h.hash(&msg).as_bytes();
    let (leaf_addr, leaves, sibs) = parse_select_digest(&h)?;
    Some(UporsSelection { ctr, leaf_addr, leaves, sibs })
}

/// Derive the 10 unbiased `U-PORS` codewords in `L_42(3, 24)` (`C = 376`) via indexed 32-byte
/// `Keyed` hashes (`TweakKind::FewCode`, 28 9-bit draws/block, 99.9996% single compression, zero XOF).
pub(crate) fn extract_upors_codewords(public: &PublicKey, d_seed: &[u8; 32], ctr: u32) -> [[u8; UPORS_N]; UPORS_K] {
    let mut msg = [0u8; 52];
    msg[16..48].copy_from_slice(d_seed);
    msg[48..52].copy_from_slice(&ctr.to_le_bytes());

    let mut out = [[0u8; UPORS_N]; UPORS_K];
    let mut got = 0usize;
    let mut block_idx = 0u16;
    while got < UPORS_K {
        msg[..16].copy_from_slice(&tweak(TweakKind::FewCode, UPORS_LAYER_U8, 0, 0, block_idx, 0));
        let blk = public.keyed(&msg);
        for j in 0..28usize {
            let v = u16::try_from(read_bits(&blk, j * 9, 9)).unwrap();
            if usize::from(v) < UPORS_C {
                out[got] = hex_unrank(v);
                got += 1;
                if got == UPORS_K {
                    break;
                }
            }
        }
        block_idx = block_idx.checked_add(1).expect("FewCode block_idx overflow");
    }
    out
}

/// Zero-allocation stack-batched `U-PORS` Octopus verifier (`270` chain + `10` leaf + `<= 44` node hashes).
/// Enforces canonical all-zero padding on unused sibling slots in constant time.
pub(crate) fn upors_verify(pub_h: &TreeHasher, sel: &UporsSelection, codewords: &[[u8; UPORS_N]; UPORS_K], sig: &[u8; UPORS_LEN]) -> Option<[u8; N]> {
    let tree = sel.leaf_addr.as_u64();
    let chains_off = UPORS_CTR_LEN;
    let octo_off = UPORS_CTR_LEN + UPORS_K * UPORS_N * N;

    // 1. Batch-advance all 30 opened U-PORS chains to step 23 on stack!
    const TOTAL: usize = UPORS_K * UPORS_N;
    let mut vals = [[0u8; N]; TOTAL];
    let mut starts = [0u8; TOTAL];
    let mut order = [(0u8, 0u8); TOTAL];
    for (t, cw) in codewords.iter().enumerate() {
        for (c, &d) in cw.iter().enumerate() {
            let idx = t * UPORS_N + c;
            let off = chains_off + idx * N;
            vals[idx].copy_from_slice(&sig[off..off + N]);
            starts[idx] = d;
            order[idx] = (UPORS_STEPS - d, u8::try_from(idx).unwrap());
        }
    }
    order.sort_unstable_by_key(|x| core::cmp::Reverse(x.0));
    let mut active = order.partition_point(|&(rem, _)| rem > 0);

    let mut b32 = [[0u8; 32]; TOTAL];
    let mut out = [[0u8; 32]; TOTAL];
    for (slot, &(_, idx_u8)) in order[..active].iter().enumerate() {
        let idx = usize::from(idx_u8);
        let t = idx / UPORS_N;
        let c = idx % UPORS_N;
        pack_tagged(
            &mut b32[slot],
            tweak(TweakKind::Chain, UPORS_LAYER_U8, tree, sel.leaves[t], u16::try_from(c).unwrap(), u32::from(starts[idx])),
            &vals[idx],
        );
    }
    for step in 1..=UPORS_STEPS {
        if active == 0 {
            break;
        }
        pub_h.hash_many(&b32[..active], &mut out[..active]);
        while active > 0 && order[active - 1].0 == step {
            active -= 1;
            vals[usize::from(order[active].1)].copy_from_slice(&out[active][..N]);
        }
        for (slot, &(_, idx_u8)) in order[..active].iter().enumerate() {
            let idx = usize::from(idx_u8);
            let m = &mut b32[slot];
            m[12..16].copy_from_slice(&u32::from(starts[idx] + step).to_le_bytes());
            m[16..32].copy_from_slice(&out[slot][..N]);
        }
    }

    // 2. Hash all 10 64-byte leaf public keys in ONE stack batch!
    let mut b64 = [Block::ZERO; UPORS_K];
    let mut leaf_hashes = [[0u8; 32]; UPORS_K];
    for t in 0..UPORS_K {
        b64[t].0[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, UPORS_LAYER_U8, tree, sel.leaves[t], 0, 0));
        let base = t * UPORS_N;
        for c in 0..UPORS_N {
            b64[t].0[16 + c * N..16 + (c + 1) * N].copy_from_slice(&vals[base + c]);
        }
    }
    pub_h.hash_many(&Batch::from_blocks(&b64[..], 64), &mut leaf_hashes[..]);

    // 3. Climb the Octopus bottom-up across levels 1..=10, batching each level on stack!
    let mut cur_idx = sel.leaves;
    let mut cur_val: [[u8; N]; UPORS_K] = core::array::from_fn(|t| first_n(&leaf_hashes[t]));
    let mut cur_len = UPORS_K;
    let mut sib_cursor = 0usize;
    let mut b48 = [[0u8; 48]; UPORS_K];
    let mut node_out = [[0u8; 32]; UPORS_K];

    for level in 1..=UPORS_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let mut next_len = 0usize;
        let mut i = 0usize;
        while i < cur_len {
            let x = cur_idx[i];
            let p = x >> 1;
            let tw = tweak(TweakKind::Node, UPORS_LAYER_U8, tree, 0, level_u16, u32::from(p));
            if i + 1 < cur_len && (x & 1) == 0 && cur_idx[i + 1] == x + 1 {
                pack_pair(&mut b48[next_len], tw, &cur_val[i], &cur_val[i + 1]);
                cur_idx[next_len] = p;
                next_len += 1;
                i += 2;
            } else {
                let off = octo_off + sib_cursor * N;
                let sib = &sig[off..off + N];
                sib_cursor += 1;
                if (x & 1) == 0 {
                    pack_pair(&mut b48[next_len], tw, &cur_val[i], sib);
                } else {
                    pack_pair(&mut b48[next_len], tw, sib, &cur_val[i]);
                }
                cur_idx[next_len] = p;
                next_len += 1;
                i += 1;
            }
        }
        pub_h.hash_many(&b48[..next_len], &mut node_out[..next_len]);
        for j in 0..next_len {
            cur_val[j] = first_n(&node_out[j]);
        }
        cur_len = next_len;
    }
    assert_eq!(sib_cursor, sel.sibs);

    // 4. Strictly enforce canonical all-zero trailing padding on unused Octopus slots.
    let pad = &sig[octo_off + sib_cursor * N..octo_off + UPORS_M_MAX * N];
    let zeros = [0u8; UPORS_M_MAX * N];
    if !constant_time_eq(pad, &zeros[..pad.len()]) {
        return None;
    }
    Some(cur_val[0])
}

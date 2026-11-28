use crate::coding::hex_unrank;
use crate::engine::{Block, HashEngine, STACK_PACKED_CAP};
use crate::params::{
    HYPER_BITS, LeafAddr, N, TweakKind, UPORS_C, UPORS_CTR_LEN, UPORS_HEIGHT, UPORS_K, UPORS_LAYER_U8, UPORS_LEN, UPORS_M_MAX, UPORS_N, UPORS_SELECT_MAX_DRAWS,
    UPORS_STEPS, pack_pair, pack_tagged, read_bits, tweak,
};
use constant_time_eq::constant_time_eq;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UporsSelection {
    pub(crate) ctr: u32,
    pub(crate) h_sel: [u8; 32],
    pub(crate) leaf_addr: LeafAddr,
    pub(crate) leaves: [u16; UPORS_K],
    pub(crate) sibs: usize,
}

/// Count exact Octopus authentication siblings for `sorted_leaves` in a height-11 binary tree.
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

/// Spec-exact `FewSelect` parser (`SPEC.md §8.1`): up to `18` consecutive `11`-bit draws for `9`
/// distinct leaves in `0..2048` with Octopus sibling count `<= 45`, plus 48-bit `leaf_addr`.
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

/// Compute the sound pure-`u64` bit-fold ancestor lower bound `5 * n_5 + n_6 + n_7 + n_8 + n_9 + n_10`
/// over the first `UPORS_K = 9` 11-bit draws in `d`.
///
/// Exact Octopus identity for `A = 11, k = 9, m_max = 45`:
/// `sibs(S) = (sum_{j=1..=10} n_j(S)) + 2 - 9 <= 45 <=> sum_{j=1..=10} n_j(S) <= 52`.
/// Because adding later draws can only increase every ancestor count `n_j(S) >= n_j(S_0)` even if
/// the first 9 draws contain duplicates, and `n_1..n_4 >= n_5`, this lower bound is 100% sound
/// (zero false negatives) and rejects `99.30%` of candidates before sorting or tree traversal.
#[inline]
pub(crate) fn select_ancestor_lower_bound(d: &[u8; 32]) -> u32 {
    let w0 = u64::from_le_bytes(d[0..8].try_into().unwrap());
    let w1 = u64::from_le_bytes(d[8..16].try_into().unwrap());
    let m5 = (1u64 << ((w0 >> 5) & 63))
        | (1u64 << ((w0 >> 16) & 63))
        | (1u64 << ((w0 >> 27) & 63))
        | (1u64 << ((w0 >> 38) & 63))
        | (1u64 << ((w0 >> 49) & 63))
        | (1u64 << ((w0 >> 60) + ((w1 & 3) << 4)))
        | (1u64 << ((w1 >> 7) & 63))
        | (1u64 << ((w1 >> 18) & 63))
        | (1u64 << ((w1 >> 29) & 63));
    let m6 = m5 | (m5 >> 1);
    let m7 = m6 | (m6 >> 2);
    let m8 = m7 | (m7 >> 4);
    let m9 = m8 | (m8 >> 8);
    let m10 = m9 | (m9 >> 16);
    5 * m5.count_ones()
        + (m6 & 0x5555_5555_5555_5555).count_ones()
        + (m7 & 0x1111_1111_1111_1111).count_ones()
        + (m8 & 0x0101_0101_0101_0101).count_ones()
        + (m9 & 0x0001_0001_0001_0001).count_ones()
        + (m10 & 0x0000_0001_0000_0001).count_ones()
}

/// Fast `FEW_SELECT` parser with sound pure-`u64` bit-fold early-out (`99.30%` rejection).
#[inline]
pub(crate) fn parse_select_fast(d: &[u8; 32]) -> Option<(LeafAddr, [u16; UPORS_K], usize)> {
    if select_ancestor_lower_bound(d) > 52 {
        return None;
    }
    parse_select_digest(d)
}

/// Grind `ctr_ft` via [`HashEngine::grind_counter`] reusing caller-provided scratch space
/// (`scratch.len() >= 1024`).
pub(crate) fn grind_upors_selection(engine: &HashEngine, d_seed: &[u8; 32], scratch: &mut [[u8; 32]]) -> UporsSelection {
    let mut tmpl = [0u8; 52];
    tmpl[..16].copy_from_slice(&tweak(TweakKind::FewSelect, UPORS_LAYER_U8, 0, 0, 0, 0));
    tmpl[16..48].copy_from_slice(d_seed);
    let (ctr, h_sel, (leaf_addr, leaves, sibs)) = engine.grind_counter(&tmpl, 12, 1u64 << 32, scratch, parse_select_fast).expect("u32 ctr_ft exhausted");
    UporsSelection { ctr, h_sel, leaf_addr, leaves, sibs }
}

/// Verify a single `ctr_ft` during verification (`1` compression).
#[inline]
pub(crate) fn verify_upors_selection(engine: &HashEngine, d_seed: &[u8; 32], ctr: u32) -> Option<UporsSelection> {
    let mut msg = [0u8; 52];
    msg[..16].copy_from_slice(&tweak(TweakKind::FewSelect, UPORS_LAYER_U8, 0, 0, 0, 0));
    msg[16..48].copy_from_slice(d_seed);
    msg[48..52].copy_from_slice(&ctr.to_le_bytes());
    let h = engine.hash_short(&msg);
    let (leaf_addr, leaves, sibs) = parse_select_fast(&h)?;
    Some(UporsSelection { ctr, h_sel: h, leaf_addr, leaves, sibs })
}

/// Derive the 9 unbiased `U-PORS` codewords in `L_42(3, 24)` (`C = 376`) via indexed 32-byte
/// `Keyed` hashes chained from `H_sel` (`TweakKind::FewCode`, `48 B` input, 28 9-bit draws/block, zero XOF).
pub(crate) fn extract_upors_codewords(engine: &HashEngine, h_sel: &[u8; 32]) -> Option<[[u8; UPORS_N]; UPORS_K]> {
    let mut msg = [0u8; 48];
    msg[16..48].copy_from_slice(h_sel);

    let mut out = [[0u8; UPORS_N]; UPORS_K];
    let mut got = 0usize;
    for block_idx in 0..=u16::MAX {
        msg[..16].copy_from_slice(&tweak(TweakKind::FewCode, UPORS_LAYER_U8, 0, 0, block_idx, 0));
        let blk = engine.hash_short(&msg);
        for j in 0..28usize {
            let v = u16::try_from(read_bits(&blk, j * 9, 9)).unwrap();
            if usize::from(v) < UPORS_C {
                out[got] = hex_unrank(v);
                got += 1;
                if got == UPORS_K {
                    return Some(out);
                }
            }
        }
    }
    None
}

/// Zero-allocation stack-batched `U-PORS` Octopus verifier (`243` chain + `9` leaf + `<= 53` node hashes).
/// Advances all 27 variable-length chains via [`HashEngine::advance_chains_varlen`], hashes the 9
/// 64-byte leaf blocks in one stack batch, climbs the Octopus via [`HashEngine::hash_packed_48_stack`],
/// and strictly enforces canonical all-zero trailing Octopus padding in constant time.
pub(crate) fn upors_verify(engine: &HashEngine, sel: &UporsSelection, codewords: &[[u8; UPORS_N]; UPORS_K], sig: &[u8; UPORS_LEN]) -> Option<[u8; N]> {
    let tree = sel.leaf_addr.as_u64();
    let chains_off = UPORS_CTR_LEN;
    let octo_off = UPORS_CTR_LEN + UPORS_K * UPORS_N * N;

    // 1. Advance all 27 U-PORS chains via the continuous-refill variable-length engine.
    const TOTAL: usize = UPORS_K * UPORS_N;
    let mut init32 = [[0u8; 32]; TOTAL];
    let mut steps = [0u8; TOTAL];
    let mut endpoints = [[0u8; N]; TOTAL];
    for (t, cw) in codewords.iter().enumerate() {
        for (c, &d) in cw.iter().enumerate() {
            let idx = t * UPORS_N + c;
            let off = chains_off + idx * N;
            steps[idx] = UPORS_STEPS - d;
            pack_tagged(
                &mut init32[idx],
                tweak(TweakKind::Chain, UPORS_LAYER_U8, tree, sel.leaves[t], u16::try_from(c).unwrap(), u32::from(d)),
                &sig[off..off + N],
            );
        }
    }
    engine.advance_chains_varlen::<TOTAL>(&init32, &steps, &mut endpoints);

    // 2. Hash all 9 64-byte leaf hashes in ONE stack batch.
    let mut b64 = [Block::ZERO; UPORS_K];
    for t in 0..UPORS_K {
        b64[t].0[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, UPORS_LAYER_U8, tree, sel.leaves[t], 0, 0));
        for c in 0..UPORS_N {
            b64[t].0[16 + c * N..16 + (c + 1) * N].copy_from_slice(&endpoints[t * UPORS_N + c]);
        }
    }
    let mut leaf_scratch = [[0u8; 32]; UPORS_K];
    let mut cur_val = [[0u8; N]; UPORS_K];
    engine.hash_blocks_64_n(&b64, &mut leaf_scratch, &mut cur_val);

    // 3. Climb the Octopus bottom-up across levels 1..=11, batching each level on stack.
    let mut cur_idx = sel.leaves;
    let mut cur_len = UPORS_K;
    let mut sib_cursor = 0usize;
    let mut b48 = [[0u8; 48]; STACK_PACKED_CAP];

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
        engine.hash_packed_48_stack(&b48, next_len, &mut cur_val);
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

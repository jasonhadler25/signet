use crate::one_time::SignWorkspace;
use crate::params::{
    HYPER_BITS, LeafAddr, N, PublicKey, SecretKey, TREE_HEIGHT, TREE_LEAVES, TweakKind, UFORS_CHAINS, UFORS_CODE, UFORS_CODE_BITS, UFORS_LAYER_BASE, UFORS_LEN,
    UFORS_STEPS, UFORS_TOTAL_CHAINS, UFORS_TOTAL_LEAVES, UFORS_TREE_LEN, UFORS_TREES, first_n, pack_pair, pack_tagged, read_bits, tweak,
};
use blake3_servil_core::throughput::{Batch, Block, TreeHasher};

const UFORS_VERIFY_CHAINS: usize = UFORS_TREES * UFORS_CHAINS;

/// Selected `(leaf, code_idx)` pair for one U-FORS tree (`leaf < 32`, `code < 64`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UforsSel {
    pub leaf: u8,
    pub code: u8,
}

/// Extract all 15 U-FORS `(leaf: 5 bits, code: 6 bits)` selections (`bits 0..165`) and the
/// 35-bit hypertree `leaf_addr` (`bits 165..200`) from the 32-byte digest `D` (`SPEC.md`).
pub(crate) fn parse_digest(digest: &[u8; 32]) -> ([UforsSel; UFORS_TREES], LeafAddr) {
    let sel = core::array::from_fn(|t| {
        let base = (TREE_HEIGHT + UFORS_CODE_BITS) * t;
        UforsSel {
            leaf: u8::try_from(read_bits(digest, base, TREE_HEIGHT)).unwrap(),
            code: u8::try_from(read_bits(digest, base + TREE_HEIGHT, UFORS_CODE_BITS)).unwrap(),
        }
    });
    let leaf_addr = LeafAddr::from_digest_word(read_bits(digest, UFORS_TREES * (TREE_HEIGHT + UFORS_CODE_BITS), HYPER_BITS));
    (sel, leaf_addr)
}

/// Build all 15 U-FORS height-5 trees (`480` leaves, `1,440 = 45 × 32` equal-length chains of 9 steps)
/// in lockstep so SIMD/SME2 stays saturated across every step, writing chain values and authentication
/// paths into `out_sig` and returning the 16-byte `ufors_root`.
pub(crate) fn build_all_ufors(
    secret: &SecretKey,
    public: &PublicKey,
    leaf_addr: LeafAddr,
    sel: &[UforsSel; UFORS_TREES],
    ws: &mut SignWorkspace,
    out_sig: &mut [u8; UFORS_LEN],
) -> [u8; N] {
    let tree = leaf_addr.as_u64();
    let pub_h = public.hasher(true);

    // 1. Derive all 1,440 U-FORS chain starts in one batched call.
    secret.derive_ufors_starts(leaf_addr, &mut ws.b16, &mut ws.out);

    let target_digits: [[u8; UFORS_CHAINS]; UFORS_TREES] = core::array::from_fn(|t| UFORS_CODE[usize::from(sel[t].code)]);

    // Capture any target chains whose codeword digit is 0 directly from the start values.
    for t in 0..UFORS_TREES {
        let target_base = (t * TREE_LEAVES + usize::from(sel[t].leaf)) * UFORS_CHAINS;
        for c in 0..UFORS_CHAINS {
            if target_digits[t][c] == 0 {
                out_sig[t * UFORS_TREE_LEN + c * N..t * UFORS_TREE_LEN + (c + 1) * N].copy_from_slice(&ws.out[target_base + c][..N]);
            }
        }
    }

    // 2. Pack the invariant 12-byte tweak prefix for all 1,440 chains, then step all 9 waves in lockstep.
    let mut slot = 0usize;
    for t in 0..UFORS_TREES {
        let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
        for leaf in 0..TREE_LEAVES {
            let leaf_u16 = u16::try_from(leaf).unwrap();
            for c in 0..UFORS_CHAINS {
                let tw = tweak(TweakKind::Chain, layer_u8, tree, leaf_u16, u16::try_from(c).unwrap(), 0);
                ws.b32[slot][..12].copy_from_slice(&tw[..12]);
                slot += 1;
            }
        }
    }

    for step in 0..UFORS_STEPS {
        let step_bytes = u32::from(step).to_le_bytes();
        for i in 0..UFORS_TOTAL_CHAINS {
            let m = &mut ws.b32[i];
            m[12..16].copy_from_slice(&step_bytes);
            m[16..32].copy_from_slice(&ws.out[i][..N]);
        }
        pub_h.hash_many(&ws.b32[..UFORS_TOTAL_CHAINS], &mut ws.out[..UFORS_TOTAL_CHAINS]);
        let completed = step + 1;
        for t in 0..UFORS_TREES {
            let target_base = (t * TREE_LEAVES + usize::from(sel[t].leaf)) * UFORS_CHAINS;
            for c in 0..UFORS_CHAINS {
                if target_digits[t][c] == completed {
                    out_sig[t * UFORS_TREE_LEN + c * N..t * UFORS_TREE_LEN + (c + 1) * N].copy_from_slice(&ws.out[target_base + c][..N]);
                }
            }
        }
    }

    // 3. Compress all 480 = 15 × 32 U-FORS leaves (exact 64 B = 1 BLAKE3 compression each!).
    for t in 0..UFORS_TREES {
        let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
        for leaf in 0..TREE_LEAVES {
            let leaf_slot = t * TREE_LEAVES + leaf;
            let chain_base = leaf_slot * UFORS_CHAINS;
            let dst = &mut ws.b64[leaf_slot].0;
            dst[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, u16::try_from(leaf).unwrap(), 0, 0));
            for c in 0..UFORS_CHAINS {
                dst[16 + c * N..16 + (c + 1) * N].copy_from_slice(&ws.out[chain_base + c][..N]);
            }
        }
    }
    pub_h.hash_many(&Batch::from_blocks(&ws.b64[..UFORS_TOTAL_LEAVES], 64), &mut ws.out[..UFORS_TOTAL_LEAVES]);

    // 4. Five uniform batched Merkle levels across all 15 trees (240 -> 120 -> 60 -> 30 -> 15).
    let mut cur_idx: [usize; UFORS_TREES] = core::array::from_fn(|t| usize::from(sel[t].leaf));
    let mut width = TREE_LEAVES;
    let auth_off = UFORS_CHAINS * N;
    for level in 1..=TREE_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        let parents = width / 2;
        let total_parents = UFORS_TREES * parents;
        for t in 0..UFORS_TREES {
            let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
            let base = t * width;
            let sib_off = t * UFORS_TREE_LEN + auth_off + (level - 1) * N;
            out_sig[sib_off..sib_off + N].copy_from_slice(&ws.out[base + (cur_idx[t] ^ 1)][..N]);
            let p_base = t * parents;
            for p in 0..parents {
                pack_pair(
                    &mut ws.b48[p_base + p],
                    tweak(TweakKind::Node, layer_u8, tree, 0, level_u16, u32::try_from(p).unwrap()),
                    &ws.out[base + 2 * p][..N],
                    &ws.out[base + 2 * p + 1][..N],
                );
            }
            cur_idx[t] >>= 1;
        }
        pub_h.hash_many(&ws.b48[..total_parents], &mut ws.out[..total_parents]);
        width = parents;
    }

    let roots: [[u8; N]; UFORS_TREES] = core::array::from_fn(|t| first_n(&ws.out[t]));
    ufors_root(&public.hasher(false), leaf_addr, &roots)
}

/// Compress the 15 U-FORS tree roots into the 16-byte `ufors_root` signed by hypertree layer 0.
pub(crate) fn ufors_root(public: &TreeHasher, leaf_addr: LeafAddr, roots: &[[u8; N]; UFORS_TREES]) -> [u8; N] {
    let mut input = [0u8; 16 + N * UFORS_TREES];
    input[..16].copy_from_slice(&tweak(TweakKind::FewRoot, 0, leaf_addr.as_u64(), 0, 0, 0));
    for t in 0..UFORS_TREES {
        input[16 + t * N..16 + (t + 1) * N].copy_from_slice(&roots[t]);
    }
    first_n(public.hash(&input).as_bytes())
}

/// Verify a U-FORS signature on the stack (zero heap allocation), batching all 45 chains across
/// all 15 trees (exact constant 165 chain compressions), 15 single-block leaf hashes, and 5 Merkle levels.
pub(crate) fn ufors_verify(public: &TreeHasher, leaf_addr: LeafAddr, sel: &[UforsSel; UFORS_TREES], sig: &[u8; UFORS_LEN]) -> [u8; N] {
    let tree = leaf_addr.as_u64();

    // Load all 45 chain values and their starting digits.
    let mut vals: [[u8; N]; UFORS_VERIFY_CHAINS] = [[0u8; N]; UFORS_VERIFY_CHAINS];
    let mut starts: [u8; UFORS_VERIFY_CHAINS] = [0u8; UFORS_VERIFY_CHAINS];
    let mut order: [(u8, u8); UFORS_VERIFY_CHAINS] = [(0, 0); UFORS_VERIFY_CHAINS];
    for t in 0..UFORS_TREES {
        let cw = UFORS_CODE[usize::from(sel[t].code)];
        for c in 0..UFORS_CHAINS {
            let idx = t * UFORS_CHAINS + c;
            vals[idx].copy_from_slice(&sig[t * UFORS_TREE_LEN + c * N..t * UFORS_TREE_LEN + (c + 1) * N]);
            starts[idx] = cw[c];
            order[idx] = (UFORS_STEPS - cw[c], u8::try_from(idx).unwrap());
        }
    }
    order.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));

    let mut active = order.partition_point(|&(rem, _)| rem > 0);

    let mut b32 = [[0u8; 32]; UFORS_VERIFY_CHAINS];
    let mut out = [[0u8; 32]; UFORS_VERIFY_CHAINS];
    for (slot, &(_, idx_u8)) in order[..active].iter().enumerate() {
        let idx = usize::from(idx_u8);
        let t = idx / UFORS_CHAINS;
        let c = idx % UFORS_CHAINS;
        let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
        pack_tagged(
            &mut b32[slot],
            tweak(TweakKind::Chain, layer_u8, tree, u16::from(sel[t].leaf), u16::try_from(c).unwrap(), u32::from(starts[idx])),
            &vals[idx],
        );
    }

    for step in 1..=UFORS_STEPS {
        if active == 0 {
            break;
        }
        public.hash_many(&b32[..active], &mut out[..active]);
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

    // Compress all 15 U-FORS leaves (64 B = 1 compression each, cache-line aligned on stack).
    let mut b64 = [Block::ZERO; UFORS_TREES];
    for t in 0..UFORS_TREES {
        let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
        let dst = &mut b64[t].0;
        dst[..16].copy_from_slice(&tweak(TweakKind::OneTimeKey, layer_u8, tree, u16::from(sel[t].leaf), 0, 0));
        for c in 0..UFORS_CHAINS {
            dst[16 + c * N..16 + (c + 1) * N].copy_from_slice(&vals[t * UFORS_CHAINS + c]);
        }
    }
    public.hash_many(&Batch::from_blocks(&b64[..], 64), &mut out[..UFORS_TREES]);

    // Walk all 15 height-5 Merkle paths in lockstep.
    let mut cur: [[u8; N]; UFORS_TREES] = core::array::from_fn(|t| first_n(&out[t]));
    let mut idx: [u32; UFORS_TREES] = core::array::from_fn(|t| u32::from(sel[t].leaf));
    let mut b48 = [[0u8; 48]; UFORS_TREES];
    let auth_off = UFORS_CHAINS * N;

    for level in 1..=TREE_HEIGHT {
        let level_u16 = u16::try_from(level).unwrap();
        for t in 0..UFORS_TREES {
            let layer_u8 = UFORS_LAYER_BASE + u8::try_from(t).unwrap();
            let sib = &sig[t * UFORS_TREE_LEN + auth_off + (level - 1) * N..t * UFORS_TREE_LEN + auth_off + level * N];
            let (left, right) = if idx[t] & 1 == 0 { (&cur[t][..], sib) } else { (sib, &cur[t][..]) };
            pack_pair(&mut b48[t], tweak(TweakKind::Node, layer_u8, tree, 0, level_u16, idx[t] >> 1), left, right);
        }
        public.hash_many(&b48[..], &mut out[..UFORS_TREES]);
        for t in 0..UFORS_TREES {
            cur[t] = first_n(&out[t]);
            idx[t] >>= 1;
        }
    }

    ufors_root(public, leaf_addr, &cur)
}

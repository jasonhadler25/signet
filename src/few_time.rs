use crate::params::{
    AUTH_NODES, FEW_HEIGHT, FEW_LEAVES, FEW_LEN, HYPER_BITS, KIND_FEW_LEAF, KIND_FEW_NODE, KIND_FEW_SECRET, KIND_PICK, N, OPENED, THRESHOLD_BITS, TREE_HEIGHT,
    first_n, tweak,
};
use crate::workspace::{GRIND, SignWorkspace, VerifyWorkspace};
use blake3_servil_core::Mode;
use blake3_servil_core::throughput::{self, Prepared, TreeHasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Picked {
    pub tree: u64,
    pub leaf: u16,
    pub indices: [u16; OPENED],
    pub merged_len: usize,
}

#[inline(always)]
fn bits_at(buf: &[u8; 40], bit: usize, width: usize) -> u64 {
    let byte = bit / 8;
    let shift = bit % 8;
    let word = u64::from_le_bytes(buf[byte..byte + 8].try_into().unwrap());
    (word >> shift) & ((1u64 << width) - 1)
}

/// Parse and check a 32-byte `PICK` output: 6 zero bits, 11 distinct leaves, merged set <= 103.
pub(crate) fn parse_pick(g: &[u8; 32]) -> Option<Picked> {
    if g[0] & ((1u8 << THRESHOLD_BITS) - 1) != 0 {
        return None;
    }
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(g);
    let position = bits_at(&buf, THRESHOLD_BITS, HYPER_BITS);
    let mut indices = [0u16; OPENED];
    let first = THRESHOLD_BITS + HYPER_BITS;
    for (j, slot) in indices.iter_mut().enumerate() {
        *slot = bits_at(&buf, first + j * FEW_HEIGHT, FEW_HEIGHT) as u16;
    }
    // Insertion sort on 11 values.
    for i in 1..OPENED {
        let key = indices[i];
        let mut j = i;
        while j > 0 && indices[j - 1] > key {
            indices[j] = indices[j - 1];
            j -= 1;
        }
        indices[j] = key;
    }
    for j in 0..OPENED - 1 {
        if indices[j] == indices[j + 1] {
            return None;
        }
    }
    let merged_len = merged_size(&indices);
    if merged_len > AUTH_NODES {
        return None;
    }
    let tree = position >> TREE_HEIGHT;
    let leaf = (position & ((1u64 << TREE_HEIGHT) - 1)) as u16;
    Some(Picked { tree, leaf, indices, merged_len })
}

/// Number of nodes in the merged authentication set of `OPENED` sorted distinct leaves.
#[inline]
pub(crate) fn merged_size(indices: &[u16; OPENED]) -> usize {
    let mut common = 0usize;
    for j in 1..OPENED {
        let diff_bits = (u16::BITS - (indices[j] ^ indices[j - 1]).leading_zeros()) as usize;
        common += FEW_HEIGHT - diff_bits;
    }
    FEW_HEIGHT + (OPENED - 1) * (FEW_HEIGHT - 2) - common
}

/// The `(height, index)` coordinates of the merged authentication set, bottom level first and left to right
/// within each level (SPEC.md, "Merged authentication set").
pub(crate) fn merged_set(indices: &[u16; OPENED]) -> Vec<(u8, u16)> {
    let mut needed = Vec::with_capacity(AUTH_NODES);
    let mut known = *indices;
    let mut len = OPENED;
    for height in 0..FEW_HEIGHT {
        let mut next_len = 0;
        let mut i = 0;
        while i < len {
            let index = known[i];
            if index & 1 == 0 && i + 1 < len && known[i + 1] == index + 1 {
                i += 2;
            } else {
                needed.push((height as u8, index ^ 1));
                i += 1;
            }
            known[next_len] = index >> 1;
            next_len += 1;
        }
        len = next_len;
    }
    debug_assert_eq!(len, 1);
    debug_assert_eq!(needed.len(), merged_size(indices));
    needed
}

/// Evaluate `PICK` for one `(digest, counter)` pair.
pub(crate) fn pick(public: &TreeHasher, digest: &[u8; 32], counter: u32) -> Option<Picked> {
    let mut input = [0u8; 52];
    input[..16].copy_from_slice(&tweak(KIND_PICK, 0, 0, 0, 0, 0));
    input[16..48].copy_from_slice(digest);
    input[48..52].copy_from_slice(&counter.to_le_bytes());
    parse_pick(public.hash(&input).as_bytes())
}

/// Find the smallest `counter` in `0..=u32::MAX` that passes `PICK`, batching `GRIND` counters at a time.
fn search_pick(public: &[u8; 32], digest: &[u8; 32], ws: &mut SignWorkspace) -> (u32, Picked) {
    const { assert!((1u64 << 32).is_multiple_of(GRIND as u64)) };
    let t = tweak(KIND_PICK, 0, 0, 0, 0, 0);
    for i in 0..GRIND {
        let m = ws.b_pick.message_mut(i);
        m[..16].copy_from_slice(&t);
        m[16..48].copy_from_slice(digest);
    }
    for base in (0u64..=u32::MAX as u64).step_by(GRIND) {
        for i in 0..GRIND {
            ws.b_pick.message_mut(i)[48..52].copy_from_slice(&((base + i as u64) as u32).to_le_bytes());
        }
        throughput::hash_many(Mode::Keyed(public), &ws.b_pick, &mut ws.out[..GRIND]);
        for (i, out) in ws.out.iter().enumerate().take(GRIND) {
            if let Some(picked) = parse_pick(out) {
                return ((base + i as u64) as u32, picked);
            }
        }
    }
    panic!("few-time counter search exhausted 2^32 tries");
}

/// Build the few-time signature into `sig_part` (`FEW_LEN` bytes) and return `(tree, leaf, few_time_root)`.
pub(crate) fn few_time_sign(secret: &[u8; 32], public: &[u8; 32], digest: &[u8; 32], sig_part: &mut [u8], ws: &mut SignWorkspace) -> (u64, u16, [u8; N]) {
    debug_assert_eq!(sig_part.len(), FEW_LEN);
    let (counter, picked) = search_pick(public, digest, ws);
    let (tree, leaf) = (picked.tree, picked.leaf);
    let needed = merged_set(&picked.indices);
    assert!(needed.len() <= AUTH_NODES);

    sig_part[0..4].copy_from_slice(&counter.to_le_bytes());

    // 2^15 leaf secrets under K_sec.
    for i in 0..FEW_LEAVES {
        ws.b16.message_mut(i).copy_from_slice(&tweak(KIND_FEW_SECRET, 0, tree, leaf, 0, i as u32));
    }
    throughput::hash_many(Mode::Keyed(secret), &ws.b16, &mut ws.out);

    for (j, &idx) in picked.indices.iter().enumerate() {
        sig_part[4 + N * j..4 + N * (j + 1)].copy_from_slice(&ws.out[idx as usize][..N]);
    }

    // 2^15 leaf hashes under K_pub.
    for i in 0..FEW_LEAVES {
        let m = ws.b32.message_mut(i);
        m[..16].copy_from_slice(&tweak(KIND_FEW_LEAF, 0, tree, leaf, 0, i as u32));
        m[16..32].copy_from_slice(&ws.out[i][..N]);
    }
    throughput::hash_many(Mode::Keyed(public), &ws.b32, &mut ws.out);

    // Harvest merged authentication nodes while folding the tree up to the root.
    let auth_out = &mut sig_part[4 + N * OPENED..];
    auth_out.fill(0);
    let mut cursor = 0usize;
    for height in 0..FEW_HEIGHT {
        while cursor < needed.len() && needed[cursor].0 == height as u8 {
            let idx = needed[cursor].1 as usize;
            auth_out[N * cursor..N * (cursor + 1)].copy_from_slice(&ws.out[idx][..N]);
            cursor += 1;
        }
        let parents = FEW_LEAVES >> (height + 1);
        for i in 0..parents {
            let m = ws.b48.message_mut(i);
            m[..16].copy_from_slice(&tweak(KIND_FEW_NODE, 0, tree, leaf, height as u16 + 1, i as u32));
            m[16..32].copy_from_slice(&ws.out[2 * i][..N]);
            m[32..48].copy_from_slice(&ws.out[2 * i + 1][..N]);
        }
        throughput::hash_many(Mode::Keyed(public), &ws.b48.part(0..parents), &mut ws.out[..parents]);
    }
    assert_eq!(cursor, needed.len());
    (tree, leaf, first_n(&ws.out[0]))
}

/// Verify the few-time signature in `sig_part` (`FEW_LEN` bytes), returning `(tree, leaf, few_time_root)`.
pub(crate) fn few_time_verify(public: &TreeHasher, digest: &[u8; 32], sig_part: &[u8], ws: &mut VerifyWorkspace) -> Option<(u64, u16, [u8; N])> {
    debug_assert_eq!(sig_part.len(), FEW_LEN);
    let counter = u32::from_le_bytes(sig_part[0..4].try_into().unwrap());
    let picked = pick(public, digest, counter)?;
    let (tree, leaf) = (picked.tree, picked.leaf);

    let (secrets, auth) = sig_part[4..].split_at(N * OPENED);

    // Check trailing unused auth slots are zero.
    if auth[N * picked.merged_len..].iter().any(|&b| b != 0) {
        return None;
    }

    // Hash the 11 opened secrets into leaf values in one batch.
    for (j, &idx) in picked.indices.iter().enumerate() {
        let m = ws.b32.message_mut(j);
        m[..16].copy_from_slice(&tweak(KIND_FEW_LEAF, 0, tree, leaf, 0, idx as u32));
        m[16..32].copy_from_slice(&secrets[N * j..N * (j + 1)]);
    }
    public.hash_many(&ws.b32.part(0..OPENED), &mut ws.out[..OPENED]);

    let mut known: [(u16, [u8; N]); OPENED] = [(0, [0u8; N]); OPENED];
    for j in 0..OPENED {
        known[j] = (picked.indices[j], first_n(&ws.out[j]));
    }

    let mut len = OPENED;
    let mut used = 0usize;
    let mut parent_indices = [0u16; OPENED];
    for height in 0..FEW_HEIGHT {
        let mut next_len = 0;
        let mut i = 0;
        while i < len {
            let (index, value) = known[i];
            let parent_idx = index >> 1;
            let m = ws.b48.message_mut(next_len);
            m[..16].copy_from_slice(&tweak(KIND_FEW_NODE, 0, tree, leaf, height as u16 + 1, parent_idx as u32));
            if index & 1 == 0 && i + 1 < len && known[i + 1].0 == index + 1 {
                m[16..32].copy_from_slice(&value);
                m[32..48].copy_from_slice(&known[i + 1].1);
                i += 2;
            } else {
                assert!(used < AUTH_NODES);
                let other = &auth[N * used..N * (used + 1)];
                used += 1;
                if index & 1 == 0 {
                    m[16..32].copy_from_slice(&value);
                    m[32..48].copy_from_slice(other);
                } else {
                    m[16..32].copy_from_slice(other);
                    m[32..48].copy_from_slice(&value);
                }
                i += 1;
            }
            parent_indices[next_len] = parent_idx;
            next_len += 1;
        }
        if next_len >= 2 {
            public.hash_many(&ws.b48.part(0..next_len), &mut ws.out[..next_len]);
            for j in 0..next_len {
                known[j] = (parent_indices[j], first_n(&ws.out[j]));
            }
        } else {
            let h = public.hash(ws.b48.message_mut(0));
            known[0] = (parent_indices[0], first_n(h.as_bytes()));
        }
        len = next_len;
    }
    assert_eq!(len, 1);
    assert_eq!(used, picked.merged_len);
    Some((tree, leaf, known[0].1))
}

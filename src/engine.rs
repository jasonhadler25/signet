//! Internal BLINCS hashing engine isolating all `blake3-servil-core` batch, chain, counter,
//! and single-block primitives behind one narrow boundary.
//!
//! Built on `blake3-servil-core = "=0.11.0"` today, structured so future upstream features
//! (`servil-software-factory/BLAKE3` #583–#586) drop in inside this file alone with zero
//! changes to protocol, tree, or coding logic in `one_time.rs`, `few_time.rs`, or `lib.rs`.

use crate::params::{N, first_n};
pub(crate) use blake3_servil_core::throughput::{Batch, Block, Packed};
use blake3_servil_core::throughput::{Prepared, TreeHasher, hash as throughput_hash};
use blake3_servil_core::{BLOCK_LEN, Mode};

/// Native on-core packed SIMD width (`11` = NEON `8+3` on AArch64; `8` = AVX2 on x86-64).
#[cfg(target_arch = "aarch64")]
pub(crate) const CORE_PACKED_WIDTH: usize = 11;
/// Native on-core packed SIMD width (`11` = NEON `8+3` on AArch64; `8` = AVX2 on x86-64).
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const CORE_PACKED_WIDTH: usize = 8;

/// Stack capacity for small packed-48 batches (covers both `UPORS_K = 9` and AArch64 `11`-lane pad).
pub(crate) const STACK_PACKED_CAP: usize = 11;

const _: () = assert!(STACK_PACKED_CAP >= CORE_PACKED_WIDTH && STACK_PACKED_CAP >= crate::params::UPORS_K);

/// Pad on-core packed batches on AArch64 NEON to `11` when `active` is in `7..11`, working
/// around the `0.11.0` `hash_packed` stack-expansion remainder cliff (`BLAKE3` #583).
///
/// Upgrade hook (`BLAKE3` #583): once `blake3-servil-core` pads NEON `7..=10` remainders
/// internally, collapse this helper to `active`.
#[inline]
pub(crate) const fn core_pad_width(active: usize) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        match active {
            7..CORE_PACKED_WIDTH => CORE_PACKED_WIDTH,
            _ => active,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        active
    }
}

/// Sort active `(remaining_steps, chain_index)` entries longest-first so shorter chains
/// backfill freed lanes immediately in [`HashEngine::advance_chains_varlen`].
#[inline]
pub(crate) fn sort_chain_queue(queue: &mut [(u8, u8)]) {
    queue.sort_unstable_by_key(|x| core::cmp::Reverse(x.0));
}

/// Prepared keyed hashing engine for public BLINCS tree, chain, and grinding operations.
pub(crate) struct HashEngine {
    key: [u8; 32],
    hasher: TreeHasher,
}

impl HashEngine {
    /// Prepare an engine for `key`. Pass `use_sme2 = true` for bulk signing/keygen waves and
    /// `use_sme2 = false` for verification and small active-chain waves (`TreeHasher::on_this_core`).
    pub(crate) fn new(key: [u8; 32], use_sme2: bool) -> Self {
        let hasher = if use_sme2 { TreeHasher::new(Mode::Keyed(&key)) } else { TreeHasher::new(Mode::Keyed(&key)).on_this_core() };
        Self { key, hasher }
    }

    /// Hash a single-block (`<= 64`-byte) message on the fast aligned `Block` path.
    ///
    /// Upgrade hook (`BLAKE3` #586): swap to `*self.hasher.hash(bytes).as_bytes()` once
    /// `TreeHasher::hash` has an inline `<= 64 B` fast path.
    #[inline]
    pub(crate) fn hash_short(&self, bytes: &[u8]) -> [u8; 32] {
        assert!(bytes.len() <= BLOCK_LEN);
        let mut blk = Block::ZERO;
        blk.0[..bytes.len()].copy_from_slice(bytes);
        *throughput_hash(Mode::Keyed(&self.key), &[blk], bytes.len()).as_bytes()
    }

    /// Hash a single-block (`<= 64`-byte) message and truncate to `N = 16` bytes.
    #[inline]
    pub(crate) fn hash_short_n(&self, bytes: &[u8]) -> [u8; N] {
        first_n(&self.hash_short(bytes))
    }

    /// Hash an arbitrary-length message (e.g. `352`-byte `WOTS_PK`) and truncate to `N = 16` bytes.
    #[inline]
    pub(crate) fn hash_n(&self, bytes: &[u8]) -> [u8; N] {
        first_n(self.hasher.hash(bytes).as_bytes())
    }

    /// Hash `blocks.len()` 64-byte leaf blocks and write truncated `16`-byte digests to `out16`.
    pub(crate) fn hash_blocks_64_n(&self, blocks: &[Block], scratch: &mut [[u8; 32]], out16: &mut [[u8; N]]) {
        assert_eq!(blocks.len(), out16.len());
        let raw = &mut scratch[..blocks.len()];
        self.hasher.hash_many(&Batch::from_blocks(blocks, BLOCK_LEN), raw);
        for (dst, src) in out16.iter_mut().zip(raw.iter()) {
            *dst = first_n(src);
        }
    }

    /// Hash the first `count` messages of a multi-block `Batch` and write truncated `16`-byte digests.
    pub(crate) fn hash_batch_n(&self, batch: &Batch, count: usize, scratch: &mut [[u8; 32]], out16: &mut [[u8; N]]) {
        assert_eq!(count, out16.len());
        let raw = &mut scratch[..count];
        self.hasher.hash_many(&batch.part(0..count), raw);
        for (dst, src) in out16.iter_mut().zip(raw.iter()) {
            *dst = first_n(src);
        }
    }

    /// Hash `count` packed `48`-byte Merkle node inputs from a heap `Packed<48>` buffer.
    pub(crate) fn hash_packed_48_bulk(&self, nodes: &Packed<48>, count: usize, scratch: &mut [[u8; 32]], out16: &mut [[u8; N]]) {
        assert_eq!(count, out16.len());
        if count == 1 {
            out16[0] = self.hash_short_n(&nodes[0]);
            return;
        }
        let raw = &mut scratch[..count];
        self.hasher.hash_many(&nodes.part(0..count), raw);
        for (dst, src) in out16.iter_mut().zip(raw.iter()) {
            *dst = first_n(src);
        }
    }

    /// Hash `count` (`1..=STACK_PACKED_CAP`) packed `48`-byte Merkle node inputs on stack,
    /// padding AArch64 NEON `7..11` batches via [`core_pad_width`] (`BLAKE3` #583).
    pub(crate) fn hash_packed_48_stack(&self, buf: &[[u8; 48]; STACK_PACKED_CAP], count: usize, out16: &mut [[u8; N]]) {
        assert!((1..=STACK_PACKED_CAP).contains(&count) && count <= out16.len());
        if count == 1 {
            out16[0] = self.hash_short_n(&buf[0]);
            return;
        }
        let run = core_pad_width(count);
        let mut raw = [[0u8; 32]; STACK_PACKED_CAP];
        self.hasher.hash_many(&buf[..run], &mut raw[..run]);
        for i in 0..count {
            out16[i] = first_n(&raw[i]);
        }
    }

    /// Advance `count` independent `32`-byte chains (`[prefix12 || 0u32 || start16]`) by `steps`
    /// fixed iterations (`steps >= 1`) with `16`-byte feedback, writing final `16`-byte endpoints.
    ///
    /// Upgrade hook (`BLAKE3` #584): replace body with a single `hash_chains_32_trunc16` call.
    pub(crate) fn advance_chains_fixed(&self, b32: &mut Packed<32>, count: usize, steps: u8, scratch: &mut [[u8; 32]], out16: &mut [[u8; N]]) {
        assert!(steps >= 1 && count == out16.len());
        self.hasher.hash_many(&b32.part(0..count), &mut scratch[..count]);
        for step in 1..steps {
            let step_bytes = u32::from(step).to_le_bytes();
            for (m, o) in b32[..count].iter_mut().zip(scratch[..count].iter()) {
                m[12..16].copy_from_slice(&step_bytes);
                m[16..32].copy_from_slice(&o[..N]);
            }
            self.hasher.hash_many(&b32.part(0..count), &mut scratch[..count]);
        }
        for (dst, src) in out16.iter_mut().zip(scratch[..count].iter()) {
            *dst = first_n(src);
        }
    }

    /// Advance a two-stage bulk wave (`0..long_count` for `long_steps`, `long_count..total_count`
    /// for `short_steps`, all starting at step `0`) and write final `16`-byte endpoints.
    ///
    /// Keeps the lockstep `0..short_steps` + `short_steps..long_steps` schedule on `0.11.0`
    /// (`59` SME2 calls instead of `82`).
    ///
    /// Upgrade hook (`BLAKE3` #584): replace body with two `hash_chains_32_trunc16` calls
    /// (`0..long_count` × `long_steps` and `long_count..total_count` × `short_steps`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_chains_staged(
        &self,
        b32: &mut Packed<32>,
        long_count: usize,
        total_count: usize,
        short_steps: u8,
        long_steps: u8,
        scratch: &mut [[u8; 32]],
        out16: &mut [[u8; N]],
    ) {
        assert!(long_count <= total_count && short_steps >= 1 && short_steps < long_steps && total_count == out16.len());
        self.hasher.hash_many(&b32.part(0..total_count), &mut scratch[..total_count]);
        for step in 1..short_steps {
            let step_bytes = u32::from(step).to_le_bytes();
            for (m, o) in b32[..total_count].iter_mut().zip(scratch[..total_count].iter()) {
                m[12..16].copy_from_slice(&step_bytes);
                m[16..32].copy_from_slice(&o[..N]);
            }
            self.hasher.hash_many(&b32.part(0..total_count), &mut scratch[..total_count]);
        }
        for (dst, src) in out16[long_count..total_count].iter_mut().zip(scratch[long_count..total_count].iter()) {
            *dst = first_n(src);
        }
        for step in short_steps..long_steps {
            let step_bytes = u32::from(step).to_le_bytes();
            for (m, o) in b32[..long_count].iter_mut().zip(scratch[..long_count].iter()) {
                m[12..16].copy_from_slice(&step_bytes);
                m[16..32].copy_from_slice(&o[..N]);
            }
            self.hasher.hash_many(&b32.part(0..long_count), &mut scratch[..long_count]);
        }
        for (dst, src) in out16[..long_count].iter_mut().zip(scratch[..long_count].iter()) {
            *dst = first_n(src);
        }
    }

    /// Zero-allocation variable-length `32`-byte chain evaluator (`init32[i]` starts at its
    /// embedded `u32` LE step word in bytes `12..16`, advances `steps[i]` times with `16`-byte
    /// feedback, and writes its `16`-byte endpoint to `out16[i]`).
    ///
    /// Schedules chains longest-first across a continuous-refill [`CORE_PACKED_WIDTH`]-lane work
    /// queue so finished lanes are backfilled immediately without shrinking batches.
    ///
    /// Upgrade hook (`BLAKE3` #584): replace body with `hash_chains_varlen_32_trunc16`.
    pub(crate) fn advance_chains_varlen<const MAX_N: usize>(&self, init32: &[[u8; 32]], steps: &[u8], out16: &mut [[u8; N]]) {
        let n = init32.len();
        assert!(n <= MAX_N && n == steps.len() && n == out16.len());

        let mut queue = [(0u8, 0u8); MAX_N];
        let mut qlen = 0usize;
        for i in 0..n {
            if steps[i] == 0 {
                out16[i].copy_from_slice(&init32[i][16..32]);
            } else {
                queue[qlen] = (steps[i], u8::try_from(i).unwrap());
                qlen += 1;
            }
        }
        sort_chain_queue(&mut queue[..qlen]);

        let mut lane_in = [[0u8; 32]; CORE_PACKED_WIDTH];
        let mut lane_out = [[0u8; 32]; CORE_PACKED_WIDTH];
        let mut lane_rem = [0u8; CORE_PACKED_WIDTH];
        let mut lane_step = [0u32; CORE_PACKED_WIDTH];
        let mut lane_idx = [0usize; CORE_PACKED_WIDTH];
        let mut active = qlen.min(CORE_PACKED_WIDTH);
        let mut qpos = active;
        for (slot, &(rem, idx_u8)) in queue[..active].iter().enumerate() {
            let idx = usize::from(idx_u8);
            lane_in[slot] = init32[idx];
            lane_step[slot] = u32::from_le_bytes(init32[idx][12..16].try_into().unwrap());
            lane_rem[slot] = rem;
            lane_idx[slot] = idx;
        }

        while active > 0 {
            if active == 1 {
                lane_out[0] = self.hash_short(&lane_in[0]);
            } else {
                let run = core_pad_width(active);
                self.hasher.hash_many(&lane_in[..run], &mut lane_out[..run]);
            }

            let mut s = 0usize;
            while s < active {
                lane_rem[s] -= 1;
                if lane_rem[s] == 0 {
                    out16[lane_idx[s]] = first_n(&lane_out[s]);
                    if qpos < qlen {
                        let (rem, idx_u8) = queue[qpos];
                        qpos += 1;
                        let idx = usize::from(idx_u8);
                        lane_in[s] = init32[idx];
                        lane_step[s] = u32::from_le_bytes(init32[idx][12..16].try_into().unwrap());
                        lane_rem[s] = rem;
                        lane_idx[s] = idx;
                        s += 1;
                    } else {
                        active -= 1;
                        lane_in[s] = lane_in[active];
                        lane_out[s] = lane_out[active];
                        lane_rem[s] = lane_rem[active];
                        lane_step[s] = lane_step[active];
                        lane_idx[s] = lane_idx[active];
                    }
                } else {
                    lane_step[s] += 1;
                    lane_in[s][12..16].copy_from_slice(&lane_step[s].to_le_bytes());
                    lane_in[s][16..32].copy_from_slice(&lane_out[s][..N]);
                    s += 1;
                }
            }
        }
    }

    /// Grind the smallest counter `ctr` in `0..limit` whose single-block digest of `tmpl`
    /// (with `u32` LE counter at `counter_word * 4`) satisfies `accept`.
    ///
    /// Upgrade hook (`BLAKE3` #585): replace the `1,024`-batch `hash_counter_range` loop with
    /// zero-word-trimmed / early-exit `find_counter_range`.
    pub(crate) fn grind_counter<T>(
        &self,
        tmpl: &[u8],
        counter_word: usize,
        limit: u64,
        scratch: &mut [[u8; 32]],
        mut accept: impl FnMut(&[u8; 32]) -> Option<T>,
    ) -> Option<(u32, [u8; 32], T)> {
        const BATCH: usize = 1024;
        assert!(limit <= (1u64 << 32) && limit.is_multiple_of(BATCH as u64));
        let out = &mut scratch[..BATCH];
        let mut start = 0u64;
        while start < limit {
            let start_u32 = u32::try_from(start).unwrap();
            self.hasher.hash_counter_range(tmpl, counter_word, start_u32, out);
            for (i, digest) in out.iter().enumerate() {
                if let Some(parsed) = accept(digest) {
                    return Some((start_u32 + u32::try_from(i).unwrap(), *digest, parsed));
                }
            }
            start += BATCH as u64;
        }
        None
    }
}

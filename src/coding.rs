use crate::params::{UPORS_C, UPORS_N, UPORS_STEPS, UPORS_SUM, WOTS_N, WOTS_STEPS, WOTS_SUM, WOTS_W};
use std::sync::LazyLock;

/// Zero-ROM closed-form hexagon unranker mapping `idx in 0..376` bijectively to `(a, b, c)`
/// in `{0..=23}^3` with `a + b + c = 42` (`U-PORS` full upper slice `L_42(3, 24)`).
#[inline]
pub(crate) fn hex_unrank(mut idx: u16) -> [u8; UPORS_N] {
    assert!(usize::from(idx) < UPORS_C, "hex_unrank index out of bounds");
    let w1 = usize::from(UPORS_STEPS);
    let a_lo = UPORS_SUM.saturating_sub(2 * w1);
    let a_hi = UPORS_SUM.min(w1);
    for a in a_lo..=a_hi {
        let rem = UPORS_SUM - a;
        let b_lo = rem.saturating_sub(w1);
        let b_hi = rem.min(w1);
        let len = u16::try_from(b_hi - b_lo + 1).unwrap();
        if idx < len {
            let b = b_lo + usize::from(idx);
            let c = rem - b;
            return [u8::try_from(a).unwrap(), u8::try_from(b).unwrap(), u8::try_from(c).unwrap()];
        }
        idx -= len;
    }
    unreachable!("hex_unrank exhausted")
}

/// Lazily computed `24 × 469` (`~180 KiB`) Sperner DP table for ~`200 ns` constant-sum unranking.
static SPERNER_TABLE: LazyLock<Box<[[u128; WOTS_SUM + 1]; WOTS_N]>> = LazyLock::new(|| {
    let mut rows: Box<[[u128; WOTS_SUM + 1]; WOTS_N]> = vec![[0u128; WOTS_SUM + 1]; WOTS_N].into_boxed_slice().try_into().unwrap();
    rows[0][0] = 1;
    for k in 1..WOTS_N {
        let mut acc = 0u128;
        for s in 0..=WOTS_SUM {
            acc += rows[k - 1][s];
            if s >= WOTS_W {
                acc -= rows[k - 1][s - WOTS_W];
            }
            rows[k][s] = acc;
        }
    }
    rows
});

/// Map a 120-bit rank (`< 2^120 < |L_468(24, 40)|`) injectively to its lexicographic tuple
/// in `L_468(24, 40)` (`SPEC.md §11.1`).
#[inline]
pub(crate) fn sperner_unrank(mut rank: u128) -> [u8; WOTS_N] {
    let table = &*SPERNER_TABLE;
    let mut out = [0u8; WOTS_N];
    let mut rem_s = WOTS_SUM;
    let max_step = usize::from(WOTS_STEPS);
    for (i, slot) in out.iter_mut().enumerate() {
        let k_rem = WOTS_N - 1 - i;
        let row = &table[k_rem];
        let lim = rem_s.min(k_rem * max_step);
        let d_lo = rem_s.saturating_sub(lim);
        let d_hi = rem_s.min(max_step);
        let mut chosen = d_hi;
        for d in d_lo..=d_hi {
            let cnt = row[rem_s - d];
            if rank < cnt {
                chosen = d;
                break;
            }
            rank -= cnt;
        }
        *slot = u8::try_from(chosen).unwrap();
        rem_s -= chosen;
    }
    assert!(rem_s == 0 && rank == 0);
    out
}

/// Convert a 15-byte little-endian `S-WOTS+Z` digest (`H_l[1..16]`, 120 bits) into a `u128` rank.
#[inline]
pub(crate) fn rank_from_15_bytes(bytes: &[u8]) -> u128 {
    let mut buf = [0u8; 16];
    buf[..15].copy_from_slice(&bytes[..15]);
    u128::from_le_bytes(buf)
}

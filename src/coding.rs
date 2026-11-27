//! Zero-table coding primitives for `BLINCS-48-X`:
//! - Closed-form `U-PORS` hexagon unranking (`L_42(3, 24)`, `C = 376`, zero static tables).
//! - Direct 6-bit `WOTS+C` decoding (`n = 21, w = 60, z = 2, S = 679`, `2 + 21 * 6 = 128` bits exact,
//!   zero division, zero Sperner DP, zero static lookup tables, zero heap allocation).

use crate::params::{UPORS_C, UPORS_N, UPORS_STEPS, UPORS_SUM, WOTS_N, WOTS_SUM, WOTS_W};

const _: () = {
    assert!(WOTS_N == 21 && WOTS_W == 60 && WOTS_SUM == 679);
    assert!(UPORS_C == 376 && UPORS_N == 3 && UPORS_STEPS == 23 && UPORS_SUM == 42);
};

/// Closed-form zero-table hexagon unranker mapping `idx in 0..376` bijectively to
/// `(a, b, c) in {0..=23}^3` with `a + b + c = 42` in strict lexicographic order (`SPEC.md §10.1`).
#[inline]
pub(crate) fn hex_unrank(mut idx: u16) -> [u8; UPORS_N] {
    assert!(usize::from(idx) < UPORS_C, "hex_unrank index out of range");
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

/// Decode `WOTS+C(n = 21, w = 60, z = 2, S = 679)` directly from `digest[0..16]` (`SPEC.md §11.1`):
/// requires `(lo & 3) == 0`, all 21 packed 6-bit digits `d_i < 60`, and `sum(d_i) == 679`.
///
/// Uses SWAR lane-parallel `< 60` rejection (`d >= 60` iff bits `2..=5` of a 6-bit lane are all `1`)
/// with zero division, zero `u128` DP, zero static lookup tables, and zero heap allocation.
#[inline]
pub(crate) fn decode_wots_c(digest: &[u8; 32]) -> Option<[u8; WOTS_N]> {
    if (digest[0] & 3) != 0 {
        return None;
    }
    let w0 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
    let w1 = u64::from_le_bytes(digest[8..16].try_into().unwrap());
    // Bit 2 of each of the 10 packed 6-bit lanes 0..10: `(v & (v>>1) & (v>>2) & (v>>3) & LANE_BIT2) != 0` iff some lane >= 60.
    const LANE_BIT2: u64 = 0x0104_1041_0410_4104;
    let a = w0 >> 2;
    if (a & (a >> 1) & (a >> 2) & (a >> 3) & LANE_BIT2) != 0 {
        return None;
    }
    let d10 = (w0 >> 62) + ((w1 & 0x0f) << 2);
    if d10 >= u64::try_from(WOTS_W).unwrap() {
        return None;
    }
    let b = w1 >> 4;
    if (b & (b >> 1) & (b >> 2) & (b >> 3) & LANE_BIT2) != 0 {
        return None;
    }
    let mut digits = [0u8; WOTS_N];
    let mut sum = u32::try_from(d10).unwrap();
    for (i, slot) in digits[..10].iter_mut().enumerate() {
        let d = u8::try_from((a >> (6 * i)) & 63).unwrap();
        *slot = d;
        sum += u32::from(d);
    }
    digits[10] = u8::try_from(d10).unwrap();
    for (i, slot) in digits[11..].iter_mut().enumerate() {
        let d = u8::try_from((b >> (6 * i)) & 63).unwrap();
        *slot = d;
        sum += u32::from(d);
    }
    if sum == u32::try_from(WOTS_SUM).unwrap() { Some(digits) } else { None }
}

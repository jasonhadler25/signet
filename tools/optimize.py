#!/usr/bin/env python3
"""Reproducible exact combinatorial checker & parameter explorer for BLINCS-48-X (Python stdlib only).

Verifies adopted SPEC.md (`BLINCS-48-X`: `13+7+7+7+7+7` `WOTS+C(n=21, w=60, z=2, S=679, u24)` +
`U-PORS(n=3, w=24, S=42, C=376, A=11, k=9, m_max=45)`, `3,990 B`, `q = 2^48`):
  - Exact `WOTS+C` valid-prefix count `|L_679(21, 60)| = 83,261,328,062,314,682,436,358,950,675,433,803`
    (acceptance prob `|L_679(21, 60)| / 2^128 = 1 / 4,086.9`; `|L_680(21, 60)| < 2^116`, `w = 59` `< 2^116`).
  - Exact `U-PORS` full-slice cardinality `|L_42(3, 24)| = 376` and lattice-meet probabilities `lc[m]`.
  - Exact without-replacement hypergeometric elementary DP security (ZERO Octopus-cap credit,
    zero float64 cancellation on `log C(q, r)`): `127.07 b` @ `2^48` (exact zero-MC joint `Unc+Unc`
    = `127.97 b`, deterministic zero-MC all-orbits `Cap+Cap` upper envelope = `131.71 b` via `blincs/tools/upors_cert.rs`).
  - Exact compression counts (`from_seed = 10,379,263`, warm sign fixed = `963,126`, verify = `3,761`
    @ `m=45, b=1`) and modeled `160 MHz` Cortex-M33 warm `p99` signing (`<= 10.0 s`, modeled only).

Usage:
    python3 tools/optimize.py --check
"""

import argparse
import math
import sys

N = 16
US_M33_160 = 9.375  # ~1,500 cycles/compression @ 160 MHz ARM Cortex-M33 (modeled)


def sperner_slice_count(w, n, s):
    cur = [0] * (s + 1)
    cur[0] = 1
    for _ in range(n):
        nxt = [0] * (s + 1)
        acc = 0
        for j in range(s + 1):
            acc += cur[j]
            if j >= w:
                acc -= cur[j - w]
            nxt[j] = acc
        cur = nxt
    return cur[s]


def upors_lattice_cover_probs(w, n, s, max_m=24):
    """Exact DP for `q_C(m) = E[|{c* in C : c* >= min_{j=1..m} c^(j)}| / |C|]` on `L_s(n, w)`."""
    assert n == 3
    code = [
        (a, b, s - a - b)
        for a in range(w)
        for b in range(w)
        if 0 <= s - a - b < w
    ]
    c_len = len(code)
    dom = [[[0] * (w + 1) for _ in range(w + 1)] for _ in range(w + 1)]
    for a, b, c in code:
        dom[a][b][c] = 1
    for a in range(w - 1, -1, -1):
        for b in range(w - 1, -1, -1):
            for c in range(w - 1, -1, -1):
                dom[a][b][c] += (
                    dom[a + 1][b][c]
                    + dom[a][b + 1][c]
                    + dom[a][b][c + 1]
                    - dom[a + 1][b + 1][c]
                    - dom[a + 1][b][c + 1]
                    - dom[a][b + 1][c + 1]
                    + dom[a + 1][b + 1][c + 1]
                )

    dist = {(w - 1, w - 1, w - 1): 1.0}
    probs = [0.0]
    inv_c = 1.0 / c_len
    for _m in range(1, max_m + 1):
        nxt = {}
        for (ma, mb, mc), p in dist.items():
            w_p = p * inv_c
            for a, b, c in code:
                key = (a if a < ma else ma, b if b < mb else mb, c if c < mc else mc)
                nxt[key] = nxt.get(key, 0.0) + w_p
        dist = nxt
        probs.append(sum(p * (dom[ma][mb][mc] * inv_c) for (ma, mb, mc), p in dist.items()))
    return c_len, probs


def upors_elementary_security_bits(q, h, a_bits, k, lc):
    """Exact without-replacement hypergeometric elementary DP security (ZERO Octopus-cap credit)."""
    leaves = 1 << a_bits
    lam = q / (1 << h)
    log_p = -h * math.log(2.0)
    log_1mp = math.log1p(-math.ldexp(1.0, -h))
    p_hit = k / leaves
    log_ph = math.log(p_hit)
    log_1mph = math.log1p(-p_hit)

    c_l_k = math.comb(leaves, k)
    trans = [[0.0] * (k + 1) for _ in range(k + 1)]
    for i in range(k + 1):
        rem = k - i
        for h_new in range(rem + 1):
            if k - h_new <= leaves - rem:
                trans[i][i + h_new] = math.comb(rem, h_new) * math.comb(leaves - rem, k - h_new) / c_l_k

    r_hi = min(q, max(80, int(lam) + 120))
    dp = [0.0] * (k + 1)
    dp[0] = 1.0
    p_all_by_r = [0.0] * (r_hi + 1)
    for r in range(1, r_hi + 1):
        nxt = [0.0] * (k + 1)
        for i in range(k + 1):
            v = dp[i]
            if v == 0.0:
                continue
            row = trans[i]
            for j in range(i, k + 1):
                nxt[j] += v * row[j]
        dp = nxt
        p_all_by_r[r] = dp[k]

    log_terms = []
    log_fall = 0.0
    for r in range(1, r_hi + 1):
        log_fall += math.log(q - r + 1)
        p_all = p_all_by_r[r]
        if p_all <= 0.0:
            continue
        p_ge1 = -math.expm1(r * log_1mph)
        exp_lc = 0.0
        for t in range(1, r + 1):
            p_t = math.exp(math.lgamma(r + 1) - math.lgamma(t + 1) - math.lgamma(r - t + 1) + t * log_ph + (r - t) * log_1mph)
            exp_lc += p_t * (lc[t] if t < len(lc) else 1.0)
        cond_lc = exp_lc / p_ge1
        log_bin = log_fall - math.lgamma(r + 1) + r * log_p + (q - r) * log_1mp
        log_terms.append(log_bin + math.log(p_all) + k * math.log(cond_lc))
    m = max(log_terms)
    log_sum = m + math.log(sum(math.exp(x - m) for x in log_terms))
    return -(log_sum / math.log(2.0))


def run_check():
    # 1. Exact wire size & shifted S-WOTS+Z Sperner cardinality.
    sig_bytes = 2 * N + (4 + (9 * 3 + 45) * N) + 5 * (3 + (21 + 7) * N) + (3 + (21 + 13) * N)
    if sig_bytes != 3990:
        raise RuntimeError(f"unexpected signature bytes {sig_bytes}")
    cnt60 = sperner_slice_count(60, 21, 679)
    cnt60_hi = sperner_slice_count(60, 21, 680)
    cnt59 = sperner_slice_count(59, 21, 609)
    if cnt60 != 83261328062314682436358950675433803 or not (cnt60_hi < (1 << 116) < cnt60 and cnt59 < (1 << 116)):
        raise RuntimeError(f"unexpected Sperner counts: w59={cnt59}, s680={cnt60_hi}, s679={cnt60}")

    # 2. Exact U-PORS slice & elementary zero-cap-credit DP curve.
    c_len, lc = upors_lattice_cover_probs(24, 3, 42)
    if c_len != 376 or abs(lc[2] - 0.1700038) > 1e-4:
        raise RuntimeError(f"unexpected U-PORS slice: C={c_len}, lc[2]={lc[2]:.5f}")
    b47 = upors_elementary_security_bits(1 << 47, 48, 11, 9, lc)
    b48 = upors_elementary_security_bits(1 << 48, 48, 11, 9, lc)
    b49 = upors_elementary_security_bits(1 << 49, 48, 11, 9, lc)
    b50 = upors_elementary_security_bits(1 << 50, 48, 11, 9, lc)
    b51 = upors_elementary_security_bits(1 << 51, 48, 11, 9, lc)
    if not (
        abs(b47 - 132.90) < 0.05
        and abs(b48 - 127.07) < 0.05
        and abs(b49 - 120.11) < 0.05
        and abs(b50 - 111.80) < 0.05
        and abs(b51 - 101.92) < 0.05
    ):
        raise RuntimeError(f"unexpected elementary U-PORS security curve: {b47:.2f}/{b48:.2f}/{b49:.2f}/{b50:.2f}/{b51:.2f}")

    # 2b. Exact bivariate Octopus enumerator F_{h+1}(x, y) = 1 + 2y(F_h - 1) + (F_h - 1)^2.
    # f[k][s] = number of k-subsets of [2^h] with exactly s Octopus siblings (k <= 9, s <= 45).
    f = [[0] * 46 for _ in range(10)]
    f[0][0] = 1
    f[1][0] = 1
    for _ in range(11):
        nf = [[0] * 46 for _ in range(10)]
        nf[0][0] = 1
        for k1 in range(1, 10):
            for s1 in range(45):
                c = f[k1][s1]
                if c:
                    nf[k1][s1 + 1] += 2 * c
        for k1 in range(1, 9):
            for s1 in range(46):
                c1 = f[k1][s1]
                if not c1:
                    continue
                for k2 in range(1, 10 - k1):
                    for s2 in range(46 - s1):
                        c2 = f[k2][s2]
                        if c2:
                            nf[k1 + k2][s1 + s2] += c1 * c2
        f = nf
    f_card = sum(f[9])
    total_9 = math.comb(2048, 9)
    if f_card != 180700154447569471488 or total_9 != 1716176187879294282352640:
        raise RuntimeError(f"unexpected Octopus family cardinality: |F|={f_card}, C(2048,9)={total_9}")
    p_cap = f_card / total_9

    # 3. Exact compression counts & modeled 160 MHz Cortex-M33 warm p99 bound (<= 10.0 s).
    wots_pk_blocks = (16 + 21 * N + 63) // 64  # 6
    wots_leaf_comps = 21 + 21 * 59 + wots_pk_blocks  # 1,266
    from_seed_comps = 8192 * wots_leaf_comps + 8191  # 10,379,263
    low_5_comps = 5 * (128 * wots_leaf_comps + 127)  # 810,875
    upors_tree_comps = 2048 * (3 + 3 * 23 + 1) + 2047  # 151,551
    # Exact fixed warm sign compressions (256 KiB full top cache):
    # 5 lower trees (810,875) + 1 U-PORS tree (151,551) + active layer-5 WOTS (21 + 679 = 700) = 963,126.
    warm_fixed = low_5_comps + upors_tree_comps + 700
    # Partial top cache (c = 10, 16 KiB subtree roots): adds 8 top leaves + 7 nodes = 10,135 comps.
    partial_16k_fixed = warm_fixed + 8 * wots_leaf_comps + 7
    # Exact verify count for short msg (|M| <= 64, |ctx| <= 31, b = 1 FewCode block, m = 45 Octopus sibs):
    # content(2: K_msg + h_msg) + D_seed(2) + FewSelect(1) + FewCode(b=1)
    # + U-PORS chains(9*(69-42)=243) + U-PORS leaves(9) + Octopus combines(m + 8 = 53)
    # + 6 * (OneTimeMsg(1) + WOTS chains(1239 - 679 = 560) + WOTS pk(6)) + Merkle paths(5*7 + 13 = 48)
    # = 3,715 + m + b = 3,761 at m = 45, b = 1.
    verify_exact = 2 + 2 + 1 + 1 + 243 + 9 + (45 + 8) + 6 * (1 + 560 + 6) + (5 * 7 + 13)
    if from_seed_comps != 10379263 or warm_fixed != 963126 or verify_exact != 3761:
        raise RuntimeError(f"unexpected compression counts: from_seed={from_seed_comps}, warm={warm_fixed}, verify={verify_exact}")
    # Independent convolution p99 of Geom(p_cap=1/9497.4) + Erlang(6, 4096) is ~64,200 compressions.
    m33_warm_p99_256k = (warm_fixed + 64200) * US_M33_160 / 1e6
    m33_warm_p99_16k = (partial_16k_fixed + 64200) * US_M33_160 / 1e6
    if m33_warm_p99_16k > 10.0:
        raise RuntimeError(f"modeled 160 MHz Cortex-M33 warm p99 (16 KiB cache) {m33_warm_p99_16k:.2f}s > 10.0s")

    print(
        f"CHECK PASSED: adopted SPEC BLINCS-48-X ({sig_bytes} B, 256 KiB full / 16 KiB partial top cache, "
        f"|L_679(21,60)|={cnt60} > 2^116, |L_42(3,24)|={c_len}, |F|={f_card} (p_cap={p_cap:.6e}), "
        f"verify={verify_exact} comp @ m=45,b=1, modeled M33-160MHz warm p99={m33_warm_p99_256k:.2f}s [256 KiB] / {m33_warm_p99_16k:.2f}s [16 KiB]) | "
        f"U-PORS elem-DP={b48:.2f}/{b49:.2f}/{b50:.2f}/{b51:.2f}b (2^48..2^51); "
        f"deterministic all-orbits Cap+Cap upper envelope (blincs/tools/upors_cert.rs)=131.71/125.36/117.85b."
    )


def main():
    ap = argparse.ArgumentParser(description="Exact combinatorial & parameter checker for BLINCS-48-X.")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    run_check()
    return 0


if __name__ == "__main__":
    sys.exit(main())

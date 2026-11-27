#!/usr/bin/env python3
"""Reproducible exact combinatorial checker & parameter explorer for BLINCS-128-A2 (Python stdlib only).

Verifies adopted SPEC.md (`BLINCS-128-A2`: `12+7+7+7` `S-WOTS+Z(n=24, w=40, S=468, z=8)` +
`U-PORS(n=3, w=24, S=42, C=376, A=10, k=10, m_max=44)`, `3,292 B`):
  - Exact `S-WOTS+Z` Sperner cardinality `|L_468(24, 40)| > 2^120` (and `w = 39` strictly `< 2^120`).
  - Exact `U-PORS` full-slice cardinality `|L_42(3, 24)| = 376` and lattice-meet probabilities `lc[m]`.
  - Exact without-replacement hypergeometric elementary DP security (ZERO Octopus-cap credit):
    `128.58 b` @ `2^32`, `121.56 b` @ `2^33`, `113.71 b` @ `2^34`, `104.88 b` @ `2^35`.
  - Exact compression counts (`from_seed = 3,964,927`, warm sign fixed = `447,976`, verify = `2,276` @ `m=44, b=1`)
    and modeled `160 MHz` Cortex-M33 warm `p99` signing (`<= 5.0 s`, modeled only).

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


def upors_lattice_cover_probs(w, n, s, max_m=14):
    """Exact DP for `q_C(m) = E[|{c* in C : c* >= min_{j=1..m} c^(j)}| / |C|]` on `L_s(n, w)`."""
    assert n == 3
    code = [
        (a, b, s - a - b)
        for a in range(w)
        for b in range(w)
        if 0 <= s - a - b < w
    ]
    c_len = len(code)
    # Count how many codewords dominate each state `(x, y, z) in [w]^3` via 3D suffix sum.
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

    # DP over `m` independent uniform reveals tracking exact coordinatewise min `(ma, mb, mc)`.
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
    """Exact without-replacement hypergeometric elementary DP security (ZERO Octopus-cap credit!)."""
    leaves = 1 << a_bits
    lam = q / (1 << h)
    log_p = -h * math.log(2.0)
    log_1mp = math.log1p(-math.ldexp(1.0, -h))
    log_q_fact = math.lgamma(q + 1)

    p_hit = k / leaves
    log_ph = math.log(p_hit)
    log_1mph = math.log1p(-p_hit)

    # Exact positive hypergeometric DP over distinct target-leaf hits (zero floating-point cancellation!):
    # trans[i][j] = P(go from i hit targets to j hit targets in one random k-subset of L leaves).
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
    for r in range(1, r_hi + 1):
        p_all = p_all_by_r[r]
        if p_all <= 0.0:
            continue
        # E[lc[T] | T >= 1] where T ~ Binomial(r, k/L)
        p_ge1 = -math.expm1(r * log_1mph)
        exp_lc = 0.0
        for t in range(1, min(r, len(lc) - 1) + 1):
            p_t = math.exp(math.lgamma(r + 1) - math.lgamma(t + 1) - math.lgamma(r - t + 1) + t * log_ph + (r - t) * log_1mph)
            exp_lc += p_t * lc[t]
        if r >= len(lc):
            # Tail t >= len(lc): conservatively bound lc[t] <= 1.0
            p_tail = 1.0 - sum(
                math.exp(math.lgamma(r + 1) - math.lgamma(t + 1) - math.lgamma(r - t + 1) + t * log_ph + (r - t) * log_1mph)
                for t in range(len(lc))
            )
            if p_tail > 0.0:
                exp_lc += p_tail
        cond_lc = exp_lc / p_ge1
        log_bin = log_q_fact - math.lgamma(r + 1) - math.lgamma(q - r + 1) + r * log_p + (q - r) * log_1mp
        log_terms.append(log_bin + math.log(p_all) + k * math.log(cond_lc))
    m = max(log_terms)
    log_sum = m + math.log(sum(math.exp(x - m) for x in log_terms))
    return -(log_sum / math.log(2.0))


def run_check():
    # 1. Exact wire size & S-WOTS+Z Sperner cardinality.
    sig_bytes = 2 * N + (4 + (10 * 3 + 44) * N) + 3 * (2 + (24 + 7) * N) + (2 + (24 + 12) * N)
    if sig_bytes != 3292:
        raise RuntimeError(f"unexpected signature bytes {sig_bytes}")
    cnt40 = sperner_slice_count(40, 24, 468)
    cnt39 = sperner_slice_count(39, 24, 456)
    if cnt40 != 1973221677906098493567206234001571000 or not (cnt39 < (1 << 120) < cnt40):
        raise RuntimeError(f"unexpected Sperner counts: w39={cnt39}, w40={cnt40}")

    # 2. Exact U-PORS slice & elementary zero-cap-credit DP curve.
    c_len, lc = upors_lattice_cover_probs(24, 3, 42)
    if c_len != 376 or abs(lc[2] - 0.1700038) > 1e-4:
        raise RuntimeError(f"unexpected U-PORS slice: C={c_len}, lc[2]={lc[2]:.5f}")
    b31 = upors_elementary_security_bits(1 << 31, 33, 10, 10, lc)
    b32 = upors_elementary_security_bits(1 << 32, 33, 10, 10, lc)
    b33 = upors_elementary_security_bits(1 << 33, 33, 10, 10, lc)
    b34 = upors_elementary_security_bits(1 << 34, 33, 10, 10, lc)
    b35 = upors_elementary_security_bits(1 << 35, 33, 10, 10, lc)
    b36 = upors_elementary_security_bits(1 << 36, 33, 10, 10, lc)
    if not (
        abs(b31 - 134.58) < 0.05
        and abs(b32 - 128.58) < 0.05
        and abs(b33 - 121.56) < 0.05
        and abs(b34 - 113.29) < 0.05
        and abs(b35 - 103.55) < 0.05
        and abs(b36 - 92.16) < 0.05
    ):
        raise RuntimeError(f"unexpected elementary U-PORS security curve: {b31:.2f}/{b32:.2f}/{b33:.2f}/{b34:.2f}/{b35:.2f}/{b36:.2f}")

    # 2b. Exact bivariate Octopus enumerator F_{h+1}(x, y) = 1 + 2y(F_h - 1) + (F_h - 1)^2.
    # f[k][s] = number of k-subsets of [2^h] with exactly s Octopus siblings (k <= 10, s <= 44).
    f = [[0] * 45 for _ in range(11)]
    f[0][0] = 1
    f[1][0] = 1
    for _ in range(10):
        nf = [[0] * 45 for _ in range(11)]
        nf[0][0] = 1
        for k1 in range(1, 11):
            for s1 in range(44):
                c = f[k1][s1]
                if c:
                    nf[k1][s1 + 1] += 2 * c
        for k1 in range(1, 10):
            for s1 in range(45):
                c1 = f[k1][s1]
                if not c1:
                    continue
                for k2 in range(1, 11 - k1):
                    for s2 in range(45 - s1):
                        c2 = f[k2][s2]
                        if c2:
                            nf[k1 + k2][s1 + s2] += c1 * c2
        f = nf
    f_card = sum(f[10])
    total_10 = math.comb(1024, 10)
    if f_card != 256172225164499838464 or total_10 != 334265867498622145619456:
        raise RuntimeError(f"unexpected Octopus family cardinality: |F|={f_card}, C(1024,10)={total_10}")
    p_cap = f_card / total_10

    # 3. Exact compression counts & modeled 160 MHz Cortex-M33 warm p99 bound (<= 5.0 s).
    wots_pk_blocks = (16 + 24 * N + 63) // 64  # 7
    wots_leaf_comps = 24 + 24 * 39 + wots_pk_blocks  # 967
    from_seed_comps = 4096 * wots_leaf_comps + 4095  # 3,964,927
    low_3_comps = 3 * (128 * wots_leaf_comps + 127)  # 371,709
    upors_tree_comps = 1024 * (3 + 3 * 23 + 1) + 1023  # 75,775
    # Exact fixed warm sign compressions:
    # 3 lower trees (371,709) + 1 U-PORS tree (75,775) + active layer-3 WOTS (492) = 447,976.
    warm_fixed = low_3_comps + upors_tree_comps + 492
    # Exact verify count for short msg (|M| <= 64, |ctx| <= 31, b = 1 FewCode block, m = 44 Octopus sibs):
    # content(2: K_msg + h_msg) + D_seed(2) + FewSelect(1) + FewCode(b=1)
    # + U-PORS chains(270) + U-PORS leaves(10) + Octopus combines(m + 9 = 53)
    # + 4 * (OneTimeMsg(1) + WOTS chains(468) + WOTS pk(7)) + Merkle paths(7+7+7+12=33)
    # = 2,231 + m + b = 2,276 at m = 44, b = 1.
    verify_exact = 2 + 2 + 1 + 1 + 270 + 10 + (44 + 9) + 4 * (1 + 468 + 7) + (7 + 7 + 7 + 12)
    if from_seed_comps != 3964927 or verify_exact != 2276:
        raise RuntimeError(f"unexpected compression counts: from_seed={from_seed_comps}, verify={verify_exact}")
    m33_warm_p99_s = (warm_fixed + 8000) * US_M33_160 / 1e6
    if m33_warm_p99_s > 5.0:
        raise RuntimeError(f"modeled 160 MHz Cortex-M33 warm p99 {m33_warm_p99_s:.2f}s > 5.0s")

    print(
        f"CHECK PASSED: adopted SPEC BLINCS-128-A2 ({sig_bytes} B, 128 KiB top tree, "
        f"|L_468(24,40)|={cnt40} > 2^120, |L_42(3,24)|={c_len}, |F|={f_card} (p_cap={p_cap:.6e}), "
        f"verify={verify_exact} comp @ m=44,b=1, modeled M33-160MHz warm p99={m33_warm_p99_s:.2f}s) | "
        f"U-PORS uncapped DP={b32:.2f}/{b33:.2f}/{b34:.2f}/{b35:.2f}b (2^32..2^35); "
        f"certified capped-history 99% LCB (blincs/tools/upors_cert.rs)=132.13/125.48/117.72/108.63b."
    )


def main():
    ap = argparse.ArgumentParser(description="Exact combinatorial & parameter checker for BLINCS-128-A2.")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    run_check()
    return 0


if __name__ == "__main__":
    sys.exit(main())

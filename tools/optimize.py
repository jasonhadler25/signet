#!/usr/bin/env python3
"""Reproducible, self-contained parameter optimizer for BLINCS (Python standard library only).

Calibrated against concrete Apple M6 measurements of `blake3-servil-core = "=0.10.0"` (`clocks` crate):
  - XMSS tree builds (including copy-back, ONE_TIME_KEY, Merkle): 11.1 + 3.8 * 1024 / (chains + 1024) ns/comp
    (measured: 13.45 ns at 672 chains down to 11.22 ns at 12,288 chains; cached top tree saves 1 of d trees).
  - PORS+FP tree builds: 10.0 + 4.8 * 2048 / (leaves + 2048) ns/comp
    (measured: 12.42 ns at 2^11 down to 10.08 ns at 2^16).
  - Counter searches (GRIND = 2048): 12.6 ns/try (measured: 12.59 ns for both 36 B and 52 B).
  - Verification (`TreeHasher::on_this_core()`, batched chains & few-time levels): 18.5 ns/batched + 45 ns/scalar
    (predicts 33.0 us for BLINCS 0.1.0 vs. 33.3 us measured).

Computes exact integer retry DPs (WOTS+C digit sums and PORS+FP merged authentication sets),
the PORS+FP + hypertree cover-probability security bound, the full 3-D Pareto frontier over plain shapes
(d = 1..=12, w in {4,8,16,32,64,128,256}), and ranks candidates under:
  1. Scale-free sum of squares of log-ratios above achievable minima: sum (ln(x_i / x_{i,min}))^2
     (plus L_inf minimax ratio, squared relative excess, span-normalized L2, plain B*S*V, and weighted sweep).
  2. Log-uniform unknown-thresholds joint survival and minimax conditional exclusion risk.
  3. Direct comparison with SLH-DSA-B (FIPS 205 128s / 128f with BLAKE3, measured on the same Apple M6).

Usage:
    python3 tools/optimize.py                       # default: 2^33 sigs, >= 128 bits, calibrated M6 model
    python3 tools/optimize.py --max-top-height 15   # irregular hypertrees with <= 1 MiB stateless top-tree cache
    python3 tools/optimize.py --four-axis           # unconstrained 4-axis (bytes, cached sign, uncached 1-shot, verify)
    python3 tools/optimize.py --sign-speedup 3.0    # e.g. 8-core leaf-parallel signing
    python3 tools/optimize.py --uncached            # count all d trees in signing time
    python3 tools/optimize.py --grinding-sweep      # m = 95..120 trade-off for BLINCS 0.1.0
    python3 tools/optimize.py --check               # verify exact DP counts, security bound, and M6 calibration
"""

import argparse
import math
import sys
import time

N = 16


def parse_q(s):
    if "^" in s:
        a, b = s.split("^", 1)
        return int(a) ** int(b)
    return int(s)


# --- Exact security bound (SPHINCS+ r3.1 Appendix A + Abri & Katz eprint 2025/2069 Theorem 1) --------
def security_bits(q, h, b, k, gf):
    """-log2 of per-query cover probability P(q) for hypertree height h, PORS+FP tree 2^b, k opened, gf threshold bits."""
    t = 1 << b
    lam = q / (1 << h)
    log_p = -h * math.log(2.0)
    log_1mp = math.log1p(-math.ldexp(1.0, -h))
    log_q_fact = math.lgamma(q + 1)
    log_denom = math.lgamma(t + 1) - math.lgamma(k + 1) - math.lgamma(t - k + 1)

    r_center = int(lam)
    spread = max(40, int(14 * math.sqrt(max(lam, 1.0))) + 40)
    r_lo = max(1, r_center - spread)
    r_hi = min(q, r_center + spread)

    log_terms = []
    for r in range(r_lo, r_hi + 1):
        log_bin = log_q_fact - math.lgamma(r + 1) - math.lgamma(q - r + 1) + r * log_p + (q - r) * log_1mp
        covered = min(t, k * r)
        if covered < k:
            continue
        if covered == t:
            log_cov = 0.0
        else:
            log_cov = math.lgamma(covered + 1) - math.lgamma(k + 1) - math.lgamma(covered - k + 1) - log_denom
        log_terms.append(log_bin + log_cov)
    if not log_terms:
        return float("inf")
    m = max(log_terms)
    log_sum = m + math.log(sum(math.exp(x - m) for x in log_terms))
    return gf - log_sum / math.log(2.0)


# --- Exact integer DP for WOTS+C digit sums -----------------------------------------------------------
def wots_sum_counts(v, width):
    """Exact count of v-tuples in [0, 2^width)^v with each sum S."""
    w = 1 << width
    dp = [1]
    for _ in range(v):
        ndp = [0] * (len(dp) + w - 1)
        running = 0
        for s in range(len(ndp)):
            if s < len(dp):
                running += dp[s]
            if s >= w and s - w < len(dp):
                running -= dp[s - w]
            ndp[s] = running
        dp = ndp
    return dp


# --- Exact integer DP for PORS+FP merged authentication set sizes -------------------------------------
def pors_merged_table(b_max, k_cap_by_b):
    """For every height b in 1..=b_max, exact dict {k: {m: subset_count}} up to k_cap_by_b(b)."""
    tbl = {0: {0: 1}, 1: {0: 1}}
    results = {}
    for h in range(1, b_max + 1):
        k_lim = k_cap_by_b(h)
        ntbl = {}
        items = [(k, d) for k, d in tbl.items() if k <= k_lim]
        for k1, d1 in items:
            for k2, d2 in items:
                k = k1 + k2
                if k > k_lim:
                    continue
                extra = 1 if (k1 == 0) != (k2 == 0) else 0
                out = ntbl.setdefault(k, {})
                for m1, c1 in d1.items():
                    for m2, c2 in d2.items():
                        m = m1 + m2 + extra
                        out[m] = out.get(m, 0) + c1 * c2
        tbl = ntbl
        if h >= 10:
            results[h] = {k: dict(d) for k, d in tbl.items() if k >= 6}
    return results


def xmss_ns_per_comp(chains):
    """Calibrated M6 cost per compression for an XMSS tree build (including copy-back & Merkle)."""
    return 11.1 + 3.8 * (1024.0 / (chains + 1024.0))


def pors_ns_per_comp(leaves):
    """Calibrated M6 cost per compression for a PORS+FP tree build."""
    return 10.0 + 4.8 * (2048.0 / (leaves + 2048.0))


def _pareto3(items):
    items.sort()
    out = []
    for it in items:
        s, v = it[1], it[2]
        if any(o[1] <= s and o[2] <= v for o in out):
            continue
        out.append(it)
    return out


def _pareto4(items):
    items.sort()
    out = []
    for it in items:
        s, v, k = it[1], it[2], it[3]
        if any(o[1] <= s and o[2] <= v and o[3] <= k for o in out):
            continue
        out.append(it)
    return out


def build_candidates_4d(
    q, target_bits, cached_top, ns_grind, ns_ver_batch, ns_ver_scalar, sign_speedup, sign_cap_ms, max_top_height=16, keep_cold_axis=True
):
    """Build exact 4-D non-dominated candidates across uniform + all optimal irregular hypertrees (h_top <= max_top_height).

    By convexity of 2^x, for fixed (h, d, h_top), lower-layer signing work is uniquely minimized when the
    (d - 1) uncached lower layers differ in height by at most 1.
    """
    b_lo, b_hi = 10, 17
    k_cap = lambda h: 32 if h <= 12 else (20 if h == 13 else (16 if h <= 15 else 12))
    pors_dp = pors_merged_table(b_hi, k_cap)

    pors_cum = {}
    for b in range(b_lo, b_hi + 1):
        for k, dist in pors_dp[b].items():
            denom = (1 << b) ** k
            k_fact = math.factorial(k)
            cum = 0
            entries = []
            for m in sorted(dist):
                cum += dist[m]
                entries.append((m, (k_fact * cum) / denom))
            pors_cum[(b, k)] = entries

    wots_options = []
    for width in (2, 3, 4, 5, 6, 7, 8):
        max_digit = (1 << width) - 1
        for g in range(0, 11):
            rem = 128 - g
            if rem % width != 0:
                continue
            v = rem // width
            if not (12 <= v <= 64):
                continue
            dp = wots_sum_counts(v, width)
            total = 1 << 128
            mid = (v * max_digit) // 2
            seen_s = set()
            for budget in (0, 1000, 3000, 10_000, 30_000, 100_000):
                chosen_s = mid if budget == 0 else None
                if budget > 0:
                    for s in range(v * max_digit, mid - 1, -1):
                        if dp[s] > 0 and total / dp[s] <= budget:
                            chosen_s = s
                            break
                if chosen_s is None or chosen_s in seen_s:
                    continue
                wtries = total / dp[chosen_s]
                if wtries > 300_000:
                    continue
                seen_s.add(chosen_s)
                vsteps = v * max_digit - chosen_s
                pk_c = (16 + N * v + 63) // 64
                leaf_c = v + v * max_digit + pk_c
                wots_options.append((v, width, g, chosen_s, vsteps, wtries, leaf_c, pk_c))

    fts_by_h = {}
    for h in range(28, 49):
        fts_choices = []
        for (b, k), entries in pors_cum.items():
            if h + k * b > 256:
                continue
            for gf in range(0, 11):
                if gf + h + k * b > 256:
                    continue
                bits = security_bits(q, h, b, k, gf)
                if bits < target_bits:
                    continue
                seen_m = set()
                for cap in (1_000, 3_000, 10_000, 30_000, 100_000, 300_000):
                    for m, prob in entries:
                        ftries = (1 << gf) / prob
                        if ftries <= cap:
                            if m not in seen_m:
                                seen_m.add(m)
                                fts_choices.append((b, k, gf, m, ftries, bits))
                            break
                break
        fts_pruned = []
        for b, k, gf, m, ftries, bits in fts_choices:
            fts_bytes = 4 + N * (k + m)
            p_leaves = 1 << b
            fts_sign_ns = (3 * p_leaves - 1) * pors_ns_per_comp(p_leaves) + ftries * ns_grind
            fts_ver_ns = (k + (k + m - 1)) * ns_ver_batch + 2 * ns_ver_scalar
            fts_pruned.append((fts_bytes, fts_sign_ns, fts_ver_ns, b, k, gf, m, ftries, bits))
        fts_pruned.sort()
        fts_front = []
        for item in fts_pruned:
            if any(o[0] <= item[0] and o[1] <= item[1] and o[2] <= item[2] for o in fts_front):
                continue
            fts_front.append(item)
        fts_by_h[h] = fts_front

    ht_by_h = {}
    for h in range(28, 49):
        if not fts_by_h[h]:
            continue
        per_h = []
        for d in range(2, 13):
            h_top_lo = max(2, h // d)
            h_top_hi = min(max_top_height, h - (d - 1) * 2) if (cached_top and max_top_height > 0) else h // d
            for h_top in range(h_top_lo, h_top_hi + 1):
                rem = h - h_top
                low_base = rem // (d - 1)
                low_hi_cnt = rem % (d - 1)
                low_lo_cnt = (d - 1) - low_hi_cnt
                max_low = low_base + (1 if low_hi_cnt else 0)
                if max_low > 12 or h_top < max_low:
                    continue
                if max_top_height == 0 and (low_hi_cnt != 0 or h_top != low_base):
                    continue
                top_leaves = 1 << h_top
                l_lo = 1 << low_base
                l_hi = 1 << (low_base + 1)
                shape_pts = []
                for v, width, g, s_val, vsteps, wtries, leaf_c, pk_c in wots_options:
                    top_tree_c = top_leaves * (leaf_c + 1) - 1
                    ns_top = xmss_ns_per_comp(top_leaves * v)
                    keygen_ms = top_tree_c * ns_top / 1e6
                    t_lo_ns = (l_lo * (leaf_c + 1) - 1) * xmss_ns_per_comp(l_lo * v) if low_lo_cnt else 0.0
                    t_hi_ns = (l_hi * (leaf_c + 1) - 1) * xmss_ns_per_comp(l_hi * v) if low_hi_cnt else 0.0
                    sign_trees_ns = low_lo_cnt * t_lo_ns + low_hi_cnt * t_hi_ns
                    if not cached_top:
                        sign_trees_ns += top_tree_c * ns_top
                    top_extra_ns = (v + v * ((1 << width) - 1) // 2) * ns_ver_batch if cached_top else 0.0
                    ht_sign_ms = ((sign_trees_ns + top_extra_ns + d * wtries * ns_grind) / sign_speedup) / 1e6
                    if ht_sign_ms >= sign_cap_ms:
                        continue
                    ht_bytes = d * (4 + N * v) + N * h
                    ht_ver_us = (d * (vsteps * ns_ver_batch + (pk_c + 1) * ns_ver_scalar) + h * ns_ver_scalar) / 1e3
                    shape_pts.append((ht_bytes, ht_sign_ms, ht_ver_us, keygen_ms, d, h_top, low_base, low_hi_cnt, v, width, g, s_val, wtries))
                prune = _pareto4 if keep_cold_axis else _pareto3
                per_h.extend(prune(shape_pts))
        ht_by_h[h] = (_pareto4 if keep_cold_axis else _pareto3)(per_h)

    out = []
    for h, ht_list in ht_by_h.items():
        for fts_bytes, fts_sign_ns, fts_ver_ns, b, k, gf, m, ftries, bits in fts_by_h[h]:
            fs_ms = (fts_sign_ns / sign_speedup) / 1e6
            fv_us = (fts_ver_ns + 2 * ns_ver_scalar) / 1e3
            for ht_bytes, ht_sign_ms, ht_ver_us, keygen_ms, d, h_top, low_base, low_hi_cnt, v, width, g, s_val, wtries in ht_list:
                sign_ms = ht_sign_ms + fs_ms
                if sign_ms > sign_cap_ms:
                    continue
                total_bytes = 2 * N + fts_bytes + ht_bytes
                ver_us = ht_ver_us + fv_us
                cold_ms = sign_ms + (keygen_ms / sign_speedup if cached_top else 0.0)
                out.append(
                    {
                        "bytes": total_bytes,
                        "sign_ms": sign_ms,
                        "verify_us": ver_us,
                        "cold_ms": cold_ms,
                        "keygen_ms": keygen_ms,
                        "cache_kib": ((2 << h_top) - 1) * N / 1024.0,
                        "bits": bits,
                        "h": h,
                        "d": d,
                        "hp": low_base,
                        "low_hi_cnt": low_hi_cnt,
                        "h_top": h_top,
                        "v": v,
                        "width": width,
                        "g": g,
                        "S": s_val,
                        "b": b,
                        "k": k,
                        "gf": gf,
                        "m": m,
                        "ftries": ftries,
                        "wtries": wtries,
                    }
                )
    return out


def build_frontier(q, target_bits, cached_top, ns_grind, ns_ver_batch, ns_ver_scalar, sign_speedup, sign_cap_ms, max_top_height=0):
    raw_sets = build_candidates_4d(
        q, target_bits, cached_top, ns_grind, ns_ver_batch, ns_ver_scalar, sign_speedup, sign_cap_ms, max_top_height, keep_cold_axis=False
    )
    raw_sets.sort(key=lambda x: (x["bytes"], x["sign_ms"], x["verify_us"]))
    frontier = []
    for p in raw_sets:
        if any(q["bytes"] <= p["bytes"] and q["sign_ms"] <= p["sign_ms"] and q["verify_us"] <= p["verify_us"] for q in frontier):
            continue
        frontier.append(p)
    return frontier


def l2_log_regret(p, mins, weights=(1.0, 1.0, 1.0)):
    """Scale-free sum of squared log-ratios above achievable minima: sum w_i * (ln(x_i / min_i))^2."""
    return (
        weights[0] * math.log(p["bytes"] / mins[0]) ** 2
        + weights[1] * math.log(p["sign_ms"] / mins[1]) ** 2
        + weights[2] * math.log(p["verify_us"] / mins[2]) ** 2
    )


def score_survival(p, u_b, u_s, u_v):
    """Joint survival probability (up to a constant independent of L_i) under independent log-uniform unknown thresholds."""
    return math.log(u_b / p["bytes"]) * math.log(u_s / p["sign_ms"]) * math.log(u_v / p["verify_us"])


def score_minimax_risk(p, mins, ceilings):
    """Maximum conditional exclusion probability across the three dimensions."""
    return max(
        math.log(p["bytes"] / mins[0]) / math.log(ceilings[0] / mins[0]),
        math.log(p["sign_ms"] / mins[1]) / math.log(ceilings[1] / mins[1]),
        math.log(p["verify_us"] / mins[2]) / math.log(ceilings[2] / mins[2]),
    )


def fmt_shape(p):
    if p["low_hi_cnt"] == 0 and p["h_top"] == p["hp"]:
        return f"h={p['h']} ({p['d']}x{p['hp']})"
    low_lo_cnt = (p["d"] - 1) - p["low_hi_cnt"]
    parts = [str(p["h_top"])]
    if p["low_hi_cnt"]:
        parts.append(f"{p['low_hi_cnt']}x{p['hp']+1}" if p["low_hi_cnt"] > 1 else str(p["hp"] + 1))
    if low_lo_cnt:
        parts.append(f"{low_lo_cnt}x{p['hp']}" if low_lo_cnt > 1 else str(p["hp"]))
    return f"h={p['h']} ({'+'.join(parts)})"


def fmt_row(p, mins=None, show_cold=False):
    rat = ""
    if mins is not None:
        rat = f" | ratios=({p['bytes']/mins[0]:.2f}x, {p['sign_ms']/mins[1]:.2f}x, {p['verify_us']/mins[2]:.2f}x)"
    cold_str = f" | 1shot={p['cold_ms']:5.1f} ms | cache={p['cache_kib']:6.1f} KiB" if show_cold else ""
    return (
        f"{p['bytes']:5d} B | sign={p['sign_ms']:5.2f} ms | ver={p['verify_us']:5.1f} us | "
        f"kg={p['keygen_ms']:6.2f} ms{cold_str} | {p['bits']:6.2f} bits | "
        f"{fmt_shape(p)} v={p['v']} w={1<<p['width']} g={p['g']} S={p['S']} "
        f"b={p['b']} k={p['k']} gf={p['gf']} m={p['m']}{rat}"
    )


def run_grinding_sweep(ns_grind):
    dp = pors_merged_table(15, lambda _: 11)[15][11]
    denom = (1 << 15) ** 11
    k_fact = math.factorial(11)
    cum = 0
    t103 = None
    print("PORS+FP grinding sweep for BLINCS 0.1.0 (h=36, d=4, v=24, w=32, g=8, S=372, b=15, k=11, gf=6):")
    print(f"{'m':>4}  {'bytes':>6}  {'mean PICK tries':>15}  {'vs m=103':>9}  {'PICK ms':>9}  {'share of 16.2ms':>15}")
    for m in sorted(dp):
        cum += dp[m]
        if m in (95, 98, 100, 102, 103, 105, 108, 110, 112, 115, 120):
            tries = 64 * denom / (k_fact * cum)
            if m == 103:
                t103 = tries
            ratio = (t103 / tries) if t103 else 0.0
            pick_ms = tries * ns_grind / 1e6
            sig_b = 3988 + 16 * (m - 103)
            pct = 100.0 * pick_ms / (16.22 - 0.27 + pick_ms)
            print(f"{m:4d}  {sig_b:6d}  {tries:15.1f}  {ratio:8.1f}x  {pick_ms:8.3f}   {pct:14.2f}%")


def run_check():
    w_dp = wots_sum_counts(24, 5)
    assert w_dp[372] == 11649843293402856602335808320281824
    assert abs((1 << 128) / w_dp[372] - 29209.179759) < 1e-4

    p_dp = pors_merged_table(15, lambda _: 11)[15][11]
    a_103 = sum(c for m, c in p_dp.items() if m <= 103)
    assert a_103 == 3464703884785508537826703938971763834880
    tries_103 = 64 * ((1 << 15) ** 11) / (math.factorial(11) * a_103)
    assert abs(tries_103 - 21642.499566) < 1e-4

    bits = security_bits(1 << 33, 36, 15, 11, 6)
    assert abs(bits - 128.4433) < 1e-3, bits

    # Verify M6 calibration against actual measured BLINCS 0.1.0 (3,988 B: 16.22 ms sign, 4.43 ms keygen, 33.3 us verify)
    leaf_c = 24 + 24 * 31 + 7
    tree_c = 512 * (leaf_c + 1) - 1
    kg_ms = tree_c * xmss_ns_per_comp(512 * 24) / 1e6
    pors_ms = (3 * 32768 - 1) * pors_ns_per_comp(32768) / 1e6
    grind_ms = (tries_103 + 4 * ((1 << 128) / w_dp[372])) * 12.6 / 1e6
    sign_ms = 3 * kg_ms + pors_ms + grind_ms
    ver_us = ((4 * 372 + 11 + 113) * 18.5 + (4 * (7 + 1 + 9) + 4) * 45.0) / 1e3
    assert abs(kg_ms - 4.43) < 0.25, kg_ms
    assert abs(sign_ms - 16.22) < 0.50, sign_ms
    assert abs(ver_us - 33.3) < 1.5, ver_us
    print(
        f"CHECK PASSED: WOTS+C tries={((1<<128)/w_dp[372]):.2f}, PORS+FP tries={tries_103:.2f}, "
        f"security={bits:.2f} bits | M6 calibration: kg={kg_ms:.2f}ms (meas 4.43), "
        f"sign={sign_ms:.2f}ms (meas 16.22), ver={ver_us:.1f}us (meas 33.3)."
    )


def main():
    ap = argparse.ArgumentParser(description="Reproducible BLINCS parameter optimizer (calibrated on Apple M6).")
    ap.add_argument("--signatures", default="2^33")
    ap.add_argument("--security", type=float, default=128.0)
    ap.add_argument("--uncached", action="store_true", help="Count all d trees in signing time (no cached top tree)")
    ap.add_argument("--ns-grind", type=float, default=12.6, help="ns per counter-search compression (M6 measured: 12.59)")
    ap.add_argument("--ns-ver-batch", type=float, default=18.5, help="ns per batched on-core verify hash")
    ap.add_argument("--ns-ver-scalar", type=float, default=45.0, help="ns per scalar verify hash")
    ap.add_argument("--sign-speedup", type=float, default=1.0, help="Signing speedup factor (e.g. 3.0 for 8-core leaf parallelism)")
    ap.add_argument("--max-top-height", type=int, default=0, help="Allow irregular cached top tree up to this height (0 = uniform heights; e.g. 15 = 1 MiB cache)")
    ap.add_argument("--four-axis", action="store_true", help="Evaluate 4-axis minimax (bytes, cached sign, uncached 1-shot sign, verify) across uniform + irregular hypertrees")
    ap.add_argument("--sign-cap-ms", type=float, default=100.0)
    ap.add_argument("--ceilings", default="7856,100,1000", help="Upper ceilings U_B (bytes), U_S (ms), U_V (us)")
    ap.add_argument("--grinding-sweep", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.check:
        run_check()
        return 0
    if args.grinding_sweep:
        run_grinding_sweep(args.ns_grind)
        return 0

    t0 = time.perf_counter()
    q = parse_q(args.signatures)
    if args.four_axis:
        cap = args.max_top_height if args.max_top_height > 0 else 16
        cands = build_candidates_4d(
            q, args.security, not args.uncached, args.ns_grind, args.ns_ver_batch, args.ns_ver_scalar, args.sign_speedup, args.sign_cap_ms, cap
        )
        elapsed = time.perf_counter() - t0
        bmin = min(p["bytes"] for p in cands)
        smin = min(p["sign_ms"] for p in cands)
        vmin = min(p["verify_us"] for p in cands)
        cmin = min(p["cold_ms"] for p in cands)
        print(f"Budget: {args.signatures} ({q:,}) sigs, >= {args.security:.0f} bits | {len(cands):,} 4-D non-dominated candidates (h_top <= {cap}, {elapsed:.2f} s)")
        print(f"Global minima: B_min={bmin} B, S_min(cached)={smin:.2f} ms, 1shot_min={cmin:.2f} ms, V_min={vmin:.1f} us\n")
        print("=== Unconstrained 4-axis (Bytes, Cached sign, Uncached 1-shot sign, Verify) ===")
        for label, fn in [
            ("4-axis L2 (1, 1, 1, 1)", lambda p: math.log(p["bytes"]/bmin)**2 + math.log(p["sign_ms"]/smin)**2 + math.log(p["cold_ms"]/cmin)**2 + math.log(p["verify_us"]/vmin)**2),
            ("4-axis L_inf max(x/min)", lambda p: max(p["bytes"]/bmin, p["sign_ms"]/smin, p["cold_ms"]/cmin, p["verify_us"]/vmin)),
            ("4-axis L2 (B=1, S=0.5, 1shot=0.5, V=1)", lambda p: math.log(p["bytes"]/bmin)**2 + 0.5*math.log(p["sign_ms"]/smin)**2 + 0.5*math.log(p["cold_ms"]/cmin)**2 + math.log(p["verify_us"]/vmin)**2),
            ("4-axis L2 (B=4, S=0.5, 1shot=0.5, V=1)", lambda p: 4*math.log(p["bytes"]/bmin)**2 + 0.5*math.log(p["sign_ms"]/smin)**2 + 0.5*math.log(p["cold_ms"]/cmin)**2 + math.log(p["verify_us"]/vmin)**2),
            ("4-axis L2 (B=16, S=0.5, 1shot=0.5, V=1)", lambda p: 16*math.log(p["bytes"]/bmin)**2 + 0.5*math.log(p["sign_ms"]/smin)**2 + 0.5*math.log(p["cold_ms"]/cmin)**2 + math.log(p["verify_us"]/vmin)**2),
            ("4-axis L2 (B=25, S=0.5, 1shot=0.5, V=1)", lambda p: 25*math.log(p["bytes"]/bmin)**2 + 0.5*math.log(p["sign_ms"]/smin)**2 + 0.5*math.log(p["cold_ms"]/cmin)**2 + math.log(p["verify_us"]/vmin)**2),
        ]:
            best = min(cands, key=fn)
            print(f"  {label:<40} -> {fmt_row(best, show_cold=True)}")
        print("\n=== Effect of top-tree cache cap on 3-axis w=(16,1,1) ===")
        for label, pred in [
            ("Uniform (h_top == h_low)", lambda p: p["low_hi_cnt"] == 0 and p["h_top"] == p["hp"]),
            ("h_top <= 10 (<= 32 KiB)", lambda p: p["h_top"] <= 10),
            ("h_top <= 12 (<= 128 KiB)", lambda p: p["h_top"] <= 12),
            ("h_top <= 14 (<= 512 KiB)", lambda p: p["h_top"] <= 14),
            ("h_top <= 15 (<= 1 MiB)", lambda p: p["h_top"] <= 15),
        ]:
            sub = [p for p in cands if pred(p)]
            b3 = min(sub, key=lambda p: 16*math.log(p["bytes"]/bmin)**2 + math.log(p["sign_ms"]/smin)**2 + math.log(p["verify_us"]/vmin)**2)
            print(f"  3-axis {label:<24} -> {fmt_row(b3, show_cold=True)}")
        return 0

    frontier = build_frontier(
        q,
        args.security,
        not args.uncached,
        args.ns_grind,
        args.ns_ver_batch,
        args.ns_ver_scalar,
        args.sign_speedup,
        args.sign_cap_ms,
        args.max_top_height,
    )
    elapsed = time.perf_counter() - t0
    show_cold = args.max_top_height > 0
    mins = (min(p["bytes"] for p in frontier), min(p["sign_ms"] for p in frontier), min(p["verify_us"] for p in frontier))
    maxs = (max(p["bytes"] for p in frontier), max(p["sign_ms"] for p in frontier), max(p["verify_us"] for p in frontier))
    print(f"Budget: {args.signatures} ({q:,}) sigs, >= {args.security:.0f} bits | {len(frontier)} Pareto-optimal plain sets ({elapsed:.2f} s)")
    print(f"Frontier minima: B_min={mins[0]} B, S_min={mins[1]:.2f} ms, V_min={mins[2]:.1f} us")
    print(f"Frontier maxima: B_max={maxs[0]} B, S_max={maxs[1]:.2f} ms, V_max={maxs[2]:.1f} us")

    # 1. Scale-free zero-knob rules
    print("\n=== 1. Scale-free rules (no ceilings, no hand-tuned weights) ===")
    span_w = tuple(1.0 / (math.log(maxs[i] / mins[i]) ** 2) for i in range(3))
    rules = [
        ("L2 log-regret: sum (ln(x/min))^2", lambda p: l2_log_regret(p, mins)),
        ("L_inf minimax ratio: max(x/min)", lambda p: max(p["bytes"] / mins[0], p["sign_ms"] / mins[1], p["verify_us"] / mins[2])),
        ("Squared % excess: sum (x/min - 1)^2", lambda p: (p["bytes"] / mins[0] - 1) ** 2 + (p["sign_ms"] / mins[1] - 1) ** 2 + (p["verify_us"] / mins[2] - 1) ** 2),
        ("Span-normalized L2: sum (ln(x/min)/ln(max/min))^2", lambda p: l2_log_regret(p, mins, span_w)),
        ("Plain product: B * S * V  (trade whenever Y < X)", lambda p: math.log(p["bytes"]) + math.log(p["sign_ms"]) + math.log(p["verify_us"])),
    ]
    for label, fn in rules:
        best = min(frontier, key=fn)
        print(f"  {label:<52} -> {fmt_row(best, mins, show_cold)}")

    # 2. Size-weighted L2 log-regret sweep
    print("\n=== 2. Weighted L2 log-regret: w_B*(ln B/Bmin)^2 + (ln S/Smin)^2 + (ln V/Vmin)^2 ===")
    for wb in (1, 4, 8, 16, 32, 64):
        best = min(frontier, key=lambda p, w=wb: l2_log_regret(p, mins, (float(w), 1.0, 1.0)))
        print(f"  w=({wb:2d}, 1, 1) -> {fmt_row(best, mins, show_cold)}")

    # 3. Unknown application cutoffs (log-uniform up to upper ceilings)
    u_b, u_s, u_v = (float(x) for x in args.ceilings.split(","))
    print("\n=== 3. Unknown application cutoffs (log-uniform up to upper ceilings) ===")
    for label, (cb, cs, cv) in [
        (f"Max cutoffs = ({int(u_b)} B, {u_s:g} ms, {u_v:g} us)", (u_b, u_s, u_v)),
        ("Max cutoffs = (7856 B [SLH-DSA-128s], 100 ms, 127 us [128s-B3])", (7856.0, 100.0, 127.0)),
        ("Max cutoffs = (5000 B [compact], 100 ms, 1000 us)", (5000.0, 100.0, 1000.0)),
    ]:
        sub = [p for p in frontier if p["bytes"] < cb and p["sign_ms"] < cs and p["verify_us"] < cv]
        if not sub:
            continue
        s_mins = (min(p["bytes"] for p in sub), min(p["sign_ms"] for p in sub), min(p["verify_us"] for p in sub))
        best_surv = max(sub, key=lambda p: score_survival(p, cb, cs, cv))
        best_mm = min(sub, key=lambda p: score_minimax_risk(p, s_mins, (cb, cs, cv)))
        print(f"  {label}:")
        print(f"    Max survival: {fmt_row(best_surv, mins, show_cold)}")
        print(f"    Minimax risk: {fmt_row(best_mm, mins, show_cold)}")

    # 4. Reference comparison with BLINCS 0.1.0 and SLH-DSA-B (measured Apple M6, 1 core)
    print("\n=== 4. Comparison with BLINCS 0.1.0 and SLH-DSA-B (Apple M6, 1 thread, 64 B) ===")
    print(f"  SLH-DSA-BLAKE3-128s (2^64, FIPS 205) :  7856 B | sign=121.7 ms | ver=126.6 us | ratios=({7856/mins[0]:.2f}x, {121.7/mins[1]:.1f}x, {126.6/mins[2]:.1f}x)")
    print(f"  SLH-DSA-BLAKE3-128f (2^64, FIPS 205) : 17088 B | sign=  5.81 ms | ver=353.7 us | ratios=({17088/mins[0]:.2f}x, {5.81/mins[1]:.1f}x, {353.7/mins[2]:.1f}x)")
    print(f"  BLINCS 0.1.0        (2^33, measured) :  3988 B | sign= 16.22 ms | ver= 33.3 us | ratios=({3988/mins[0]:.2f}x, {16.22/mins[1]:.1f}x, {33.3/mins[2]:.1f}x)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

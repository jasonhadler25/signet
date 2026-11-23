#!/usr/bin/env python3
"""Reproducible, self-contained parameter optimizer for BLINCS (Python standard library only).

Computes exact integer retry counts (WOTS+C digit sums and PORS+FP merged authentication sets),
evaluates the PORS+FP + hypertree cover-probability security bound, builds the 3-D Pareto frontier
(signature bytes, signing time, verification time), and ranks points under the quantitative
unknown-thresholds model described in DESIGN.md.

Usage:
    python3 tools/optimize.py                       # default: 2^33 sigs, >= 128 bits, BLINCS M6 model
    python3 tools/optimize.py --ceilings 7856,100,1000
    python3 tools/optimize.py --ceilings 5000,100,1000
    python3 tools/optimize.py --sign-speedup 3.0    # e.g. multithreaded signing
    python3 tools/optimize.py --grinding-sweep      # m = 95..120 trade-off for BLINCS (b=15, k=11, gf=6)
    python3 tools/optimize.py --check               # verify exact integer DP counts and security bound
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
    lam = q / (1 << h)  # mean signatures hitting one hypertree leaf (Poisson approximates Binomial(q, 2^-h) tightly for q >> 1, 2^-h << 1)
    # Exact log Binomial(q, 2^-h) pmf via lgamma around the mode r = floor(lam).
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
        # Binomial pmf
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
        # Prefix sum sliding window in O(len(dp))
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
def pors_merged_table(b_max, k_max):
    """For every height b in 1..=b_max and subset size k in 1..=k_max, exact dict {m: subset_count}."""
    # tbl[k][m] = count of k-leaf subsets of a height-h perfect tree needing m auth nodes.
    tbl = {0: {0: 1}, 1: {0: 1}}
    results = {}
    for h in range(1, b_max + 1):
        ntbl = {}
        items = list(tbl.items())
        for k1, d1 in items:
            for k2, d2 in items:
                k = k1 + k2
                if k > k_max:
                    continue
                extra = 1 if (k1 == 0) != (k2 == 0) else 0
                out = ntbl.setdefault(k, {})
                for m1, c1 in d1.items():
                    for m2, c2 in d2.items():
                        m = m1 + m2 + extra
                        out[m] = out.get(m, 0) + c1 * c2
        tbl = ntbl
        if h >= 11:
            results[h] = {k: dict(d) for k, d in tbl.items() if k >= 6}
    return results


def build_frontier(q, target_bits, cached_top, ns_batch, ns_grind, ns_ver_batch, ns_ver_scalar, sign_speedup, sign_cap_ms):
    # Precompute exact PORS+FP merged-set cumulative probabilities for b in 11..=17, k in 6..=24.
    b_lo, b_hi, k_lo, k_hi = 11, 17, 6, 24
    pors_dp = pors_merged_table(b_hi, k_hi)
    # Build sorted list of (m, cum_valid_ordered_frac) per (b, k)
    pors_cum = {}
    for b in range(b_lo, b_hi + 1):
        for k in range(k_lo, k_hi + 1):
            dist = pors_dp[b].get(k)
            if not dist:
                continue
            denom = (1 << b) ** k
            k_fact = math.factorial(k)
            cum = 0
            entries = []
            for m in sorted(dist):
                cum += dist[m]
                # Probability an ordered k-tuple is distinct and has merged_len <= m
                prob = (k_fact * cum) / denom
                entries.append((m, prob))
            pors_cum[(b, k)] = entries

    # Precompute WOTS+C options for plain uniform chain lengths w = 2^width, v * width = 128 - g (g in 0..=10)
    wots_options = []
    for width in (3, 4, 5, 6, 7, 8):
        max_digit = (1 << width) - 1
        for g in range(0, 11):
            rem = 128 - g
            if rem % width != 0:
                continue
            v = rem // width
            if not (12 <= v <= 44):
                continue
            dp = wots_sum_counts(v, width)
            total = (1 << 128)
            mid = (v * max_digit) // 2
            # Include the midpoint and raised targets up to 10^5 tries/layer
            seen_budgets = set()
            for budget in (0, 1000, 3000, 10_000, 30_000, 100_000):
                chosen_s = None
                if budget == 0:
                    chosen_s = mid
                else:
                    for s in range(v * max_digit, mid - 1, -1):
                        if dp[s] > 0 and total / dp[s] <= budget:
                            chosen_s = s
                            break
                if chosen_s is None or chosen_s in seen_budgets:
                    continue
                wtries = total / dp[chosen_s]
                if wtries > 300_000:
                    continue
                seen_budgets.add(chosen_s)
                vsteps = v * max_digit - chosen_s
                pk_c = (16 + N * v + 63) // 64
                leaf_c = v + v * max_digit + pk_c
                wots_options.append((v, width, g, chosen_s, vsteps, wtries, leaf_c, pk_c))

    # Build candidate hypertrees (plain shapes: equal layer heights h = d * hp) and combine with PORS+FP
    raw_sets = []
    for d in range(3, 9):
        for hp in range(4, 12):
            h = d * hp
            if not (28 <= h <= 45):
                continue
            leaves = 1 << hp
            # Find valid PORS+FP tuples for this h
            fts_choices = []
            for b in range(b_lo, b_hi + 1):
                for k in range(k_lo, k_hi + 1):
                    if h + k * b > 256:
                        continue
                    for gf in range(0, 11):
                        if gf + h + k * b > 256:
                            continue
                        bits = security_bits(q, h, b, k, gf)
                        if bits < target_bits:
                            continue
                        # Smallest m for each retry cap (1e3 .. 1e6)
                        entries = pors_cum.get((b, k), [])
                        seen_m = set()
                        for cap in (1_000, 3_000, 10_000, 30_000, 100_000, 300_000):
                            for m, prob in entries:
                                ftries = (1 << gf) / prob
                                if ftries <= cap:
                                    if m not in seen_m:
                                        seen_m.add(m)
                                        fts_choices.append((b, k, gf, m, ftries, bits))
                                    break
                        break  # smallest gf that reaches target_bits for this (b, k) is dominant or check gf+1 too
            if not fts_choices:
                continue

            # Keep only Pareto-undominated few-time choices per h on (k+m, ftries + tree_cost, k+m)
            # Tree cost of PORS+FP: 3 * 2^b - 1 compressions
            fts_pruned = []
            for b, k, gf, m, ftries, bits in fts_choices:
                fts_bytes = 4 + N * (k + m)
                fts_sign_ns = (3 * (1 << b) - 1) * ns_batch + ftries * ns_grind
                fts_ver_ns = (k + (k + m - 1)) * ns_ver_batch + 2 * ns_ver_scalar
                fts_pruned.append((fts_bytes, fts_sign_ns, fts_ver_ns, b, k, gf, m, ftries, bits))
            fts_pruned.sort()
            fts_front = []
            for item in fts_pruned:
                if any(o[0] <= item[0] and o[1] <= item[1] and o[2] <= item[2] for o in fts_front):
                    continue
                fts_front.append(item)

            trees_built = (d - 1) if cached_top else d
            for v, width, g, s_val, vsteps, wtries, leaf_c, pk_c in wots_options:
                tree_c = leaves * (leaf_c + 1) - 1
                keygen_ms = tree_c * ns_batch / 1e6
                ht_bytes = d * (4 + N * v) + N * h
                # Top cached layer still hashes 24 chains (avg half steps) if cached_top
                top_extra_c = (v + v * ((1 << width) - 1) // 2) if cached_top else 0
                ht_sign_ns = ((trees_built * tree_c + top_extra_c) * ns_batch + d * wtries * ns_grind) / sign_speedup
                if ht_sign_ns / 1e6 >= sign_cap_ms:
                    continue
                ht_ver_ns = d * (vsteps * ns_ver_batch + (pk_c + 1 + hp) * ns_ver_scalar)
                for fts_bytes, fts_sign_ns, fts_ver_ns, b, k, gf, m, ftries, bits in fts_front:
                    total_bytes = 2 * N + fts_bytes + ht_bytes
                    total_sign_ms = (ht_sign_ns + fts_sign_ns / sign_speedup) / 1e6
                    if total_sign_ms > sign_cap_ms:
                        continue
                    total_ver_us = (ht_ver_ns + fts_ver_ns + 2 * ns_ver_scalar) / 1e3
                    raw_sets.append(
                        {
                            "bytes": total_bytes,
                            "sign_ms": total_sign_ms,
                            "verify_us": total_ver_us,
                            "keygen_ms": keygen_ms,
                            "bits": bits,
                            "h": h,
                            "d": d,
                            "hp": hp,
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

    # 3-D Pareto frontier on (bytes, sign_ms, verify_us)
    raw_sets.sort(key=lambda x: (x["bytes"], x["sign_ms"], x["verify_us"]))
    frontier = []
    for p in raw_sets:
        if any(q["bytes"] <= p["bytes"] and q["sign_ms"] <= p["sign_ms"] and q["verify_us"] <= p["verify_us"] for q in frontier):
            continue
        frontier.append(p)
    return frontier


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


def fmt_row(p):
    return (
        f"{p['bytes']:5d} B | sign={p['sign_ms']:5.2f} ms | ver={p['verify_us']:5.1f} us | "
        f"kg={p['keygen_ms']:4.2f} ms | {p['bits']:6.2f} bits | "
        f"h={p['h']} d={p['d']} v={p['v']} w={1<<p['width']} g={p['g']} S={p['S']} "
        f"b={p['b']} k={p['k']} gf={p['gf']} m={p['m']} (ft={p['ftries']:.0f}, wt={p['wtries']:.0f})"
    )


def run_grinding_sweep(ns_grind):
    dp = pors_merged_table(15, 11)[15][11]
    denom = (1 << 15) ** 11
    k_fact = math.factorial(11)
    cum = 0
    t103 = None
    print("PORS+FP grinding sweep for BLINCS (h=36, d=4, v=24, w=32, g=8, S=372, b=15, k=11, gf=6):")
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
    # Verify exact DP counts and BLINCS security bound
    w_dp = wots_sum_counts(24, 5)
    assert w_dp[372] == 11649843293402856602335808320281824
    assert abs((1 << 128) / w_dp[372] - 29209.179759) < 1e-4

    p_dp = pors_merged_table(15, 11)[15][11]
    a_103 = sum(c for m, c in p_dp.items() if m <= 103)
    assert a_103 == 3464703884785508537826703938971763834880
    tries_103 = 64 * ((1 << 15) ** 11) / (math.factorial(11) * a_103)
    assert abs(tries_103 - 21642.499566) < 1e-4

    bits = security_bits(1 << 33, 36, 15, 11, 6)
    assert abs(bits - 128.4433) < 1e-3, bits
    print(f"CHECK PASSED: WOTS+C tries={((1<<128)/w_dp[372]):.2f}, PORS+FP tries={tries_103:.2f}, security={bits:.2f} bits at 2^33.")


def main():
    ap = argparse.ArgumentParser(description="Reproducible BLINCS parameter optimizer under unknown thresholds.")
    ap.add_argument("--signatures", default="2^33")
    ap.add_argument("--security", type=float, default=128.0)
    ap.add_argument("--uncached", action="store_true", help="Count all d trees in signing time (no cached top tree)")
    ap.add_argument("--ns-batch", type=float, default=11.0, help="ns per batched compression in tree builds (M6 default: 11.0)")
    ap.add_argument("--ns-grind", type=float, default=12.6, help="ns per counter-search compression (M6 default: 12.6)")
    ap.add_argument("--ns-ver-batch", type=float, default=18.0, help="ns per batched on-core verify hash (M6 default: 18.0)")
    ap.add_argument("--ns-ver-scalar", type=float, default=45.0, help="ns per scalar verify hash (M6 default: 45.0)")
    ap.add_argument("--sign-speedup", type=float, default=1.0, help="Signing speedup factor (e.g. 3.0 for 8-core multithreading)")
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
    frontier = build_frontier(
        q,
        args.security,
        not args.uncached,
        args.ns_batch,
        args.ns_grind,
        args.ns_ver_batch,
        args.ns_ver_scalar,
        args.sign_speedup,
        args.sign_cap_ms,
    )
    elapsed = time.perf_counter() - t0
    u_b, u_s, u_v = (float(x) for x in args.ceilings.split(","))
    print(f"Budget: {args.signatures} ({q:,}) sigs, >= {args.security:.0f} bits | {len(frontier)} Pareto-optimal plain sets ({elapsed:.2f} s)")

    for label, (cb, cs, cv) in [
        (f"Requested ceilings U = ({cb_s(u_b)}, {u_s:g} ms, {u_v:g} us)", (u_b, u_s, u_v)),
        ("SLH-DSA-128s / 10-per-s / SLH-DSA-B-128s verify U = (7856 B, 100 ms, 127 us)", (7856.0, 100.0, 127.0)),
        ("Compact ceiling U = (5000 B, 100 ms, 1000 us)", (5000.0, 100.0, 1000.0)),
    ]:
        sub = [p for p in frontier if p["bytes"] < cb and p["sign_ms"] < cs and p["verify_us"] < cv]
        if not sub:
            print(f"\n{label}: no feasible sets")
            continue
        mins = (min(p["bytes"] for p in sub), min(p["sign_ms"] for p in sub), min(p["verify_us"] for p in sub))
        best_surv = max(sub, key=lambda p: score_survival(p, cb, cs, cv))
        best_mm = min(sub, key=lambda p: score_minimax_risk(p, mins, (cb, cs, cv)))
        print(f"\n=== {label} ({len(sub)} feasible) ===")
        print(f"  Max joint survival: {fmt_row(best_surv)}")
        print(f"  Minimax excl. risk: {fmt_row(best_mm)}")

    # Zero-external-parameter frontier minimax
    f_mins = (min(p["bytes"] for p in frontier), min(p["sign_ms"] for p in frontier), min(p["verify_us"] for p in frontier))
    f_maxs = (max(p["bytes"] for p in frontier), max(p["sign_ms"] for p in frontier), max(p["verify_us"] for p in frontier))
    best_zero = min(frontier, key=lambda p: score_minimax_risk(p, f_mins, f_maxs))
    print(f"\n=== Zero-parameter frontier log-minimax [{f_mins[0]}..{f_maxs[0]} B, {f_mins[1]:.2f}..{f_maxs[1]:.1f} ms, {f_mins[2]:.1f}..{f_maxs[2]:.1f} us] ===")
    print(f"  Minimax excl. risk: {fmt_row(best_zero)}")
    return 0


def cb_s(x):
    return f"{int(x)} B" if x == int(x) else f"{x:g} B"


if __name__ == "__main__":
    sys.exit(main())

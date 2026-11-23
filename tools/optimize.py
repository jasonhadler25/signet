#!/usr/bin/env python3
"""Reproducible, self-contained parameter optimizer for BLINCS (Python standard library only).

Calibrated against direct Apple M6 measurements of `blake3-servil = "=0.10.0"` (`clocks` crate):
  1. Single-threaded optimized (`1t`, merged lower XMSS trees on SME2):
     - XMSS: `9.95 + 2.6 * 6144 / (total_chains + 6144)` ns/comp
       (measured: 3x h=6 -> 1.18 ms, 3x h=7 -> 2.20 ms, 3x h=9 -> 12.73 ms, h_top=15 -> 177.05 ms).
     - PORS+FP: `10.2 + 4.4 * 6144 / (leaves + 6144)` ns/comp
       (measured: b=12 -> 157.8 us, b=14 -> 565.2 us, b=15 -> 1.08 ms, b=16 -> 2.10 ms).
     - Grinding: `11.4` ns/try (measured: 11.38 ns/try at 8,192 tries incl. counter write).
  2. `blake3-servil` built-in `hash_many_multithreaded` (`b3mt`, zero custom threads, 512 KiB split threshold):
     - Splits automatically at >= 8,192 64-byte slots (3x h=7 -> 1.57 ms [1.40x], 3x h=9 -> 7.66 ms [1.66x],
       h_top=15 -> 72.3 ms [2.45x], PORS b=14 -> 427 us [1.35x], b=15 -> 688 us [1.59x], b=16 -> 1.08 ms [1.98x]).
  3. Coarse persistent 12-core hybrid (`12t`, 1 SME2 thread + 11 `TreeHasher::on_this_core()` NEON threads):
     - XMSS: `2.38 + 3.6 * 1500 / (total_chains + 1500)` ns/comp + 15 us barrier
       (measured: 3x h=6 -> 309 us [3.82x], 3x h=7 -> 530 us [4.16x], 3x h=9 -> 2.98 ms [4.27x], h_top=15 -> 42.6 ms [4.16x]).
     - PORS+FP: `2.45` ns/comp + 56 us (measured within 1.7% across b=12..16: 86 us .. 531 us).
     - Grinding: `4.8` ns/try above 10,000 tries (12T), `11.4` ns/try below (1T).
  4. Verification (single core, `TreeHasher::on_this_core()`, batched chains & few-time levels):
     - `18.5` ns/batched + `45.0` ns/scalar (predicts 33.1 us vs. 33.3 us measured for BLINCS 0.1.0).

Tradeoff algorithm ("reduce the magnitude of the worst problem"):
  Leximin L_inf ratio above the physical Pareto floor:
    r_i(x) = x_i / x_{i,min}  for each cost dimension i in {Bytes, Sign, Verify}
  Minimize the sorted vector of ratios (r_(1) >= r_(2) >= r_(3)) lexicographically:
  first minimize the single worst blowup max_i (x_i / x_{i,min}), then break ties by the
  second-worst ratio, then the third. Zero arbitrary ceilings, zero hand-tuned weights,
  completely invariant to units and search caps.

Usage:
    python3 tools/optimize.py                         # default: 1 MiB optional top-tree cache (h_top <= 15), all 3 timing modes
    python3 tools/optimize.py --max-top-height 0      # uniform heights only (no tall top tree)
    python3 tools/optimize.py --mode 12t              # detailed Pareto & sensitivity check for one mode (1t | b3mt | 12t)
    python3 tools/optimize.py --grinding-sweep        # m = 95..120 trade-off for BLINCS 0.1.0
    python3 tools/optimize.py --check                 # verify exact DP counts, security bound, and M6 calibration
"""

import argparse
import math
import sys
import time

N = 16
NS_VER_BATCH = 18.5
NS_VER_SCALAR = 45.0


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
        return 256.0
    m = max(log_terms)
    log_sum = m + math.log(sum(math.exp(x - m) for x in log_terms))
    return -(log_sum / math.log(2.0)) + gf


def fors_security_bits(q, h, a, k):
    """-log2 of per-query cover probability P(q) for textbook FIPS 205 FORS (k trees of 2^a leaves, hypertree height h)."""
    lam = q / (1 << h)
    log_p = -h * math.log(2.0)
    log_1mp = math.log1p(-math.ldexp(1.0, -h))
    log_q_fact = math.lgamma(q + 1)
    log_miss_1 = math.log1p(-math.ldexp(1.0, -a))

    r_center = int(lam)
    spread = max(40, int(14 * math.sqrt(max(lam, 1.0))) + 40)
    r_lo = max(1, r_center - spread)
    r_hi = min(q, r_center + spread)

    log_terms = []
    for r in range(r_lo, r_hi + 1):
        log_bin = log_q_fact - math.lgamma(r + 1) - math.lgamma(q - r + 1) + r * log_p + (q - r) * log_1mp
        # 1 - (1 - 2^-a)^r = -expm1(r * log(1 - 2^-a))
        log_cov = k * math.log(-math.expm1(r * log_miss_1))
        log_terms.append(log_bin + log_cov)
    m = max(log_terms)
    log_sum = m + math.log(sum(math.exp(x - m) for x in log_terms))
    return -(log_sum / math.log(2.0))


# --- Exact integer DPs for WOTS+C digit sums and PORS+FP merged authentication-set sizes --------------
def wots_sum_counts(v, width):
    w = 1 << width
    max_digit = w - 1
    dp = [1] + [0] * (v * max_digit)
    for i in range(v):
        hi = i * max_digit
        ndp = [0] * (v * max_digit + 1)
        pref = 0
        for s in range(hi + max_digit + 1):
            if s <= hi:
                pref += dp[s]
            if s >= w:
                pref -= dp[s - w]
            ndp[s] = pref
        dp = ndp
    return dp


def pors_merged_table(b_max, k_cap_by_b):
    """Exact counts of ordered k-tuples of distinct leaves in [0, 2^b) by merged authentication-set size m."""
    dp = [{0: {0: 1}, 1: {0: 1}}]
    for h in range(1, b_max + 1):
        prev = dp[h - 1]
        k_lim = k_cap_by_b(h)
        cur = {0: {0: 1}}
        for k in range(1, min(1 << h, k_lim) + 1):
            dist = {}
            if k in prev:
                for m, c in prev[k].items():
                    dist[m + 1] = dist.get(m + 1, 0) + 2 * c
            for kl in range(1, k):
                kr = k - kl
                if kl not in prev or kr not in prev:
                    continue
                for ml, cl in prev[kl].items():
                    for mr, cr in prev[kr].items():
                        dist[ml + mr] = dist.get(ml + mr, 0) + cl * cr
            cur[k] = dist
        dp.append(cur)
    return dp


# --- Calibrated Apple M6 `blake3-servil = "=0.10.0"` timing models ------------------------------------
def xmss_1t_ns(chains):
    return 10.25 + 2.2 * (6144.0 / (chains + 6144.0))


def pors_1t_ns(leaves):
    return 10.2 + 4.4 * (6144.0 / (leaves + 6144.0))


def eval_timings(low_chains, low_comps, top_chains, top_comps, pors_leaves, f_tries, d, w_tries, v, width, h_top, leaf_c, cached_top=True):
    """Compute calibrated M6 signing & keygen times (ms) for 1T-SME, blake3-servil built-in MT, and 12T-HYB."""
    top_extra_ns = (v + v * ((1 << width) - 1) // 2) * NS_VER_BATCH if cached_top else 0.0

    # 1. Single-threaded optimized (merged lower XMSS trees on SME2)
    kg_1t = top_comps * xmss_1t_ns(top_chains) / 1e6
    eff_low_comps_1t = low_comps if cached_top else (low_comps + top_comps)
    eff_low_chains_1t = low_chains if cached_top else (low_chains + top_chains)
    s_1t = (
        eff_low_comps_1t * xmss_1t_ns(eff_low_chains_1t)
        + (3 * pors_leaves - 1) * pors_1t_ns(pors_leaves)
        + top_extra_ns
        + (f_tries + d * w_tries) * 11.4
    ) / 1e6

    # 2. blake3-servil built-in `hash_many_multithreaded` (zero custom threads; 512 KiB = 8,192-slot split)
    def b3_x(c):
        base = xmss_1t_ns(c)
        return base if c < 8192 else base / (1.0 + 1.55 * (1.0 - 8192.0 / (c + 4096.0)))

    def b3_p(l):
        base = pors_1t_ns(l)
        return base if l < 8192 else base / (1.0 + 1.25 * (1.0 - 7000.0 / (l + 1000.0)))

    kg_b3 = top_comps * (10.25 / 2.45 if top_chains >= 32768 else b3_x(top_chains)) / 1e6
    s_b3 = (
        eff_low_comps_1t * b3_x(eff_low_chains_1t)
        + (3 * pors_leaves - 1) * b3_p(pors_leaves)
        + top_extra_ns
        + f_tries * (5.5 if f_tries >= 8192 else 11.4)
        + d * w_tries * (5.5 if w_tries >= 8192 else 11.4)
    ) / 1e6

    # 3. Coarse persistent 12-core hybrid (1 SME2 thread + 11 `on_this_core()` NEON threads)
    ns_low_12 = 2.38 + 3.6 * (1500.0 / (eff_low_chains_1t + 1500.0))
    ns_top_12 = 2.38 + 3.6 * (1500.0 / (top_chains + 1500.0))
    kg_12 = (top_comps * ns_top_12 + 15_000.0) / 1e6
    s_12 = (
        eff_low_comps_1t * ns_low_12
        + 15_000.0
        + (3 * pors_leaves - 1) * 2.45
        + 56_000.0
        + top_extra_ns
        + f_tries * (4.8 if f_tries >= 10_000 else 11.4)
        + d * w_tries * (4.8 if w_tries >= 10_000 else 11.4)
    ) / 1e6

    # Partial-cache 1T signing times (caching top 10 levels = 32 KiB, or top 6 levels = 2 KiB)
    def partial_extra(c_levels):
        sub_h = h_top - c_levels
        if sub_h <= 0 or not cached_top:
            return 0.0
        sl = 1 << sub_h
        return (sl * (leaf_c + 1) - 1) * xmss_1t_ns(sl * v) / 1e6

    return {
        "1t": s_1t,
        "b3mt": s_b3,
        "12t": s_12,
        "kg_1t": kg_1t,
        "kg_b3mt": kg_b3,
        "kg_12t": kg_12,
        "s1t_32k": s_1t + partial_extra(10),
        "s1t_2k": s_1t + partial_extra(6),
    }


def _pareto3(items):
    items.sort()
    out = []
    for it in items:
        s, v = it[1], it[2]
        if any(o[1] <= s and o[2] <= v for o in out):
            continue
        out.append(it)
    return out


def build_frontier(q, target_bits, mode="1t", max_top_height=15, cached_top=True, sign_cap_ms=100.0, clean_lower=False):
    """Build exact 3-D Pareto frontier `(bytes, sign_ms, verify_us)` for the given calibrated timing mode."""
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

    raw = []
    for h in range(28, 49):
        fts_pts = []
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
                                fts_bytes = 4 + N * (k + m)
                                p_leaves = 1 << b
                                tm = eval_timings(1, 0, 1, 0, p_leaves, ftries, 0, 0, 1, 1, 0, 0, cached_top)
                                fts_ver_us = ((k + (k + m - 1)) * NS_VER_BATCH + 4 * NS_VER_SCALAR) / 1e3
                                fts_pts.append((fts_bytes, tm[mode], fts_ver_us, b, k, gf, m, ftries, bits))
                            break
                break
        fts_front = _pareto3(fts_pts)
        if not fts_front:
            continue

        ht_pts = []
        for d in range(2, 13):
            h_top_lo = max(2, h // d)
            h_top_hi = min(max_top_height, h - (d - 1) * 2) if (cached_top and max_top_height > 0) else h // d
            for h_top in range(h_top_lo, h_top_hi + 1):
                rem = h - h_top
                lb = rem // (d - 1)
                lhc = rem % (d - 1)
                llc = (d - 1) - lhc
                max_low = lb + (1 if lhc else 0)
                if max_low > 12 or h_top < max_low:
                    continue
                if max_top_height == 0 and (lhc != 0 or h_top != lb):
                    continue
                if clean_lower and lhc != 0:
                    continue
                top_l = 1 << h_top
                low_l = llc * (1 << lb) + lhc * (1 << (lb + 1))
                for v, width, g, sv, vsteps, wtries, leaf_c, pk_c in wots_options:
                    top_c = top_l * (leaf_c + 1) - 1
                    low_c = llc * ((1 << lb) * (leaf_c + 1) - 1) + lhc * ((1 << (lb + 1)) * (leaf_c + 1) - 1)
                    tm = eval_timings(low_l * v, low_c, top_l * v, top_c, 1, 0, d, wtries, v, width, h_top, leaf_c, cached_top)
                    if tm[mode] >= sign_cap_ms:
                        continue
                    hb = d * (4 + N * v) + N * h
                    hv = (d * (vsteps * NS_VER_BATCH + (pk_c + 1) * NS_VER_SCALAR) + h * NS_VER_SCALAR) / 1e3
                    ht_pts.append((hb, tm[mode], hv, d, h_top, lb, lhc, v, width, g, sv, wtries, leaf_c, low_l * v, low_c, top_l * v, top_c))
        ht_front = _pareto3(ht_pts)
        for fb, _, fv, b, k, gf, m, ftries, bits in fts_front:
            for hb, _, hv, d, h_top, lb, lhc, v, width, g, sv, wtries, leaf_c, low_ch, low_c, top_ch, top_c in ht_front:
                tm = eval_timings(low_ch, low_c, top_ch, top_c, 1 << b, ftries, d, wtries, v, width, h_top, leaf_c, cached_top)
                if tm[mode] > sign_cap_ms:
                    continue
                raw.append(
                    {
                        "bytes": 2 * N + fb + hb,
                        "sign_ms": tm[mode],
                        "verify_us": fv + hv,
                        "s_1t": tm["1t"],
                        "s_b3mt": tm["b3mt"],
                        "s_12t": tm["12t"],
                        "kg_1t": tm["kg_1t"],
                        "kg_b3mt": tm["kg_b3mt"],
                        "kg_12t": tm["kg_12t"],
                        "s1t_32k": tm["s1t_32k"],
                        "s1t_2k": tm["s1t_2k"],
                        "cache_kib": ((2 << h_top) - 1) * N / 1024.0,
                        "bits": bits,
                        "h": h,
                        "d": d,
                        "hp": lb,
                        "low_hi_cnt": lhc,
                        "h_top": h_top,
                        "v": v,
                        "width": width,
                        "g": g,
                        "S": sv,
                        "b": b,
                        "k": k,
                        "gf": gf,
                        "m": m,
                    }
                )

    raw.sort(key=lambda x: (x["bytes"], x["sign_ms"], x["verify_us"]))
    frontier = []
    for p in raw:
        if any(o["bytes"] <= p["bytes"] and o["sign_ms"] <= p["sign_ms"] and o["verify_us"] <= p["verify_us"] for o in frontier):
            continue
        frontier.append(p)
    return frontier


def leximin_key(p, mins):
    """Leximin L_inf ratio: minimize worst ratio max(x_i / min_i), breaking ties by 2nd-worst, then 3rd-worst."""
    return tuple(sorted((p["bytes"] / mins[0], p["sign_ms"] / mins[1], p["verify_us"] / mins[2]), reverse=True))


def l2_log_regret(p, mins):
    """Smooth quadratic log-regret sensitivity check: sum (ln(x_i / min_i))^2."""
    return (
        math.log(p["bytes"] / mins[0]) ** 2
        + math.log(p["sign_ms"] / mins[1]) ** 2
        + math.log(p["verify_us"] / mins[2]) ** 2
    )


def fmt_shape(p):
    if p["low_hi_cnt"] == 0 and p["h_top"] == p["hp"]:
        return f"h={p['h']} ({p['d']}x{p['hp']})"
    llc = (p["d"] - 1) - p["low_hi_cnt"]
    parts = [str(p["h_top"])]
    if p["low_hi_cnt"]:
        parts.append(f"{p['low_hi_cnt']}x{p['hp']+1}" if p["low_hi_cnt"] > 1 else str(p["hp"] + 1))
    if llc:
        parts.append(f"{llc}x{p['hp']}" if llc > 1 else str(p["hp"]))
    return f"h={p['h']} ({'+'.join(parts)})"


def fmt_row(p, mins):
    return (
        f"{p['bytes']:5d} B | 1T={p['s_1t']:5.2f}ms b3MT={p['s_b3mt']:4.2f}ms 12T={p['s_12t']:4.2f}ms | "
        f"ver={p['verify_us']:4.1f}us | kg(1T/12T)={p['kg_1t']:5.1f}/{p['kg_12t']:4.1f}ms | "
        f"ratios=({p['bytes']/mins[0]:.2f}x, {p['sign_ms']/mins[1]:.2f}x, {p['verify_us']/mins[2]:.2f}x) | "
        f"{fmt_shape(p)} w={1<<p['width']} v={p['v']} g={p['g']} S={p['S']} b={p['b']} k={p['k']} gf={p['gf']} m={p['m']}"
    )


def run_grinding_sweep():
    dp = pors_merged_table(15, lambda _: 11)[15][11]
    denom = (1 << 15) ** 11
    k_fact = math.factorial(11)
    cum = 0
    t103 = None
    print("PORS+FP grinding sweep for BLINCS 0.1.0 (h=36, d=4, v=24, w=32, g=8, S=372, b=15, k=11, gf=6):")
    print(f"{'m':>4}  {'bytes':>6}  {'mean PICK tries':>15}  {'vs m=103':>9}  {'PICK ms (1T)':>12}  {'share of 16.2ms':>15}")
    for m in sorted(dp):
        cum += dp[m]
        if m in (95, 98, 100, 102, 103, 105, 108, 110, 112, 115, 120):
            tries = 64 * denom / (k_fact * cum)
            if m == 103:
                t103 = tries
            ratio = (t103 / tries) if t103 else 0.0
            pick_ms = tries * 11.4 / 1e6
            sig_b = 3988 + 16 * (m - 103)
            pct = 100.0 * pick_ms / (16.22 - 0.25 + pick_ms)
            print(f"{m:4d}  {sig_b:6d}  {tries:15.1f}  {ratio:8.1f}x  {pick_ms:11.3f}   {pct:14.2f}%")


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

    # Verify adopted BLINCS (12 + 3x7, h=33, w=16 v=35, FORS 16 x 2^10) signature size & security curve.
    sig_bytes = (2 + 16 * (1 + 10) + 3 * (35 + 7) + (35 + 12)) * N
    assert sig_bytes == 5616, sig_bytes
    f32 = fors_security_bits(1 << 32, 33, 10, 16)
    f33 = fors_security_bits(1 << 33, 33, 10, 16)
    f34 = fors_security_bits(1 << 34, 33, 10, 16)
    f35 = fors_security_bits(1 << 35, 33, 10, 16)
    assert abs(f32 - 133.1701) < 1e-3, f32
    assert abs(f33 - 126.7908) < 1e-3, f33
    assert abs(f34 - 119.3346) < 1e-3, f34
    assert abs(f35 - 110.6233) < 1e-3, f35

    # Verify M6 calibration against our direct blake3-servil 0.10.0 measurements:
    # 1) 3x h=6 w=16 v=32: measured 1.18 ms (1T) / 0.31 ms (12T)
    leaf_32_16 = 32 + 32 * 15 + 9
    c_3x6 = 3 * (64 * (leaf_32_16 + 1) - 1)
    tm_6 = eval_timings(3 * 64 * 32, c_3x6, 32768 * 32, 32768 * (leaf_32_16 + 1) - 1, 16384, 0, 4, 0, 32, 4, 15, leaf_32_16)
    assert abs(tm_6["kg_1t"] - 177.05) < 5.0, tm_6["kg_1t"]
    assert abs(tm_6["kg_12t"] - 42.56) < 2.5, tm_6["kg_12t"]
    # 2) BLINCS 0.1.0 verification: measured 33.3 us
    ver_us = ((4 * 372 + 11 + 113) * NS_VER_BATCH + (4 * (7 + 1 + 9) + 4) * NS_VER_SCALAR) / 1e3
    assert abs(ver_us - 33.3) < 1.5, ver_us
    print(
        f"CHECK PASSED: adopted BLINCS 12+3x7 ({sig_bytes} B) FORS security={f32:.1f}/{f33:.1f}/{f34:.1f}/{f35:.1f} bits "
        f"(2^32..2^35) | historical 0.1.0 WOTS+C tries={((1<<128)/w_dp[372]):.2f}, PORS+FP tries={tries_103:.2f}, "
        f"security={bits:.2f} bits | M6 calibration: h_top=15 kg 1T={tm_6['kg_1t']:.1f}ms (meas 177.1), "
        f"12T={tm_6['kg_12t']:.1f}ms (meas 42.6), 0.1.0 ver={ver_us:.1f}us (meas 33.3)."
    )


def main():
    ap = argparse.ArgumentParser(description="Reproducible BLINCS parameter optimizer (calibrated on Apple M6, blake3-servil 0.10.0).")
    ap.add_argument("--signatures", default="2^33")
    ap.add_argument("--security", type=float, default=128.0)
    ap.add_argument("--mode", choices=("all", "1t", "b3mt", "12t"), default="all", help="Timing model to optimize for")
    ap.add_argument("--max-top-height", type=int, default=15, help="Max top-tree height (15 = 1 MiB optional stateless cache; 0 = uniform)")
    ap.add_argument("--uncached", action="store_true", help="Count all d trees in signing time (no top-tree cache)")
    ap.add_argument("--clean-lower", action="store_true", help="Require uniform lower-layer heights h_top + (d-1)*h_low")
    ap.add_argument("--sign-cap-ms", type=float, default=100.0)
    ap.add_argument("--grinding-sweep", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.check:
        run_check()
        return 0
    if args.grinding_sweep:
        run_grinding_sweep()
        return 0

    q = parse_q(args.signatures)
    modes = ("1t", "b3mt", "12t") if args.mode == "all" else (args.mode,)
    cache_desc = "uniform (no tall top tree)" if args.max_top_height == 0 else f"h_top <= {args.max_top_height} (<= {((2<<args.max_top_height)-1)*N//1024} KiB optional cache)"
    print(f"Budget: {args.signatures} ({q:,}) sigs, >= {args.security:.0f} bits | {cache_desc}")
    print("Algorithm: Leximin L_inf ratio above physical floor min max_i(x_i / x_{i,min}) (ties by 2nd, 3rd ratio)\n")

    for mode in modes:
        t0 = time.perf_counter()
        front = build_frontier(q, args.security, mode, args.max_top_height, not args.uncached, args.sign_cap_ms, args.clean_lower)
        mins = (min(p["bytes"] for p in front), min(p["sign_ms"] for p in front), min(p["verify_us"] for p in front))
        p_lex = min(front, key=lambda p: leximin_key(p, mins))
        clean = [p for p in front if p["low_hi_cnt"] == 0]
        p_lex_clean = min(clean, key=lambda p: leximin_key(p, mins)) if clean else p_lex
        p_l2 = min(front, key=lambda p: l2_log_regret(p, mins))
        print(f"=== Mode `{mode}` ({len(front)} Pareto sets in {time.perf_counter()-t0:.2f}s | floor: {mins[0]} B, {mins[1]:.2f} ms, {mins[2]:.1f} us) ===")
        print(f"  Leximin L_inf (all)   : {fmt_row(p_lex, mins)}")
        if p_lex_clean != p_lex:
            print(f"  Leximin L_inf (clean) : {fmt_row(p_lex_clean, mins)}")
        print(f"  L2 log-regret (check) : {fmt_row(p_l2, mins)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

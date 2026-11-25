#!/usr/bin/env python3
"""Reproducible single-threaded parameter optimizer and FORS security checker for BLINCS (stdlib only).

Calibrated against direct Apple M6 single-core measurements of `blake3-servil-core = "=0.11.0"`
(`clocks` crate, 0% E-cores):
  - Top tree (`h_top = 12`, 4,096 WOTS+ leaves): 20.53 ms (`~8.7 ns/comp` on 1-core SME2 batching)
  - Lower trees + FORS (`3 x h=7` + `16 x 2^10` FORS): 2.54 ms (`~9.4 ns/comp` average incl. FORS)
  - Verification (1 core, `TreeHasher::on_this_core()`, batched chains & FORS levels): 21.3 us

Usage:
    python3 tools/optimize.py                    # single-threaded WOTS+ + FORS Pareto & Leximin L_inf
    python3 tools/optimize.py --max-top-height 0 # uniform hypertree heights only
    python3 tools/optimize.py --check            # verify BLINCS 12+3x7 size, FORS curve, and 1T calibration
"""

import argparse
import math
import sys

N = 16
NS_TREE_1T = 8.70
NS_FORS_1T = 10.60
NS_VER_BATCH = 14.5
NS_VER_SCALAR = 35.0


def parse_q(s):
    if "^" in s:
        a, b = s.split("^", 1)
        return int(a) ** int(b)
    return int(s)


def fors_security_bits(q, h, a, k):
    """-log2 of single-query FORS leaf-cover probability P(q) under ideal hashes (k trees of 2^a leaves, height h)."""
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
        log_cov = k * math.log(-math.expm1(r * log_miss_1))
        log_terms.append(log_bin + log_cov)
    m = max(log_terms)
    log_sum = m + math.log(sum(math.exp(x - m) for x in log_terms))
    return -(log_sum / math.log(2.0))


def wots_params(width):
    w = 1 << width
    msg_chains = (N * 8 + width - 1) // width
    max_csum = msg_chains * (w - 1)
    csum_chains = 0
    cap = 1
    while cap <= max_csum:
        cap *= w
        csum_chains += 1
    chains = msg_chains + csum_chains
    pk_blocks = (16 + N * chains + 63) // 64
    leaf_comps = chains + chains * (w - 1) + pk_blocks
    avg_steps = chains * (w - 1) / 2.0
    return w, chains, pk_blocks, leaf_comps, avg_steps


def eval_candidate(h_top, d, h_low, width, a, k, cached_top=True):
    h = h_top + (d - 1) * h_low
    w, chains, pk_blocks, leaf_comps, avg_steps = wots_params(width)
    sig_bytes = (2 + k * (1 + a) + d * chains + h) * N
    top_comps = (1 << h_top) * (leaf_comps + 1) - 1
    low_comps = (d - 1) * ((1 << h_low) * (leaf_comps + 1) - 1)
    fors_comps = k * (3 * (1 << a) - 1) + (16 + N * k + 63) // 64
    layer_sign_comps = d * (chains + avg_steps)

    keygen_ms = top_comps * NS_TREE_1T / 1e6
    sign_comps = low_comps if cached_top else (low_comps + top_comps)
    sign_ms = (sign_comps * NS_TREE_1T + fors_comps * NS_FORS_1T + layer_sign_comps * NS_VER_BATCH) / 1e6
    ver_us = ((k * (1 + a) + d * avg_steps) * NS_VER_BATCH + (d * (pk_blocks + h_low) + (h_top - h_low) + 4) * NS_VER_SCALAR) / 1e3
    return {
        "bytes": sig_bytes,
        "sign_ms": sign_ms,
        "verify_us": ver_us,
        "keygen_ms": keygen_ms,
        "top_kib": ((2 << h_top) * N) / 1024.0,
        "h": h,
        "h_top": h_top,
        "d": d,
        "h_low": h_low,
        "w": w,
        "chains": chains,
        "a": a,
        "k": k,
    }


def build_frontier(q, target_bits, max_top_height=12, cached_top=True, sign_cap_ms=50.0):
    raw = []
    for d in range(2, 9):
        for h_low in range(3, 11):
            h_top_lo = h_low if max_top_height > 0 else h_low
            h_top_hi = max_top_height if (cached_top and max_top_height > 0) else h_low
            for h_top in range(h_top_lo, h_top_hi + 1):
                h = h_top + (d - 1) * h_low
                if not (28 <= h <= 44):
                    continue
                for a in range(6, 15):
                    for k in range(8, 33):
                        if h + a * k > 256:
                            continue
                        bits = fors_security_bits(q, h, a, k)
                        if bits < target_bits:
                            continue
                        for width in (3, 4, 5):
                            c = eval_candidate(h_top, d, h_low, width, a, k, cached_top)
                            if c["sign_ms"] <= sign_cap_ms:
                                c["bits"] = bits
                                raw.append(c)
                        break

    raw.sort(key=lambda x: (x["bytes"], x["sign_ms"], x["verify_us"]))
    front = []
    for p in raw:
        if any(o["bytes"] <= p["bytes"] and o["sign_ms"] <= p["sign_ms"] and o["verify_us"] <= p["verify_us"] for o in front):
            continue
        front.append(p)
    return front


def leximin_key(p, mins):
    return tuple(sorted((p["bytes"] / mins[0], p["sign_ms"] / mins[1], p["verify_us"] / mins[2]), reverse=True))


def run_check():
    c = eval_candidate(12, 4, 7, 4, 10, 16, cached_top=True)
    assert c["bytes"] == 5616, c["bytes"]
    f32 = fors_security_bits(1 << 32, 33, 10, 16)
    f33 = fors_security_bits(1 << 33, 33, 10, 16)
    f34 = fors_security_bits(1 << 34, 33, 10, 16)
    f35 = fors_security_bits(1 << 35, 33, 10, 16)
    assert abs(f32 - 133.1701) < 1e-3, f32
    assert abs(f33 - 126.7908) < 1e-3, f33
    assert abs(f34 - 119.3346) < 1e-3, f34
    assert abs(f35 - 110.6233) < 1e-3, f35
    assert abs(c["keygen_ms"] - 20.53) < 1.5, c["keygen_ms"]
    assert abs(c["sign_ms"] - 2.54) < 0.35, c["sign_ms"]
    assert abs(c["verify_us"] - 21.3) < 2.5, c["verify_us"]
    print(
        f"CHECK PASSED: BLINCS 12+3x7 ({c['bytes']} B, {c['top_kib']:.0f} KiB top tree) | "
        f"FORS single-query cover={f32:.1f}/{f33:.1f}/{f34:.1f}/{f35:.1f} bits (2^32..2^35) | "
        f"1-core M6 model: keygen={c['keygen_ms']:.2f}ms (meas 20.53), sign={c['sign_ms']:.2f}ms (meas 2.54), "
        f"verify={c['verify_us']:.1f}us (meas 21.3)."
    )


def main():
    ap = argparse.ArgumentParser(description="BLINCS single-threaded WOTS+ + FORS parameter optimizer (Apple M6, blake3-servil-core 0.11.0).")
    ap.add_argument("--signatures", default="2^32")
    ap.add_argument("--security", type=float, default=128.0)
    ap.add_argument("--max-top-height", type=int, default=12)
    ap.add_argument("--uncached", action="store_true")
    ap.add_argument("--sign-cap-ms", type=float, default=50.0)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.check:
        run_check()
        return 0

    q = parse_q(args.signatures)
    front = build_frontier(q, args.security, args.max_top_height, not args.uncached, args.sign_cap_ms)
    mins = (min(p["bytes"] for p in front), min(p["sign_ms"] for p in front), min(p["verify_us"] for p in front))
    best = min(front, key=lambda p: leximin_key(p, mins))
    print(f"Budget: {args.signatures} ({q:,}), >= {args.security:.0f} bits | {len(front)} Pareto points")
    print(f"Floor : {mins[0]} B, {mins[1]:.2f} ms, {mins[2]:.1f} us")
    print(
        f"Winner: {best['bytes']} B | sign={best['sign_ms']:.2f}ms | ver={best['verify_us']:.1f}us | "
        f"kg={best['keygen_ms']:.1f}ms ({best['top_kib']:.0f} KiB) | "
        f"{best['h_top']}+{best['d']-1}x{best['h_low']} w={best['w']} FORS({best['a']},{best['k']}) {best['bits']:.1f}b"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

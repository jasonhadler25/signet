#!/usr/bin/env python3
"""Reproducible constrained-device-first parameter search for BLINCS (Python stdlib only).

Design approach (inspired by Conor Deegan of Project 11):
  1. Fix security target and budget: WOTS+ + FORS (zero counter grinding), q = 2^32 signatures,
     >= 128-bit single-query FORS leaf-cover exponent under ideal hashes.
  2. Enforce "Good Enough UX" on the most constrained feasible signing devices:
     - Reference device: Ledger Nano S+ / Flex / Stax (ST33K1M5 Secure Element, ~60 MHz ARM
       SC300/Cortex-M33, 160 KB RAM, 1.5 MB Flash, Rust `no_std`).
     - Streaming Merkle TreeHash requires only ~1.5 KiB working RAM and zero per-key Flash cache
       (so multi-account BIP-32/SLIP-10 wallets do not exhaust Flash).
     - Calibrated scalar Thumb-2 BLAKE3 cost: ~1,500 cycles/compression (~25 us/comp @ 60 MHz;
       ~9.4 us/comp on 150-160 MHz Cortex-M33 devices like Nitrokey 3 / SoloKey 2 / Trezor Safe 5).
  3. Among all parameter sets that meet the constrained-device UX bounds, minimize costs to
     desktop users (signature bytes, 1-core signing time, and 1-core verification time on
     `blake3-servil-core = "=0.11.0"`, Apple M6) via Leximin L_inf above the feasible frontier.

Usage:
    python3 tools/optimize.py                         # default ST33 p99 <= 5.0s constrained-device search
    python3 tools/optimize.py --nibble-only           # restrict to w=16 nibble WOTS+
    python3 tools/optimize.py --max-bytes 5950        # enforce 8 KiB Base64 HTTP-header ceiling
    python3 tools/optimize.py --check                 # verify adopted SPEC.md (7x5, FORS(8,20)) security & M6 fit
"""

import argparse
import math
import sys

N = 16

# Constrained-device scalar BLAKE3 models (~1,500 cycles/compression on 32-bit ARM Cortex-M/SC300):
US_LEDGER_ST33 = 25.0  # ~60 MHz (Ledger Nano S+ / Flex / Stax)
US_M33_160 = 9.4       # ~150-160 MHz (Nitrokey 3 / SoloKey 2 / Trezor Safe 5)

# Desktop single-core model (Apple M6, `blake3-servil-core = "=0.11.0"`, `clocks`, 0% E-cores):
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


def eval_candidate(h_top, d, h_low, width, a, k):
    h = h_top + (d - 1) * h_low
    w, chains, pk_blocks, leaf_comps, avg_steps = wots_params(width)
    sig_bytes = (2 + k * (1 + a) + d * chains + h) * N
    top_comps = (1 << h_top) * (leaf_comps + 1) - 1
    low_comps = (d - 1) * ((1 << h_low) * (leaf_comps + 1) - 1)
    fors_comps = k * (3 * (1 << a) - 1) + (16 + N * k + 63) // 64
    layer_sign_comps = d * (chains + avg_steps)

    # Constrained-device costs (streaming TreeHash, ~1.5 KiB working RAM, zero per-key Flash cache):
    h_max = max(h_top, h_low, a)
    working_ram_bytes = (h_max + 1) * N + (16 + N * chains) + (16 + N * k) + 512
    ledger_keygen_s = top_comps * US_LEDGER_ST33 / 1e6
    ledger_sign_uncached_s = (top_comps + low_comps + fors_comps + layer_sign_comps) * US_LEDGER_ST33 / 1e6
    ledger_sign_cached_s = (low_comps + fors_comps + layer_sign_comps) * US_LEDGER_ST33 / 1e6
    m33_sign_uncached_s = (top_comps + low_comps + fors_comps + layer_sign_comps) * US_M33_160 / 1e6

    # Desktop 1-core costs (Apple M6, blake3-servil-core 0.11.0, in-memory top tree):
    m6_keygen_ms = top_comps * NS_TREE_1T / 1e6
    m6_sign_ms = (low_comps * NS_TREE_1T + fors_comps * NS_FORS_1T + layer_sign_comps * NS_VER_BATCH) / 1e6
    m6_ver_us = ((k * (1 + a) + d * avg_steps) * NS_VER_BATCH + (d * (pk_blocks + h_low) + (h_top - h_low) + 4) * NS_VER_SCALAR) / 1e3

    return {
        "bytes": sig_bytes,
        "b64": ((sig_bytes + 2) // 3) * 4,
        "top_kib": ((2 << h_top) * N) / 1024.0,
        "work_ram_b": working_ram_bytes,
        "ledger_kg_s": ledger_keygen_s,
        "ledger_sign_s": ledger_sign_uncached_s,
        "ledger_cached_s": ledger_sign_cached_s,
        "m33_sign_s": m33_sign_uncached_s,
        "m6_kg_ms": m6_keygen_ms,
        "m6_sign_ms": m6_sign_ms,
        "m6_cold_ms": m6_keygen_ms + m6_sign_ms,
        "m6_ver_us": m6_ver_us,
        "h": h,
        "h_top": h_top,
        "d": d,
        "h_low": h_low,
        "w": w,
        "chains": chains,
        "a": a,
        "k": k,
    }


def search_feasible(q, target_bits, max_ledger_kg_s, max_ledger_sign_s, max_bytes, widths=(3, 4, 5)):
    """Enumerate all WOTS+ + FORS parameter sets meeting security + constrained-device UX constraints."""
    feasible = []
    for d in range(2, 10):
        for h_low in range(3, 11):
            for h_top in range(h_low, 13):
                h = h_top + (d - 1) * h_low
                if not (28 <= h <= 42):
                    continue
                for a in range(6, 15):
                    for k in range(8, 33):
                        if h + a * k > 256:
                            continue
                        b32 = fors_security_bits(q, h, a, k)
                        if b32 < target_bits:
                            continue
                        b2x = fors_security_bits(2 * q, h, a, k)
                        for width in widths:
                            c = eval_candidate(h_top, d, h_low, width, a, k)
                            if c["bytes"] <= max_bytes and c["ledger_kg_s"] <= max_ledger_kg_s and c["ledger_sign_s"] <= max_ledger_sign_s:
                                c["b32"] = b32
                                c["b2x"] = b2x
                                feasible.append(c)
                        break

    # Pareto-filter on desktop costs (bytes, warm 1-core sign, 1-core verify) + constrained uncached sign.
    feasible.sort(key=lambda x: (x["bytes"], x["m6_sign_ms"], x["m6_ver_us"], x["ledger_sign_s"]))
    pareto = []
    for p in feasible:
        if any(
            o["bytes"] <= p["bytes"]
            and o["m6_sign_ms"] <= p["m6_sign_ms"]
            and o["m6_ver_us"] <= p["m6_ver_us"]
            and o["ledger_sign_s"] <= p["ledger_sign_s"]
            for o in pareto
        ):
            continue
        pareto.append(p)
    return feasible, pareto


def desktop_leximin_key(p, mins):
    """Minimize the worst desktop cost blowup (bytes, 1T warm sign, 1T verify) above the feasible floor."""
    return tuple(sorted((p["bytes"] / mins[0], p["m6_sign_ms"] / mins[1], p["m6_ver_us"] / mins[2]), reverse=True))


def fmt_shape(c):
    return f"{c['d']}x{c['h_low']}" if c["h_top"] == c["h_low"] else f"{c['h_top']}+{c['d']-1}x{c['h_low']}"


def fmt_row(c):
    return (
        f"{c['bytes']:5d} B ({c['b64']:4d} b64) | {fmt_shape(c):<7} w={c['w']:2d} FORS({c['a']:2d},{c['k']:2d}) | "
        f"{c['b32']:5.1f}/{c['b2x']:5.1f}b | Top={c['top_kib']:4.0f}K | "
        f"ST33 kg={c['ledger_kg_s']:4.1f}s unc={c['ledger_sign_s']:4.1f}s | NK3={c['m33_sign_s']:4.2f}s | "
        f"M6-1T kg={c['m6_kg_ms']:4.1f}ms sign={c['m6_sign_ms']:4.2f}ms cold={c['m6_cold_ms']:4.1f}ms ver={c['m6_ver_us']:4.1f}us"
    )


def run_check():
    # Verify adopted SPEC.md implementation (uniform 7x5, w=16, byte-aligned FORS(8,20)) size, FORS cover curve, and 1T M6 calibration.
    # Zero grinding => algorithmic signing time is constant (mean == p99 == p99.9 == max).
    c = eval_candidate(5, 7, 5, 4, 8, 20)
    if c["bytes"] != 7392:
        raise RuntimeError(f"unexpected bytes {c['bytes']}")
    f32 = fors_security_bits(1 << 32, 35, 8, 20)
    f33 = fors_security_bits(1 << 33, 35, 8, 20)
    f34 = fors_security_bits(1 << 34, 35, 8, 20)
    f35 = fors_security_bits(1 << 35, 35, 8, 20)
    f36 = fors_security_bits(1 << 36, 35, 8, 20)
    if not (abs(f32 - 134.4633) < 1e-3 and abs(f33 - 128.8484) < 1e-3 and abs(f34 - 122.3896) < 1e-3 and abs(f35 - 114.9014) < 1e-3 and abs(f36 - 106.1754) < 1e-3):
        raise RuntimeError(f"unexpected FORS curve {f32}/{f33}/{f34}/{f35}/{f36}")
    if not (c["ledger_sign_s"] <= 5.0 and abs(c["m6_kg_ms"] - 0.17) < 0.1 and abs(c["m6_sign_ms"] - 1.31) < 0.25 and abs(c["m6_ver_us"] - 34.9) < 4.0):
        raise RuntimeError(f"unexpected ST33/M6 1T calibration: st33={c['ledger_sign_s']} kg={c['m6_kg_ms']} sign={c['m6_sign_ms']} ver={c['m6_ver_us']}")
    feasible, pareto = search_feasible(1 << 32, 128.0, 2.0, 5.0, 7856)
    if not (feasible and pareto):
        raise RuntimeError("constrained search returned no feasible candidates")
    print(
        f"CHECK PASSED: adopted SPEC 7x5 FORS(8,20) ({c['bytes']} B, {c['top_kib']:.0f} KiB top tree, ST33 kg={c['ledger_kg_s']:.2f}s p99={c['ledger_sign_s']:.2f}s) | "
        f"FORS={f32:.1f}/{f33:.1f}/{f34:.1f}/{f35:.1f}/{f36:.1f}b (2^32..2^36) | "
        f"M6-1T kg={c['m6_kg_ms']:.2f}ms (meas 0.17), sign={c['m6_sign_ms']:.2f}ms (meas 1.31), ver={c['m6_ver_us']:.1f}us (meas 34.9) | "
        f"ST33 p99 <= 5.0s search (<= 7856 B): {len(feasible)} feasible / {len(pareto)} Pareto."
    )


def main():
    ap = argparse.ArgumentParser(description="Constrained-device-first BLINCS parameter search (inspired by Conor Deegan, Project 11).")
    ap.add_argument("--signatures", default="2^32")
    ap.add_argument("--security", type=float, default=128.0)
    ap.add_argument("--max-ledger-keygen", type=float, default=2.0, help="Max Ledger ST33 keygen time (seconds)")
    ap.add_argument("--max-ledger-sign", type=float, default=5.0, help="Max Ledger ST33 uncached p99 sign time (seconds; constant for zero-grinding)")
    ap.add_argument("--max-bytes", type=int, default=7856, help="Max signature bytes (default 7,856 = SLH-DSA-128s; use 5,950 for 8 KiB HTTP headers)")
    ap.add_argument("--nibble-only", action="store_true", help="Restrict to w=16 nibble WOTS+")
    ap.add_argument("--top", type=int, default=10, help="Number of Pareto rows to display")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.check:
        run_check()
        return 0

    q = parse_q(args.signatures)
    widths = (4,) if args.nibble_only else (3, 4, 5)
    feasible, pareto = search_feasible(q, args.security, args.max_ledger_keygen, args.max_ledger_sign, args.max_bytes, widths)
    if not pareto:
        print("No feasible parameter sets found under these constraints.")
        return 1

    mins = (min(p["bytes"] for p in pareto), min(p["m6_sign_ms"] for p in pareto), min(p["m6_ver_us"] for p in pareto))
    winner = min(pareto, key=lambda p: desktop_leximin_key(p, mins))
    print(
        f"Constraints: q={args.signatures}, >= {args.security:.0f}b FORS | "
        f"Ledger ST33 keygen <= {args.max_ledger_keygen:.1f}s, uncached sign <= {args.max_ledger_sign:.1f}s | <= {args.max_bytes} B"
    )
    print(f"Found {len(feasible)} feasible sets ({len(pareto)} Pareto). Desktop floor: {mins[0]} B, {mins[1]:.2f} ms sign, {mins[2]:.1f} us verify.\n")
    print(f"Desktop-minimax winner : {fmt_row(winner)}\n")
    print(f"Smallest {min(args.top, len(pareto))} Pareto sets:")
    for c in pareto[: args.top]:
        print("  " + fmt_row(c))
    return 0


if __name__ == "__main__":
    sys.exit(main())

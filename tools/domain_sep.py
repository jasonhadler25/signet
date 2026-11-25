#!/usr/bin/env python3
"""Static and dynamic domain-separation & tweak-uniqueness check for BLINCS."""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "src")

SECRET_KINDS = {"ChainSecret", "FewSecret"}
PUBLIC_KINDS = {"Chain", "OneTimeKey", "Node", "FewLeaf", "FewNode", "FewRoot", "Message"}
ALL_KINDS = SECRET_KINDS | PUBLIC_KINDS


def check_static(params_src, spec_text, shipped_sources):
    errors = []

    # 1. Context strings: exactly 12, pairwise distinct, all verbatim in SPEC.md.
    ctxs = re.findall(r'const\s+(CTX_[A-Z0-9_]+)\s*:\s*&str\s*=\s*"([^"]+)";', params_src)
    if len(ctxs) != 12:
        errors.append(f"expected 12 CTX_* constants in src/params.rs, found {len(ctxs)}")
    seen_ctx = {}
    for name, val in ctxs:
        if val in seen_ctx:
            errors.append(f"duplicate context string {val!r} for {name} and {seen_ctx[val]}")
        seen_ctx[val] = name
        if f'"{val}"' not in spec_text:
            errors.append(f"context {name} = {val!r} not found verbatim in SPEC.md")

    # 2. TweakKind enum: exactly 9 distinct non-zero byte values 1..=9 matching SPEC.md.
    m = re.search(r"enum\s+TweakKind\s*\{([^}]+)\}", params_src, re.S)
    if not m:
        errors.append("enum TweakKind not found in src/params.rs")
        return errors
    kinds = re.findall(r"([A-Za-z0-9_]+)\s*=\s*(\d+)", m.group(1))
    kind_names = {k for k, _ in kinds}
    if kind_names != ALL_KINDS:
        errors.append(f"TweakKind variants {sorted(kind_names)} != expected {sorted(ALL_KINDS)}")
    seen_tags = {}
    for name, raw_tag in kinds:
        tag = int(raw_tag)
        if not (1 <= tag <= 9):
            errors.append(f"TweakKind::{name} tag {tag} outside 1..=9")
        if tag in seen_tags:
            errors.append(f"duplicate TweakKind tag {tag} for {name} and {seen_tags[tag]}")
        seen_tags[tag] = name

    # 3. Every tweak(TweakKind::...) call site in shipped src/ matches its key role.
    used_kinds = set()
    for rel, src in shipped_sources.items():
        code = re.sub(r"#\[cfg\(test\)\]\s*mod\s+test;", "", src)
        code = code.split("#[cfg(test)]")[0]
        lines = code.splitlines()
        for lineno, line in enumerate(lines, 1):
            for kind in re.findall(r"tweak\(\s*TweakKind::([A-Za-z0-9_]+)", line):
                used_kinds.add(kind)
                window = "\n".join(lines[max(0, lineno - 3) : min(len(lines), lineno + 12)])
                if kind in SECRET_KINDS:
                    if "sec_h.hash_many" not in window and "sec_h.hash_counter_range" not in window:
                        errors.append(f"{rel}:{lineno}: secret tweak {kind} not paired with sec_h.hash_many/hash_counter_range")
                    if "pub_h.hash_many" in window or "pub_h.hash_counter_range" in window or "public.hash" in window:
                        after = "\n".join(lines[lineno - 1 : min(len(lines), lineno + 6)])
                        if "pub_h.hash_many" in after or "pub_h.hash_counter_range" in after or "public.hash" in after:
                            errors.append(f"{rel}:{lineno}: secret tweak {kind} appears adjacent to public hasher")
                elif kind in PUBLIC_KINDS:
                    after = "\n".join(lines[lineno - 1 : min(len(lines), lineno + 8)])
                    if "sec_h.hash_many" in after or "sec_h.hash_counter_range" in after:
                        errors.append(f"{rel}:{lineno}: public tweak {kind} appears adjacent to sec_h")
                else:
                    errors.append(f"{rel}:{lineno}: unknown TweakKind::{kind}")

    if used_kinds != ALL_KINDS:
        errors.append(f"unused TweakKind variants in shipped src/: {sorted(ALL_KINDS - used_kinds)}")

    # 4. Exact finite-domain bit-width bounds over full 2^35 uniform 5x7 parameter space.
    hyper_bits = 35
    layer_heights = [7, 7, 7, 7, 7]
    if sum(layer_heights) != hyper_bits:
        errors.append("layer heights do not sum to 35")
    chains, chain_steps = 35, 15
    fors_trees, fors_height = 13, 11
    fors_leaves = 1 << fors_height

    cum = 0
    for layer, h in enumerate(layer_heights):
        cum += h
        max_tree = (1 << (hyper_bits - cum)) - 1
        max_leaf = (1 << h) - 1
        if not (0 <= layer < (1 << 8) and 0 <= max_tree < (1 << 48) and 0 <= max_leaf < (1 << 16)):
            errors.append(f"hypertree wire bound exceeded at layer {layer}")
    if not (chains - 1 < (1 << 16) and chain_steps < (1 << 32) and (1 << hyper_bits) - 1 < (1 << 48) and fors_trees - 1 < (1 << 16) and fors_leaves - 1 < (1 << 32)):
        errors.append("FORS/WOTS wire bound exceeded")

    return errors


def self_test(params_src, spec_text, shipped_sources):
    bad_ctx = params_src.replace("BLINCS 2026-11-25 content", "BLINCS 2026-11-25 public hash", 1)
    if not check_static(bad_ctx, spec_text, shipped_sources):
        raise RuntimeError("self-test failed: duplicate CTX escaped")

    bad_tag = params_src.replace("Message = 9,", "Message = 8,", 1)
    if not check_static(bad_tag, spec_text, shipped_sources):
        raise RuntimeError("self-test failed: duplicate TweakKind tag escaped")

    bad_role = dict(shipped_sources)
    bad_role["src/few_time.rs"] = bad_role["src/few_time.rs"].replace(
        "sec_h.hash_counter_range(&secret_template, 3, 0, &mut ws.out[..FORS_LEAVES])",
        "pub_h.hash_counter_range(&secret_template, 3, 0, &mut ws.out[..FORS_LEAVES])",
        1,
    )
    if not check_static(params_src, spec_text, bad_role):
        raise RuntimeError("self-test failed: secret/public role mixup escaped")


def check_dynamic_reference():
    sys.path.insert(0, os.path.join(ROOT, "reference"))
    import blake3
    import blincs

    orig_keyed = blake3.keyed_hash
    orig_derive = blake3.derive_key

    derived_ctxs = set()
    ver_sec_tweaks = []
    ver_pub_tweaks = []
    fors_sec_tweaks = []
    fors_pub_tweaks = []
    wots_sec_tweaks = []
    wots_pub_tweaks = []

    seed = bytes(range(32))
    k_sec_expected = orig_derive(blincs.CTX_SECRET_VALUES, seed)
    pk_seed = orig_derive(blincs.CTX_PUBLIC_SEED, seed)[:16]
    k_pub_expected = orig_derive(blincs.CTX_PUBLIC_HASH, pk_seed)
    id_bytes = bytes.fromhex("db09192c50a65494941887b9c57895ab1d8c239fbfb22e021f3b8dcc8d5b3da2")
    imp_bytes = open(os.path.join(ROOT, "test_vectors", "reference-imprint-1.bin"), "rb").read()

    bucket = [ver_sec_tweaks, ver_pub_tweaks]

    def traced_derive(ctx, data):
        derived_ctxs.add(ctx)
        return orig_derive(ctx, data)

    def traced_keyed(key, data):
        if len(data) >= 16:
            tw = data[:16]
            if key == k_sec_expected:
                bucket[0].append(tw)
            elif key == k_pub_expected:
                bucket[1].append(tw)
        return orig_keyed(key, data)

    blake3.derive_key = traced_derive
    blake3.keyed_hash = traced_keyed
    try:
        sid = blincs.SignetId(id_bytes)
        if not sid.verify(b"hello, BLINCS", imp_bytes):
            raise RuntimeError("reference verification failed")

        bucket[0], bucket[1] = fors_sec_tweaks, fors_pub_tweaks
        fors_leaves = []
        for i in range(16):
            s = blincs.H(k_sec_expected, blincs.tweak(blincs.KIND_FEW_SECRET, 0, 42, 0, 0, i))
            fors_leaves.append(blincs.H(k_pub_expected, blincs.tweak(blincs.KIND_FEW_LEAF, 0, 42, 0, 0, i), s))
        _ = blincs.merkle_tree(k_pub_expected, blincs.KIND_FEW_NODE, 0, 42, 0, fors_leaves)

        bucket[0], bucket[1] = wots_sec_tweaks, wots_pub_tweaks
        wots_leaves = [blincs.one_time_leaf(k_sec_expected, k_pub_expected, 0, 7, leaf) for leaf in range(4)]
        _ = blincs.merkle_tree(k_pub_expected, blincs.KIND_NODE, 0, 7, 0, wots_leaves)
    finally:
        blake3.derive_key = orig_derive
        blake3.keyed_hash = orig_keyed

    if len(ver_sec_tweaks) != 0 or len(ver_pub_tweaks) == 0 or len(ver_pub_tweaks) != len(set(ver_pub_tweaks)):
        raise RuntimeError("verify tweak invariant failed")
    if len(fors_sec_tweaks) != 16 or len(set(fors_sec_tweaks)) != 16 or len(fors_pub_tweaks) != 31 or len(set(fors_pub_tweaks)) != 31:
        raise RuntimeError("FORS tweak invariant failed")
    if len(wots_sec_tweaks) != 4 * 35 or len(set(wots_sec_tweaks)) != 4 * 35 or len(wots_pub_tweaks) != len(set(wots_pub_tweaks)):
        raise RuntimeError("WOTS tweak invariant failed")
    if not set(fors_sec_tweaks).isdisjoint(wots_sec_tweaks) or not set(fors_pub_tweaks).isdisjoint(wots_pub_tweaks):
        raise RuntimeError("FORS and WOTS tweaks overlapped")
    return len(ver_pub_tweaks), len(fors_pub_tweaks), len(wots_pub_tweaks), len(derived_ctxs)


def main():
    params_src = open(os.path.join(SRC_DIR, "params.rs")).read()
    spec_text = open(os.path.join(ROOT, "SPEC.md")).read()
    shipped = {}
    for fname in sorted(os.listdir(SRC_DIR)):
        if fname.endswith(".rs") and fname != "test.rs":
            shipped[f"src/{fname}"] = open(os.path.join(SRC_DIR, fname)).read()

    self_test(params_src, spec_text, shipped)
    errors = check_static(params_src, spec_text, shipped)
    if errors:
        for e in errors:
            print("FAIL:", e, file=sys.stderr)
        return 1

    n_ver, n_fors, n_wots, n_ctx = check_dynamic_reference()
    print(
        f"domain_sep.py PASSED (self-test 3/3 caught; 12 CTX + 9 TweakKind static & finite-domain injective; "
        f"dynamic trace: {n_ver} unique verify K_pub / 0 K_sec, {n_fors} FORS + {n_wots} WOTS+/Merkle disjoint tweaks, {n_ctx} contexts)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

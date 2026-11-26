#!/usr/bin/env python3
"""Static and dynamic domain-separation & tweak-uniqueness check for Signet (BLINCS-128-7x5)."""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "src")

SECRET_KINDS = {"ChainSecret", "FewSecret"}
PUBLIC_KINDS = {"Chain", "OneTimeKey", "Node", "FewLeaf", "FewNode", "FewRoot", "Message"}
ALL_KINDS = SECRET_KINDS | PUBLIC_KINDS

# Mapping between Rust TweakKind CamelCase variant names and SPEC.md SCREAMING_SNAKE names.
KIND_TO_SPEC = {
    "ChainSecret": "CHAIN_SECRET",
    "Chain": "CHAIN",
    "OneTimeKey": "ONE_TIME_KEY",
    "Node": "NODE",
    "FewSecret": "FEW_SECRET",
    "FewLeaf": "FEW_LEAF",
    "FewNode": "FEW_NODE",
    "FewRoot": "FEW_ROOT",
    "Message": "MESSAGE",
}


def strip_cfg_test_items(src):
    """Remove only #[cfg(test)] items without discarding shipped code that follows them."""
    out = []
    lines = src.splitlines()
    i = 0
    while i < len(lines):
        if re.match(r"^\s*#\[cfg\(test\)\]\s*$", lines[i]):
            i += 1
            if i < len(lines) and ";" in lines[i] and "{" not in lines[i]:
                i += 1
                continue
            depth = 0
            started = False
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                if lines[i].count("{") > 0:
                    started = True
                i += 1
                if started and depth <= 0:
                    break
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def parse_spec_contexts(spec_text):
    """Parse exact name -> value table from SPEC.md 'Key-derivation contexts', rejecting duplicate rows."""
    m = re.search(r"## Key-derivation contexts(.*?)(?=\n## |\Z)", spec_text, re.S)
    if not m:
        return None, ["Key-derivation contexts table not found in SPEC.md"]
    rows = re.findall(r'^\|\s*`([A-Z0-9_]+)`\s*\|\s*`"([^"]+)"`\s*\|', m.group(1), re.M)
    out = {}
    errs = []
    for name, val in rows:
        if name in out:
            errs.append(f"duplicate SPEC.md context row for {name}")
        out[name] = val
    return out, errs


def parse_spec_tweaks(spec_text):
    """Parse exact tag -> (SPEC_NAME, key_role) table from SPEC.md 'Tweaks', rejecting duplicate rows."""
    m = re.search(r"## Tweaks(.*?)(?=\n## |\Z)", spec_text, re.S)
    if not m:
        return None, ["Tweaks table not found in SPEC.md"]
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`([A-Z0-9_]+)`\s*\|\s*`(K_sec|K_pub)`\s*\|", m.group(1), re.M)
    out = {}
    errs = []
    for tag_s, name, role in rows:
        tag = int(tag_s)
        if tag in out:
            errs.append(f"duplicate SPEC.md tweak tag {tag}")
        out[tag] = (name, role)
    return out, errs


def check_static(params_src, spec_text, shipped_sources, verify_src=None):
    errors = []

    # 1. Exact 1-to-1 CTX_* name -> value equality between src/params.rs and SPEC.md table.
    ctxs = re.findall(r'const\s+CTX_([A-Z0-9_]+)\s*:\s*&str\s*=\s*"([^"]+)";', params_src)
    if len(ctxs) != 12:
        errors.append(f"expected 12 CTX_* constants in src/params.rs, found {len(ctxs)}")
    rust_ctx_map = {}
    seen_vals = {}
    for name, val in ctxs:
        if val in seen_vals:
            errors.append(f"duplicate context string {val!r} for CTX_{name} and CTX_{seen_vals[val]}")
        seen_vals[val] = name
        rust_ctx_map[name] = val

    spec_ctx_map, spec_ctx_errs = parse_spec_contexts(spec_text)
    errors.extend(spec_ctx_errs)
    if spec_ctx_map is not None and rust_ctx_map != spec_ctx_map:
        errors.append(f"src/params.rs CTX_* map != SPEC.md table (rust={sorted(rust_ctx_map.items())}, spec={sorted(spec_ctx_map.items())})")

    # 2. Exact 1-to-1 TweakKind tag -> name and key-role match between src/params.rs and SPEC.md table.
    m = re.search(r"enum\s+TweakKind\s*\{([^}]+)\}", params_src, re.S)
    if not m:
        errors.append("enum TweakKind not found in src/params.rs")
        return errors
    kinds = re.findall(r"([A-Za-z0-9_]+)\s*=\s*(\d+)", m.group(1))
    kind_names = {k for k, _ in kinds}
    if kind_names != ALL_KINDS:
        errors.append(f"TweakKind variants {sorted(kind_names)} != expected {sorted(ALL_KINDS)}")

    rust_tweak_map = {}
    for name, raw_tag in kinds:
        tag = int(raw_tag)
        if not (1 <= tag <= 9):
            errors.append(f"TweakKind::{name} tag {tag} outside 1..=9")
        if tag in rust_tweak_map:
            errors.append(f"duplicate TweakKind tag {tag} for {name} and {rust_tweak_map[tag]}")
        role = "K_sec" if name in SECRET_KINDS else "K_pub"
        rust_tweak_map[tag] = (KIND_TO_SPEC.get(name, name), role)

    spec_tweak_map, spec_tweak_errs = parse_spec_tweaks(spec_text)
    errors.extend(spec_tweak_errs)
    if spec_tweak_map is not None and rust_tweak_map != spec_tweak_map:
        errors.append(f"src/params.rs TweakKind table != SPEC.md table (rust={rust_tweak_map}, spec={spec_tweak_map})")

    # 2b. Verify standalone #![no_std] signet-verify matches SPEC.md public contexts and tweak tags.
    if verify_src is not None and spec_ctx_map is not None and spec_tweak_map is not None:
        v_ctxs = dict(re.findall(r'const\s+CTX_([A-Z0-9_]+)\s*:\s*&str\s*=\s*"([^"]+)";', verify_src))
        want_v_ctxs = {k: spec_ctx_map[k] for k in ("PUBLIC_HASH", "CONTENT")}
        if v_ctxs != want_v_ctxs:
            errors.append(f"signet-verify CTX_* {v_ctxs} != expected {want_v_ctxs}")
        vm = re.search(r"enum\s+TweakKind\s*\{([^}]+)\}", verify_src, re.S)
        if not vm:
            errors.append("enum TweakKind not found in crates/signet-verify/src/lib.rs")
        else:
            v_tweaks = {int(t): (KIND_TO_SPEC.get(n, n), "K_pub") for n, t in re.findall(r"([A-Za-z0-9_]+)\s*=\s*(\d+)", vm.group(1))}
            want_v_tweaks = {t: v for t, v in spec_tweak_map.items() if v[1] == "K_pub"}
            if v_tweaks != want_v_tweaks:
                errors.append(f"signet-verify TweakKind {v_tweaks} != expected {want_v_tweaks}")

    # 3. Every tweak(TweakKind::...) call site in shipped src/ matches its key role.
    used_kinds = set()
    for rel, src in shipped_sources.items():
        code = strip_cfg_test_items(src)
        lines = code.splitlines()
        for lineno, line in enumerate(lines, 1):
            for kind in re.findall(r"tweak\(\s*TweakKind::([A-Za-z0-9_]+)", line):
                used_kinds.add(kind)
                window = "\n".join(lines[max(0, lineno - 3) : min(len(lines), lineno + 12)])
                if kind in SECRET_KINDS:
                    if "sec_h.hash_many" not in window and "sec_h.hash_counter_range" not in window:
                        errors.append(f"{rel}:{lineno}: secret tweak {kind} not paired with sec_h.hash_many/hash_counter_range")
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

    # 4. Verify parameter constants parsed directly from src/params.rs stay within wire tweak bit widths.
    def const_int(cname):
        cm = re.search(rf"const\s+{cname}\s*:\s*(?:usize|u8)\s*=\s*(\d+);", params_src)
        if not cm:
            errors.append(f"const {cname} not found in src/params.rs")
            return 0
        return int(cm.group(1))

    n_bytes = const_int("N")
    csum_chains = const_int("CSUM_CHAINS")
    layers = const_int("LAYERS")
    tree_h = const_int("TREE_HEIGHT")
    hyper_bits = layers * tree_h
    fors_h = const_int("FORS_HEIGHT")
    fors_trees = const_int("FORS_TREES")
    chain_steps = const_int("CHAIN_STEPS")
    chains = 2 * n_bytes + csum_chains
    if hyper_bits != 35 or chains != 35:
        errors.append(f"unexpected HYPER_BITS={hyper_bits} or CHAINS={chains}")
    for layer in range(layers):
        max_tree = (1 << (hyper_bits - (layer + 1) * tree_h)) - 1
        max_leaf = (1 << tree_h) - 1
        if not (0 <= layer < (1 << 8) and 0 <= max_tree < (1 << 48) and 0 <= max_leaf < (1 << 16)):
            errors.append(f"hypertree wire bound exceeded at layer {layer}")
    if not (
        chains - 1 < (1 << 16)
        and chain_steps < (1 << 32)
        and (1 << hyper_bits) - 1 < (1 << 48)
        and fors_trees - 1 < (1 << 16)
        and (1 << fors_h) - 1 < (1 << 32)
    ):
        errors.append("FORS/WOTS wire bound exceeded")

    return errors


def self_test(params_src, spec_text, shipped_sources, verify_src):
    bad_ctx = params_src.replace('"BLINCS-128-7x5 2026-11-25 content"', '"BLINCS-128-7x5 2026-11-25 public hash"', 1)
    ctx_errs = check_static(bad_ctx, spec_text, shipped_sources, verify_src)
    if not any("duplicate context string" in e for e in ctx_errs):
        raise RuntimeError(f"self-test failed: duplicate CTX diagnostic not triggered: {ctx_errs}")

    bad_spec = spec_text.replace('| `CONTENT` | `"BLINCS-128-7x5 2026-11-25 content"` |', '| `CONTENT` | `"BLINCS-128-7x5 2026-11-25 wrong"` |', 1)
    if not check_static(params_src, bad_spec, shipped_sources, verify_src):
        raise RuntimeError("self-test failed: SPEC.md name-to-value mismatch escaped")

    bad_tag = params_src.replace("Message = 9,", "Message = 8,", 1)
    tag_errs = check_static(bad_tag, spec_text, shipped_sources, verify_src)
    if not any("duplicate TweakKind tag" in e for e in tag_errs):
        raise RuntimeError(f"self-test failed: duplicate TweakKind tag escaped: {tag_errs}")

    bad_role = dict(shipped_sources)
    bad_role["src/few_time.rs"] = bad_role["src/few_time.rs"].replace(
        "sec_h.hash_counter_range(&secret_template, 3, 0, &mut ws.out[base..base + FORS_LEAVES])",
        "pub_h.hash_counter_range(&secret_template, 3, 0, &mut ws.out[base..base + FORS_LEAVES])",
        1,
    )
    if not check_static(params_src, spec_text, bad_role, verify_src):
        raise RuntimeError("self-test failed: secret/public role mixup escaped")

    bad_verify = verify_src.replace("Message = 9,", "Message = 8,", 1)
    if not check_static(params_src, spec_text, shipped_sources, bad_verify):
        raise RuntimeError("self-test failed: signet-verify TweakKind mismatch escaped")


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
    id_bytes = bytes.fromhex("b58abfb655db7c92808f12c3a8ffd2d04841cf61994321648cf193638876c492")
    imp_bytes = open(os.path.join(ROOT, "test_vectors", "reference-imprint-1.bin"), "rb").read()
    ref_ctx = b"BLINCS-128-7x5 reference vector v1"

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
        if not sid.verify(ref_ctx, b"hello, BLINCS", imp_bytes):
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
    verify_src = open(os.path.join(ROOT, "crates", "signet-verify", "src", "lib.rs")).read()

    self_test(params_src, spec_text, shipped, verify_src)
    errors = check_static(params_src, spec_text, shipped, verify_src)
    if errors:
        for e in errors:
            print("FAIL:", e, file=sys.stderr)
        return 1

    n_ver, n_fors, n_wots, n_ctx = check_dynamic_reference()
    print(
        f"domain_sep.py PASSED (self-test 5/5 caught; 12 CTX + 9 TweakKind SPEC-table exact match, signet-verify parity & finite-domain bounds; "
        f"dynamic trace: {n_ver} unique verify K_pub / 0 K_sec, {n_fors} FORS + {n_wots} WOTS+/Merkle disjoint tweaks, {n_ctx} contexts)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

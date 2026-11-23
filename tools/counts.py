#!/usr/bin/env python3
"""Shipped-code safety counts for BLINCS (emulating SSF #499 monotone count gates).

    python3 tools/counts.py              # report counts and enforce zero-tolerance invariants
    python3 tools/counts.py --self-test  # prove every zero-tolerance check rejects a planted violation

Ratcheted zero-tolerance counts over shipped Rust files (`src/*.rs` excluding `src/test.rs` and
`#[cfg(test)]` items/blocks, stripping comments and string literals):
  unsafe_blocks      `unsafe` keyword occurrences (`#![forbid(unsafe_code)]` belt + suspenders)
  debug_asserts      `debug_assert*!` invocations (invariants must hold in release builds too)
  truncation_allows  `allow(...cast_possible_truncation...)` attributes
  print_macros       `print!` / `println!` / `eprint!` / `eprintln!` / `dbg!`
  drop_impls         `impl Drop for` (pure crash-only lifecycle)

Reported for visibility:
  shipped_code_lines non-blank, non-comment shipped lines
  cfg_conditions     `cfg(` / `cfg_attr(` occurrences in shipped code
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNSAFE_RE = re.compile(r"\bunsafe\b")
DEBUG_ASSERT_RE = re.compile(r"\bdebug_assert(?:_eq|_ne)?!")
TRUNC_ALLOW_RE = re.compile(r"#!?\[[^\]]*\ballow\s*\([^)]*\bclippy::cast_possible_truncation\b")
PRINT_RE = re.compile(r"\b(?:e?println|e?print|dbg)!")
DROP_IMPL_RE = re.compile(r"\bimpl\b[^{]*\bDrop\b\s+for\b")
CFG_RE = re.compile(r"\bcfg(?:_attr)?!?\s*\(")

ZERO_TOLERANCE = ("unsafe_blocks", "debug_asserts", "truncation_allows", "print_macros", "drop_impls")


def strip_comments_and_strings(text):
    """Return code with line/block comments and string literals blanked out, preserving line count."""
    out = []
    i = 0
    n = len(text)
    block_depth = 0
    in_str = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if block_depth > 0:
            if ch == "/" and nxt == "*":
                block_depth += 1
                out.append("  ")
                i += 2
            elif ch == "*" and nxt == "/":
                block_depth -= 1
                out.append("  ")
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif in_str:
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
            elif ch == '"':
                in_str = False
                out.append('"')
                i += 1
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        else:
            if ch == "/" and nxt == "/":
                while i < n and text[i] != "\n":
                    out.append(" ")
                    i += 1
            elif ch == "/" and nxt == "*":
                block_depth = 1
                out.append("  ")
                i += 2
            elif ch == '"':
                in_str = True
                out.append('"')
                i += 1
            else:
                out.append(ch)
                i += 1
    return "".join(out)


def non_test_code(text):
    """Strip comments/strings and drop `#[cfg(test)]` items (tracked by brace depth)."""
    cleaned = strip_comments_and_strings(text)
    lines = cleaned.splitlines()
    kept = []
    skip_cfg_test = False
    brace_depth = 0
    saw_open = False
    for line in lines:
        stripped = line.strip()
        if not skip_cfg_test and stripped == "#[cfg(test)]":
            skip_cfg_test = True
            brace_depth = 0
            saw_open = False
            continue
        if skip_cfg_test:
            opens = line.count("{")
            closes = line.count("}")
            if opens:
                saw_open = True
            brace_depth += opens - closes
            if (saw_open and brace_depth <= 0) or (not saw_open and stripped.endswith(";")):
                skip_cfg_test = False
            continue
        kept.append(line)
    return "\n".join(kept)


def measure_map(files):
    counts = {
        "unsafe_blocks": 0,
        "debug_asserts": 0,
        "truncation_allows": 0,
        "print_macros": 0,
        "drop_impls": 0,
        "shipped_code_lines": 0,
        "cfg_conditions": 0,
    }
    for _rel, text in sorted(files.items()):
        body = non_test_code(text)
        counts["unsafe_blocks"] += len(UNSAFE_RE.findall(body))
        counts["debug_asserts"] += len(DEBUG_ASSERT_RE.findall(body))
        counts["truncation_allows"] += len(TRUNC_ALLOW_RE.findall(body))
        counts["print_macros"] += len(PRINT_RE.findall(body))
        counts["drop_impls"] += len(DROP_IMPL_RE.findall(body))
        counts["cfg_conditions"] += len(CFG_RE.findall(body))
        counts["shipped_code_lines"] += sum(1 for ln in body.splitlines() if ln.strip())
    return counts


def shipped_files():
    out = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "src", "*.rs"))):
        rel = os.path.relpath(path, ROOT)
        if rel == os.path.join("src", "test.rs"):
            continue
        with open(path) as f:
            out[rel] = f.read()
    return out


def self_test():
    clean = "fn ok(x: u32) -> u32 { x + 1 }\n// debug_assert!(false); unsafe {}\n#[cfg(test)]\nfn t() { debug_assert!(true); println!(\"hi\"); }\n"
    c = measure_map({"src/a.rs": clean})
    for k in ZERO_TOLERANCE:
        assert c[k] == 0, f"clean snippet tripped {k}: {c}"

    planted = {
        "unsafe_blocks": "fn f() { unsafe { } }",
        "debug_asserts": "fn f(x: usize) { debug_assert_eq!(x, 1); }",
        "truncation_allows": "#[allow(clippy::cast_possible_truncation)]\nfn f(x: usize) -> u8 { x as u8 }",
        "print_macros": "fn f() { println!(\"leak\"); }",
        "drop_impls": "struct S; impl Drop for S { fn drop(&mut self) {} }",
    }
    for key, snippet in planted.items():
        got = measure_map({"src/planted.rs": snippet})
        assert got[key] >= 1, f"planted {key} was NOT detected: {got}"
    print(f"counts.py self-test PASSED (all {len(planted)} planted violations caught).")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if sys.argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2

    self_test()
    counts = measure_map(shipped_files())
    summary = ", ".join(f"{k}={v}" for k, v in counts.items())
    print(f"Shipped counts: {summary}")
    bad = [f"{k}={counts[k]}" for k in ZERO_TOLERANCE if counts[k] != 0]
    if bad:
        print("FAIL: non-zero forbidden shipped count(s): " + ", ".join(bad), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

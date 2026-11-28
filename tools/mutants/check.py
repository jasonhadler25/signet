#!/usr/bin/env python3
"""Run cargo-mutants against BLINCS in release mode and enforce tools/mutants/known.txt.

    python3 tools/mutants/check.py                 # full mutation run
    python3 tools/mutants/check.py --check-dir DIR # check an existing mutants.out directory

Fails if any mutant times out, if any unexpected mutant survives, or if any entry in
tools/mutants/known.txt no longer matches a survivor (stale entries earn removal).
"""

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KNOWN = os.path.join(ROOT, "tools", "mutants", "known.txt")
LINE_RE = re.compile(r"^([^:]+):\d+:\d+:\s+(.*)$")


def load_known():
    entries = {}
    for raw in open(KNOWN):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise ValueError(f"bad known.txt line: {raw!r}")
        key = (parts[0], parts[1])
        if key in entries:
            raise ValueError(f"duplicate known.txt entry: {key!r}")
        entries[key] = parts[2]
    return entries


def parse_mutants_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"missing cargo-mutants output file: {path}")
    out = []
    for raw in open(path):
        line = raw.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            raise ValueError(f"unexpected mutant line: {line!r}")
        out.append((m.group(1), m.group(2), line))
    return out


def verify_dir(out_dir):
    for required in ("outcomes.json", "missed.txt", "timeout.txt"):
        req_path = os.path.join(out_dir, required)
        if not os.path.isfile(req_path):
            print(f"FAIL: missing required cargo-mutants artifact: {req_path}", file=sys.stderr)
            return 1
    known = load_known()
    missed = parse_mutants_file(os.path.join(out_dir, "missed.txt"))
    timeouts = parse_mutants_file(os.path.join(out_dir, "timeout.txt"))

    if timeouts:
        print(f"FAIL: {len(timeouts)} mutant(s) timed out (clock-only catches do not count):", file=sys.stderr)
        for _, _, full in timeouts:
            print(f"  TIMEOUT  {full}", file=sys.stderr)
        return 1

    unexpected = []
    seen_known = set()
    for path, desc, full in missed:
        key = (path, desc)
        if key in known:
            seen_known.add(key)
        else:
            unexpected.append(full)

    stale = sorted(set(known) - seen_known)
    if unexpected:
        print(f"FAIL: {len(unexpected)} unexpected surviving mutant(s):", file=sys.stderr)
        for full in unexpected:
            print(f"  MISSED   {full}", file=sys.stderr)
    if stale:
        print(f"FAIL: {len(stale)} stale entry/entries in tools/mutants/known.txt:", file=sys.stderr)
        for path, desc in stale:
            print(f"  STALE    {path}\t{desc}", file=sys.stderr)
    if unexpected or stale:
        return 1

    print(f"PASS: 0 timeouts, 0 unexpected survivors ({len(seen_known)} known equivalent/unobservable survivors matched).")
    return 0


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--check-dir":
        return verify_dir(args[1])
    if args:
        print(__doc__, file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="blincs-mutants-") as tmp:
        cmd = [
            "cargo",
            "mutants",
            "--profile",
            "mutants",
            "--test-tool",
            "nextest",
            "--timeout",
            "20",
            "-j",
            str(min(6, os.cpu_count() or 2)),
            "-o",
            tmp,
            "--",
            "--profile",
            "mutants",
            "--locked",
        ]
        res = subprocess.run(cmd, cwd=ROOT)
        if res.returncode not in (0, 2):
            print(f"cargo-mutants failed with exit code {res.returncode}", file=sys.stderr)
            return res.returncode
        return verify_dir(os.path.join(tmp, "mutants.out"))


if __name__ == "__main__":
    sys.exit(main())

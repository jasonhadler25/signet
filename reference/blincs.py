#!/usr/bin/env python3
"""BLINCS — reference implementation from SPEC.md.

Self-contained except for reference/blake3.py (BLAKE3 from its spec).
"""

import concurrent.futures
import os
import sys

import blake3

N = 16
LAYERS, LOWER_HEIGHT, TOP_HEIGHT = 4, 7, 12
W, CHAIN_STEPS, MSG_CHAINS, CSUM_CHAINS, CHAINS = 16, 15, 32, 3, 35
FORS_HEIGHT, FORS_TREES = 10, 16
HYPER_BITS = TOP_HEIGHT + (LAYERS - 1) * LOWER_HEIGHT
FORS_LEN = FORS_TREES * (1 + FORS_HEIGHT) * N
LOWER_LAYER_LEN = (CHAINS + LOWER_HEIGHT) * N
TOP_LAYER_LEN = (CHAINS + TOP_HEIGHT) * N
SIGNATURE_LEN = 2 * N + FORS_LEN + (LAYERS - 1) * LOWER_LAYER_LEN + TOP_LAYER_LEN

# Key-derivation contexts (SPEC.md, "Key-derivation contexts").
CTX_SECRET_VALUES = "BLINCS 2026-11-23 signing key: secret values"
CTX_CONTENT_SALT = "BLINCS 2026-11-23 signing key: content salt"
CTX_RANDOMIZER = "BLINCS 2026-11-23 signing key: randomizer"
CTX_PUBLIC_SEED = "BLINCS 2026-11-23 signing key: public seed"
CTX_PUBLIC_HASH = "BLINCS 2026-11-23 public hash"
CTX_CONTENT = "BLINCS 2026-11-23 content"
CTX_MIX = "BLINCS 2026-11-23 randomness: mix"
CTX_NEXT_SEED = "BLINCS 2026-11-23 randomness: seed kept in the file"
CTX_RUN_KEY = "BLINCS 2026-11-23 randomness: key of this run"

# Tweak kinds (SPEC.md, "Tweaks").
KIND_CHAIN_SECRET, KIND_CHAIN, KIND_ONE_TIME_KEY, KIND_NODE = 1, 2, 3, 4
KIND_FEW_SECRET, KIND_FEW_LEAF, KIND_FEW_NODE, KIND_FEW_ROOT = 5, 6, 7, 8
KIND_MESSAGE = 9


def _check_len(name, value, expected):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    out = bytes(value)
    if len(out) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(out)}")
    return out


def tweak(kind, layer=0, tree=0, leaf=0, a=0, b=0):
    return (
        bytes([kind, layer])
        + tree.to_bytes(6, "little")
        + leaf.to_bytes(2, "little")
        + a.to_bytes(2, "little")
        + b.to_bytes(4, "little")
    )


def H(key, t, data=b""):
    return blake3.keyed_hash(key, t + data)[:N]


def chain(public, layer, tree, leaf, c, value, start, steps):
    for step in range(start, start + steps):
        value = H(public, tweak(KIND_CHAIN, layer, tree, leaf, c, step), value)
    return value


def digits(node):
    """32 message nibbles (little-endian within each byte) + 3 little-endian checksum nibbles."""
    out = []
    csum = 0
    for byte in node:
        lo, hi = byte & 0x0F, byte >> 4
        out.append(lo)
        out.append(hi)
        csum += (CHAIN_STEPS - lo) + (CHAIN_STEPS - hi)
    out.append(csum & 0x0F)
    out.append((csum >> 4) & 0x0F)
    out.append((csum >> 8) & 0x0F)
    return out


def parse_digest(digest):
    """16 ten-bit FORS leaf indices (digest[:20]) and 33-bit hypertree leaf address (digest[20:28])."""
    fors_bits = int.from_bytes(digest[:20], "little")
    indices = [(fors_bits >> (10 * j)) & 0x3FF for j in range(FORS_TREES)]
    leaf_addr = int.from_bytes(digest[20:28], "little") & ((1 << HYPER_BITS) - 1)
    return indices, leaf_addr


def one_time_leaf(secret, public, layer, tree, leaf):
    ends = []
    for c in range(CHAINS):
        s = H(secret, tweak(KIND_CHAIN_SECRET, layer, tree, leaf, c, 0))
        ends.append(chain(public, layer, tree, leaf, c, s, 0, CHAIN_STEPS))
    return H(public, tweak(KIND_ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))


def _wots_leaf_range(args):
    secret, public, layer, tree, start, count = args
    return [one_time_leaf(secret, public, layer, tree, leaf) for leaf in range(start, start + count)]


def merkle_tree(public, kind, layer, tree, extra_leaf, leaves):
    """Build a complete binary Merkle tree (levels[0] = leaves, levels[-1] = [root])."""
    levels = [list(leaves)]
    level = 1
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [
            H(public, tweak(kind, layer, tree, extra_leaf, level, p), cur[2 * p] + cur[2 * p + 1])
            for p in range(len(cur) // 2)
        ]
        levels.append(nxt)
        level += 1
    return levels


def content(content_key, salt, message):
    msg_key = blake3.keyed_hash(content_key, salt)
    return salt + blake3.keyed_hash(msg_key, message)


def mix(seed, count, system, clock):
    seed = _check_len("seed", seed, 32)
    system = _check_len("system", system, 32)
    if not isinstance(count, int) or isinstance(count, bool) or not (0 <= count < 1 << 64):
        raise ValueError("count must be a u64")
    pool = blake3.derive_key(CTX_MIX, seed + count.to_bytes(8, "little") + system + bytes(clock))
    return blake3.derive_key(CTX_NEXT_SEED, pool), blake3.derive_key(CTX_RUN_KEY, pool)


def draw(run_key, count):
    run_key = _check_len("run_key", run_key, 32)
    if not isinstance(count, int) or isinstance(count, bool) or not (0 <= count < 1 << 64):
        raise ValueError("count must be a u64")
    return blake3.keyed_hash(run_key, count.to_bytes(8, "little"))


class VerifyingKey:
    def __init__(self, key_bytes):
        key_bytes = _check_len("verifying key", key_bytes, 2 * N)
        self.bytes = key_bytes
        self.public_seed, self.root = key_bytes[:N], key_bytes[N:]
        self.public = blake3.derive_key(CTX_PUBLIC_HASH, self.public_seed)
        self.content_key = blake3.derive_key(CTX_CONTENT, self.bytes)

    def verify(self, message, signature):
        if len(signature) != SIGNATURE_LEN:
            return False
        salt, randomizer, at = signature[:N], signature[N : 2 * N], 2 * N
        short = content(self.content_key, salt, message)
        digest = blake3.keyed_hash(self.public, tweak(KIND_MESSAGE) + randomizer + self.root + short)
        indices, leaf_addr = parse_digest(digest)

        # FORS verification
        fors_roots = []
        for t in range(FORS_TREES):
            idx = indices[t]
            sec = signature[at : at + N]
            at += N
            cur = H(self.public, tweak(KIND_FEW_LEAF, 0, leaf_addr, t, 0, idx), sec)
            for level in range(1, FORS_HEIGHT + 1):
                sib = signature[at : at + N]
                at += N
                pair = cur + sib if idx % 2 == 0 else sib + cur
                idx //= 2
                cur = H(self.public, tweak(KIND_FEW_NODE, 0, leaf_addr, t, level, idx), pair)
            fors_roots.append(cur)
        node = H(self.public, tweak(KIND_FEW_ROOT, 0, leaf_addr), b"".join(fors_roots))

        # Hypertree verification
        addr = leaf_addr
        for layer in range(LAYERS):
            height = TOP_HEIGHT if layer == LAYERS - 1 else LOWER_HEIGHT
            leaf = addr & ((1 << height) - 1)
            tree = addr >> height
            ds = digits(node)
            ends = []
            for c, d in enumerate(ds):
                val = signature[at : at + N]
                at += N
                ends.append(chain(self.public, layer, tree, leaf, c, val, d, CHAIN_STEPS - d))
            cur = H(self.public, tweak(KIND_ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))
            idx = leaf
            for level in range(1, height + 1):
                sib = signature[at : at + N]
                at += N
                pair = cur + sib if idx % 2 == 0 else sib + cur
                idx //= 2
                cur = H(self.public, tweak(KIND_NODE, layer, tree, 0, level, idx), pair)
            node = cur
            addr = tree
        return at == SIGNATURE_LEN and node == self.root


class SigningKey:
    def __init__(self, seed):
        seed = _check_len("seed", seed, 32)
        self.secret = blake3.derive_key(CTX_SECRET_VALUES, seed)
        self.salt_key = blake3.derive_key(CTX_CONTENT_SALT, seed)
        self.randomizer_key = blake3.derive_key(CTX_RANDOMIZER, seed)
        public_seed = blake3.derive_key(CTX_PUBLIC_SEED, seed)[:N]
        self.public = blake3.derive_key(CTX_PUBLIC_HASH, public_seed)

        top_n = 1 << TOP_HEIGHT
        workers = min(os.cpu_count() or 1, 12)
        if workers > 1:
            chunk = 512
            tasks = [(self.secret, self.public, LAYERS - 1, 0, start, chunk) for start in range(0, top_n, chunk)]
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
                top_leaves = [leaf for batch in ex.map(_wots_leaf_range, tasks) for leaf in batch]
        else:
            top_leaves = _wots_leaf_range((self.secret, self.public, LAYERS - 1, 0, 0, top_n))
        self.top_levels = merkle_tree(self.public, KIND_NODE, LAYERS - 1, 0, 0, top_leaves)
        self.verifying_key = VerifyingKey(public_seed + self.top_levels[-1][0])

    def sign(self, message, draw_bytes):
        draw_bytes = _check_len("draw", draw_bytes, 32)
        public, vk = self.public, self.verifying_key
        salt = blake3.keyed_hash(self.salt_key, draw_bytes)[:N]
        short = content(vk.content_key, salt, message)
        randomizer = blake3.keyed_hash(self.randomizer_key, short)[:N]
        digest = blake3.keyed_hash(public, tweak(KIND_MESSAGE) + randomizer + vk.root + short)
        indices, leaf_addr = parse_digest(digest)

        out = bytearray(salt + randomizer)

        # FORS signature
        fors_roots = []
        for t in range(FORS_TREES):
            secs = [H(self.secret, tweak(KIND_FEW_SECRET, 0, leaf_addr, t, 0, i)) for i in range(1 << FORS_HEIGHT)]
            leaves = [H(public, tweak(KIND_FEW_LEAF, 0, leaf_addr, t, 0, i), secs[i]) for i in range(1 << FORS_HEIGHT)]
            levels = merkle_tree(public, KIND_FEW_NODE, 0, leaf_addr, t, leaves)
            idx = indices[t]
            out += secs[idx]
            for level in range(FORS_HEIGHT):
                out += levels[level][(idx >> level) ^ 1]
            fors_roots.append(levels[-1][0])
        node = H(public, tweak(KIND_FEW_ROOT, 0, leaf_addr), b"".join(fors_roots))

        # Hypertree signature
        addr = leaf_addr
        for layer in range(LAYERS):
            height = TOP_HEIGHT if layer == LAYERS - 1 else LOWER_HEIGHT
            leaf = addr & ((1 << height) - 1)
            tree = addr >> height
            if layer == LAYERS - 1:
                levels = self.top_levels
            else:
                leaves = [one_time_leaf(self.secret, public, layer, tree, i) for i in range(1 << height)]
                levels = merkle_tree(public, KIND_NODE, layer, tree, 0, leaves)
            ds = digits(node)
            for c, d in enumerate(ds):
                s = H(self.secret, tweak(KIND_CHAIN_SECRET, layer, tree, leaf, c, 0))
                out += chain(public, layer, tree, leaf, c, s, 0, d)
            for level in range(height):
                out += levels[level][(leaf >> level) ^ 1]
            node = levels[-1][0]
            addr = tree

        assert len(out) == SIGNATURE_LEN
        return bytes(out)


def _cli():
    args = sys.argv[1:]
    if len(args) == 5 and args[0] == "sign":
        seed, draw_bytes = bytes.fromhex(args[1]), bytes.fromhex(args[2])
        msg = open(args[3], "rb").read()
        sk = SigningKey(seed)
        sig = sk.sign(msg, draw_bytes)
        open(args[4], "wb").write(sig)
        print(f"verifying_key: {sk.verifying_key.bytes.hex()}")
        print(f"signature:     {len(sig)} bytes -> {args[4]}")
    elif len(args) == 4 and args[0] == "verify":
        vk = VerifyingKey(bytes.fromhex(args[1]))
        msg = open(args[2], "rb").read()
        sig = open(args[3], "rb").read()
        ok = vk.verify(msg, sig)
        print("OK" if ok else "INVALID")
        sys.exit(0 if ok else 1)
    else:
        print("usage: blincs.py sign <seed-hex> <draw-hex> <msg-file> <sig-out>")
        print("       blincs.py verify <vk-hex> <msg-file> <sig-file>")
        sys.exit(2)


if __name__ == "__main__":
    _cli()

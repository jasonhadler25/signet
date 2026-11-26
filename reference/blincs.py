#!/usr/bin/env python3
"""BLINCS-128-7x5 — educational / vector-conformance reference implementation from SPEC.md.

NOT FOR PRODUCTION USE: pure Python, reads whole messages into RAM, and the CLI accepts test seeds
on argv (never pass real signing seeds on command lines). Self-contained except reference/blake3.py.
"""

import hmac
import sys

import blake3

SUITE_NAME = "BLINCS-128-7x5"
MAX_CONTEXT_LEN = 255

N = 16
LAYERS, TREE_HEIGHT = 7, 5
W, CHAIN_STEPS, MSG_CHAINS, CSUM_CHAINS, CHAINS = 16, 15, 32, 3, 35
FORS_HEIGHT, FORS_TREES = 8, 20
HYPER_BITS = LAYERS * TREE_HEIGHT
FORS_LEN = FORS_TREES * (1 + FORS_HEIGHT) * N
LAYER_LEN = (CHAINS + TREE_HEIGHT) * N
IMPRINT_LEN = 2 * N + FORS_LEN + LAYERS * LAYER_LEN

# Key-derivation contexts (SPEC.md, "Key-derivation contexts").
CTX_SECRET_VALUES = "BLINCS-128-7x5 2026-11-25 secret values"
CTX_CONTENT_SALT = "BLINCS-128-7x5 2026-11-25 content salt"
CTX_RANDOMIZER = "BLINCS-128-7x5 2026-11-25 randomizer"
CTX_PUBLIC_SEED = "BLINCS-128-7x5 2026-11-25 public seed"
CTX_PUBLIC_HASH = "BLINCS-128-7x5 2026-11-25 public hash"
CTX_CONTENT = "BLINCS-128-7x5 2026-11-25 content"
CTX_GENERATE_SIGNET = "Signet BLINCS-128-7x5 2026-11-25 generate signet"
CTX_MIX = "Signet 2026-11-25 randomness: mix"
CTX_NEXT_SEED = "Signet 2026-11-25 randomness: next seed"
CTX_RUN_KEY = "Signet 2026-11-25 randomness: key of this run"
CTX_KEYGEN_KEY = "Signet 2026-11-25 randomness: keygen key"

# Tweak kinds (SPEC.md, "Tweaks").
KIND_CHAIN_SECRET, KIND_CHAIN, KIND_ONE_TIME_KEY, KIND_NODE = 1, 2, 3, 4
KIND_FEW_SECRET, KIND_FEW_LEAF, KIND_FEW_NODE, KIND_FEW_ROOT = 5, 6, 7, 8
KIND_MESSAGE = 9


def _to_bytes(name, value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)


def _check_len(name, value, expected):
    out = _to_bytes(name, value)
    if len(out) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(out)}")
    return out


def frame_context(ctx):
    ctx = _to_bytes("ctx", ctx)
    if len(ctx) > MAX_CONTEXT_LEN:
        raise ValueError(f"context length {len(ctx)} exceeds {MAX_CONTEXT_LEN} bytes")
    return bytes([len(ctx)]) + ctx


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
    """20 byte-aligned FORS leaf indices (digest[:20]) and 35-bit leaf address (digest[20:28])."""
    indices = list(digest[:FORS_TREES])
    leaf_addr = int.from_bytes(digest[20:28], "little") & ((1 << HYPER_BITS) - 1)
    return indices, leaf_addr


def one_time_leaf(secret, public, layer, tree, leaf):
    ends = []
    for c in range(CHAINS):
        s = H(secret, tweak(KIND_CHAIN_SECRET, layer, tree, leaf, c, 0))
        ends.append(chain(public, layer, tree, leaf, c, s, 0, CHAIN_STEPS))
    return H(public, tweak(KIND_ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))


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


def content_framed(content_key, salt, framed_ctx, message):
    msg_key = blake3.keyed_hash(content_key, salt + framed_ctx)
    return salt + blake3.keyed_hash(msg_key, message)


def content(content_key, salt, ctx, message):
    return content_framed(content_key, salt, frame_context(ctx), message)


def generate_seed(local, os_bytes):
    local = _check_len("local", local, 32)
    os_bytes = _check_len("os", os_bytes, 32)
    return blake3.derive_key(CTX_GENERATE_SIGNET, local + os_bytes)


def mix_pool(prior_salt, system, pid, clock):
    system = _check_len("system", system, 32)
    clock = _to_bytes("clock", clock)
    if not isinstance(pid, int) or isinstance(pid, bool) or not (0 <= pid < 1 << 32):
        raise ValueError("pid must be a u32")
    if prior_salt is None:
        prefix = b"\x00"
    else:
        prior = _check_len("prior_salt", prior_salt, 32)
        prefix = bytes([32]) + prior
    material = prefix + system + pid.to_bytes(4, "little") + clock
    return blake3.derive_key(CTX_MIX, material)


def expand_pool(pool):
    pool = _check_len("pool", pool, 32)
    return (
        blake3.derive_key(CTX_NEXT_SEED, pool),
        blake3.derive_key(CTX_RUN_KEY, pool),
        blake3.derive_key(CTX_KEYGEN_KEY, pool),
    )


def draw(key, count):
    key = _check_len("key", key, 32)
    if not isinstance(count, int) or isinstance(count, bool) or not (0 <= count < 1 << 64):
        raise ValueError("count must be a u64")
    return blake3.keyed_hash(key, count.to_bytes(8, "little"))


class SignetId:
    def __init__(self, id_bytes):
        id_bytes = _check_len("signet id", id_bytes, 2 * N)
        self.bytes = id_bytes
        self.public_seed, self.root = id_bytes[:N], id_bytes[N:]
        self.public = blake3.derive_key(CTX_PUBLIC_HASH, self.public_seed)
        self.content_key = blake3.derive_key(CTX_CONTENT, self.bytes)

    def verify(self, ctx, message, imprint):
        framed_ctx = frame_context(ctx)
        message = _to_bytes("message", message)
        imprint = _to_bytes("imprint", imprint)
        if len(imprint) != IMPRINT_LEN:
            return False
        salt, randomizer, at = imprint[:N], imprint[N : 2 * N], 2 * N
        short = content_framed(self.content_key, salt, framed_ctx, message)
        digest = blake3.keyed_hash(self.public, tweak(KIND_MESSAGE) + randomizer + self.root + short + framed_ctx)
        indices, leaf_addr = parse_digest(digest)

        # FORS verification (20 trees x 256 leaves)
        fors_roots = []
        for t in range(FORS_TREES):
            idx = indices[t]
            sec = imprint[at : at + N]
            at += N
            cur = H(self.public, tweak(KIND_FEW_LEAF, 0, leaf_addr, t, 0, idx), sec)
            for level in range(1, FORS_HEIGHT + 1):
                sib = imprint[at : at + N]
                at += N
                pair = cur + sib if idx % 2 == 0 else sib + cur
                idx //= 2
                cur = H(self.public, tweak(KIND_FEW_NODE, 0, leaf_addr, t, level, idx), pair)
            fors_roots.append(cur)
        node = H(self.public, tweak(KIND_FEW_ROOT, 0, leaf_addr), b"".join(fors_roots))

        # Hypertree verification (7 uniform height-5 layers)
        addr = leaf_addr
        for layer in range(LAYERS):
            leaf = addr & ((1 << TREE_HEIGHT) - 1)
            tree = addr >> TREE_HEIGHT
            ds = digits(node)
            ends = []
            for c, d in enumerate(ds):
                val = imprint[at : at + N]
                at += N
                ends.append(chain(self.public, layer, tree, leaf, c, val, d, CHAIN_STEPS - d))
            cur = H(self.public, tweak(KIND_ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))
            idx = leaf
            for level in range(1, TREE_HEIGHT + 1):
                sib = imprint[at : at + N]
                at += N
                pair = cur + sib if idx % 2 == 0 else sib + cur
                idx //= 2
                cur = H(self.public, tweak(KIND_NODE, layer, tree, 0, level, idx), pair)
            node = cur
            addr = tree
        return at == IMPRINT_LEN and hmac.compare_digest(node, self.root)


class Signet:
    def __init__(self, seed):
        seed = _check_len("seed", seed, 32)
        self.secret = blake3.derive_key(CTX_SECRET_VALUES, seed)
        self.salt_key = blake3.derive_key(CTX_CONTENT_SALT, seed)
        self.randomizer_key = blake3.derive_key(CTX_RANDOMIZER, seed)
        public_seed = blake3.derive_key(CTX_PUBLIC_SEED, seed)[:N]
        self.public = blake3.derive_key(CTX_PUBLIC_HASH, public_seed)

        top_leaves = [one_time_leaf(self.secret, self.public, LAYERS - 1, 0, leaf) for leaf in range(1 << TREE_HEIGHT)]
        self.top_levels = merkle_tree(self.public, KIND_NODE, LAYERS - 1, 0, 0, top_leaves)
        self.id = SignetId(public_seed + self.top_levels[-1][0])

    def imprint(self, ctx, message, draw_bytes):
        framed_ctx = frame_context(ctx)
        message = _to_bytes("message", message)
        draw_bytes = _check_len("draw", draw_bytes, 32)
        public, sid = self.public, self.id
        salt = blake3.keyed_hash(self.salt_key, draw_bytes)[:N]
        short = content_framed(sid.content_key, salt, framed_ctx, message)
        randomizer = blake3.keyed_hash(self.randomizer_key, short + framed_ctx)[:N]
        digest = blake3.keyed_hash(public, tweak(KIND_MESSAGE) + randomizer + sid.root + short + framed_ctx)
        indices, leaf_addr = parse_digest(digest)

        out = bytearray(salt + randomizer)

        # FORS imprint (20 trees x 256 leaves)
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

        # Hypertree imprint (7 uniform height-5 layers)
        addr = leaf_addr
        for layer in range(LAYERS):
            leaf = addr & ((1 << TREE_HEIGHT) - 1)
            tree = addr >> TREE_HEIGHT
            if layer == LAYERS - 1:
                levels = self.top_levels
            else:
                leaves = [one_time_leaf(self.secret, public, layer, tree, i) for i in range(1 << TREE_HEIGHT)]
                levels = merkle_tree(public, KIND_NODE, layer, tree, 0, leaves)
            for c, d in enumerate(digits(node)):
                s = H(self.secret, tweak(KIND_CHAIN_SECRET, layer, tree, leaf, c, 0))
                out += chain(public, layer, tree, leaf, c, s, 0, d)
            for level in range(TREE_HEIGHT):
                out += levels[level][(leaf >> level) ^ 1]
            node = levels[-1][0]
            addr = tree
        if len(out) != IMPRINT_LEN:
            raise RuntimeError(f"unexpected imprint length {len(out)}")
        return bytes(out)


def main(argv):
    if len(argv) == 6 and argv[1] == "verify":
        sid = SignetId(bytes.fromhex(argv[2]))
        ctx = bytes.fromhex(argv[3])
        msg = open(argv[4], "rb").read()
        imp = open(argv[5], "rb").read()
        ok = sid.verify(ctx, msg, imp)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1
    if len(argv) == 7 and argv[1] == "imprint":
        signet = Signet(bytes.fromhex(argv[2]))
        draw_bytes = bytes.fromhex(argv[3])
        ctx = bytes.fromhex(argv[4])
        msg = open(argv[5], "rb").read()
        imp = signet.imprint(ctx, msg, draw_bytes)
        open(argv[6], "wb").write(imp)
        print(signet.id.bytes.hex())
        return 0
    print(f"usage: {argv[0]} verify <signet_id_hex> <ctx_hex> <msg_path> <imprint_path>", file=sys.stderr)
    print(f"       {argv[0]} imprint <test_seed_hex> <draw_hex> <ctx_hex> <msg_path> <imprint_out_path>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

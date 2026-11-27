#!/usr/bin/env python3
"""BLINCS-128-A2 — educational / vector-conformance reference implementation from SPEC.md.

NOT FOR PRODUCTION USE: pure Python, reads whole messages into RAM, and the CLI accepts test seeds
on argv (never pass real signing seeds on command lines). Self-contained except reference/blake3.py.
"""

import hmac
import sys

import blake3

SUITE_NAME = "BLINCS-128-A2"
MAX_CONTEXT_LEN = 255

N = 16
LAYERS = 4
LOW_HEIGHT, TOP_HEIGHT = 7, 12
LOW_LEAVES, TOP_LEAVES = 1 << LOW_HEIGHT, 1 << TOP_HEIGHT
HYPER_BITS = 3 * LOW_HEIGHT + TOP_HEIGHT  # 33

WOTS_N, WOTS_W, WOTS_STEPS, WOTS_SUM, WOTS_CTR_LEN = 24, 40, 39, 468, 2
UPORS_HEIGHT, UPORS_LEAVES = 10, 1024
UPORS_N, UPORS_W, UPORS_STEPS, UPORS_SUM, UPORS_C = 3, 24, 23, 42, 376
UPORS_K, UPORS_M_MAX, UPORS_CTR_LEN = 10, 44, 4
UPORS_LAYER, UPORS_SELECT_MAX_DRAWS = 0x80, 22

UPORS_LEN = UPORS_CTR_LEN + (UPORS_K * UPORS_N + UPORS_M_MAX) * N  # 1188
LOW_LAYER_LEN = WOTS_CTR_LEN + (WOTS_N + LOW_HEIGHT) * N  # 498
TOP_LAYER_LEN = WOTS_CTR_LEN + (WOTS_N + TOP_HEIGHT) * N  # 578
IMPRINT_LEN = 2 * N + UPORS_LEN + 3 * LOW_LAYER_LEN + TOP_LAYER_LEN  # 3292

# Key-derivation contexts (SPEC.md, "Key-derivation contexts").
CTX_SECRET_VALUES = "BLINCS-128-A2 2026-11-26 secret values"
CTX_CONTENT_SALT = "BLINCS-128-A2 2026-11-26 content salt"
CTX_RANDOMIZER = "BLINCS-128-A2 2026-11-26 randomizer"
CTX_PUBLIC_SEED = "BLINCS-128-A2 2026-11-26 public seed"
CTX_PUBLIC_HASH = "BLINCS-128-A2 2026-11-26 public hash"
CTX_CONTENT = "BLINCS-128-A2 2026-11-26 content"
CTX_GENERATE_SIGNET = "Signet BLINCS-128-A2 2026-11-26 generate signet"
CTX_MIX = "Signet 2026-11-26 randomness: mix"
CTX_NEXT_SEED = "Signet 2026-11-26 randomness: next seed"
CTX_RUN_KEY = "Signet 2026-11-26 randomness: key of this run"
CTX_KEYGEN_KEY = "Signet 2026-11-26 randomness: keygen key"

# Tweak kinds (SPEC.md, "Tweaks").
KIND_CHAIN_SECRET, KIND_CHAIN, KIND_ONE_TIME_KEY, KIND_NODE = 1, 2, 3, 4
KIND_ONE_TIME_MSG, KIND_MESSAGE, KIND_FEW_SELECT, KIND_FEW_CODE = 5, 6, 7, 8


def _build_sperner_dp():
    dp = [[0] * (WOTS_SUM + 1) for _ in range(WOTS_N + 1)]
    dp[0][0] = 1
    for k in range(1, WOTS_N + 1):
        acc = 0
        prev = dp[k - 1]
        cur = dp[k]
        for s in range(WOTS_SUM + 1):
            acc += prev[s]
            if s >= WOTS_W:
                acc -= prev[s - WOTS_W]
            cur[s] = acc
    return dp


_SPERNER_DP = _build_sperner_dp()


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


def read_bits(digest, bit_off, width):
    val = int.from_bytes(digest, "little")
    return (val >> bit_off) & ((1 << width) - 1)


def hex_unrank(idx):
    """Map idx in 0..376 bijectively to (a, b, c) in {0..23}^3 with a + b + c = 42."""
    if not (0 <= idx < UPORS_C):
        raise ValueError(f"hex_unrank index {idx} out of range")
    rem_idx = idx
    for a in range(UPORS_STEPS + 1):
        rem = UPORS_SUM - a
        if rem < 0:
            break
        b_lo = max(0, rem - UPORS_STEPS)
        b_hi = min(rem, UPORS_STEPS)
        if b_hi < b_lo:
            continue
        length = b_hi - b_lo + 1
        if rem_idx < length:
            b = b_lo + rem_idx
            return (a, b, rem - b)
        rem_idx -= length
    raise RuntimeError("hex_unrank exhausted")


def sperner_unrank(rank):
    """Map 120-bit rank injectively into L_468(24, 40)."""
    if not (0 <= rank < _SPERNER_DP[WOTS_N][WOTS_SUM]):
        raise ValueError("Sperner rank out of range")
    out = []
    rem = WOTS_SUM
    for i in range(WOTS_N):
        k_rem = WOTS_N - 1 - i
        row = _SPERNER_DP[k_rem]
        for d in range(min(rem, WOTS_STEPS) + 1):
            cnt = row[rem - d]
            if rank < cnt:
                out.append(d)
                rem -= d
                break
            rank -= cnt
    return out


def count_octopus_sibs(sorted_leaves):
    cur = list(sorted_leaves)
    sibs = 0
    for _ in range(UPORS_HEIGHT):
        nxt = []
        i = 0
        while i < len(cur):
            x = cur[i]
            if i + 1 < len(cur) and (x ^ 1) == cur[i + 1]:
                nxt.append(x >> 1)
                i += 2
            else:
                sibs += 1
                nxt.append(x >> 1)
                i += 1
        cur = nxt
    return sibs


def parse_select_digest(digest):
    leaves = []
    seen = set()
    for i in range(UPORS_SELECT_MAX_DRAWS):
        x = read_bits(digest, i * UPORS_HEIGHT, UPORS_HEIGHT)
        if x not in seen:
            seen.add(x)
            leaves.append(x)
            if len(leaves) == UPORS_K:
                break
    if len(leaves) < UPORS_K:
        return None
    leaves.sort()
    sibs = count_octopus_sibs(leaves)
    if sibs > UPORS_M_MAX:
        return None
    leaf_addr = read_bits(digest, UPORS_SELECT_MAX_DRAWS * UPORS_HEIGHT, HYPER_BITS)
    return leaf_addr, leaves, sibs


def extract_upors_codewords(public, d_seed, ctr_ft):
    out = []
    block_idx = 0
    tail = d_seed + ctr_ft.to_bytes(4, "little")
    while len(out) < UPORS_K:
        blk = blake3.keyed_hash(public, tweak(KIND_FEW_CODE, UPORS_LAYER, 0, 0, block_idx, 0) + tail)
        for j in range(28):
            v = read_bits(blk, j * 9, 9)
            if v < UPORS_C:
                out.append(hex_unrank(v))
                if len(out) == UPORS_K:
                    break
        block_idx += 1
    return out


def chain_leaf(secret, public, layer, tree, leaf, num_chains, max_steps):
    ends = []
    for c in range(num_chains):
        slot = leaf * num_chains + c
        s = H(secret, tweak(KIND_CHAIN_SECRET, layer, tree, 0, 0, slot))
        ends.append(chain(public, layer, tree, leaf, c, s, 0, max_steps))
    return H(public, tweak(KIND_ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))


def merkle_tree(public, layer, tree, leaves):
    levels = [list(leaves)]
    level = 1
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [
            H(public, tweak(KIND_NODE, layer, tree, 0, level, p), cur[2 * p] + cur[2 * p + 1])
            for p in range(len(cur) // 2)
        ]
        levels.append(nxt)
        level += 1
    return levels


def verify_merkle_path(public, layer, tree, height, leaf, cur, auth_bytes):
    idx = leaf
    for level in range(1, height + 1):
        sib = auth_bytes[(level - 1) * N : level * N]
        pair = cur + sib if idx % 2 == 0 else sib + cur
        idx //= 2
        cur = H(public, tweak(KIND_NODE, layer, tree, 0, level, idx), pair)
    return cur


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
        d_seed = blake3.keyed_hash(self.public, tweak(KIND_MESSAGE) + randomizer + self.root + short + framed_ctx)

        # U-PORS verification (height-10 single tree + Octopus multi-proof)
        ctr_ft = int.from_bytes(imprint[at : at + UPORS_CTR_LEN], "little")
        at += UPORS_CTR_LEN
        d_sel = blake3.keyed_hash(self.public, tweak(KIND_FEW_SELECT, UPORS_LAYER) + d_seed + ctr_ft.to_bytes(4, "little"))
        parsed = parse_select_digest(d_sel)
        if parsed is None:
            return False
        leaf_addr, leaves, expected_sibs = parsed
        codewords = extract_upors_codewords(self.public, d_seed, ctr_ft)

        cur_val = []
        for leaf, cw in zip(leaves, codewords):
            ends = []
            for c, d in enumerate(cw):
                val = imprint[at : at + N]
                at += N
                ends.append(chain(self.public, UPORS_LAYER, leaf_addr, leaf, c, val, d, UPORS_STEPS - d))
            cur_val.append(H(self.public, tweak(KIND_ONE_TIME_KEY, UPORS_LAYER, leaf_addr, leaf), b"".join(ends)))

        octo_bytes = imprint[at : at + UPORS_M_MAX * N]
        at += UPORS_M_MAX * N
        cur_idx = list(leaves)
        sib_cursor = 0
        for level in range(1, UPORS_HEIGHT + 1):
            nxt_idx, nxt_val = [], []
            i = 0
            while i < len(cur_idx):
                x = cur_idx[i]
                p = x >> 1
                tw = tweak(KIND_NODE, UPORS_LAYER, leaf_addr, 0, level, p)
                if i + 1 < len(cur_idx) and (x ^ 1) == cur_idx[i + 1]:
                    pair = cur_val[i] + cur_val[i + 1]
                    i += 2
                else:
                    sib = octo_bytes[sib_cursor * N : (sib_cursor + 1) * N]
                    sib_cursor += 1
                    pair = cur_val[i] + sib if (x & 1) == 0 else sib + cur_val[i]
                    i += 1
                nxt_idx.append(p)
                nxt_val.append(H(self.public, tw, pair))
            cur_idx, cur_val = nxt_idx, nxt_val
        if sib_cursor != expected_sibs:
            return False
        pad = octo_bytes[sib_cursor * N :]
        if not hmac.compare_digest(pad, bytes(len(pad))):
            return False
        node = cur_val[0]

        # Hypertree verification (12+7+7+7 S-WOTS+Z)
        addr = leaf_addr
        for layer in range(LAYERS):
            h_l = TOP_HEIGHT if layer == 3 else LOW_HEIGHT
            leaf = addr & ((1 << h_l) - 1)
            tree = addr >> h_l
            ctr_l = int.from_bytes(imprint[at : at + WOTS_CTR_LEN], "little")
            at += WOTS_CTR_LEN
            h_msg = blake3.keyed_hash(
                self.public,
                tweak(KIND_ONE_TIME_MSG, layer, tree, leaf) + node + ctr_l.to_bytes(4, "little"),
            )
            if h_msg[0] != 0:
                return False
            rank = int.from_bytes(h_msg[1:16], "little")
            ds = sperner_unrank(rank)
            ends = []
            for c, d in enumerate(ds):
                val = imprint[at : at + N]
                at += N
                ends.append(chain(self.public, layer, tree, leaf, c, val, d, WOTS_STEPS - d))
            cur = H(self.public, tweak(KIND_ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))
            auth = imprint[at : at + h_l * N]
            at += h_l * N
            node = verify_merkle_path(self.public, layer, tree, h_l, leaf, cur, auth)
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

        top_leaves = [chain_leaf(self.secret, self.public, 3, 0, leaf, WOTS_N, WOTS_STEPS) for leaf in range(TOP_LEAVES)]
        self.top_levels = merkle_tree(self.public, 3, 0, top_leaves)
        self.id = SignetId(public_seed + self.top_levels[-1][0])

    def imprint(self, ctx, message, draw_bytes):
        framed_ctx = frame_context(ctx)
        message = _to_bytes("message", message)
        draw_bytes = _check_len("draw", draw_bytes, 32)
        public, sid = self.public, self.id
        salt = blake3.keyed_hash(self.salt_key, draw_bytes)[:N]
        short = content_framed(sid.content_key, salt, framed_ctx, message)
        randomizer = blake3.keyed_hash(self.randomizer_key, short + framed_ctx)[:N]
        d_seed = blake3.keyed_hash(public, tweak(KIND_MESSAGE) + randomizer + sid.root + short + framed_ctx)

        ctr_ft = 0
        while True:
            d_sel = blake3.keyed_hash(public, tweak(KIND_FEW_SELECT, UPORS_LAYER) + d_seed + ctr_ft.to_bytes(4, "little"))
            parsed = parse_select_digest(d_sel)
            if parsed is not None:
                leaf_addr, leaves, _ = parsed
                break
            ctr_ft += 1
        codewords = extract_upors_codewords(public, d_seed, ctr_ft)

        out = bytearray(salt + randomizer + ctr_ft.to_bytes(4, "little"))

        # U-PORS tree + Octopus siblings
        upors_leaves = [chain_leaf(self.secret, public, UPORS_LAYER, leaf_addr, i, UPORS_N, UPORS_STEPS) for i in range(UPORS_LEAVES)]
        upors_levels = merkle_tree(public, UPORS_LAYER, leaf_addr, upors_leaves)
        for leaf, cw in zip(leaves, codewords):
            for c, d in enumerate(cw):
                s = H(self.secret, tweak(KIND_CHAIN_SECRET, UPORS_LAYER, leaf_addr, 0, 0, leaf * UPORS_N + c))
                out += chain(public, UPORS_LAYER, leaf_addr, leaf, c, s, 0, d)
        cur_idx = list(leaves)
        octo_sibs = []
        for level in range(UPORS_HEIGHT):
            nxt = []
            i = 0
            while i < len(cur_idx):
                x = cur_idx[i]
                if i + 1 < len(cur_idx) and (x ^ 1) == cur_idx[i + 1]:
                    nxt.append(x >> 1)
                    i += 2
                else:
                    octo_sibs.append(upors_levels[level][x ^ 1])
                    nxt.append(x >> 1)
                    i += 1
            cur_idx = nxt
        for s in octo_sibs:
            out += s
        out += bytes((UPORS_M_MAX - len(octo_sibs)) * N)
        node = upors_levels[-1][0]

        # Hypertree 12+7+7+7 S-WOTS+Z
        addr = leaf_addr
        for layer in range(LAYERS):
            h_l = TOP_HEIGHT if layer == 3 else LOW_HEIGHT
            leaf = addr & ((1 << h_l) - 1)
            tree = addr >> h_l
            ctr_l = 0
            while True:
                h_msg = blake3.keyed_hash(public, tweak(KIND_ONE_TIME_MSG, layer, tree, leaf) + node + ctr_l.to_bytes(4, "little"))
                if h_msg[0] == 0:
                    rank = int.from_bytes(h_msg[1:16], "little")
                    break
                ctr_l += 1
            out += ctr_l.to_bytes(2, "little")
            for c, d in enumerate(sperner_unrank(rank)):
                s = H(self.secret, tweak(KIND_CHAIN_SECRET, layer, tree, 0, 0, leaf * WOTS_N + c))
                out += chain(public, layer, tree, leaf, c, s, 0, d)
            if layer == 3:
                levels = self.top_levels
            else:
                layer_leaves = [chain_leaf(self.secret, public, layer, tree, i, WOTS_N, WOTS_STEPS) for i in range(LOW_LEAVES)]
                levels = merkle_tree(public, layer, tree, layer_leaves)
            for level in range(h_l):
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

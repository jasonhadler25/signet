"""BLINCS in plain Python: the reference that the Rust implementation is checked against.

It follows SPEC.md section by section and favours the shortest correct statement of each rule over speed:
it builds every tree whole, searches every counter from zero, and finds the merged authentication set by
walking the tree. It shares no code with the Rust implementation, and its BLAKE3 is `blake3.py` beside it.

The command-line interface is a deterministic test-vector tool (passing seeds on the command line and
reading whole files into memory), not a production signer:

    python3 reference/blincs.py verify <verifying key, hex> <message file> <signature file>
    python3 reference/blincs.py sign <seed, hex> <draw, hex> <message file> <signature file>
    python3 reference/blincs.py verifying-key <seed, hex>

Signing takes about a minute and loading a signing key about ten seconds; verifying takes a fraction of a second.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blake3

# --- Parameters (SPEC.md, "Parameters") ---------------------------------------------------------------
N = 16  # bytes of every hash value in a key or a signature
LAYERS, TREE_HEIGHT = 4, 9  # the hypertree: four layers of trees with 2^9 leaves
CHAINS, CHAIN_STEPS, ZERO_BITS, DIGIT_SUM = 24, 31, 8, 372  # one-time signatures
FEW_HEIGHT, OPENED, AUTH_NODES, THRESHOLD_BITS = 15, 11, 103, 6  # few-time signatures
HYPER_BITS = LAYERS * TREE_HEIGHT
FEW_LEN = 4 + N * (OPENED + AUTH_NODES)
LAYER_LEN = 4 + N * (CHAINS + TREE_HEIGHT)
SIGNATURE_LEN = 2 * N + FEW_LEN + LAYERS * LAYER_LEN
assert SIGNATURE_LEN == 3988

# --- Key-derivation contexts ---------------------------------------------------------------------------
SECRET_VALUES = "BLINCS 2026-11-23 signing key: secret values"
CONTENT_SALT = "BLINCS 2026-11-23 signing key: content salt"
RANDOMIZER = "BLINCS 2026-11-23 signing key: randomizer"
PUBLIC_SEED = "BLINCS 2026-11-23 signing key: public seed"
PUBLIC_HASH = "BLINCS 2026-11-23 public hash"
CONTENT = "BLINCS 2026-11-23 content"
MIX = "BLINCS 2026-11-23 randomness: mix"
NEXT_SEED = "BLINCS 2026-11-23 randomness: seed kept in the file"
RUN_KEY = "BLINCS 2026-11-23 randomness: key of this run"

# --- Tweaks (SPEC.md, "Tweaks") --------------------------------------------------------------------------
CHAIN_SECRET, CHAIN, ONE_TIME_KEY, ONE_TIME_MESSAGE, NODE, FEW_SECRET, FEW_LEAF, FEW_NODE, MESSAGE, PICK = range(1, 11)


def tweak(kind, layer=0, tree=0, leaf=0, a=0, b=0):
    return bytes([kind, layer]) + tree.to_bytes(6, "little") + leaf.to_bytes(2, "little") + a.to_bytes(2, "little") + b.to_bytes(4, "little")


def short_hash(key, tweak_bytes, data=b""):
    """The 16-byte tweakable hash every tree and chain is made of."""
    return blake3.keyed_words(key, tweak_bytes + data)[:N]


# --- Content (SPEC.md, "Content") ------------------------------------------------------------------------
def content(content_key, salt, message):
    """What the tree part signs for a message: the salt and the keyed BLAKE3 hash of the message."""
    msg_key = blake3.keyed_hash(content_key, salt)
    return salt + blake3.keyed_hash(msg_key, message)


# --- One-time signatures (SPEC.md, "One-time signatures") ----------------------------------------------
def digits(public, layer, tree, leaf, node, counter):
    """The 24 digits `counter` gives for `node`, or None when the digest fails the two tests."""
    digest = int.from_bytes(short_hash(public, tweak(ONE_TIME_MESSAGE, layer, tree, leaf), node + counter.to_bytes(4, "little")), "little")
    if digest % (1 << ZERO_BITS) != 0:
        return None
    found = [(digest >> (ZERO_BITS + 5 * i)) & 31 for i in range(CHAINS)]
    return found if sum(found) == DIGIT_SUM else None


def chain(public, layer, tree, leaf, index, value, start, end):
    for step in range(start, end):
        value = short_hash(public, tweak(CHAIN, layer, tree, leaf, index, step), value)
    return value


def one_time_key(public, layer, tree, leaf, ends):
    return short_hash(public, tweak(ONE_TIME_KEY, layer, tree, leaf), b"".join(ends))


def climb(public, layer, tree, leaf, node, path):
    """The root of a hypertree tree from one leaf and its authentication path."""
    for height, sibling in enumerate(path):
        index = leaf >> height
        pair = node + sibling if index % 2 == 0 else sibling + node
        node = short_hash(public, tweak(NODE, layer, tree, 0, height + 1, index >> 1), pair)
    return node


# --- Few-time signatures (SPEC.md, "Few-time signatures") ----------------------------------------------
def merged_set(indices):
    """The merged authentication set of the opened leaves (`indices`, ascending): the (height, index) of
    each node a verifier needs and cannot compute, bottom level first and left to right within a level."""
    needed, known = [], list(indices)
    for height in range(FEW_HEIGHT):
        parents, i = [], 0
        while i < len(known):
            index = known[i]
            if index % 2 == 0 and i + 1 < len(known) and known[i + 1] == index + 1:
                i += 2  # both children are known
            else:
                needed.append((height, index ^ 1))
                i += 1
            parents.append(index >> 1)
        known = parents
    return needed


def merged_root(public, tree, leaf, indices, leaves, auth):
    """The few-time tree's root from the opened leaves and the nodes of their merged authentication set."""
    supplied = dict(zip(merged_set(indices), auth))
    known = dict(zip(indices, leaves))
    for height in range(FEW_HEIGHT):
        parents = {}
        for index in known:
            left, right = (known[i] if i in known else supplied[(height, i)] for i in (index & ~1, index | 1))
            parents[index >> 1] = short_hash(public, tweak(FEW_NODE, 0, tree, leaf, height + 1, index >> 1), left + right)
        known = parents
    return known[0]


def pick(public, digest, counter):
    """The few-time key and the leaves `counter` picks for `digest`, or None when it fails a test."""
    g = int.from_bytes(blake3.keyed_words(public, tweak(PICK) + digest + counter.to_bytes(4, "little")), "little")
    if g % (1 << THRESHOLD_BITS) != 0:
        return None
    position = (g >> THRESHOLD_BITS) % (1 << HYPER_BITS)
    indices = sorted((g >> (THRESHOLD_BITS + HYPER_BITS + FEW_HEIGHT * j)) % (1 << FEW_HEIGHT) for j in range(OPENED))
    if len(set(indices)) != OPENED or len(merged_set(indices)) > AUTH_NODES:
        return None
    return position, indices


# --- Keys (SPEC.md, "Keys") -----------------------------------------------------------------------------
def _exact_bytes(value, length, name):
    frozen = bytes(value)
    if len(frozen) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(frozen)}")
    return frozen


class VerifyingKey:
    def __init__(self, key_bytes):
        key_bytes = _exact_bytes(key_bytes, 2 * N, "verifying key")
        self.bytes = key_bytes
        self.root = key_bytes[N:]
        self.public = blake3.key_words(blake3.derive_key(PUBLIC_HASH, key_bytes[:N]))
        self.content_key = blake3.derive_key(CONTENT, key_bytes)

    def message_digest(self, randomizer, short):
        return blake3.keyed_words(self.public, tweak(MESSAGE) + randomizer + self.root + short)

    def verify(self, message, signature):
        message = bytes(message)
        signature = bytes(signature)
        if len(signature) != SIGNATURE_LEN:
            return False
        public = self.public
        salt, randomizer, at = signature[:N], signature[N : 2 * N], 2 * N
        short = content(self.content_key, salt, message)
        # The few-time signature.
        counter = int.from_bytes(signature[at : at + 4], "little")
        picked = pick(public, self.message_digest(randomizer, short), counter)
        if picked is None:
            return False
        position, indices = picked
        tree, leaf = position >> TREE_HEIGHT, position % (1 << TREE_HEIGHT)
        values = [signature[at + 4 + N * j :][:N] for j in range(OPENED)]
        auth = [signature[at + 4 + N * (OPENED + j) :][:N] for j in range(AUTH_NODES)]
        leaves = [short_hash(public, tweak(FEW_LEAF, 0, tree, leaf, 0, index), value) for index, value in zip(indices, values)]
        used = len(merged_set(indices))
        if any(auth[j] != bytes(N) for j in range(used, AUTH_NODES)):
            return False  # the places the set leaves unused hold zeros
        node = merged_root(public, tree, leaf, indices, leaves, auth[:used])
        at += FEW_LEN
        # The hypertree, bottom layer first.
        for layer in range(LAYERS):
            counter = int.from_bytes(signature[at : at + 4], "little")
            found = digits(public, layer, tree, leaf, node, counter)
            if found is None:
                return False
            ends = [chain(public, layer, tree, leaf, i, signature[at + 4 + N * i :][:N], found[i], CHAIN_STEPS) for i in range(CHAINS)]
            path = [signature[at + 4 + N * (CHAINS + j) :][:N] for j in range(TREE_HEIGHT)]
            node = climb(public, layer, tree, leaf, one_time_key(public, layer, tree, leaf, ends), path)
            tree, leaf = tree >> TREE_HEIGHT, tree % (1 << TREE_HEIGHT)
            at += LAYER_LEN
        return node == self.root


class SigningKey:
    def __init__(self, seed):
        seed = _exact_bytes(seed, 32, "signing key seed")
        self.secret = blake3.key_words(blake3.derive_key(SECRET_VALUES, seed))
        self.salt_key = blake3.derive_key(CONTENT_SALT, seed)
        self.randomizer_key = blake3.derive_key(RANDOMIZER, seed)
        public_seed = blake3.derive_key(PUBLIC_SEED, seed)[:N]
        self.public = blake3.key_words(blake3.derive_key(PUBLIC_HASH, public_seed))
        self.top = self.tree_levels(LAYERS - 1, 0)
        self.verifying_key = VerifyingKey(public_seed + self.top[TREE_HEIGHT][0])

    def chain_secret(self, layer, tree, leaf, index):
        return short_hash(self.secret, tweak(CHAIN_SECRET, layer, tree, leaf, index))

    def tree_levels(self, layer, tree):
        """Every node of one hypertree tree: levels[height][index]."""
        public, leaves = self.public, []
        for leaf in range(1 << TREE_HEIGHT):
            ends = [chain(public, layer, tree, leaf, i, self.chain_secret(layer, tree, leaf, i), 0, CHAIN_STEPS) for i in range(CHAINS)]
            leaves.append(one_time_key(public, layer, tree, leaf, ends))
        levels = [leaves]
        for height in range(1, TREE_HEIGHT + 1):
            below = levels[-1]
            levels.append([short_hash(public, tweak(NODE, layer, tree, 0, height, i), below[2 * i] + below[2 * i + 1]) for i in range(len(below) // 2)])
        return levels

    def sign(self, draw, message):
        """The signature of `message` with `draw`, the 32 bytes the signer's randomness gives this signature."""
        draw = _exact_bytes(draw, 32, "draw")
        message = bytes(message)
        public, vk = self.public, self.verifying_key
        salt = blake3.keyed_hash(self.salt_key, draw)[:N]
        short = content(vk.content_key, salt, message)
        randomizer = blake3.keyed_hash(self.randomizer_key, short)[:N]
        digest = vk.message_digest(randomizer, short)
        # The few-time signature: the first counter that passes, then the whole tree of that few-time key.
        counter = 0
        while (picked := pick(public, digest, counter)) is None:
            counter += 1
        position, indices = picked
        tree, leaf = position >> TREE_HEIGHT, position % (1 << TREE_HEIGHT)
        secrets = [short_hash(self.secret, tweak(FEW_SECRET, 0, tree, leaf, 0, i)) for i in range(1 << FEW_HEIGHT)]
        levels = [[short_hash(public, tweak(FEW_LEAF, 0, tree, leaf, 0, i), secrets[i]) for i in range(1 << FEW_HEIGHT)]]
        for height in range(1, FEW_HEIGHT + 1):
            below = levels[-1]
            levels.append([short_hash(public, tweak(FEW_NODE, 0, tree, leaf, height, i), below[2 * i] + below[2 * i + 1]) for i in range(len(below) // 2)])
        auth = [levels[height][index] for height, index in merged_set(indices)]
        assert merged_root(public, tree, leaf, indices, [levels[0][i] for i in indices], auth) == levels[FEW_HEIGHT][0]
        node = levels[FEW_HEIGHT][0]
        signature = salt + randomizer + counter.to_bytes(4, "little") + b"".join(secrets[i] for i in indices)
        signature += b"".join(auth) + bytes(N * (AUTH_NODES - len(auth)))
        # The hypertree, bottom layer first.
        for layer in range(LAYERS):
            counter = 0
            while (found := digits(public, layer, tree, leaf, node, counter)) is None:
                counter += 1
            signature += counter.to_bytes(4, "little")
            signature += b"".join(chain(public, layer, tree, leaf, i, self.chain_secret(layer, tree, leaf, i), 0, found[i]) for i in range(CHAINS))
            levels = self.top if layer == LAYERS - 1 else self.tree_levels(layer, tree)
            signature += b"".join(levels[height][(leaf >> height) ^ 1] for height in range(TREE_HEIGHT))
            node = levels[TREE_HEIGHT][0]
            tree, leaf = tree >> TREE_HEIGHT, tree % (1 << TREE_HEIGHT)
        if len(signature) != SIGNATURE_LEN or node != vk.root:
            raise RuntimeError("internal signing invariant failed")
        return signature


# --- The signer's randomness (SPEC.md, "The signer's randomness") --------------------------------------
def mix(seed, count, system, clock):
    """One start of a signer: the seed to keep in the file and the key of this run."""
    seed = _exact_bytes(seed, 32, "seed")
    system = _exact_bytes(system, 32, "system randomness")
    clock = bytes(clock)
    pool = blake3.derive_key(MIX, seed + count.to_bytes(8, "little") + system + clock)
    return blake3.derive_key(NEXT_SEED, pool), blake3.derive_key(RUN_KEY, pool)


def draw(run_key, number):
    run_key = _exact_bytes(run_key, 32, "run key")
    return blake3.keyed_hash(run_key, number.to_bytes(8, "little"))


def main(args):
    if len(args) == 4 and args[0] == "verify":
        key = VerifyingKey(bytes.fromhex(args[1]))
        with open(args[2], "rb") as f:
            message = f.read()
        with open(args[3], "rb") as f:
            signature = f.read()
        ok = key.verify(message, signature)
        print("valid" if ok else "INVALID")
        return 0 if ok else 1
    if len(args) == 5 and args[0] == "sign":
        key = SigningKey(bytes.fromhex(args[1]))
        draw_bytes = bytes.fromhex(args[2])
        with open(args[3], "rb") as f:
            message = f.read()
        signature = key.sign(draw_bytes, message)
        with open(args[4], "wb") as f:
            f.write(signature)
        return 0
    if len(args) == 2 and args[0] == "verifying-key":
        print(SigningKey(bytes.fromhex(args[1])).verifying_key.bytes.hex())
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

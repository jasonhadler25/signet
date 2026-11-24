"""BLAKE3 in plain Python, written from the BLAKE3 specification for BLINCS's reference implementation.

It is independent of the library BLINCS's Rust code calls, so the two implementations of BLINCS share no
hashing code. `python3 reference/blake3.py` checks it against BLAKE3's official test vectors.

It gives the three modes with 32-byte output: `hash`, `keyed_hash`, `derive_key`.
"""

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL = 1, 2, 4, 8, 16, 32, 64
CHUNK_LEN = 1024
PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _compress_source():
    """The compression function as straight-line Python: seven rounds of eight quarter-rounds, the message
    words permuted between rounds. Written out once, at import, because a loop costs CPython several times
    as much per call."""
    lines = [
        "def compress(cv, m, counter, block_len, flags):",
        "    v0, v1, v2, v3, v4, v5, v6, v7 = cv",
        "    v8, v9, v10, v11 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A",
        "    v12, v13, v14, v15 = counter & M, counter >> 32, block_len, flags",
    ]
    order = list(range(16))
    quarter_rounds = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15), (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
    for _ in range(7):
        for i, (a, b, c, d) in enumerate(quarter_rounds):
            x, y = order[2 * i], order[2 * i + 1]
            lines += [
                f"    v{a} = (v{a} + v{b} + m[{x}]) & M",
                f"    t = v{d} ^ v{a}; v{d} = (t >> 16 | t << 16) & M",
                f"    v{c} = (v{c} + v{d}) & M",
                f"    t = v{b} ^ v{c}; v{b} = (t >> 12 | t << 20) & M",
                f"    v{a} = (v{a} + v{b} + m[{y}]) & M",
                f"    t = v{d} ^ v{a}; v{d} = (t >> 8 | t << 24) & M",
                f"    v{c} = (v{c} + v{d}) & M",
                f"    t = v{b} ^ v{c}; v{b} = (t >> 7 | t << 25) & M",
            ]
        order = [order[p] for p in PERMUTATION]
    lines.append("    return (v0 ^ v8, v1 ^ v9, v2 ^ v10, v3 ^ v11, v4 ^ v12, v5 ^ v13, v6 ^ v14, v7 ^ v15)")
    return "\n".join(lines)


_namespace = {"M": 0xFFFFFFFF}
exec(_compress_source(), _namespace)
compress = _namespace["compress"]
"""compress(cv, m, counter, block_len, flags): the first eight words of BLAKE3's compression function, which
are all that 32-byte outputs need. `cv` is eight words, `m` sixteen."""


def _words(block):
    """Sixteen little-endian words from a block of at most 64 bytes, zero-padded."""
    padded = block + bytes(64 - len(block))
    return [int.from_bytes(padded[i : i + 4], "little") for i in range(0, 64, 4)]


def _bytes(words):
    return b"".join(w.to_bytes(4, "little") for w in words)


def _chunk(key, chunk, index, flags, root):
    """The chaining value of one chunk (at most 1024 bytes), or its root output."""
    cv = key
    blocks = [chunk[i : i + 64] for i in range(0, len(chunk), 64)] or [b""]
    for i, block in enumerate(blocks):
        f = flags
        if i == 0:
            f |= CHUNK_START
        if i == len(blocks) - 1:
            f |= CHUNK_END | (ROOT if root else 0)
        cv = compress(cv, _words(block), index, len(block), f)
    return cv


def _subtree(key, data, first_chunk, flags, root):
    """The chaining value of the subtree over `data`, whose first chunk has index `first_chunk`."""
    if len(data) <= CHUNK_LEN:
        return _chunk(key, data, first_chunk, flags, root)
    # The left subtree takes the largest power of two of chunks that leaves at least one byte for the right.
    left_chunks = 1
    while left_chunks * 2 * CHUNK_LEN < len(data):
        left_chunks *= 2
    left = _subtree(key, data[: left_chunks * CHUNK_LEN], first_chunk, flags, False)
    right = _subtree(key, data[left_chunks * CHUNK_LEN :], first_chunk + left_chunks, flags, False)
    return compress(key, left + right, 0, 64, flags | PARENT | (ROOT if root else 0))


def _hash(key, data, flags):
    return _bytes(_subtree(key, bytes(data), 0, flags, True))


def hash(data):
    return _hash(IV, data, 0)


def key_words(key):
    """A 32-byte key as the eight words `keyed_words` takes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes-like")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes, got {len(key)}")
    return tuple(int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4))


def keyed_hash(key, data):
    return _hash(key_words(key), data, KEYED_HASH)


def keyed_words(key, data):
    """`keyed_hash` with the key already as words: what a caller with one key and many messages uses."""
    if len(data) <= 64:  # one block: one compression
        return _bytes(compress(key, _words(data), 0, len(data), KEYED_HASH | CHUNK_START | CHUNK_END | ROOT))
    return _hash(key, data, KEYED_HASH)


def derive_key(context, material):
    context_key = _subtree(IV, context.encode(), 0, DERIVE_KEY_CONTEXT, True)
    return _hash(context_key, material, DERIVE_KEY_MATERIAL)


def _self_test(path):
    import json

    vectors = json.load(open(path))
    cases = vectors["cases"]
    if len(cases) != 35:
        raise AssertionError(f"expected 35 official BLAKE3 vectors, got {len(cases)}")
    key, context = vectors["key"].encode(), vectors["context_string"]
    for case in cases:
        data = bytes(i % 251 for i in range(case["input_len"]))
        if hash(data).hex() != case["hash"][:64]:
            raise AssertionError(f"hash mismatch at len {case['input_len']}")
        if keyed_hash(key, data).hex() != case["keyed_hash"][:64]:
            raise AssertionError(f"keyed_hash mismatch at len {case['input_len']}")
        if keyed_words(key_words(key), data).hex() != case["keyed_hash"][:64]:
            raise AssertionError(f"keyed_words mismatch at len {case['input_len']}")
        if derive_key(context, data).hex() != case["derive_key"][:64]:
            raise AssertionError(f"derive_key mismatch at len {case['input_len']}")
    return len(cases)


if __name__ == "__main__":
    import os, sys, time

    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "blake3_test_vectors.json")
    cases = _self_test(path)
    start = time.perf_counter()
    key = key_words(bytes(32))
    for i in range(20000):
        keyed_words(key, i.to_bytes(32, "little"))
    print(f"BLAKE3 in Python: {cases} official test vectors pass in three modes; {(time.perf_counter() - start) / 20000 * 1e6:.1f} us per one-block keyed hash")

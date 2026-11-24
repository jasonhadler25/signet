# Test vectors

## Primary reference vector (`reference-imprint-1.bin`)

`reference-imprint-1.bin` is the imprint the Python reference (`reference/blincs.py`) makes for:

- signet seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
- draw `0707070707070707070707070707070707070707070707070707070707070707`,
- message `hello, BLINCS` (13 bytes, no newline).

The signet ID of that seed is `8e15ddf8f53bf3066099aaa8b8c073a0b2955754ebc88c5be38e23f708c8f3e9`.

The imprint's hashes:
- SHA-256: `f94f0a1f23135a4941ba79b11435cde6e3802894840f2ff306d2026d5e628784`
- BLAKE3:  `53405a42fe874e64f69d9f0e52140c7016226eabf7a59f33e8d5bed61614b94b`

To make it again (about 19 seconds across CPU cores):

    printf 'hello, BLINCS' > /tmp/message
    python3 reference/blincs.py imprint 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0707070707070707070707070707070707070707070707070707070707070707 /tmp/message /tmp/imprint

## Edge-case vectors (`edge-vectors.json`)

`edge-vectors.json` records four additional deterministic vectors under the same seed (`00..1f`) covering empty input (`0 B`), a single zero byte (`1 B`), the exact BLAKE3 chunk boundary (`1,024 B`, `bytes((i * 31) & 0xff)`), and a multi-chunk streaming boundary (`16,385 B`, `bytes((i * 37 + 5) & 0xff)`) whose 33-bit `leaf_addr` (`0x1e9edcd93`) exercises bit 32 and the upper half of the 12-bit top hypertree. All four imprints are verified byte for byte by Rust (`src/`), pure Python (`reference/blincs.py`), and the educational spec-only TypeScript verifier (`reference/blincs.ts`).

`edge-vectors.json` hashes:
- SHA-256: `51dcec9fe12f78d726ffd39ef3748e8c8ff469a0069ab1c8f44c2b7e773a9d71`
- BLAKE3:  `a95d39c94d4d253ffdedd70924e84787705f9eb302ef1251cbaca0ffb730cf20`

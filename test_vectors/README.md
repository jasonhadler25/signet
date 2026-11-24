# Test vectors

## Primary reference vector (`reference-signature-1.bin`)

`reference-signature-1.bin` is the signature the Python reference (`reference/blincs.py`) makes for:

- signing-key seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
- draw `0707070707070707070707070707070707070707070707070707070707070707`,
- message `hello, BLINCS` (13 bytes, no newline).

The verifying key of that seed is `0ad9c13b8972b912a211f9fd2ba1eec863399e14d2f6c8c3309f9d7e61a53c46`.

The signature's hashes:
- SHA-256: `7fbc1537b5b516c823542c425f48129fe78d974a1806ae24fe0c8dc382a7436c`
- BLAKE3:  `ab80843efd3f5860ccc87f578b8831a79eaf3bb595ac516954823f2ed6886b23`

To make it again (about 19 seconds across CPU cores):

    printf 'hello, BLINCS' > /tmp/message
    python3 reference/blincs.py sign 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0707070707070707070707070707070707070707070707070707070707070707 /tmp/message /tmp/signature

## Edge-case vectors (`edge-vectors.json`)

`edge-vectors.json` records four additional deterministic vectors under the same seed (`00..1f`) covering empty input (`0 B`), a single zero byte (`1 B`), the exact BLAKE3 chunk boundary (`1,024 B`, `bytes((i * 31) & 0xff)`), and a multi-chunk streaming boundary (`16,385 B`, `bytes((i * 37 + 5) & 0xff)`) whose 33-bit `leaf_addr` (`0x1c573eb9c`) exercises bit 32 and the upper half of the 12-bit top hypertree. All four signatures are verified byte for byte by Rust (`src/`), pure Python (`reference/blincs.py`), and the independent spec-only TypeScript verifier (`reference/blincs.ts`).

`edge-vectors.json` hashes:
- SHA-256: `4be3ee44ca7318bdd15a492e77dd1b749ee8d957124701fe070615a52d4a3437`
- BLAKE3:  `ffddb6318d2d4a33974fb3d9062f3ec98c796bb58e1a59c9c8f9ab63232f1efe`

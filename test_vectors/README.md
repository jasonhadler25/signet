# BLINCS test vectors (`BLINCS 2026-11-25`, uniform `7×5`, byte-aligned `FORS(8, 20)`, `7,392 B`)

Generated independently from [`SPEC.md`](../SPEC.md) by `reference/blincs.py` (`reference/blake3.py`), verified byte-for-byte by both the Rust crate (`src/test.rs`, `tests/integration.rs`) and Node 24 TypeScript (`reference/blincs.ts`).

Common deterministic seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
Derived `SignetId` (32 bytes): `db09192c50a65494941887b9c57895ab817750c6dacc82855e914ae9adca39da`

## `reference-imprint-1.bin` (`7,392` bytes)

- Message: `b"hello, BLINCS"` (`13` bytes)
- Draw: `07` × 32
- SHA-256: `ab9d2c8bf1e375e49ef57c3df2fe0c3700ffd5553d5085bd2f48abaac4e2386d`
- BLAKE3:  `b72623d86ea8e954b39604329aeb2694c701f1e2043f6ca62285fbd770af9421`

## `edge-vectors.json` (4 boundary vectors)

Covers empty message (`0 B`), single zero byte (`1 B`), BLAKE3 chunk boundary (`1,024 B`), and streaming boundary (`16,385 B`) with top bit 34 of `leaf_addr` set (`0x44df158f0`):

- SHA-256: `bd46fb9730fcaa11be294f6ed7e5d6ad931906cb89957681fe6315af4b1ca4e8`
- BLAKE3:  `dc3ba2d0b4094aed404ec293994deded59294c970cf5de0d23eb6c21bdd124bf`

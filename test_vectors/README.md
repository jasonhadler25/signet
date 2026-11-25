# BLINCS test vectors (`BLINCS 2026-11-25`, uniform `5×7`, `FORS(11, 13)`, `5,888 B`)

Generated independently from [`SPEC.md`](../SPEC.md) by `reference/blincs.py` (`reference/blake3.py`), verified byte-for-byte by both the Rust crate (`src/test.rs`, `tests/integration.rs`) and Node 24 TypeScript (`reference/blincs.ts`).

Common deterministic seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
Derived `SignetId` (32 bytes): `db09192c50a65494941887b9c57895ab1d8c239fbfb22e021f3b8dcc8d5b3da2`

## `reference-imprint-1.bin` (`5,888` bytes)

- Message: `b"hello, BLINCS"` (`13` bytes)
- Draw: `07` × 32
- SHA-256: `965c4bf2ccc1b670f17f26d1ecaeda126f6de57839c8cf964ef2f6ffac749bb0`
- BLAKE3:  `9f88101241de2493b0c2e3584e2cef5c8463d64e606040086f2d602e4bed8351`

## `edge-vectors.json` (4 boundary vectors)

Covers empty message (`0 B`), single zero byte (`1 B`), BLAKE3 chunk boundary (`1,024 B`), and streaming boundary (`16,385 B`) with top bit 34 of `leaf_addr` set (`0x4f683bf82`):

- SHA-256: `f5d6ab2ee23c650231e8098fc28e5684b0d1522196e9e6b5929ba6b1128c301e`
- BLAKE3:  `57d7af23421b796c128f9c012a41cc22951d6db6e220bcaffea8c319a429aa52`

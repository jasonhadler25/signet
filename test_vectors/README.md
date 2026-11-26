# BLINCS-128-7x5 test vectors (`6,432 B`, framed `Context`, `U-FORS(3, 10, 16, 64, 5, 15)`)

Generated independently from [`SPEC.md`](../SPEC.md) in pure Python (from-scratch BLAKE3 reference implementation) and verified byte-for-byte by `blincs-reference` (`reference/tests/vectors.rs`, on `blake3-servil-core = "=0.11.0"`) and the production `signet` crate (`jasonhadler25/signet`).

Common deterministic seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
Derived `SignetId` (32 bytes): `98a5b8314b854e78f72cbadc9f5ed67c15bc2ad253cd98be1d5951595f217512`

## `reference-imprint-1.bin` (`6,432` bytes)

- Context: `b"BLINCS-128-7x5 reference vector v1"` (`34` bytes)
- Message: `b"hello, BLINCS"` (`13` bytes)
- Draw: `07` × 32
- SHA-256: `5d1b63aa041a6cd3f44b9e5a2c2ed27d4ab6b4d166d3a28a8d019a611472ced6`
- BLAKE3:  `e9e433283ad714c487275b7dcc747fb5e93c7f43d98353d24dd98d2e4794b231`
- Intermediate KATs:
  - `e`: `3ee655b325f3fef998372326a6ad5bd4`
  - `K_msg`: `10dc74ca12332248a57f4a7d634d0e33a66e328daefc974846b4f797357bc9b0`
  - `h_msg`: `97519fba890010cfb56d70e5b362d7a7a08acc9ed03a55b961abe1f67c1812f3`
  - `R`: `4f6bc05208d26834de62980950f120c4`
  - `D`: `e68bbde745c55884532af2f0ebeb2fa98e03de57be31ca2cb88ec347edff9495`
  - `leaf_addr`: `0x5c166518d`

## `edge-vectors.json` (4 boundary vectors)

Covers empty message + empty context (`0 B` / `ctx = ""`), single zero byte (`1 B` / `ctx = "edge-ctx"`), BLAKE3 chunk boundary (`1,024 B` / `ctx = "chunk-boundary-v1"`), and streaming boundary (`16,385 B`) with maximum `255`-byte context and top bit 34 of `leaf_addr` set (`0x58902132a`):

- SHA-256: `ef06e6fe467be56bae91434c2042f73bc7b994ae116a4de68f463de12fc747e1`
- BLAKE3:  `981210f93509158996974e12f521a002e62b24ace355cbd720ff0ee7db8e6bb2`

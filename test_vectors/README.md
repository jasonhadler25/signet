# BLINCS-128-7x5 test vectors (`7,392 B`, framed `Context`, byte-aligned `FORS(8, 20)`)

Generated independently from [`SPEC.md`](../SPEC.md) by `reference/blincs.py` (`reference/blake3.py`), verified byte-for-byte by both the `signet` Rust crate (`src/test.rs`, `tests/integration.rs`) and Node 24 TypeScript (`reference/blincs.ts`).

Common deterministic seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
Derived `SignetId` (32 bytes): `b58abfb655db7c92808f12c3a8ffd2d04841cf61994321648cf193638876c492`

## `reference-imprint-1.bin` (`7,392` bytes)

- Context: `b"BLINCS-128-7x5 reference vector v1"` (`34` bytes)
- Message: `b"hello, BLINCS"` (`13` bytes)
- Draw: `07` × 32
- SHA-256: `056e4c91aab74cf3ae9dedc3b0799e25f0eb19d25070e285f3b114c601ffe993`
- BLAKE3:  `1f90309febb00685d497c84edfae3bf9563206e15215f143a1eab51bcc5332bf`
- Intermediate KATs:
  - `e`: `c59c076073bef65dd74facc7453fdcdc`
  - `K_msg`: `1c28a56af15ce2bb6792393b0b477388d924a2236ca3aedb061fb93d5e52bd8e`
  - `h_msg`: `ad7606a939db70dcc963a91e0fa003d59fc4462e163c16dd2138c4cd0cc66fab`
  - `R`: `8538feb0b1803987e8a2344e0991d9b2`
  - `D`: `6e13239c0efaa15bda213d2b03ca8b8d726cc1f9e6e0c6c686fdac69f6af9c68`
  - `leaf_addr`: `0x6c6c6e0e6`

## `edge-vectors.json` (4 boundary vectors)

Covers empty message + empty context (`0 B` / `ctx = ""`), single zero byte (`1 B` / `ctx = "edge-ctx"`), BLAKE3 chunk boundary (`1,024 B` / `ctx = "chunk-boundary-v1"`), and streaming boundary (`16,385 B`) with maximum `255`-byte context and top bit 34 of `leaf_addr` set (`0x67ca481fc`):

- SHA-256: `4ef1f28a65247ee8a17981a6faa6d3dda99b68126ae721cd40572b0379e48299`
- BLAKE3:  `0616c04735308daff990d1051a8992da5052d4f9d1fc63c18acba7a67df68483`

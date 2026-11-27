# BLINCS-128-A2 test vectors (`3,292 B`, framed `Context`, `12+7+7+7 S-WOTS+Z` + `U-PORS`)

Generated from [`SPEC.md`](../SPEC.md) and independently verified byte-for-byte by `blincs-reference` (`reference/tests/vectors.rs`, on `blake3-servil-core = "=0.11.0"`), an independent pure-Python verifier (`reference/blincs.py` on from-scratch Python BLAKE3), and the production `signet` crate (`jasonhadler25/signet`).

Common deterministic seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
Derived `SignetId` (32 bytes): `eb8e97a4ff2446ed3791cfd9515e1e23982ff22b5103bc0117c3ab69db42bac4`

## `reference-imprint-1.bin` (`3,292` bytes)

- Context: `b"BLINCS-128-A2 reference vector v1"` (`33` bytes)
- Message: `b"hello, BLINCS"` (`13` bytes)
- Draw: `07` × 32
- SHA-256: `1617a3dc44e94dda77f019913006a64bedfc4d68b7230d792dde909dc98101ee`
- BLAKE3:  `43c5443aaaf0698cde86c7d2d24898cbac6e7980734023f759d2eac72e79cef2`
- Intermediate KATs:
  - `e`: `73eabb4a158088cb5560a0ac53a56f94`
  - `K_msg`: `e81dcdc2fbf14d588961d18dbf8d8c13d0b88d9620c91fa4b1d9d3e5bc803867`
  - `h_msg`: `e02cefa736d2adf65658b8271bc8edb4216696b1291a83d66b2a4afadf78ab38`
  - `R`: `99b91679fcf65f9a5c6921f33e560c35`
  - `D_seed`: `b5044d6e9253abc1cdb13893663db4531e015000ca5a666f5521c11a18f8b69f`
  - `ctr_ft`: `2049` (`sibs = 44 / 44`), `leaf_addr`: `0x166278a1d`
  - `layer_ctrs`: `[42, 225, 134, 44]`

## `edge-vectors.json` (4 boundary vectors)

Covers empty message + empty context (`0 B` / `ctx = ""`), single zero byte with canonical Octopus trailing zero-padding (`1 B` / `ctx = "edge-ctx"`, `sibs = 41 / 44`), BLAKE3 chunk boundary with trailing zero-padding (`1,024 B` / `ctx = "chunk-boundary-v1"`, `sibs = 43 / 44`), and streaming boundary (`16,385 B`) with maximum `255`-byte context and top bit `32` of `leaf_addr` set (`0x166c2f678`):

- SHA-256: `c947dfa6d4ec02497d7401742c61cd297bf41eb9a544b18b5ed7e5614147f997`
- BLAKE3:  `0167f83e8886d90a79ec638a0735504fe7c7e39986320117cdd831fa7a12ee45`

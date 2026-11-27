# Canonical `BLINCS-48-X` Test Vectors

Canonical byte-for-byte test vectors for the **`BLINCS-48-X`** suite (`SPEC.md`, draft `0.5.0`, `3,990` bytes, `q = 2^48`). Every vector below is independently cross-verified by both [`reference/`](../reference) (Rust) and pure-Python BLAKE3.

## Seed and SignetId

- `seed` (`32 B`): `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- `SignetId` (`32 B`): `7ee7fe20dac820b17625cad3a38a8af696a69a74992f01a7c9ed3680699d2c5c`

## `reference-imprint-1.bin` (`3,990` bytes)

- `draw` (`32 B`): `[0x07; 32]`
- `ctx`: `b"BLINCS-48-X reference vector v1"` (`31` bytes)
- `msg`: `b"hello, BLINCS"` (`13` bytes)
- `SHA-256`: `b04c4dced60324af28d66f54dab90c5787b9e2d71aa7f84fe4e2b5696da7b162`
- `BLAKE3`: `99c84c6eb8599b1ace04345c650749ff0b3c96fd8a90e1d928f86abac153dfa1`
- Intermediate KATs:
  - `e`: `9a70dfb49286d13de2a56ed4374946eb`
  - `K_msg`: `28b5bf0bad61349ba7f2cc3ba730cd3b1fd1a8a58fff9acc8115f154fe044847`
  - `h_msg`: `7d978bc5d7a7df9bd2ff34dd4288dbf51963eb8da05365a9cc53ea2d05e2e09a`
  - `R`: `32b08c4c9d15504265fa2984b9b7cf25`
  - `D_seed`: `2151d28e0fd8b76f3d514feb22bc966bb26fab87dee126eb3917d320072f30f9`
  - `ctr_ft = 5530`, `sibs = 45/45`, `leaf_addr = 0xbbce641c7560` (`bit 47 = 1`), `layer_ctrs = [595, 4088, 413, 3803, 1277, 1312]`.

## `edge-vectors.json` (`33,883` bytes)

- `SHA-256`: `29090a430b80dc3a41cea2988f303c274595fa18c4377d7f0cc816c8f60744fc`
- `BLAKE3`: `d3acd8bd81f65d0ed4b4d889ea87b8967a99c1289626899f4e4cfbfc5da8adc7`
- Four boundary vectors:
  1. `empty` (`0 B` msg, `0 B` ctx, `sibs = 43/45` — 2 zero-padded Octopus slots)
  2. `one-byte-zero` (`1 B` `0x00` msg, `sibs = 44/45` — 1 zero-padded Octopus slot)
  3. `chunk-1024` (`1,024 B` BLAKE3 chunk boundary, `255 B` max context, `bit 47 = 1`)
  4. `stream-16385-high-leaf` (`16,385 B` multi-chunk streaming boundary, `bit 47 = 1`)

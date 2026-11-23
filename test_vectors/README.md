# Test vectors

`reference-signature-1.bin` is the signature the Python reference (`reference/blincs.py`) makes for

- signing-key seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
- draw `0707070707070707070707070707070707070707070707070707070707070707`,
- message `hello, BLINCS` (13 bytes, no newline).

The verifying key of that seed is `0ad9c13b8972b912a211f9fd2ba1eec80f172d89ea2869ab004a78588619f97c`.

The signature's hashes: SHA-256 `dbeeb3cf497205fb4f3bf0f18c1861a8d62acdd69febe3e22f31decdd16942b2`,
BLAKE3 `dc4e894a5640047ce03904bffc6a6384fc03b534cd0343636cad4ad2c048a8b1`.

To make it again (about a minute):

    printf 'hello, BLINCS' > /tmp/message
    python3 reference/blincs.py sign 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0707070707070707070707070707070707070707070707070707070707070707 /tmp/message /tmp/signature

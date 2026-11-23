# Test vectors

`reference-signature-1.bin` is the signature the Python reference (`reference/blincs.py`) makes for

- signing-key seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
- draw `0707070707070707070707070707070707070707070707070707070707070707`,
- message `hello, BLINCS` (13 bytes, no newline).

The verifying key of that seed is `0ad9c13b8972b912a211f9fd2ba1eec86ec7ac0e8af7b03012a5cf3a6d9bdbb0`.

The signature's hashes: SHA-256 `03d4fe3f6646f8b3b986a45333947931497c941f4a225db00d06303ff3ee65dc`,
BLAKE3 `5c56af6af07a04f769008290dcb5d608bcdd25c1e62765d8309948ab2f5b25ea`.

To make it again (about 85 seconds across CPU cores):

    printf 'hello, BLINCS' > /tmp/message
    python3 reference/blincs.py sign 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0707070707070707070707070707070707070707070707070707070707070707 /tmp/message /tmp/signature

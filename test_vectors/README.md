# Test vectors

`reference-signature-1.bin` is the signature the Python reference (`reference/blincs.py`) makes for

- signing-key seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
- draw `0707070707070707070707070707070707070707070707070707070707070707`,
- message `hello, BLINCS` (13 bytes, no newline).

The verifying key of that seed is `0ad9c13b8972b912a211f9fd2ba1eec80f172d89ea2869ab004a78588619f97c`.

The signature's hashes: SHA-256 `ac0808dbf5a435ab21d7426df178abb707f89f3a26a1b84cd13cda083f6f00e1`,
BLAKE3 `f5de1861fe29352b6f290469517a749cc426cf22c48d246acc494cb75d10a4c8`.

To make it again (about a minute):

    printf 'hello, BLINCS' > /tmp/message
    python3 reference/blincs.py sign 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0707070707070707070707070707070707070707070707070707070707070707 /tmp/message /tmp/signature

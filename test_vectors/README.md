# Test vectors

`reference-signature-1.bin` is the signature the Python reference (`reference/blincs.py`) makes for

- signing-key seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
- draw `0707070707070707070707070707070707070707070707070707070707070707`,
- message `hello, BLINCS` (13 bytes, no newline).

The verifying key of that seed is `0ad9c13b8972b912a211f9fd2ba1eec863399e14d2f6c8c3309f9d7e61a53c46`.

The signature's hashes: SHA-256 `7fbc1537b5b516c823542c425f48129fe78d974a1806ae24fe0c8dc382a7436c`,
BLAKE3 `ab80843efd3f5860ccc87f578b8831a79eaf3bb595ac516954823f2ed6886b23`.

To make it again (about 19 seconds across CPU cores):

    printf 'hello, BLINCS' > /tmp/message
    python3 reference/blincs.py sign 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0707070707070707070707070707070707070707070707070707070707070707 /tmp/message /tmp/signature

include!("../../../tools/require_nextest.rs");

use signet_verify::{
    Context, ContextTooLong, IMPRINT_LEN, ImprintRef, InvalidImprint, MAX_CONTEXT_LEN, SIGNET_ID_LEN, SUITE_NAME, SignetId, StreamVerifyError,
};

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn json_str_field<'a>(block: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\": \"");
    let start = block.find(&needle).unwrap() + needle.len();
    let end = block[start..].find('"').unwrap() + start;
    &block[start..end]
}

fn json_u64_field(block: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\": ");
    let start = block.find(&needle).unwrap() + needle.len();
    let rest = &block[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().unwrap()
}

#[test]
fn reference_and_edge_vectors_verify_oneshot_and_streamed() {
    assert_eq!(SUITE_NAME, "BLINCS-128-7x5");
    assert_eq!(SIGNET_ID_LEN, 32);
    assert_eq!(IMPRINT_LEN, 7392);
    assert_eq!(MAX_CONTEXT_LEN, 255);
    assert_eq!(Context::try_new(&[0u8; 256]), Err(ContextTooLong { len: 256 }));

    // 1. Primary reference vector (`test_vectors/reference-imprint-1.bin`).
    let id_bytes = hex_decode("b58abfb655db7c92808f12c3a8ffd2d04841cf61994321648cf193638876c492");
    let id = SignetId::try_from(id_bytes.as_slice()).unwrap();
    let imp_bytes = include_bytes!("../../../test_vectors/reference-imprint-1.bin");
    let sig = ImprintRef::try_from(imp_bytes.as_slice()).unwrap();
    assert!(ImprintRef::try_from(&imp_bytes[..IMPRINT_LEN - 1]).is_err());

    let ctx = Context::new(b"BLINCS-128-7x5 reference vector v1");
    let msg = b"hello, BLINCS";
    assert_eq!(id.verify(ctx, msg, sig), Ok(()));

    // Wrong context, wrong message, wrong SignetId all fail closed.
    assert_eq!(id.verify(Context::EMPTY, msg, sig), Err(InvalidImprint));
    assert_eq!(id.verify(ctx, b"BLINCS reference vector 2", sig), Err(InvalidImprint));
    let mut wrong_id_bytes = *id.as_bytes();
    wrong_id_bytes[31] ^= 1;
    let wrong_id = SignetId::from_bytes(&wrong_id_bytes);
    assert_eq!(wrong_id.verify(ctx, msg, sig), Err(InvalidImprint));

    // Mutate one byte in EVERY 16-byte wire field (462 fields across 7,392 B): every mutation rejects!
    let mut buf = *sig.as_bytes();
    for field in 0..(IMPRINT_LEN / 16) {
        let pos = field * 16 + (field % 16);
        buf[pos] ^= 0x80;
        assert_eq!(id.verify(ctx, msg, ImprintRef::from_bytes(&buf)), Err(InvalidImprint), "field {field} escaped");
        buf[pos] ^= 0x80;
    }

    // Streaming `Verifier` across varied chunk sizes + empty updates.
    for chunk_size in [1usize, 3, 7, 16, 63, 64, 65] {
        let mut v = id.verifier(ctx, sig);
        v.update(b"").unwrap();
        for chunk in msg.chunks(chunk_size) {
            v.update(chunk).unwrap();
            v.update(b"").unwrap();
        }
        assert_eq!(v.finalize(), Ok(()));
    }
    let mut v_bad = id.verifier(Context::EMPTY, sig);
    v_bad.update(msg).unwrap();
    assert_eq!(v_bad.finalize(), Err(StreamVerifyError::InvalidImprint));

    // 2. All 4 edge vectors in `test_vectors/edge-vectors.json` (including 16,385 B & 255-B context).
    let edge_json = include_str!("../../../test_vectors/edge-vectors.json");
    let messages: [(&str, Vec<u8>); 4] = [
        ("empty", vec![]),
        ("one-byte-zero", vec![0u8]),
        ("chunk-1024", (0..1024usize).map(|i| u8::try_from((i * 31) & 0xff).unwrap()).collect()),
        ("stream-16385-high-leaf", (0..16_385usize).map(|i| u8::try_from((i * 37 + 5) & 0xff).unwrap()).collect()),
    ];
    let blocks: Vec<&str> = edge_json.split("\"name\": \"").skip(1).collect();
    assert_eq!(blocks.len(), messages.len());
    for (chunk, (expected_name, message)) in blocks.iter().zip(messages.iter()) {
        assert_eq!(&chunk[..chunk.find('"').unwrap()], *expected_name);
        let ctx_bytes = hex_decode(json_str_field(chunk, "ctx_hex"));
        let msg_len = usize::try_from(json_u64_field(chunk, "msg_len")).unwrap();
        assert_eq!(msg_len, message.len());
        let raw_imp = hex_decode(json_str_field(chunk, "imprint_hex"));
        let sig = ImprintRef::try_from(raw_imp.as_slice()).unwrap();
        let ctx = Context::try_new(&ctx_bytes).unwrap();

        assert_eq!(id.verify(ctx, message, sig), Ok(()));
        for split in [1usize, 63, 64, 65, 1023, 1024, 1025, 16_383, 16_384, 16_385] {
            if msg_len == 0 && split > 1 {
                continue;
            }
            let mut v = id.verifier(ctx, sig);
            v.update(b"").unwrap();
            for part in message.chunks(split) {
                v.update(part).unwrap();
            }
            v.update(b"").unwrap();
            assert_eq!(v.finalize(), Ok(()));
        }
    }
}

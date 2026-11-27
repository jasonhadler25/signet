include!("../tools/require_nextest.rs");

use signet::{Context, Imprint, InvalidImprint, Randomness, SEED_LEN, Signet, SignetId};
use std::fs;
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::process::Command;

const INT_CTX: Context<'static> = Context::new(b"signet integration test v1");
const REF_CTX: Context<'static> = Context::new(b"BLINCS-128-A2 reference vector v1");

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("signet-int-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

#[test]
fn public_api_round_trip_and_python_reference_cross_check() {
    let dir = temp_dir("cross-check");
    let state_file = dir.join("signet.salt");
    Randomness::create(&state_file).unwrap();
    let rng = Randomness::initialize(&state_file).unwrap();

    let publisher = Signet::generate(&rng).unwrap();
    let expected_publisher = SignetId::from_bytes(publisher.id().as_bytes());
    let vk_hex = to_hex(expected_publisher.as_bytes());
    let ctx_hex = to_hex(INT_CTX.as_bytes());

    let py = concat!(env!("CARGO_MANIFEST_DIR"), "/reference/blincs.py");

    for (name, len) in [("empty", 0usize), ("small", 43), ("64k", 64 * 1024), ("512k-plus", 512 * 1024 + 123)] {
        let msg: Vec<u8> = (0..len).map(|i| u8::try_from((i * 73 + 11) & 0xff).unwrap()).collect();
        let sig = publisher.imprint(&rng, INT_CTX, &msg);
        expected_publisher.verify(INT_CTX, &msg, &sig).unwrap();
        expected_publisher
            .verify_with(INT_CTX, &sig, |sink| {
                io::copy(&mut Cursor::new(&msg), sink)?;
                Ok::<(), io::Error>(())
            })
            .unwrap();

        // Differential cross-check against standalone #![no_std] `signet-verify` (one-shot + streaming).
        let nostd_id = signet_verify::SignetId::from_bytes(expected_publisher.as_bytes());
        let nostd_ctx = signet_verify::Context::new(INT_CTX.as_bytes());
        let nostd_sig = signet_verify::ImprintRef::from_bytes(sig.as_bytes());
        nostd_id.verify(nostd_ctx, &msg, nostd_sig).unwrap();
        let mut nostd_v = nostd_id.verifier(nostd_ctx, nostd_sig);
        for chunk in msg.chunks(1021) {
            nostd_v.update(chunk).unwrap();
        }
        nostd_v.finalize().unwrap();

        let msg_path = dir.join(format!("{name}.msg"));
        let sig_path = dir.join(format!("{name}.sig"));
        fs::write(&msg_path, &msg).unwrap();
        fs::write(&sig_path, sig.as_bytes()).unwrap();

        let out = Command::new("python3").args([py, "verify", &vk_hex, &ctx_hex, msg_path.to_str().unwrap(), sig_path.to_str().unwrap()]).output().unwrap();
        assert!(out.status.success(), "python reference rejected Rust signature for {name}: {}", String::from_utf8_lossy(&out.stderr));

        let mut bad = *sig.as_bytes();
        bad[100] ^= 1;
        let bad_path = dir.join(format!("{name}.bad.sig"));
        fs::write(&bad_path, bad).unwrap();
        let bad_out = Command::new("python3").args([py, "verify", &vk_hex, &ctx_hex, msg_path.to_str().unwrap(), bad_path.to_str().unwrap()]).output().unwrap();
        assert_eq!(bad_out.status.code(), Some(1), "python reference did not exit 1 for tampered {name}");
        assert_eq!(String::from_utf8_lossy(&bad_out.stdout).trim(), "INVALID", "unexpected python stdout for tampered {name}");
        assert!(bad_out.stderr.is_empty(), "python reference emitted stderr on tampered {name}: {}", String::from_utf8_lossy(&bad_out.stderr));
    }

    // Two signatures of the same message have distinct salts (different draws).
    let s1 = publisher.imprint(&rng, INT_CTX, b"same message");
    let s2 = publisher
        .imprint_with(&rng, INT_CTX, |sink| {
            sink.update(b"same ");
            sink.update(b"message");
            Ok::<(), io::Error>(())
        })
        .unwrap();
    assert_ne!(&s1.as_bytes()[..16], &s2.as_bytes()[..16]);
    expected_publisher.verify(INT_CTX, b"same message", &s1).unwrap();
    expected_publisher.verify(INT_CTX, b"same message", &s2).unwrap();

    // A valid imprint from a different publisher or different context must be rejected.
    let other_publisher = Signet::generate(&rng).unwrap();
    let other_imprint = other_publisher.imprint(&rng, INT_CTX, b"same message");
    other_publisher.id().verify(INT_CTX, b"same message", &other_imprint).unwrap();
    assert_eq!(expected_publisher.verify(INT_CTX, b"same message", &other_imprint), Err(InvalidImprint));
    assert_eq!(expected_publisher.verify(Context::new(b"other-ctx"), b"same message", &s1), Err(InvalidImprint));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reference_vector_verifies_via_public_api() {
    let raw = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-imprint-1.bin")).unwrap();
    let sig = Imprint::try_from(raw.as_slice()).unwrap();
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let expected_publisher = Signet::from_seed(&seed).id();
    expected_publisher.verify(REF_CTX, b"hello, BLINCS", &sig).unwrap();
    assert_eq!(expected_publisher.verify(REF_CTX, b"hello, blincs", &sig), Err(InvalidImprint));
    assert_eq!(expected_publisher.verify(Context::EMPTY, b"hello, BLINCS", &sig), Err(InvalidImprint));
}

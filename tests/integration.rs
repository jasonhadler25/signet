include!("../tools/require_nextest.rs");

use blincs::{Randomness, SEED_LEN, Signature, SigningKey, VerifyingKey};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("blincs-int-{}-{tag}", std::process::id()));
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
    let state = dir.join("state.bin");
    Randomness::create(&state).unwrap();
    let rng = Randomness::initialize(&state).unwrap();

    let seed = [0x5au8; SEED_LEN];
    let sk = SigningKey::from_seed(&seed);
    let vk = VerifyingKey::from_bytes(sk.verifying_key().as_bytes());
    let vk_hex = to_hex(vk.as_bytes());

    let py = concat!(env!("CARGO_MANIFEST_DIR"), "/reference/blincs.py");

    for (name, len) in [("empty", 0usize), ("small", 43), ("64k", 64 * 1024), ("512k-plus", 512 * 1024 + 123)] {
        let msg: Vec<u8> = (0..len).map(|i| u8::try_from((i * 73 + 11) & 0xff).unwrap()).collect();
        let sig = sk.sign(&rng, &msg);
        assert!(vk.verify(&msg, &sig));
        assert!(vk.verify_reader(Cursor::new(&msg), &sig).unwrap());

        let msg_path = dir.join(format!("{name}.msg"));
        let sig_path = dir.join(format!("{name}.sig"));
        fs::write(&msg_path, &msg).unwrap();
        fs::write(&sig_path, sig.as_bytes()).unwrap();

        let out = Command::new("python3").args([py, "verify", &vk_hex, msg_path.to_str().unwrap(), sig_path.to_str().unwrap()]).output().unwrap();
        assert!(out.status.success(), "python reference rejected Rust signature for {name}: {}", String::from_utf8_lossy(&out.stderr));

        // Flip one byte in the signature and confirm Python reference rejects it too.
        let mut bad = *sig.as_bytes();
        bad[100] ^= 1;
        let bad_path = dir.join(format!("{name}.bad.sig"));
        fs::write(&bad_path, bad).unwrap();
        let bad_out = Command::new("python3").args([py, "verify", &vk_hex, msg_path.to_str().unwrap(), bad_path.to_str().unwrap()]).output().unwrap();
        assert!(!bad_out.status.success(), "python reference accepted tampered signature for {name}");
    }

    // Two signatures of the same message have distinct salts (different draws).
    let s1 = sk.sign(&rng, b"same message");
    let s2 = sk.sign_reader(&rng, Cursor::new(b"same message")).unwrap();
    assert_ne!(&s1.as_bytes()[..16], &s2.as_bytes()[..16]);
    assert!(vk.verify(b"same message", &s1));
    assert!(vk.verify(b"same message", &s2));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reference_vector_verifies_via_public_api() {
    let raw = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-signature-1.bin")).unwrap();
    let sig = Signature::try_from(raw.as_slice()).unwrap();
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let vk = SigningKey::from_seed(&seed).verifying_key();
    assert!(vk.verify(b"hello, BLINCS", &sig));
    assert!(!vk.verify(b"hello, blincs", &sig));
}

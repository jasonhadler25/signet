include!("../tools/require_nextest.rs");

use crate::content::{checked_add_stream_len, content_from_reader};
use crate::few_time::parse_digest;
use crate::one_time::{Pos, advance_chains, digits, lower_tree_len_check};
use crate::params::{
    CHAIN_STEPS, CHAINS, ContentKey, FORS_HEIGHT, FORS_TREES, HYPER_BITS, Layer, MSG_CHAINS, N, PublicKey, SIGNATURE_LEN, TreeIndex, TweakKind, ensure_init,
};
use crate::randomness::{STATE_LEN, mix, read_exact_or_reject, read_monotonic_clock};
use crate::{Randomness, SEED_LEN, Signature, SigningKey, VERIFYING_KEY_LEN, VerifyingKey};
use blake3_servil::throughput::Batch;
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

const REF_VK_HEX: &str = "0ad9c13b8972b912a211f9fd2ba1eec863399e14d2f6c8c3309f9d7e61a53c46";

fn from_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

fn temp_state_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("blincs-test-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join("state.bin")
}

struct FragmentedReader<'a> {
    data: &'a [u8],
    pos: usize,
    step: usize,
    interrupt_every: usize,
    calls: usize,
    saw_eof: bool,
}

impl<'a> FragmentedReader<'a> {
    fn new(data: &'a [u8], step: usize, interrupt_every: usize) -> Self {
        Self { data, pos: 0, step, interrupt_every, calls: 0, saw_eof: false }
    }
}

impl<'a> Read for FragmentedReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(!buf.is_empty(), "read() called with empty buffer");
        assert!(!self.saw_eof, "read() called again after EOF");
        self.calls += 1;
        if self.interrupt_every > 0 && self.calls.is_multiple_of(self.interrupt_every) {
            return Err(io::Error::new(ErrorKind::Interrupted, "simulated EINTR"));
        }
        if self.pos >= self.data.len() {
            self.saw_eof = true;
            return Ok(0);
        }
        let n = (self.data.len() - self.pos).min(self.step).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[derive(Default)]
struct FailingReader {
    calls: usize,
}
impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        assert_eq!(self.calls, 1, "retried non-Interrupted I/O error");
        Err(io::Error::new(ErrorKind::BrokenPipe, "simulated failure"))
    }
}

/// Yields `prefix_len` zero bytes and then returns `BrokenPipe` (exercises `Pipeline::abort`).
struct FailAfterReader {
    remaining: usize,
    failed: bool,
}
impl Read for FailAfterReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(!self.failed, "retried non-Interrupted I/O error after prefix");
        if self.remaining > 0 {
            let n = self.remaining.min(buf.len());
            buf[..n].fill(0x5A);
            self.remaining -= n;
            return Ok(n);
        }
        self.failed = true;
        Err(io::Error::new(ErrorKind::BrokenPipe, "simulated mid-stream failure"))
    }
}

#[test]
fn reference_vector_matches_python_byte_for_byte() {
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let draw = [7u8; 32];
    let msg = b"hello, BLINCS";

    let sk = SigningKey::from_seed(&seed);
    assert_eq!(sk.seed(), &seed);
    assert_eq!(to_hex(sk.verifying_key().as_bytes()), REF_VK_HEX);
    assert_eq!(lower_tree_len_check(), 8_192);

    let expected = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-signature-1.bin")).unwrap();
    assert_eq!(expected.len(), SIGNATURE_LEN);
    let ref_sig = Signature::try_from(expected.as_slice()).unwrap();

    let rust_sig = sk.sign_with_draw(&draw, msg);
    assert_eq!(rust_sig.as_bytes().as_slice(), expected.as_slice());

    let reader_sig = sk.sign_reader_with_draw(&draw, Cursor::new(msg)).unwrap();
    assert_eq!(reader_sig, rust_sig);

    let vk = VerifyingKey::try_from(sk.verifying_key().as_bytes().as_slice()).unwrap();
    assert_eq!(vk, VerifyingKey::from_bytes(sk.verifying_key().as_bytes()));
    assert!(VerifyingKey::try_from(&vk.as_bytes()[..VERIFYING_KEY_LEN - 1]).is_err());
    assert!(VerifyingKey::try_from([vk.as_bytes().as_slice(), &[0u8]].concat().as_slice()).is_err());
    assert!(vk.verify(msg, &ref_sig));
    assert!(vk.verify_reader(Cursor::new(msg), &ref_sig).unwrap());
    assert!(!vk.verify(b"hello, BLINCS!", &ref_sig));
}

#[test]
fn verify_alone_initializes_blake3_in_fresh_process() {
    let vk_bytes: [u8; VERIFYING_KEY_LEN] = from_hex(REF_VK_HEX).try_into().unwrap();
    let sig_bytes = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-signature-1.bin")).unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes);
    let sig = Signature::try_from(sig_bytes.as_slice()).unwrap();
    assert!(vk.verify(b"hello, BLINCS", &sig));
}

#[test]
fn wots_digits_and_checksum_boundaries() {
    // All zeros: 32 zero nibbles, checksum = 32 * 15 = 480 = 0x1e0 -> [0, 14, 1].
    let d0 = digits(&[0u8; N]);
    assert!(d0[..MSG_CHAINS].iter().all(|&x| x == 0));
    assert_eq!(&d0[MSG_CHAINS..], &[0, 14, 1]);

    // All 0xff: 32 nibbles of 15, checksum = 0 -> [0, 0, 0].
    let dmax = digits(&[0xffu8; N]);
    assert!(dmax[..MSG_CHAINS].iter().all(|&x| x == 15));
    assert_eq!(&dmax[MSG_CHAINS..], &[0, 0, 0]);

    // Single-bit message: csum = 480 - 1 = 479 = 0x1df -> nonzero low nibble [15, 13, 1].
    let mut one = [0u8; N];
    one[0] = 1;
    let d1 = digits(&one);
    assert_eq!(&d1[MSG_CHAINS..], &[15, 13, 1]);

    // Mixed nibbles: verify little-endian nibble ordering and exact checksum.
    let node: [u8; N] = core::array::from_fn(|i| {
        let hi = u8::try_from(i).unwrap();
        let lo = u8::try_from(15 - i).unwrap();
        (hi << 4) | lo
    });
    let dm = digits(&node);
    for i in 0..N {
        assert_eq!(dm[2 * i], u8::try_from(15 - i).unwrap());
        assert_eq!(dm[2 * i + 1], u8::try_from(i).unwrap());
    }
    let expected_csum: u16 = dm[..MSG_CHAINS].iter().map(|&v| 15 - u16::from(v)).sum();
    assert_eq!(expected_csum, 240); // 0x0f0 -> [0, 15, 0]
    assert_eq!(&dm[MSG_CHAINS..], &[0, 15, 0]);
}

#[test]
fn parse_digest_extracts_all_fors_indices_and_33bit_leaf_addr() {
    let mut d = [0u8; 32];
    // Pack known distinct 10-bit values into bytes 0..20 (4 values per 5 bytes).
    let expected_idx: [u16; FORS_TREES] = core::array::from_fn(|t| u16::try_from((t * 67 + 13) & 0x3ff).unwrap());
    for group in 0..4 {
        let mut bits = 0u64;
        for j in 0..4 {
            bits |= u64::from(expected_idx[group * 4 + j]) << (10 * j);
        }
        let le = bits.to_le_bytes();
        d[group * 5..group * 5 + 5].copy_from_slice(&le[..5]);
    }
    // Pack a 33-bit leaf_addr with bit 32 set AND junk in bits 33..63 to verify exact masking.
    let expected_addr = (1u64 << (HYPER_BITS - 1)) | 0x0123_4567;
    let raw_addr = expected_addr | (0x7fff_fffe_u64 << HYPER_BITS);
    d[20..28].copy_from_slice(&raw_addr.to_le_bytes());

    let (indices, addr) = parse_digest(&d);
    let got_idx: [u16; FORS_TREES] = indices.map(|x| x.as_u16());
    assert_eq!(got_idx, expected_idx);
    assert_eq!(addr.as_u64(), expected_addr);
}

#[test]
fn advance_chains_handles_zero_partial_and_full_lengths() {
    ensure_init();
    let public = PublicKey::from_public_seed(&[0x33u8; N]);
    let starts: [u8; CHAINS] = core::array::from_fn(|i| u8::try_from(i % 5).unwrap());
    let ends: [u8; CHAINS] = core::array::from_fn(|i| if i % 6 == 0 { starts[i] } else { CHAIN_STEPS - u8::try_from(i % 4).unwrap() });
    let initial: [[u8; N]; CHAINS] = core::array::from_fn(|i| [u8::try_from(i).unwrap(); N]);

    let mut batched = initial;
    let mut b32 = Batch::new(32, CHAINS);
    let mut out = [[0u8; 32]; CHAINS];
    let pub_core = public.tree_hasher(false);
    let pos2 = Pos::new(Layer::L2, TreeIndex::new(17), 9);
    advance_chains(&pub_core, pos2, &mut batched, &starts, &ends, &mut b32, &mut out);

    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in starts[c]..ends[c] {
            let t = crate::params::tweak(TweakKind::Chain, Layer::L2.as_u8(), TreeIndex::new(17), 9, u16::try_from(c).unwrap(), u32::from(step));
            expected = crate::params::short_hash(&public, t, &expected);
        }
        assert_eq!(batched[c], expected, "chain {c}");
    }

    let mut noop = initial;
    advance_chains(&pub_core, Pos::new(Layer::L0, TreeIndex::ZERO, 0), &mut noop, &[5u8; CHAINS], &[5u8; CHAINS], &mut b32, &mut out);
    assert_eq!(noop, initial);

    // Early-finish case: every chain finishes by step 4 (< CHAIN_STEPS).
    let mut short = initial;
    let short_starts = [2u8; CHAINS];
    let short_ends: [u8; CHAINS] = core::array::from_fn(|i| 2 + u8::try_from(i % 5).unwrap());
    advance_chains(&pub_core, Pos::new(Layer::L1, TreeIndex::new(3), 2), &mut short, &short_starts, &short_ends, &mut b32, &mut out);
    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in short_starts[c]..short_ends[c] {
            let t = crate::params::tweak(TweakKind::Chain, Layer::L1.as_u8(), TreeIndex::new(3), 2, u16::try_from(c).unwrap(), u32::from(step));
            expected = crate::params::short_hash(&public, t, &expected);
        }
        assert_eq!(short[c], expected, "short chain {c}");
    }
}

#[test]
fn every_signature_region_is_checked() {
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let sk = SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    let msg = b"hello, BLINCS";
    let base = sk.sign_with_draw(&[7u8; 32], msg);
    assert!(vk.verify(msg, &base));

    let flip = |offset: usize| -> bool {
        let mut raw = *base.as_bytes();
        raw[offset] ^= 1;
        vk.verify(msg, &Signature::from_bytes(&raw))
    };

    // Salt and randomizer boundaries.
    for &off in &[0, 15, 16, 31] {
        assert!(!flip(off), "accepted flip at offset {off}");
    }

    // Every FORS tree: secret, first auth node, last auth node.
    let fors_stride = (1 + FORS_HEIGHT) * N;
    for t in 0..FORS_TREES {
        let base_off = 2 * N + t * fors_stride;
        assert!(!flip(base_off), "accepted flip in FORS tree {t} secret");
        assert!(!flip(base_off + N), "accepted flip in FORS tree {t} auth 0");
        assert!(!flip(base_off + FORS_HEIGHT * N), "accepted flip in FORS tree {t} last auth");
    }

    // Every hypertree layer: every chain value, first auth node, and last auth node.
    for layer in Layer::ALL {
        let at = layer.sig_offset();
        let height = layer.height();
        for c in 0..CHAINS {
            assert!(!flip(at + c * N), "accepted flip in layer {} chain {c}", layer.as_u8());
        }
        assert!(!flip(at + CHAINS * N), "accepted flip in layer {} auth 0", layer.as_u8());
        assert!(!flip(at + (CHAINS + height - 1) * N), "accepted flip in layer {} last auth", layer.as_u8());
    }
    assert_eq!(Layer::TOP.sig_offset() + Layer::TOP.sig_len(), SIGNATURE_LEN);

    // Wrong verifying key (public_seed byte 0, root byte 31).
    let mut bad_vk = *vk.as_bytes();
    bad_vk[0] ^= 1;
    assert!(!VerifyingKey::from_bytes(&bad_vk).verify(msg, &base));
    let mut bad_root = *vk.as_bytes();
    bad_root[31] ^= 1;
    assert!(!VerifyingKey::from_bytes(&bad_root).verify(msg, &base));

    // Signature slice length checks.
    assert!(Signature::try_from(&base.as_bytes()[..SIGNATURE_LEN - 1]).is_err());
    let mut too_long = base.as_bytes().to_vec();
    too_long.push(0);
    assert!(Signature::try_from(too_long.as_slice()).is_err());
}

#[test]
fn streaming_boundaries_and_fragmented_readers_match_slices() {
    let seed = [0x11u8; SEED_LEN];
    let sk = SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    let draw = [0x22u8; 32];

    // Covers small (< 16 KiB on-core path), exact 16 KiB and 64 KiB boundaries, Pipeline path (> 16 KiB),
    // and multithreaded slice threshold (>= 512 KiB).
    for &len in &[0usize, 1, 63, 64, 65, 1024, 16_383, 16_384, 16_385, 65_535, 65_536, 65_537, 256 * 1024, 512 * 1024, 1024 * 1024 + 19] {
        let msg: Vec<u8> = (0..len).map(|i| u8::try_from((i.wrapping_mul(37) ^ (i >> 8)) & 0xff).unwrap()).collect();
        let sig = sk.sign_with_draw(&draw, &msg);
        assert!(vk.verify(&msg, &sig), "slice verify failed for len {len}");

        let frag_sign = FragmentedReader::new(&msg, 7717, 5);
        let sig_reader = sk.sign_reader_with_draw(&draw, frag_sign).unwrap();
        assert_eq!(sig_reader, sig, "reader signature differed for len {len}");

        let frag_ver = FragmentedReader::new(&msg, 11113, 3);
        assert!(vk.verify_reader(frag_ver, &sig).unwrap(), "reader verify failed for len {len}");

        let mut longer = msg.clone();
        longer.push(0);
        assert!(!vk.verify(&longer, &sig), "accepted trailing zero byte for len {len}");
        if !msg.is_empty() {
            let mut flipped = msg.clone();
            flipped[len - 1] ^= 1;
            assert!(!vk.verify(&flipped, &sig), "accepted last-byte flip for len {len}");
        }
    }

    let ck = ContentKey::from_vk_bytes(vk.as_bytes());
    // Immediate I/O errors propagate cleanly.
    let err = content_from_reader(&ck, &[0u8; N], FailingReader::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    assert_eq!(sk.sign_reader_with_draw(&draw, FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);
    let sig = sk.sign_with_draw(&draw, b"x");
    assert_eq!(vk.verify_reader(FailingReader::default(), &sig).unwrap_err().kind(), ErrorKind::BrokenPipe);

    // Mid-stream I/O error AFTER 16 KiB cleanly aborts the Pipeline without panicking.
    let err_mid = content_from_reader(&ck, &[0u8; N], FailAfterReader { remaining: 90_000, failed: false }).unwrap_err();
    assert_eq!(err_mid.kind(), ErrorKind::BrokenPipe);
}

#[test]
fn concurrent_signing_threads_produce_identical_signatures() {
    let sk = Arc::new(SigningKey::from_seed(&[0x55u8; SEED_LEN]));
    let vk = sk.verifying_key();
    let expected: Vec<Signature> = (0u8..8).map(|i| sk.sign_with_draw(&[i; 32], &[i; 128])).collect();

    let handles: Vec<_> = (0u8..8)
        .map(|i| {
            let sk = Arc::clone(&sk);
            thread::spawn(move || sk.sign_with_draw(&[i; 32], &[i; 128]))
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        let sig = h.join().unwrap();
        assert_eq!(sig, expected[i]);
        assert!(vk.verify(&[u8::try_from(i).unwrap(); 128], &sig));
    }
}

#[test]
fn randomness_mix_matches_python_reference() {
    ensure_init();
    let seed = [0x01u8; 32];
    let system = [0x02u8; 32];
    let clock = b"clock-reading";
    let (next_seed, run_key) = mix(&seed, 42, &system, clock);

    assert_eq!(to_hex(&next_seed), "c0c6b6b9b4b215c0c9f1b2009f61a44b0f3756c95f33987fd05accc567079596");
    assert_eq!(to_hex(&run_key), "ad9e373e2f5993eb67f17095c133073f746d32759f51fae8c5e9cc2ee7e96ad9");

    let r1 = Randomness::from_run_key_at(run_key, 0);
    assert_eq!(to_hex(&r1.draw()), "cd039bca0638eaf52a052a25c92cd471572fe06bc2f0eeaea4a5a6c5022b7877");
    assert_eq!(to_hex(&r1.draw()), "5c71abf8b05980f9901486582351396292e987cadf689ed5bb5934e46c0ceec9");
}

#[test]
#[should_panic(expected = "randomness draw counter exhausted")]
fn randomness_draw_panics_on_counter_exhaustion() {
    ensure_init();
    let r = Randomness::from_run_key_at([1u8; 32], u64::MAX);
    let _ = r.draw();
}

#[test]
fn randomness_create_and_initialize_lifecycle_and_rejection() {
    let path = temp_state_path("lifecycle");
    assert_eq!(Randomness::initialize(&path).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(!path.exists());

    assert_eq!(STATE_LEN, 48);
    Randomness::create(&path).unwrap();
    let initial = fs::read(&path).unwrap();
    assert_eq!(initial.len(), 48);
    assert_eq!(&initial[..8], b"BLINCSr1");
    assert_eq!(u64::from_le_bytes(initial[8..16].try_into().unwrap()), 0);
    assert_ne!(&initial[16..48], &[0u8; 32]);
    assert_ne!(&initial[16..48], &[1u8; 32]);
    assert_eq!(Randomness::create(&path).unwrap_err().kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), initial);

    let path_other = temp_state_path("lifecycle-other");
    Randomness::create(&path_other).unwrap();
    let other_initial = fs::read(&path_other).unwrap();
    assert_ne!(&initial[16..48], &other_initial[16..48]);
    let _ = fs::remove_dir_all(path_other.parent().unwrap());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let rng1 = Randomness::initialize(&path).unwrap();
    let after1 = fs::read(&path).unwrap();
    assert_eq!(after1.len(), STATE_LEN);
    assert_eq!(&after1[..8], b"BLINCSr1");
    assert_eq!(u64::from_le_bytes(after1[8..16].try_into().unwrap()), 1);
    assert_ne!(&after1[16..48], &initial[16..48]);

    let rng2 = Randomness::initialize(&path).unwrap();
    let after2 = fs::read(&path).unwrap();
    assert_eq!(u64::from_le_bytes(after2[8..16].try_into().unwrap()), 2);
    assert_ne!(&after2[16..48], &after1[16..48]);
    assert_ne!(rng1.draw(), rng2.draw());

    let shared = Arc::new(path.clone());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let p = Arc::clone(&shared);
            thread::spawn(move || Randomness::initialize(&*p).unwrap().draw())
        })
        .collect();
    let mut draws: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    draws.sort_unstable();
    draws.dedup();
    assert_eq!(draws.len(), 8);
    let after10 = fs::read(&path).unwrap();
    assert_eq!(u64::from_le_bytes(after10[8..16].try_into().unwrap()), 10);

    for (name, bad) in [
        ("empty", vec![]),
        ("short", b"BLINCSr1short".to_vec()),
        ("long", vec![b'x'; 49]),
        ("long-valid-magic", [b"BLINCSr1".as_slice(), &[0u8; 41]].concat()),
        ("wrong-magic", [b"NOTBLINC".as_slice(), &[0u8; 40]].concat()),
        ("exhausted", [b"BLINCSr1".as_slice(), &u64::MAX.to_le_bytes(), &[9u8; 32]].concat()),
    ] {
        let p = temp_state_path(name);
        fs::write(&p, &bad).unwrap();
        assert_eq!(Randomness::initialize(&p).unwrap_err().kind(), ErrorKind::InvalidData, "accepted {name}");
        assert_eq!(fs::read(&p).unwrap(), bad, "modified rejected file {name}");
        let _ = fs::remove_dir_all(p.parent().unwrap());
    }

    let valid_raw = [b"BLINCSr1".as_slice(), &7u64.to_le_bytes(), &[0x55u8; 32]].concat();
    let mut frag = FragmentedReader::new(&valid_raw, 5, 2);
    assert_eq!(read_exact_or_reject(&mut frag).unwrap().as_slice(), valid_raw.as_slice());
    let long_raw = [valid_raw.as_slice(), &[0u8]].concat();
    let mut frag_long = FragmentedReader::new(&long_raw, 7, 3);
    assert_eq!(read_exact_or_reject(&mut frag_long).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(read_exact_or_reject(&mut FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);

    let _ = fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn monotonic_clock_advances_and_is_nontrivial() {
    ensure_init();
    let c1 = read_monotonic_clock();
    assert!(c1.len() >= 8);
    let (s1, k1) = mix(&[0x10u8; 32], 1, &[0x20u8; 32], b"clock-a");
    let (s2, k2) = mix(&[0x10u8; 32], 1, &[0x20u8; 32], b"clock-b");
    assert_ne!(s1, s2);
    assert_ne!(k1, k2);
}

#[test]
fn create_works_with_bare_relative_filename() {
    let dir = std::env::temp_dir().join(format!("blincs-rel-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    std::env::set_current_dir(&dir).unwrap();
    Randomness::create("state.bin").unwrap();
    assert_eq!(fs::read("state.bin").unwrap().len(), 48);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn debug_redacts_secrets() {
    let seed = [0xabu8; SEED_LEN];
    let sk = SigningKey::from_seed(&seed);
    let s = format!("{sk:?}");
    assert!(!s.contains("abababab"), "SigningKey Debug leaked seed: {s}");
    assert!(s.contains(&to_hex(sk.verifying_key().as_bytes())));

    let rng = Randomness::from_run_key_at([0xcdu8; 32], 0);
    assert_eq!(format!("{rng:?}"), "Randomness { .. }");

    let sig = sk.sign_with_draw(&[1u8; 32], b"dbg");
    let sd = format!("{sig:?}");
    assert!(sd.contains("5616 bytes") && sd.contains(&to_hex(&sig.as_bytes()[..N])));
}

#[test]
fn create_alone_initializes_blake3_in_fresh_process() {
    let path = temp_state_path("create-only");
    Randomness::create(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap().len(), STATE_LEN);
    let _ = fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn initialize_alone_initializes_blake3_in_fresh_process() {
    let path = temp_state_path("init-only");
    let mut raw = [0u8; STATE_LEN];
    raw[..8].copy_from_slice(b"BLINCSr1");
    fs::write(&path, raw).unwrap();
    let rng = Randomness::initialize(&path).unwrap();
    let _ = rng.draw();
    let _ = fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn signing_key_alone_initializes_blake3_in_fresh_process() {
    let sk = SigningKey::from_seed(&[3u8; SEED_LEN]);
    assert_eq!(sk.verifying_key().as_bytes().len(), VERIFYING_KEY_LEN);
}

#[test]
fn reader_never_sees_previous_callers_bytes() {
    struct SnoopingReader<'a> {
        data: &'a [u8],
        pos: usize,
        saw_nonzero: bool,
    }
    impl Read for SnoopingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // Every newly exposed slice (both stack buffer and Pipeline rooms) must be zeroed.
            if buf.iter().any(|&b| b != 0) {
                self.saw_nonzero = true;
            }
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    #[derive(Default)]
    struct DirtyThenFail {
        calls: usize,
    }
    impl Read for DirtyThenFail {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            assert_eq!(self.calls, 1, "retried non-Interrupted I/O error");
            buf.fill(0xBB);
            Err(io::Error::new(ErrorKind::BrokenPipe, "fail after dirtying buffer"))
        }
    }

    let sk = SigningKey::from_seed(&[0x33u8; SEED_LEN]);
    let vk = sk.verifying_key();
    let secret_msg = vec![0xAAu8; 256 * 1024];

    // First call dirties stack buffer AND multiple Pipeline rooms (256 KiB).
    let sig = sk.sign_reader_with_draw(&[1u8; 32], Cursor::new(&secret_msg)).unwrap();

    // Small snooping reader inspects stack fast path.
    let mut snoop_small = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    let sig2 = sk.sign_reader_with_draw(&[2u8; 32], &mut snoop_small).unwrap();
    assert!(!snoop_small.saw_nonzero, "small sign_reader observed previous caller's bytes");
    assert!(vk.verify(b"second", &sig2));

    // Large snooping reader (200 KiB > 16 KiB and > 3 rooms) inspects newly acquired & recycled Pipeline rooms.
    let big_data = vec![0x55u8; 200 * 1024];
    let mut snoop_big_sign = SnoopingReader { data: &big_data, pos: 0, saw_nonzero: false };
    let sig_big = sk.sign_reader_with_draw(&[3u8; 32], &mut snoop_big_sign).unwrap();
    assert!(!snoop_big_sign.saw_nonzero, "Pipeline sign_reader observed nonzero room bytes");
    assert!(vk.verify(&big_data, &sig_big));

    assert!(vk.verify_reader(Cursor::new(&secret_msg), &sig).unwrap());
    assert!(vk.verify_reader(DirtyThenFail::default(), &sig).is_err());
    let mut snoop_ver = SnoopingReader { data: &big_data, pos: 0, saw_nonzero: false };
    assert!(vk.verify_reader(&mut snoop_ver, &sig_big).unwrap());
    assert!(!snoop_ver.saw_nonzero, "Pipeline verify_reader observed nonzero room bytes");
}

#[test]
fn reentrant_reader_can_sign_and_verify_without_borrowing_panic() {
    let sk = SigningKey::from_seed(&[0x44u8; SEED_LEN]);
    let vk = sk.verifying_key();
    let inner_sig = sk.sign_with_draw(&[9u8; 32], b"inner");

    struct ReentrantReader<'a> {
        sk: &'a SigningKey,
        vk: VerifyingKey,
        inner_sig: &'a Signature,
        prefix_remaining: usize,
        done: bool,
    }
    impl Read for ReentrantReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.prefix_remaining > 0 {
                let n = self.prefix_remaining.min(buf.len());
                buf[..n].fill(0x41);
                self.prefix_remaining -= n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            self.done = true;
            let nested = self.sk.sign_reader_with_draw(&[8u8; 32], Cursor::new(b"nested")).unwrap();
            assert!(self.vk.verify_reader(Cursor::new(b"nested"), &nested).unwrap());
            assert!(self.vk.verify(b"inner", self.inner_sig));
            let msg = b"outer";
            buf[..msg.len()].copy_from_slice(msg);
            Ok(msg.len())
        }
    }

    // Re-enter from the < 16 KiB stack path.
    let outer = sk.sign_reader_with_draw(&[7u8; 32], ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 0, done: false }).unwrap();
    assert!(vk.verify(b"outer", &outer));
    assert!(vk.verify_reader(ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 0, done: false }, &outer).unwrap());

    // Re-enter from the >= 16 KiB Pipeline room path.
    let mut expected_big = vec![0x41u8; 32 * 1024];
    expected_big.extend_from_slice(b"outer");
    let outer_big =
        sk.sign_reader_with_draw(&[6u8; 32], ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 32 * 1024, done: false }).unwrap();
    assert!(vk.verify(&expected_big, &outer_big));
    assert!(vk.verify_reader(ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 32 * 1024, done: false }, &outer_big).unwrap());
}

#[test]
fn checked_constructors_reject_out_of_range_values() {
    let max_tree = TreeIndex::new((1u64 << 48) - 1);
    assert_eq!(max_tree.to_le_6(), [0xff; 6]);
    assert!(catch_unwind(|| TreeIndex::new(1u64 << 48)).is_err());

    let _ = Pos::new(Layer::L0, TreeIndex::ZERO, 127);
    assert!(catch_unwind(|| Pos::new(Layer::L0, TreeIndex::ZERO, 128)).is_err());
    let _ = Pos::new(Layer::TOP, TreeIndex::ZERO, 4095);
    assert!(catch_unwind(|| Pos::new(Layer::TOP, TreeIndex::ZERO, 4096)).is_err());

    // Stream length overflow helper (u64::MAX boundary).
    assert_eq!(checked_add_stream_len(u64::MAX - 10, 10).unwrap(), u64::MAX);
    assert_eq!(checked_add_stream_len(u64::MAX - 10, 11).unwrap_err().kind(), ErrorKind::InvalidData);
}

#[test]
fn public_sign_with_shared_randomness_works_on_fresh_thread() {
    let state_path = temp_state_path("fresh-thread-sign");
    Randomness::create(&state_path).unwrap();
    let rng = Arc::new(Randomness::initialize(&state_path).unwrap());
    let sk = Arc::new(SigningKey::from_seed(&[0x77u8; SEED_LEN]));
    let vk = sk.verifying_key();

    let rng_t = Arc::clone(&rng);
    let sk_t = Arc::clone(&sk);
    let sig = thread::spawn(move || sk_t.sign(&rng_t, b"fresh thread message")).join().unwrap();
    assert!(vk.verify(b"fresh thread message", &sig));
    let _ = fs::remove_dir_all(state_path.parent().unwrap());
}

#[test]
fn hostile_filesystem_and_non_regular_state_paths_are_rejected() {
    let dir = std::env::temp_dir().join(format!("blincs-hostile-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Directory is not a regular state file.
    assert!(Randomness::initialize(&dir).is_err());

    // Dangling symlink must never be followed by create().
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = dir.join("never-created.bin");
        let link = dir.join("dangling.state");
        symlink(&target, &link).unwrap();
        assert_eq!(Randomness::create(&link).unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert!(!target.exists());
    }

    // Special device (/dev/null) is not a regular file and must be rejected cleanly with InvalidInput.
    #[cfg(unix)]
    {
        let err = Randomness::initialize("/dev/null").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn oversized_read_return_and_caught_panic_are_handled_cleanly() {
    struct OversizedReader {
        prefix: usize,
    }
    impl Read for OversizedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.prefix > 0 {
                let n = self.prefix.min(buf.len());
                buf[..n].fill(0x11);
                self.prefix -= n;
                return Ok(n);
            }
            Ok(buf.len() + 1)
        }
    }
    struct PanickingAfterReader {
        prefix: usize,
    }
    impl Read for PanickingAfterReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.prefix > 0 {
                let n = self.prefix.min(buf.len());
                buf[..n].fill(0x22);
                self.prefix -= n;
                return Ok(n);
            }
            panic!("simulated reader panic mid-stream");
        }
    }

    let sk = SigningKey::from_seed(&[0x66u8; SEED_LEN]);
    let vk = sk.verifying_key();
    let ck = ContentKey::from_vk_bytes(vk.as_bytes());

    // Oversized Read return panics fail-stop in small path, Pipeline path, and state reader.
    assert!(catch_unwind(|| content_from_reader(&ck, &[0u8; N], OversizedReader { prefix: 0 })).is_err());
    assert!(catch_unwind(|| content_from_reader(&ck, &[0u8; N], OversizedReader { prefix: 32_768 })).is_err());
    assert!(catch_unwind(|| read_exact_or_reject(&mut OversizedReader { prefix: 0 })).is_err());

    // Caught panic mid-Pipeline (after > 64 KiB room commit is in flight) leaves sign_reader / verify_reader reusable.
    let res_sign = catch_unwind(AssertUnwindSafe(|| sk.sign_reader_with_draw(&[3u8; 32], PanickingAfterReader { prefix: 80_000 })));
    assert!(res_sign.is_err());
    let sig = sk.sign_reader_with_draw(&[4u8; 32], Cursor::new(vec![0x77u8; 90_000])).unwrap();
    let res_ver = catch_unwind(AssertUnwindSafe(|| vk.verify_reader(PanickingAfterReader { prefix: 80_000 }, &sig)));
    assert!(res_ver.is_err());
    assert!(vk.verify_reader(Cursor::new(vec![0x77u8; 90_000]), &sig).unwrap());
}

#[test]
fn all_public_operations_fit_within_128kib_stack_budget() {
    let handle = thread::Builder::new()
        .name("blincs-stack-budget".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            let state_path = temp_state_path("stack-128k");
            Randomness::create(&state_path).unwrap();
            let rng = Randomness::initialize(&state_path).unwrap();
            let sk = SigningKey::from_seed(&[0x88u8; SEED_LEN]);
            let vk = VerifyingKey::from_bytes(sk.verifying_key().as_bytes());

            let small = b"bounded stack budget check";
            let s_small = sk.sign(&rng, small);
            assert!(vk.verify(small, &s_small));
            let s_small_r = sk.sign_reader(&rng, Cursor::new(small)).unwrap();
            assert!(vk.verify_reader(Cursor::new(small), &s_small_r).unwrap());

            let big = vec![0xA5u8; 100 * 1024];
            let s_big = sk.sign_reader(&rng, Cursor::new(&big)).unwrap();
            assert!(vk.verify_reader(Cursor::new(&big), &s_big).unwrap());
            assert!(vk.verify(&big, &s_big));

            let _ = fs::remove_dir_all(state_path.parent().unwrap());
        })
        .unwrap();
    handle.join().unwrap();
}

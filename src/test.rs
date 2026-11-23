include!("../tools/require_nextest.rs");

use crate::content::content_from_reader;
use crate::few_time::parse_digest;
use crate::one_time::{Pos, advance_chains, digits, lower_tree_len_check};
use crate::params::{
    CHAIN_STEPS, CHAINS, FORS_HEIGHT, FORS_LEN, FORS_TREES, HYPER_BITS, LAYERS, LOWER_HEIGHT, LOWER_LAYER_LEN, MSG_CHAINS, N, SIGNATURE_LEN, TOP_HEIGHT,
    TOP_LAYER_LEN, ensure_init,
};
use crate::randomness::{STATE_LEN, mix, read_exact_or_reject, read_monotonic_clock};
use crate::{Randomness, SEED_LEN, Signature, SigningKey, VERIFYING_KEY_LEN, VerifyingKey};
use blake3_servil::Mode;
use blake3_servil::throughput::{Batch, TreeHasher};
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read};
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
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| i as u8);
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

    let vk = VerifyingKey::from_bytes(sk.verifying_key().as_bytes());
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
    let node: [u8; N] = core::array::from_fn(|i| ((i as u8) << 4) | ((15 - i) as u8));
    let dm = digits(&node);
    for i in 0..N {
        assert_eq!(dm[2 * i], (15 - i) as u8);
        assert_eq!(dm[2 * i + 1], i as u8);
    }
    let expected_csum: u16 = dm[..MSG_CHAINS].iter().map(|&v| 15 - v as u16).sum();
    assert_eq!(expected_csum, 240); // 0x0f0 -> [0, 15, 0]
    assert_eq!(&dm[MSG_CHAINS..], &[0, 15, 0]);
}

#[test]
fn parse_digest_extracts_all_fors_indices_and_33bit_leaf_addr() {
    let mut d = [0u8; 32];
    // Pack known distinct 10-bit values into bytes 0..20 (4 values per 5 bytes).
    let expected_idx: [u16; FORS_TREES] = core::array::from_fn(|t| ((t * 67 + 13) & 0x3ff) as u16);
    for group in 0..4 {
        let mut bits = 0u64;
        for j in 0..4 {
            bits |= (expected_idx[group * 4 + j] as u64) << (10 * j);
        }
        let le = bits.to_le_bytes();
        d[group * 5..group * 5 + 5].copy_from_slice(&le[..5]);
    }
    // Pack a 33-bit leaf_addr with bit 32 set AND junk in bits 33..63 to verify exact masking.
    let expected_addr = (1u64 << (HYPER_BITS - 1)) | 0x0123_4567;
    let raw_addr = expected_addr | (0x7fff_fffe_u64 << HYPER_BITS);
    d[20..28].copy_from_slice(&raw_addr.to_le_bytes());

    let (indices, addr) = parse_digest(&d);
    assert_eq!(indices, expected_idx);
    assert_eq!(addr, expected_addr);
}

#[test]
fn advance_chains_handles_zero_partial_and_full_lengths() {
    ensure_init();
    let public = [0x33u8; 32];
    let starts: [u8; CHAINS] = core::array::from_fn(|i| (i % 5) as u8);
    let ends: [u8; CHAINS] = core::array::from_fn(|i| if i % 6 == 0 { starts[i] } else { CHAIN_STEPS as u8 - (i % 4) as u8 });
    let initial: [[u8; N]; CHAINS] = core::array::from_fn(|i| [i as u8; N]);

    let mut batched = initial;
    let mut b32 = Batch::new(32, CHAINS);
    let mut out = [[0u8; 32]; CHAINS];
    let pub_core = TreeHasher::new(Mode::Keyed(&public)).on_this_core();
    advance_chains(&pub_core, Pos { layer: 2, tree: 17, leaf: 9 }, &mut batched, &starts, &ends, &mut b32, &mut out);

    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in starts[c]..ends[c] {
            expected = crate::params::short_hash(&public, crate::params::tweak(crate::params::KIND_CHAIN, 2, 17, 9, c as u16, step as u32), &expected);
        }
        assert_eq!(batched[c], expected, "chain {c}");
    }

    let mut noop = initial;
    advance_chains(&pub_core, Pos { layer: 0, tree: 0, leaf: 0 }, &mut noop, &[5u8; CHAINS], &[5u8; CHAINS], &mut b32, &mut out);
    assert_eq!(noop, initial);

    // Early-finish case: every chain finishes by step 4 (< CHAIN_STEPS).
    let mut short = initial;
    let short_starts = [2u8; CHAINS];
    let short_ends: [u8; CHAINS] = core::array::from_fn(|i| 2 + (i % 5) as u8);
    advance_chains(&pub_core, Pos { layer: 1, tree: 3, leaf: 2 }, &mut short, &short_starts, &short_ends, &mut b32, &mut out);
    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in short_starts[c]..short_ends[c] {
            expected = crate::params::short_hash(&public, crate::params::tweak(crate::params::KIND_CHAIN, 1, 3, 2, c as u16, step as u32), &expected);
        }
        assert_eq!(short[c], expected, "short chain {c}");
    }
}

#[test]
fn every_signature_region_is_checked() {
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| i as u8);
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
    let mut at = 2 * N + FORS_LEN;
    for layer in 0..LAYERS {
        let (height, layer_len) = if layer + 1 == LAYERS { (TOP_HEIGHT, TOP_LAYER_LEN) } else { (LOWER_HEIGHT, LOWER_LAYER_LEN) };
        for c in 0..CHAINS {
            assert!(!flip(at + c * N), "accepted flip in layer {layer} chain {c}");
        }
        assert!(!flip(at + CHAINS * N), "accepted flip in layer {layer} auth 0");
        assert!(!flip(at + (CHAINS + height - 1) * N), "accepted flip in layer {layer} last auth");
        at += layer_len;
    }
    assert_eq!(at, SIGNATURE_LEN);

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

    // Covers small (< 64 KiB on-core path), exact 64 KiB boundary, Pipeline path (> 64 KiB),
    // and multithreaded slice threshold (>= 512 KiB).
    for &len in &[0usize, 1, 63, 64, 65, 1024, 65_535, 65_536, 65_537, 256 * 1024, 512 * 1024, 1024 * 1024 + 19] {
        let msg: Vec<u8> = (0..len).map(|i| ((i.wrapping_mul(37) ^ (i >> 8)) & 0xff) as u8).collect();
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

    // Immediate I/O errors propagate cleanly.
    let err = content_from_reader(&[0u8; 32], &[0u8; N], FailingReader::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    assert_eq!(sk.sign_reader_with_draw(&draw, FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);
    let sig = sk.sign_with_draw(&draw, b"x");
    assert_eq!(vk.verify_reader(FailingReader::default(), &sig).unwrap_err().kind(), ErrorKind::BrokenPipe);

    // Mid-stream I/O error AFTER 64 KiB cleanly aborts the Pipeline without panicking.
    let err_mid = content_from_reader(&[0u8; 32], &[0u8; N], FailAfterReader { remaining: 90_000, failed: false }).unwrap_err();
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
        assert!(vk.verify(&[i as u8; 128], &sig));
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
    let c1 = read_monotonic_clock();
    assert!(c1.len() >= 8 && c1 != [0] && c1 != [1]);
    thread::sleep(std::time::Duration::from_millis(2));
    let c2 = read_monotonic_clock();
    assert_eq!(c1.len(), c2.len());
    assert_ne!(c1, c2);
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
    struct SnoopingReader {
        data: &'static [u8],
        pos: usize,
        saw_nonzero: bool,
    }
    impl Read for SnoopingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos == 0 && buf.iter().any(|&b| b != 0) {
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
    let secret_msg = vec![0xAAu8; 128 * 1024];

    let sig = sk.sign_reader_with_draw(&[1u8; 32], Cursor::new(&secret_msg)).unwrap();
    let mut snoop_sign = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    let sig2 = sk.sign_reader_with_draw(&[2u8; 32], &mut snoop_sign).unwrap();
    assert!(!snoop_sign.saw_nonzero, "second sign_reader observed previous caller's bytes");
    assert!(vk.verify(b"second", &sig2));

    assert!(vk.verify_reader(Cursor::new(&secret_msg), &sig).unwrap());
    assert!(vk.verify_reader(DirtyThenFail::default(), &sig).is_err());
    let mut snoop_ver = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    assert!(vk.verify_reader(&mut snoop_ver, &sig2).unwrap());
    assert!(!snoop_ver.saw_nonzero, "second verify_reader observed previous caller's bytes");
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
        done: bool,
    }
    impl Read for ReentrantReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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

    let outer = sk.sign_reader_with_draw(&[7u8; 32], ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, done: false }).unwrap();
    assert!(vk.verify(b"outer", &outer));
    assert!(vk.verify_reader(ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, done: false }, &outer).unwrap());
}

include!("../tools/require_nextest.rs");

use crate::content::{content_from_reader, content_from_slice};
use crate::few_time::{merged_set, merged_size, parse_pick, pick};
use crate::one_time::{Pos, advance_chains, digits, parse_digits};
use crate::params::{
    AUTH_NODES, CHAIN_STEPS, CHAINS, CHUNK_LEN, DIGIT_SUM, FEW_HEIGHT, FEW_LEN, HYPER_BITS, LAYER_LEN, LAYERS, N, OPENED, SIGNATURE_LEN, THRESHOLD_BITS,
    TREE_HEIGHT,
};
use crate::randomness::{STATE_LEN, mix, read_exact_or_reject, read_monotonic_clock};
use crate::{Randomness, SEED_LEN, Signature, SigningKey, VERIFYING_KEY_LEN, VerifyingKey};
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

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

struct FailingReader;
impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(ErrorKind::BrokenPipe, "simulated failure"))
    }
}

/// Pack a synthetic 32-byte `PICK` digest from its fields for targeted boundary tests.
fn pack_pick(threshold: u8, position: u64, indices: &[u16; OPENED]) -> [u8; 32] {
    let mut bits = [0u8; 256];
    for (b, slot) in bits.iter_mut().enumerate().take(THRESHOLD_BITS) {
        *slot = (threshold >> b) & 1;
    }
    for b in 0..HYPER_BITS {
        bits[THRESHOLD_BITS + b] = ((position >> b) & 1) as u8;
    }
    for (j, &idx) in indices.iter().enumerate() {
        for b in 0..FEW_HEIGHT {
            bits[THRESHOLD_BITS + HYPER_BITS + j * FEW_HEIGHT + b] = ((idx >> b) & 1) as u8;
        }
    }
    let mut out = [0u8; 32];
    for (i, &bit) in bits.iter().enumerate() {
        out[i / 8] |= bit << (i % 8);
    }
    out
}

/// Pack a synthetic 32-byte `ONE_TIME_MESSAGE` digest from its low zero byte and 24 five-bit digits.
fn pack_digits(low_byte: u8, d: &[u8; CHAINS]) -> [u8; 32] {
    let mut x = low_byte as u128;
    for (i, &v) in d.iter().enumerate() {
        assert!(v < 32);
        x |= (v as u128) << (8 + 5 * i);
    }
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&x.to_le_bytes());
    out
}

#[test]
fn reference_vector_matches_python_byte_for_byte() {
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| i as u8);
    let draw = [7u8; 32];
    let msg = b"hello, BLINCS";

    let sk = SigningKey::from_seed(&seed);
    assert_eq!(sk.seed(), &seed);
    assert_eq!(to_hex(sk.verifying_key().as_bytes()), "0ad9c13b8972b912a211f9fd2ba1eec80f172d89ea2869ab004a78588619f97c");

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
    let vk_bytes: [u8; VERIFYING_KEY_LEN] = from_hex("0ad9c13b8972b912a211f9fd2ba1eec80f172d89ea2869ab004a78588619f97c").try_into().unwrap();
    let sig_bytes = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-signature-1.bin")).unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes);
    let sig = Signature::try_from(sig_bytes.as_slice()).unwrap();
    assert!(vk.verify(b"hello, BLINCS", &sig));
}

#[test]
fn parse_pick_checks_threshold_distinctness_and_merged_limit() {
    // 11 consecutive leaves starting at 0: merged size is small (14).
    let compact: [u16; OPENED] = core::array::from_fn(|i| i as u16);
    assert_eq!(merged_size(&compact), merged_set(&compact).len());
    let valid = pack_pick(0, 0x123456789, &compact);
    let p = parse_pick(&valid).expect("valid pick");
    assert_eq!((p.tree << TREE_HEIGHT) | p.leaf as u64, 0x123456789);
    assert_eq!(p.indices, compact);
    assert_eq!(p.merged_len, merged_size(&compact));

    // Unsorted inputs sort ascending and give the same result.
    let mut reversed = compact;
    reversed.reverse();
    assert_eq!(parse_pick(&pack_pick(0, 0x123456789, &reversed)), Some(p));

    // Any threshold bit set is rejected.
    for bit in 0..THRESHOLD_BITS {
        let bad = pack_pick(1 << bit, 0x123456789, &compact);
        assert!(parse_pick(&bad).is_none(), "threshold bit {bit} accepted");
    }

    // Duplicate leaf index is rejected even when threshold is 0 and merged size would be tiny.
    let mut dup = compact;
    dup[5] = dup[4];
    assert!(parse_pick(&pack_pick(0, 7, &dup)).is_none());

    // Exact merged-set boundary: construct sets with merged_size == 103 (accepted) and 104 (rejected).
    // Two widely spaced leaves contribute ~15 each; adjust one leaf to land on 103 and 104.
    let mut set103 = None;
    let mut set104 = None;
    let mut state = 0x9e3779b97f4a7c15u64;
    for _ in 0..200_000 {
        let mut idx = [0u16; OPENED];
        for slot in &mut idx {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *slot = ((state >> 33) & 0x7fff) as u16;
        }
        idx.sort_unstable();
        if idx.windows(2).any(|w| w[0] == w[1]) {
            continue;
        }
        let sz = merged_size(&idx);
        assert_eq!(sz, merged_set(&idx).len());
        if sz == AUTH_NODES && set103.is_none() {
            set103 = Some(idx);
        }
        if sz == AUTH_NODES + 1 && set104.is_none() {
            set104 = Some(idx);
        }
        if set103.is_some() && set104.is_some() {
            break;
        }
    }
    let s103 = set103.expect("found size-103 set");
    let s104 = set104.expect("found size-104 set");
    assert_eq!(parse_pick(&pack_pick(0, 1, &s103)).unwrap().merged_len, AUTH_NODES);
    assert!(parse_pick(&pack_pick(0, 1, &s104)).is_none());
}

#[test]
fn parse_digits_checks_zero_bits_and_exact_sum() {
    // 12 * 15 + 12 * 16 = 180 + 192 = 372.
    let valid_d: [u8; CHAINS] = core::array::from_fn(|i| if i < 12 { 15 } else { 16 });
    assert_eq!(valid_d.iter().map(|&v| v as u32).sum::<u32>(), DIGIT_SUM);
    assert_eq!(parse_digits(&pack_digits(0, &valid_d)), Some(valid_d));

    for bit in 0..8 {
        assert!(parse_digits(&pack_digits(1 << bit, &valid_d)).is_none(), "zero bit {bit} accepted");
    }
    let mut low = valid_d;
    low[0] -= 1;
    assert!(parse_digits(&pack_digits(0, &low)).is_none());
    let mut high = valid_d;
    high[0] += 1;
    assert!(parse_digits(&pack_digits(0, &high)).is_none());
}

#[test]
fn advance_chains_handles_zero_partial_and_full_lengths() {
    blake3_servil_core::initialize();
    let public = [0x33u8; 32];
    let starts: [u8; CHAINS] = core::array::from_fn(|i| (i % 5) as u8);
    let ends: [u8; CHAINS] = core::array::from_fn(|i| if i % 6 == 0 { starts[i] } else { CHAIN_STEPS as u8 - (i % 4) as u8 });
    let initial: [[u8; N]; CHAINS] = core::array::from_fn(|i| [i as u8; N]);

    let mut batched = initial;
    let mut b32 = blake3_servil_core::throughput::Batch::new(32, CHAINS);
    let mut out = [[0u8; 32]; CHAINS];
    let pub_core = blake3_servil_core::throughput::TreeHasher::new(blake3_servil_core::Mode::Keyed(&public)).on_this_core();
    advance_chains(&pub_core, Pos { layer: 2, tree: 17, leaf: 9 }, &mut batched, &starts, &ends, &mut b32, &mut out);

    // Compare against scalar one-step-at-a-time computation.
    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in starts[c]..ends[c] {
            expected = crate::params::short_hash(&public, crate::params::tweak(crate::params::KIND_CHAIN, 2, 17, 9, c as u16, step as u32), &expected);
        }
        assert_eq!(batched[c], expected, "chain {c}");
    }

    // All-zero lengths leave every value unchanged.
    let mut noop = initial;
    advance_chains(&pub_core, Pos { layer: 0, tree: 0, leaf: 0 }, &mut noop, &[5u8; CHAINS], &[5u8; CHAINS], &mut b32, &mut out);
    assert_eq!(noop, initial);
}

#[test]
fn every_signature_region_and_unused_padding_is_checked() {
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| i as u8);
    let sk = SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    let pub_core = blake3_servil_core::throughput::TreeHasher::new(blake3_servil_core::Mode::Keyed(&vk.public)).on_this_core();
    let msg = b"hello, BLINCS";

    // Find a signature with spare auth slots (< 103) so we exercise the trailing zero-padding check too.
    let (base, picked) = (0u8..=255)
        .find_map(|d| {
            let sig = sk.sign_with_draw(&[d; 32], msg);
            let salt: [u8; N] = sig.as_bytes()[..N].try_into().unwrap();
            let rand: [u8; N] = sig.as_bytes()[N..2 * N].try_into().unwrap();
            let short = content_from_slice(&vk.content_key, &salt, msg);
            let digest = vk.message_digest(&pub_core, &rand, &short);
            let fts_counter = u32::from_le_bytes(sig.as_bytes()[32..36].try_into().unwrap());
            let picked = pick(&pub_core, &digest, fts_counter).unwrap();
            (picked.merged_len < AUTH_NODES).then_some((sig, picked))
        })
        .expect("found signature with spare auth slots");
    assert!(vk.verify(msg, &base));

    let salt: [u8; N] = base.as_bytes()[..N].try_into().unwrap();
    let rand: [u8; N] = base.as_bytes()[N..2 * N].try_into().unwrap();
    let short = content_from_slice(&vk.content_key, &salt, msg);
    let digest = vk.message_digest(&pub_core, &rand, &short);

    let flip = |offset: usize| -> bool {
        let mut raw = *base.as_bytes();
        raw[offset] ^= 1;
        vk.verify(msg, &Signature::from_bytes(&raw))
    };

    // Salt, randomizer, fts_counter.
    for &off in &[0, 15, 16, 31, 32, 35] {
        assert!(!flip(off), "accepted flip at offset {off}");
    }
    // Every opened fts secret.
    for j in 0..OPENED {
        assert!(!flip(36 + N * j), "accepted flip in fts secret {j}");
    }
    // First and last used fts auth node.
    assert!(!flip(212));
    assert!(!flip(212 + N * (picked.merged_len - 1)));
    // First and last UNUSED fts auth padding byte (canonical zero check).
    assert!(!flip(212 + N * picked.merged_len), "accepted nonzero unused auth byte");
    assert!(!flip(212 + N * AUTH_NODES - 1), "accepted nonzero last unused auth byte");

    // Every hypertree layer: counter, chain 0, chain 23, path 0, path 8.
    let mut tree = picked.tree;
    let mut leaf = picked.leaf;
    let mut node = crate::workspace::with_verify_workspace(|ws| {
        crate::few_time::few_time_verify(&pub_core, &digest, &base.as_bytes()[2 * N..2 * N + FEW_LEN], ws).unwrap().2
    });
    for layer in 0..LAYERS {
        let pos = Pos { layer: layer as u8, tree, leaf };
        let at = 2 * N + FEW_LEN + layer * LAYER_LEN;
        assert!(!flip(at), "accepted flip in layer {layer} counter");
        let counter = u32::from_le_bytes(base.as_bytes()[at..at + 4].try_into().unwrap());
        let d = digits(&pub_core, pos, &node, counter).unwrap();
        // Flip every chain value in this layer.
        for (c, &dc) in d.iter().enumerate() {
            assert!(!flip(at + 4 + N * c), "accepted flip in layer {layer} chain {c} (d={dc})");
        }
        assert!(!flip(at + 4 + N * CHAINS), "accepted flip in layer {layer} path 0");
        assert!(!flip(at + 4 + N * (CHAINS + TREE_HEIGHT - 1)), "accepted flip in layer {layer} path 8");
        node = crate::workspace::with_verify_workspace(|ws| {
            crate::one_time::verify_layer(&pub_core, pos, &node, &base.as_bytes()[at..at + LAYER_LEN], ws).unwrap()
        });
        leaf = (tree & ((1u64 << TREE_HEIGHT) - 1)) as u16;
        tree >>= TREE_HEIGHT;
    }

    // Wrong verifying key (pk_seed byte 0, root byte 31).
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
fn chunk_boundaries_and_fragmented_readers_match_slices() {
    let seed = [0x11u8; SEED_LEN];
    let sk = SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    let draw = [0x22u8; 32];

    for &len in &[0usize, 1, 63, 64, 65, 1024, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN + 1, 2 * CHUNK_LEN, 2 * CHUNK_LEN + 19] {
        let msg: Vec<u8> = (0..len).map(|i| ((i.wrapping_mul(37) ^ (i >> 8)) & 0xff) as u8).collect();
        let sig = sk.sign_with_draw(&draw, &msg);
        assert!(vk.verify(&msg, &sig), "slice verify failed for len {len}");

        let frag_sign = FragmentedReader::new(&msg, 7717, 5);
        let sig_reader = sk.sign_reader_with_draw(&draw, frag_sign).unwrap();
        assert_eq!(sig_reader, sig, "reader signature differed for len {len}");

        let frag_ver = FragmentedReader::new(&msg, 11113, 3);
        assert!(vk.verify_reader(frag_ver, &sig).unwrap(), "reader verify failed for len {len}");

        // Length change and content flip must fail.
        let mut longer = msg.clone();
        longer.push(0);
        assert!(!vk.verify(&longer, &sig), "accepted trailing zero byte for len {len}");
        if !msg.is_empty() {
            let mut flipped = msg.clone();
            flipped[len - 1] ^= 1;
            assert!(!vk.verify(&flipped, &sig), "accepted last-byte flip for len {len}");
        }
    }

    // Content helper propagates real I/O errors.
    let mut blocks = vec![blake3_servil_core::throughput::Block::ZERO; CHUNK_LEN / 64];
    let err = content_from_reader(&[0u8; 32], Ok([0u8; N]), FailingReader, &mut blocks).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    assert_eq!(sk.sign_reader_with_draw(&draw, FailingReader).unwrap_err().kind(), ErrorKind::BrokenPipe);
    let sig = sk.sign_with_draw(&draw, b"x");
    assert_eq!(vk.verify_reader(FailingReader, &sig).unwrap_err().kind(), ErrorKind::BrokenPipe);
}

#[test]
fn randomness_mix_matches_python_reference() {
    blake3_servil_core::initialize();
    let seed = [0x01u8; 32];
    let system = [0x02u8; 32];
    let clock = b"clock-reading";
    let (next_seed, run_key) = mix(&seed, 42, &system, clock);

    // Exact hex values from `reference/blincs.py::mix` and `blincs.py::draw`.
    assert_eq!(to_hex(&next_seed), "c0c6b6b9b4b215c0c9f1b2009f61a44b0f3756c95f33987fd05accc567079596");
    assert_eq!(to_hex(&run_key), "ad9e373e2f5993eb67f17095c133073f746d32759f51fae8c5e9cc2ee7e96ad9");

    let r1 = Randomness::from_run_key_at(run_key, 0);
    assert_eq!(to_hex(&r1.draw()), "cd039bca0638eaf52a052a25c92cd471572fe06bc2f0eeaea4a5a6c5022b7877");
    assert_eq!(to_hex(&r1.draw()), "5c71abf8b05980f9901486582351396292e987cadf689ed5bb5934e46c0ceec9");
}

#[test]
#[should_panic(expected = "randomness draw counter exhausted")]
fn randomness_draw_panics_on_counter_exhaustion() {
    blake3_servil_core::initialize();
    let r = Randomness::from_run_key_at([1u8; 32], u64::MAX);
    let _ = r.draw();
}

#[test]
fn randomness_create_and_initialize_lifecycle_and_rejection() {
    let path = temp_state_path("lifecycle");
    // Missing file: initialize fails and does not create it.
    assert_eq!(Randomness::initialize(&path).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(!path.exists());

    // Explicit create makes a 48-byte file with count = 0 and refuses to overwrite.
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

    // A second independent create gets fresh OS randomness.
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

    // Sequential initializes increment the counter and rotate the seed without touching magic.
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

    // Concurrent initializes serialize via the file lock.
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

    // Invalid files are rejected without modifying a single byte.
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

    // State-file reader handles EINTR, short reads, non-EINTR errors, and exact-length checks.
    let valid_raw = [b"BLINCSr1".as_slice(), &7u64.to_le_bytes(), &[0x55u8; 32]].concat();
    let mut frag = FragmentedReader::new(&valid_raw, 5, 2);
    assert_eq!(read_exact_or_reject(&mut frag).unwrap().as_slice(), valid_raw.as_slice());
    let long_raw = [valid_raw.as_slice(), &[0u8]].concat();
    let mut frag_long = FragmentedReader::new(&long_raw, 7, 3);
    assert_eq!(read_exact_or_reject(&mut frag_long).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(read_exact_or_reject(&mut FailingReader).unwrap_err().kind(), ErrorKind::BrokenPipe);

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
    // Safe because cargo-nextest runs every test in its own process.
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
    assert!(sd.contains("3988 bytes") && sd.contains(&to_hex(&sig.as_bytes()[..N])));
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
    struct DirtyThenFail;
    impl Read for DirtyThenFail {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(0xBB);
            Err(io::Error::new(ErrorKind::BrokenPipe, "fail after dirtying buffer"))
        }
    }

    let sk = SigningKey::from_seed(&[0x33u8; SEED_LEN]);
    let vk = sk.verifying_key();
    let secret_msg = vec![0xAAu8; CHUNK_LEN];

    // Sign a full 0xAA chunk, then ensure a subsequent signing reader sees all zeros.
    let sig = sk.sign_reader_with_draw(&[1u8; 32], Cursor::new(&secret_msg)).unwrap();
    let mut snoop_sign = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    let sig2 = sk.sign_reader_with_draw(&[2u8; 32], &mut snoop_sign).unwrap();
    assert!(!snoop_sign.saw_nonzero, "second sign_reader observed previous caller's bytes");
    assert!(vk.verify(b"second", &sig2));

    // Verify a full 0xAA chunk, then fail a reader that dirtied the buffer, then ensure next reader sees zeros.
    assert!(vk.verify_reader(Cursor::new(&secret_msg), &sig).unwrap());
    assert!(vk.verify_reader(DirtyThenFail, &sig).is_err());
    let mut snoop_ver = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    assert!(vk.verify_reader(&mut snoop_ver, &sig2).unwrap());
    assert!(!snoop_ver.saw_nonzero, "second verify_reader observed previous caller's bytes");

    // Confirm ChunkLease returns the zeroed buffer to the thread-local pool for reuse.
    {
        let _lease = crate::workspace::ChunkLease::take();
        assert!(!crate::workspace::ChunkLease::pool_has_buffer(), "pool should be empty while leased");
    }
    assert!(crate::workspace::ChunkLease::pool_has_buffer(), "ChunkLease::drop did not return buffer to pool");
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
            // Nested sign, sign_reader, verify, and verify_reader on the same thread.
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

#[test]
fn throughput_hash_ignores_dirty_block_tail() {
    blake3_servil_core::initialize();
    let key = [0x77u8; 32];
    let salt = [0x88u8; N];
    let mut blocks = vec![blake3_servil_core::throughput::Block::ZERO; CHUNK_LEN / 64];
    // Deliberately fill the entire aligned buffer with 0xFF before reading a short 19-byte message.
    blake3_servil_core::throughput::Block::bytes_mut(&mut blocks).fill(0xFF);
    let msg = b"short-with-dirty-tl";
    let (_, short_dirty) = content_from_reader(&key, Ok(salt), Cursor::new(msg), &mut blocks).unwrap();
    let short_clean = content_from_slice(&key, &salt, msg);
    assert_eq!(short_dirty, short_clean);
}

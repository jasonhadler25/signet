include!("../tools/require_nextest.rs");

use crate::content::{checked_add_stream_len, content_from_reader};
use crate::few_time::parse_digest;
use crate::one_time::{Pos, advance_chains, digits};
use crate::params::{
    CHAIN_STEPS, CHAINS, CTX_CONTENT, FORS_HEIGHT, FORS_TREES, HYPER_BITS, IMPRINT_LEN, LAYER_LEN, Layer, MSG_CHAINS, N, PublicKey, TREE_HEIGHT, TweakKind,
    derive_key, ensure_init, tweak,
};
use crate::randomness::{
    SEED_FILE_MAX_LEN, expand_pool, is_seed_filename, mix_pool, read_bounded_seed, read_monotonic_clock, read_os_randomness, read_seed_if_present,
    remove_if_present, seed_filename, write_next_seed,
};
use crate::{Imprint, Randomness, SEED_LEN, SIGNET_ID_LEN, Signet, SignetId};
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read};
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

const REF_VK_HEX: &str = "db09192c50a65494941887b9c57895ab1d8c239fbfb22e021f3b8dcc8d5b3da2";

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

fn temp_state_dir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("blincs-test-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    base.join("state.d")
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

    let sk = Signet::from_seed(&seed);
    assert_eq!(sk.seed(), &seed);
    assert_eq!(to_hex(sk.id().as_bytes()), REF_VK_HEX);

    let expected = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-imprint-1.bin")).unwrap();
    assert_eq!(expected.len(), IMPRINT_LEN);
    let ref_sig = Imprint::try_from(expected.as_slice()).unwrap();

    let rust_sig = sk.imprint_with_draw(&draw, msg);
    assert_eq!(rust_sig.as_bytes().as_slice(), expected.as_slice());

    let reader_sig = sk.imprint_reader_with_draw(&draw, Cursor::new(msg)).unwrap();
    assert_eq!(reader_sig, rust_sig);

    let vk = SignetId::try_from(sk.id().as_bytes().as_slice()).unwrap();
    assert_eq!(vk, SignetId::from_bytes(sk.id().as_bytes()));
    assert!(SignetId::try_from(&vk.as_bytes()[..SIGNET_ID_LEN - 1]).is_err());
    assert!(SignetId::try_from([vk.as_bytes().as_slice(), &[0u8]].concat().as_slice()).is_err());
    assert!(vk.verify(msg, &ref_sig));
    assert!(vk.verify_reader(Cursor::new(msg), &ref_sig).unwrap());
    assert!(!vk.verify(b"hello, BLINCS!", &ref_sig));
}

#[test]
fn verify_alone_initializes_blake3_in_fresh_process() {
    let vk_bytes: [u8; SIGNET_ID_LEN] = from_hex(REF_VK_HEX).try_into().unwrap();
    let sig_bytes = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-imprint-1.bin")).unwrap();
    let vk = SignetId::from_bytes(&vk_bytes);
    let sig = Imprint::try_from(sig_bytes.as_slice()).unwrap();
    assert!(vk.verify(b"hello, BLINCS", &sig));
}

#[test]
fn wots_digits_and_checksum_boundaries() {
    let d0 = digits(&[0u8; N]);
    assert!(d0[..MSG_CHAINS].iter().all(|&x| x == 0));
    assert_eq!(&d0[MSG_CHAINS..], &[0, 14, 1]);

    let dmax = digits(&[0xffu8; N]);
    assert!(dmax[..MSG_CHAINS].iter().all(|&x| x == 15));
    assert_eq!(&dmax[MSG_CHAINS..], &[0, 0, 0]);

    let mut one = [0u8; N];
    one[0] = 1;
    let d1 = digits(&one);
    assert_eq!(&d1[MSG_CHAINS..], &[15, 13, 1]);

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
    assert_eq!(expected_csum, 240);
    assert_eq!(&dm[MSG_CHAINS..], &[0, 15, 0]);
}

#[test]
fn parse_digest_extracts_all_fors_indices_and_35bit_leaf_addr() {
    let mut d = [0u8; 32];
    let expected_idx: [u16; FORS_TREES] = core::array::from_fn(|t| u16::try_from((t * 157 + 29) & 0x7ff).unwrap());
    let mut acc = 0u128;
    // Pack first 11 indices (121 bits) into bytes 0..16, remaining 2 indices into bits 121..143.
    for (t, &idx) in expected_idx.iter().enumerate() {
        let bit = FORS_HEIGHT * t;
        if bit < 112 {
            acc |= u128::from(idx) << bit;
        }
    }
    d[..16].copy_from_slice(&acc.to_le_bytes());
    let mut hi_acc = 0u64;
    for (t, &idx) in expected_idx.iter().enumerate() {
        let bit = FORS_HEIGHT * t;
        if bit >= 112 {
            hi_acc |= u64::from(idx) << (bit - 112);
        }
    }
    let hi_le = hi_acc.to_le_bytes();
    for k in 0..4 {
        d[14 + k] |= hi_le[k];
    }
    // Set unused bit 143 and bytes 18..20 to 0xff to prove they do not affect extraction.
    d[17] |= 0x80;
    d[18] = 0xff;
    d[19] = 0xff;

    let expected_addr = (1u64 << (HYPER_BITS - 1)) | 0x0123_4567;
    let raw_addr = expected_addr | (0x1fff_ffff_u64 << HYPER_BITS);
    d[20..28].copy_from_slice(&raw_addr.to_le_bytes());

    let (indices, addr) = parse_digest(&d);
    assert_eq!(indices, expected_idx);
    assert_eq!(addr.as_u64(), expected_addr);
}

#[test]
fn advance_chains_handles_zero_partial_and_full_lengths() {
    ensure_init();
    let public = PublicKey::from_seed(&[0x33u8; N]);
    let starts: [u8; CHAINS] = core::array::from_fn(|i| u8::try_from(i % 5).unwrap());
    let ends: [u8; CHAINS] = core::array::from_fn(|i| if i % 6 == 0 { starts[i] } else { CHAIN_STEPS - u8::try_from(i % 4).unwrap() });
    let initial: [[u8; N]; CHAINS] = core::array::from_fn(|i| [u8::try_from(i).unwrap(); N]);

    let mut batched = initial;
    let pub_core = public.hasher(false);
    let pos2 = Pos::new(Layer::L2, 17, 9);
    advance_chains(&pub_core, pos2, &mut batched, &starts, &ends);

    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in starts[c]..ends[c] {
            let t = tweak(TweakKind::Chain, Layer::L2.as_u8(), 17, 9, u16::try_from(c).unwrap(), u32::from(step));
            expected = crate::params::short_hash(&public, t, &expected);
        }
        assert_eq!(batched[c], expected, "chain {c}");
    }

    let mut noop = initial;
    advance_chains(&pub_core, Pos::new(Layer::L0, 0, 0), &mut noop, &[5u8; CHAINS], &[5u8; CHAINS]);
    assert_eq!(noop, initial);

    let mut short = initial;
    let short_starts = [2u8; CHAINS];
    let short_ends: [u8; CHAINS] = core::array::from_fn(|i| 2 + u8::try_from(i % 5).unwrap());
    advance_chains(&pub_core, Pos::new(Layer::L1, 3, 2), &mut short, &short_starts, &short_ends);
    for c in 0..CHAINS {
        let mut expected = initial[c];
        for step in short_starts[c]..short_ends[c] {
            let t = tweak(TweakKind::Chain, Layer::L1.as_u8(), 3, 2, u16::try_from(c).unwrap(), u32::from(step));
            expected = crate::params::short_hash(&public, t, &expected);
        }
        assert_eq!(short[c], expected, "short chain {c}");
    }
}

#[test]
fn every_signature_region_is_checked() {
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let sk = Signet::from_seed(&seed);
    let vk = sk.id();

    let msg = b"hello, BLINCS";
    let base = sk.imprint_with_draw(&[7u8; 32], msg);
    assert!(vk.verify(msg, &base));

    let flip = |offset: usize| -> bool {
        let mut raw = *base.as_bytes();
        raw[offset] ^= 1;
        vk.verify(msg, &Imprint::from_bytes(&raw))
    };

    for &off in &[0, 15, 16, 31] {
        assert!(!flip(off), "accepted flip at offset {off}");
    }

    let fors_stride = (1 + FORS_HEIGHT) * N;
    for t in 0..FORS_TREES {
        let base_off = 2 * N + t * fors_stride;
        assert!(!flip(base_off), "accepted flip in FORS tree {t} secret");
        assert!(!flip(base_off + N), "accepted flip in FORS tree {t} auth 0");
        assert!(!flip(base_off + FORS_HEIGHT * N), "accepted flip in FORS tree {t} last auth");
    }

    for layer in Layer::ALL {
        let at = layer.sig_offset();
        for c in 0..CHAINS {
            assert!(!flip(at + c * N), "accepted flip in layer {} chain {c}", layer.as_u8());
        }
        assert!(!flip(at + CHAINS * N), "accepted flip in layer {} auth 0", layer.as_u8());
        assert!(!flip(at + (CHAINS + TREE_HEIGHT - 1) * N), "accepted flip in layer {} last auth", layer.as_u8());
    }
    assert_eq!(Layer::TOP.sig_offset() + LAYER_LEN, IMPRINT_LEN);

    let mut bad_vk = *vk.as_bytes();
    bad_vk[0] ^= 1;
    assert!(!SignetId::from_bytes(&bad_vk).verify(msg, &base));
    let mut bad_root = *vk.as_bytes();
    bad_root[31] ^= 1;
    assert!(!SignetId::from_bytes(&bad_root).verify(msg, &base));

    // A valid imprint from a different signet must be rejected.
    let other_sk = Signet::from_seed(&[0x99u8; SEED_LEN]);
    let other_sig = other_sk.imprint_with_draw(&[7u8; 32], msg);
    assert!(other_sk.id().verify(msg, &other_sig));
    assert!(!vk.verify(msg, &other_sig));

    assert!(Imprint::try_from(&base.as_bytes()[..IMPRINT_LEN - 1]).is_err());
    let mut too_long = base.as_bytes().to_vec();
    too_long.push(0);
    assert!(Imprint::try_from(too_long.as_slice()).is_err());
}

#[test]
fn streaming_boundaries_and_fragmented_readers_match_slices() {
    let seed = [0x11u8; SEED_LEN];
    let sk = Signet::from_seed(&seed);
    let vk = sk.id();
    let draw = [0x22u8; 32];

    for &len in &[0usize, 1, 63, 64, 65, 1024, 16_383, 16_384, 16_385, 65_535, 65_536, 65_537, 256 * 1024, 512 * 1024, 1024 * 1024 + 19] {
        let msg: Vec<u8> = (0..len).map(|i| u8::try_from((i.wrapping_mul(37) ^ (i >> 8)) & 0xff).unwrap()).collect();
        let sig = sk.imprint_with_draw(&draw, &msg);
        assert!(vk.verify(&msg, &sig), "slice verify failed for len {len}");

        let frag_sign = FragmentedReader::new(&msg, 7717, 5);
        let sig_reader = sk.imprint_reader_with_draw(&draw, frag_sign).unwrap();
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

    let ck = derive_key(CTX_CONTENT, vk.as_bytes());
    let err = content_from_reader(&ck, &[0u8; N], FailingReader::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    assert_eq!(sk.imprint_reader_with_draw(&draw, FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);
    let sig = sk.imprint_with_draw(&draw, b"x");
    assert_eq!(vk.verify_reader(FailingReader::default(), &sig).unwrap_err().kind(), ErrorKind::BrokenPipe);

    let err_mid = content_from_reader(&ck, &[0u8; N], FailAfterReader { remaining: 90_000, failed: false }).unwrap_err();
    assert_eq!(err_mid.kind(), ErrorKind::BrokenPipe);
}

#[test]
fn concurrent_signing_threads_produce_identical_signatures() {
    let sk = Arc::new(Signet::from_seed(&[0x55u8; SEED_LEN]));
    let vk = sk.id();
    let expected: Vec<Imprint> = (0u8..8).map(|i| sk.imprint_with_draw(&[i; 32], &[i; 128])).collect();

    let handles: Vec<_> = (0u8..8)
        .map(|i| {
            let sk = Arc::clone(&sk);
            thread::spawn(move || sk.imprint_with_draw(&[i; 32], &[i; 128]))
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
    let s1 = [0x01u8; 32];
    let s2 = [0xaau8, 0xbb];
    let system = [0x02u8; 32];
    let clock = b"clock-reading";
    let pool = mix_pool(&[&s1, &s2], &system, clock);
    let (file_id, next_seed, run_key, keygen_key) = expand_pool(&pool);

    assert_eq!(to_hex(&file_id), "25867ca5a64bc1144508c40dcf8811b3");
    assert_eq!(to_hex(&next_seed), "faa9e83e7a6c973128ae3731f620be90cc9d5e041b851ceb66dd333f949a4e33");
    assert_eq!(to_hex(&run_key), "e83d7320fb5db53ebb9b5ea8f04895e7936c56a11bc71681d201b2902426ebf8");
    assert_eq!(to_hex(&keygen_key), "5ed0b294833d747b589829846d84c0ab0b15478d04b047a42a292c9891c8a4ab");

    // Distinct seeds/framing produce distinct pools.
    assert_ne!(mix_pool(&[&s1], &system, clock), pool);
    assert_ne!(mix_pool(&[&[0x01u8], &[0x02, 0x03]], &system, clock), mix_pool(&[&[0x01u8, 0x02], &[0x03]], &system, clock));

    let r = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&r.draw()), "4cf8c5e80dcee5740ccc5def4297a61106e66c759679878dfb79b6b00574b9fc");
    assert_eq!(to_hex(&r.draw()), "39e6c944a4e723109e6d5405bd98d714268cdc267ea1bd349868e0216c8c8185");
    let rk = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&rk.draw_for_keygen()), "d1e76af88105198cefd2348e1fd3f969cebf1abe76a10ac7d27c6d380ae501e6");
}

#[test]
#[should_panic(expected = "randomness draw counter exhausted")]
fn randomness_draw_panics_on_counter_exhaustion() {
    ensure_init();
    let r = Randomness::from_keys_at([1u8; 32], [2u8; 32], u64::MAX);
    let _ = r.draw();
}

#[test]
fn randomness_seed_directory_lifecycle_concurrency_and_self_healing() {
    let dir = temp_state_dir("lifecycle");
    assert_eq!(Randomness::initialize(&dir).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(!dir.exists());

    // Filename validator boundary checks.
    assert!(is_seed_filename("blincs-r2-0123456789abcdef0123456789abcdef"));
    assert!(!is_seed_filename("blincs-r2-0123456789ABCDEF0123456789abcdef"));
    assert!(!is_seed_filename("blincs-r2-0123456789abcdef0123456789abcde"));
    assert!(!is_seed_filename("other-r2-0123456789abcdef0123456789abcdef"));

    Randomness::create(&dir).unwrap();
    assert_eq!(Randomness::create(&dir).unwrap_err().kind(), ErrorKind::AlreadyExists);

    let list_files = |d: &PathBuf| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = fs::read_dir(d)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name().into_string().unwrap(), fs::read(e.path()).unwrap())
            })
            .collect();
        v.sort();
        v
    };

    let init_files = list_files(&dir);
    assert_eq!(init_files.len(), 1);
    assert!(is_seed_filename(&init_files[0].0));
    assert_eq!(init_files[0].1.len(), 32);
    assert_ne!(init_files[0].1.as_slice(), &[0u8; 32]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dir.join(&init_files[0].0)).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // Separate create() produces distinct seed and filename.
    let dir_other = temp_state_dir("lifecycle-other");
    Randomness::create(&dir_other).unwrap();
    let other_files = list_files(&dir_other);
    assert_ne!(init_files[0].0, other_files[0].0);
    assert_ne!(init_files[0].1, other_files[0].1);
    let _ = fs::remove_dir_all(dir_other.parent().unwrap());

    // Sequential initializations replace the seed file with a new content-addressed filename & seed.
    let rng1 = Randomness::initialize(&dir).unwrap();
    let after1 = list_files(&dir);
    assert_eq!(after1.len(), 1);
    assert_ne!(after1[0].0, init_files[0].0);
    assert_ne!(after1[0].1, init_files[0].1);

    let rng2 = Randomness::initialize(&dir).unwrap();
    let after2 = list_files(&dir);
    assert_eq!(after2.len(), 1);
    assert_ne!(after2[0].0, after1[0].0);
    assert_ne!(rng1.draw(), rng2.draw());

    // Self-healing: leave a simulated 0-byte crash file alongside the valid 32-byte seed file.
    let crash_name = "blincs-r2-00000000000000000000000000000000";
    fs::write(dir.join(crash_name), b"").unwrap();
    assert_eq!(list_files(&dir).len(), 2);
    let _rng3 = Randomness::initialize(&dir).unwrap();
    let healed = list_files(&dir);
    assert_eq!(healed.len(), 1);
    assert_ne!(healed[0].0, crash_name);
    assert_eq!(healed[0].1.len(), 32);

    // Concurrent lock-free startups across 8 threads x 10 rounds (= 80 overlapping rotations) all succeed with distinct draws, and a follow-up startup collapses cleanly back to 1 file.
    let shared = Arc::new(dir.clone());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let p = Arc::clone(&shared);
            thread::spawn(move || (0..10).map(|_| Randomness::initialize(&*p).unwrap().draw()).collect::<Vec<_>>())
        })
        .collect();
    let mut draws: Vec<[u8; 32]> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    draws.sort_unstable();
    draws.dedup();
    assert_eq!(draws.len(), 80);
    let _collapse = Randomness::initialize(&dir).unwrap();
    assert_eq!(list_files(&dir).len(), 1);

    // read_os_randomness returns fresh, non-constant 32-byte OS entropy.
    let os_a = read_os_randomness().unwrap();
    let os_b = read_os_randomness().unwrap();
    assert_ne!(os_a, os_b);
    assert_ne!(os_a, [0u8; 32]);
    assert_ne!(os_a, [1u8; 32]);

    // read_seed_if_present & remove_if_present ignore NotFound (concurrent deletion) but propagate other I/O errors (ENOTDIR).
    let missing = dir.join("blincs-r2-00000000000000000000000000000000");
    assert_eq!(read_seed_if_present(&missing).unwrap(), None);
    remove_if_present(&missing).unwrap();
    let existing_file = dir.join(&list_files(&dir)[0].0);
    let impossible_child = existing_file.join("child");
    assert!(read_seed_if_present(&impossible_child).is_err());
    assert!(remove_if_present(&impossible_child).is_err());

    // write_next_seed re-hashes pool with CTX_MIX on AlreadyExists without clobbering the colliding file.
    let pool = [0x42u8; 32];
    let (id1, _, _, _) = expand_pool(&pool);
    let pool2 = derive_key(crate::params::CTX_MIX, &pool);
    let (id2, seed2, rk2, kk2) = expand_pool(&pool2);
    let collider = dir.join(seed_filename(&id1));
    fs::write(&collider, [0xeeu8; 32]).unwrap();
    let (got_rk, got_kk) = write_next_seed(&dir, pool).unwrap();
    assert_eq!((got_rk, got_kk), (rk2, kk2));
    assert_eq!(fs::read(&collider).unwrap(), vec![0xeeu8; 32]);
    assert_eq!(fs::read(dir.join(seed_filename(&id2))).unwrap(), seed2.to_vec());

    // read_bounded_seed accepts 0..=32 bytes and rejects 33 bytes.
    let mut frag32 = FragmentedReader::new(&[0x55u8; SEED_FILE_MAX_LEN], 5, 2);
    assert_eq!(read_bounded_seed(&mut frag32).unwrap(), vec![0x55u8; SEED_FILE_MAX_LEN]);
    let mut frag33 = FragmentedReader::new(&[0x55u8; SEED_FILE_MAX_LEN + 1], 7, 3);
    assert_eq!(read_bounded_seed(&mut frag33).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(read_bounded_seed(&mut FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);

    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn hostile_directory_and_unexpected_files_are_rejected_without_deletion() {
    let base = std::env::temp_dir().join(format!("blincs-hostile-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    // Regular file is not a directory.
    let reg = base.join("regular.bin");
    fs::write(&reg, b"not a dir").unwrap();
    assert_eq!(Randomness::initialize(&reg).unwrap_err().kind(), ErrorKind::InvalidInput);

    // Empty directory is rejected.
    let empty_dir = base.join("empty.d");
    fs::create_dir_all(&empty_dir).unwrap();
    assert_eq!(Randomness::initialize(&empty_dir).unwrap_err().kind(), ErrorKind::InvalidData);

    // Directory containing an unrelated file is rejected without touching it.
    let mixed_dir = base.join("mixed.d");
    Randomness::create(&mixed_dir).unwrap();
    let unrelated = mixed_dir.join("notes.txt");
    fs::write(&unrelated, b"keep me").unwrap();
    assert_eq!(Randomness::initialize(&mixed_dir).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(fs::read(&unrelated).unwrap(), b"keep me");

    // Directory containing an oversized (>32 B) seed-named file is rejected without touching it.
    let over_dir = base.join("over.d");
    Randomness::create(&over_dir).unwrap();
    let big_seed = over_dir.join("blincs-r2-ffffffffffffffffffffffffffffffff");
    fs::write(&big_seed, [0x77u8; 33]).unwrap();
    assert_eq!(Randomness::initialize(&over_dir).unwrap_err().kind(), ErrorKind::InvalidData);
    assert!(big_seed.exists());

    // Symlink to directory or symlink inside directory is rejected.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real_dir = base.join("real.d");
        Randomness::create(&real_dir).unwrap();
        let dir_link = base.join("link.d");
        symlink(&real_dir, &dir_link).unwrap();
        assert_eq!(Randomness::initialize(&dir_link).unwrap_err().kind(), ErrorKind::InvalidInput);

        let sym_inside = base.join("sym-inside.d");
        Randomness::create(&sym_inside).unwrap();
        symlink(&reg, sym_inside.join("blincs-r2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
        assert_eq!(Randomness::initialize(&sym_inside).unwrap_err().kind(), ErrorKind::InvalidData);
    }

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn monotonic_clock_advances_and_is_nontrivial() {
    ensure_init();
    let c1 = read_monotonic_clock();
    assert!(c1.len() >= 8);
    let p1 = mix_pool(&[&[0x10u8; 32]], &[0x20u8; 32], b"clock-a");
    let p2 = mix_pool(&[&[0x10u8; 32]], &[0x20u8; 32], b"clock-b");
    assert_ne!(p1, p2);
}

#[test]
fn signet_generate_produces_distinct_valid_signets() {
    let dir = temp_state_dir("generate");
    Randomness::create(&dir).unwrap();
    let rng = Randomness::initialize(&dir).unwrap();

    let s1 = Signet::generate(&rng).unwrap();
    let s2 = Signet::generate(&rng).unwrap();
    assert_ne!(s1.seed(), s2.seed());
    assert_ne!(s1.id(), s2.id());
    assert_eq!(Signet::from_seed(s1.seed()).id(), s1.id());

    let imp1 = s1.imprint(&rng, b"release-1");
    assert!(s1.id().verify(b"release-1", &imp1));
    assert!(!s2.id().verify(b"release-1", &imp1));

    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn debug_redacts_secrets() {
    let seed = [0xabu8; SEED_LEN];
    let sk = Signet::from_seed(&seed);
    let s = format!("{sk:?}");
    assert!(!s.contains("abababab"), "Signet Debug leaked seed: {s}");
    assert!(s.contains(&to_hex(sk.id().as_bytes())));

    let rng = Randomness::from_keys_at([0xcdu8; 32], [0xefu8; 32], 0);
    assert_eq!(format!("{rng:?}"), "Randomness { .. }");

    let sig = sk.imprint_with_draw(&[1u8; 32], b"dbg");
    let sd = format!("{sig:?}");
    assert!(sd.contains("5888 bytes") && sd.contains(&to_hex(&sig.as_bytes()[..N])));
}

#[test]
fn create_alone_initializes_blake3_in_fresh_process() {
    let dir = temp_state_dir("create-only");
    Randomness::create(&dir).unwrap();
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn initialize_alone_initializes_blake3_in_fresh_process() {
    let dir = temp_state_dir("init-only");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("blincs-r2-0123456789abcdef0123456789abcdef"), [0x42u8; 32]).unwrap();
    let rng = Randomness::initialize(&dir).unwrap();
    let _ = rng.draw();
    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn signing_key_alone_initializes_blake3_in_fresh_process() {
    let sk = Signet::from_seed(&[3u8; SEED_LEN]);
    assert_eq!(sk.id().as_bytes().len(), SIGNET_ID_LEN);
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

    let sk = Signet::from_seed(&[0x33u8; SEED_LEN]);
    let vk = sk.id();
    let secret_msg = vec![0xAAu8; 256 * 1024];

    let sig = sk.imprint_reader_with_draw(&[1u8; 32], Cursor::new(&secret_msg)).unwrap();

    let mut snoop_small = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    let sig2 = sk.imprint_reader_with_draw(&[2u8; 32], &mut snoop_small).unwrap();
    assert!(!snoop_small.saw_nonzero, "small sign_reader observed previous caller's bytes");
    assert!(vk.verify(b"second", &sig2));

    let big_data = vec![0x55u8; 200 * 1024];
    let mut snoop_big_sign = SnoopingReader { data: &big_data, pos: 0, saw_nonzero: false };
    let sig_big = sk.imprint_reader_with_draw(&[3u8; 32], &mut snoop_big_sign).unwrap();
    assert!(!snoop_big_sign.saw_nonzero, "stream sign_reader observed nonzero buffer bytes");
    assert!(vk.verify(&big_data, &sig_big));

    assert!(vk.verify_reader(Cursor::new(&secret_msg), &sig).unwrap());
    assert!(vk.verify_reader(DirtyThenFail::default(), &sig).is_err());
    let mut snoop_ver = SnoopingReader { data: &big_data, pos: 0, saw_nonzero: false };
    assert!(vk.verify_reader(&mut snoop_ver, &sig_big).unwrap());
    assert!(!snoop_ver.saw_nonzero, "stream verify_reader observed nonzero buffer bytes");
}

#[test]
fn reentrant_reader_can_sign_and_verify_without_borrowing_panic() {
    let sk = Signet::from_seed(&[0x44u8; SEED_LEN]);
    let vk = sk.id();
    let inner_sig = sk.imprint_with_draw(&[9u8; 32], b"inner");

    struct ReentrantReader<'a> {
        sk: &'a Signet,
        vk: SignetId,
        inner_sig: &'a Imprint,
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
            let nested = self.sk.imprint_reader_with_draw(&[8u8; 32], Cursor::new(b"nested")).unwrap();
            assert!(self.vk.verify_reader(Cursor::new(b"nested"), &nested).unwrap());
            assert!(self.vk.verify(b"inner", self.inner_sig));
            let msg = b"outer";
            buf[..msg.len()].copy_from_slice(msg);
            Ok(msg.len())
        }
    }

    let outer = sk.imprint_reader_with_draw(&[7u8; 32], ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 0, done: false }).unwrap();
    assert!(vk.verify(b"outer", &outer));
    assert!(vk.verify_reader(ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 0, done: false }, &outer).unwrap());

    let mut expected_big = vec![0x41u8; 32 * 1024];
    expected_big.extend_from_slice(b"outer");
    let outer_big =
        sk.imprint_reader_with_draw(&[6u8; 32], ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 32 * 1024, done: false }).unwrap();
    assert!(vk.verify(&expected_big, &outer_big));
    assert!(vk.verify_reader(ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 32 * 1024, done: false }, &outer_big).unwrap());
}

#[test]
fn checked_constructors_reject_out_of_range_values() {
    let max_t = tweak(TweakKind::Node, 0, (1u64 << 48) - 1, 0, 0, 0);
    assert_eq!(&max_t[2..8], &[0xff; 6]);
    assert!(catch_unwind(|| tweak(TweakKind::Node, 0, 1u64 << 48, 0, 0, 0)).is_err());

    // Exact per-layer hypertree bounds: L0 < 2^28, L1 < 2^21, L2 < 2^14, L3 < 2^7, L4 == 0 (all 128 leaves).
    for (layer, max_trees) in [(Layer::L0, 1u64 << 28), (Layer::L1, 1u64 << 21), (Layer::L2, 1u64 << 14), (Layer::L3, 1u64 << 7), (Layer::L4, 1)] {
        let _ = Pos::new(layer, max_trees - 1, 127);
        assert!(catch_unwind(|| Pos::new(layer, max_trees, 0)).is_err());
        assert!(catch_unwind(|| Pos::new(layer, 0, 128)).is_err());
    }

    assert_eq!(checked_add_stream_len(u64::MAX - 10, 10).unwrap(), u64::MAX);
    assert_eq!(checked_add_stream_len(u64::MAX - 10, 11).unwrap_err().kind(), ErrorKind::InvalidData);
}

#[test]
fn public_sign_with_shared_randomness_works_on_fresh_thread() {
    let dir = temp_state_dir("fresh-thread-sign");
    Randomness::create(&dir).unwrap();
    let rng = Arc::new(Randomness::initialize(&dir).unwrap());
    let sk = Arc::new(Signet::from_seed(&[0x77u8; SEED_LEN]));
    let vk = sk.id();

    let rng_t = Arc::clone(&rng);
    let sk_t = Arc::clone(&sk);
    let sig = thread::spawn(move || sk_t.imprint(&rng_t, b"fresh thread message")).join().unwrap();
    assert!(vk.verify(b"fresh thread message", &sig));
    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn oversized_read_return_fails_stop() {
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

    let sk = Signet::from_seed(&[0x66u8; SEED_LEN]);
    let vk = sk.id();
    let ck = derive_key(CTX_CONTENT, vk.as_bytes());

    assert!(catch_unwind(|| content_from_reader(&ck, &[0u8; N], OversizedReader { prefix: 0 })).is_err());
    assert!(catch_unwind(|| content_from_reader(&ck, &[0u8; N], OversizedReader { prefix: 32_768 })).is_err());
    assert!(catch_unwind(|| read_bounded_seed(&mut OversizedReader { prefix: 0 })).is_err());
}

#[test]
fn all_public_operations_fit_within_128kib_stack_budget() {
    let handle = thread::Builder::new()
        .name("blincs-stack-budget".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            let dir = temp_state_dir("stack-128k");
            Randomness::create(&dir).unwrap();
            let rng = Randomness::initialize(&dir).unwrap();
            let sk = Signet::generate(&rng).unwrap();
            let vk = SignetId::from_bytes(sk.id().as_bytes());

            let small = b"bounded stack budget check";
            let s_small = sk.imprint(&rng, small);
            assert!(vk.verify(small, &s_small));
            let s_small_r = sk.imprint_reader(&rng, Cursor::new(small)).unwrap();
            assert!(vk.verify_reader(Cursor::new(small), &s_small_r).unwrap());

            let big = vec![0xA5u8; 100 * 1024];
            let s_big = sk.imprint_reader(&rng, Cursor::new(&big)).unwrap();
            assert!(vk.verify_reader(Cursor::new(&big), &s_big).unwrap());
            assert!(vk.verify(&big, &s_big));

            let _ = fs::remove_dir_all(dir.parent().unwrap());
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn edge_vectors_match_python_byte_for_byte() {
    let json = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/edge-vectors.json")).unwrap();
    let extract = |block: &str, key: &str| -> String {
        let pat = format!("\"{key}\": \"");
        let start = block.find(&pat).unwrap() + pat.len();
        let end = block[start..].find('"').unwrap();
        block[start..start + end].to_owned()
    };

    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let sk = Signet::from_seed(&seed);
    let vk = sk.id();

    let messages: [(&str, Vec<u8>); 4] = [
        ("empty", vec![]),
        ("one-byte-zero", vec![0u8]),
        ("chunk-1024", (0..1024usize).map(|i| u8::try_from((i * 31) & 0xff).unwrap()).collect()),
        ("stream-16385-high-leaf", (0..16385usize).map(|i| u8::try_from((i * 37 + 5) & 0xff).unwrap()).collect()),
    ];

    let blocks: Vec<&str> = json.split("\"name\": \"").skip(1).collect();
    assert_eq!(blocks.len(), messages.len());
    for (block, (expected_name, msg)) in blocks.iter().zip(messages.iter()) {
        let name_end = block.find('"').unwrap();
        assert_eq!(&block[..name_end], *expected_name);
        let draw: [u8; 32] = from_hex(&extract(block, "draw_hex")).try_into().unwrap();
        let expected_sig = from_hex(&extract(block, "imprint_hex"));
        assert_eq!(expected_sig.len(), IMPRINT_LEN);

        let sig_slice = sk.imprint_with_draw(&draw, msg);
        assert_eq!(sig_slice.as_bytes().as_slice(), expected_sig.as_slice(), "slice mismatch on {expected_name}");
        let sig_reader = sk.imprint_reader_with_draw(&draw, Cursor::new(msg)).unwrap();
        assert_eq!(sig_reader, sig_slice, "reader mismatch on {expected_name}");
        assert!(vk.verify(msg, &sig_slice));
        assert!(vk.verify_reader(Cursor::new(msg), &sig_slice).unwrap());

        let mut bad = *sig_slice.as_bytes();
        bad[IMPRINT_LEN - 1] ^= 1;
        assert!(!vk.verify(msg, &Imprint::from_bytes(&bad)));
    }
}

#[test]
fn stateful_lifecycle_and_trait_contracts() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Signet>();
    assert_send_sync::<SignetId>();
    assert_send_sync::<Imprint>();
    assert_send_sync::<Randomness>();

    let d1 = temp_state_dir("lifecycle-contract-1");
    let d2 = temp_state_dir("lifecycle-contract-2");
    Randomness::create(&d1).unwrap();
    Randomness::create(&d2).unwrap();
    let r1 = Randomness::initialize(&d1).unwrap();
    let r2 = Randomness::initialize(&d2).unwrap();

    let sk1 = Signet::from_seed(&[0x10u8; SEED_LEN]);
    let sk2 = Signet::from_seed(&[0x20u8; SEED_LEN]);
    let vk1 = sk1.id();
    let vk1_copy = vk1;
    let vk1_rt = SignetId::try_from(vk1.as_bytes().as_slice()).unwrap();
    let vk2 = sk2.id();
    assert_eq!(vk1, vk1_copy);
    assert_eq!(vk1, vk1_rt);
    assert_ne!(vk1, vk2);

    let s1a = sk1.imprint(&r1, b"alpha");
    let s1b = sk1.imprint(&r1, b"alpha");
    assert_ne!(s1a, s1b, "distinct draws must yield distinct signatures");
    let s1a_clone = s1a.clone();
    assert_eq!(s1a, s1a_clone);
    assert_eq!(Imprint::try_from(s1a.as_bytes().as_slice()).unwrap(), s1a);

    let s2 = sk2.imprint_reader(&r2, Cursor::new(b"beta")).unwrap();
    assert!(vk1.verify(b"alpha", &s1a));
    assert!(vk1_rt.verify_reader(Cursor::new(b"alpha"), &s1b).unwrap());
    assert!(vk2.verify(b"beta", &s2));
    assert!(!vk1.verify(b"beta", &s2));
    assert!(!vk2.verify(b"alpha", &s1a));

    let _ = fs::remove_dir_all(d1.parent().unwrap());
    let _ = fs::remove_dir_all(d2.parent().unwrap());
}

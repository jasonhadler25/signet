include!("../tools/require_nextest.rs");

use crate::content::{checked_add_stream_len, content_from_reader, content_from_slice, derive_msg_key};
use crate::few_time::{build_all_fors, fors_verify, parse_digest};
use crate::one_time::{Pos, SignWorkspace, advance_chains, digits};
use crate::params::{
    CHAIN_STEPS, CHAINS, CTX_CONTENT, FORS_LEN, FORS_TREES, HYPER_BITS, IMPRINT_LEN, LAYER_LEN, Layer, LeafAddr, MAX_CONTEXT_LEN, MSG_CHAINS, N, PublicKey,
    SUITE_NAME, SecretKey, TweakKind, derive_key, ensure_init, tweak,
};
use crate::randomness::{
    SEED_FILE_LEN, expand_pool, is_seed_filename, mix_pool, read_exact_seed, read_monotonic_clock, read_os_randomness, read_seed_if_present, remove_if_present,
    seed_filename, write_next_seed,
};
use crate::{
    Context, ContextTooLong, Imprint, InvalidImprint, Randomness, SEED_LEN, SIGNET_ID_LEN, Signet, SignetId, VerifyError, compute_message_digest, generate_seed,
};
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read};
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

const REF_VK_HEX: &str = "b58abfb655db7c92808f12c3a8ffd2d04841cf61994321648cf193638876c492";
const REF_CTX: Context<'static> = Context::new(b"BLINCS-128-7x5 reference vector v1");
const TEST_CTX: Context<'static> = Context::new(b"signet unit test v1");

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
    let base = std::env::temp_dir().join(format!("signet-test-{}-{tag}", std::process::id()));
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
fn reference_vector_and_intermediate_kats_match_python_byte_for_byte() {
    assert_eq!(SUITE_NAME, "BLINCS-128-7x5");
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let draw = [7u8; 32];
    let msg = b"hello, BLINCS";

    let sk = Signet::from_seed(&seed);
    assert_eq!(sk.seed(), &seed);
    assert_eq!(to_hex(sk.id().as_bytes()), REF_VK_HEX);

    let expected = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-imprint-1.bin")).unwrap();
    assert_eq!(expected.len(), IMPRINT_LEN);
    let ref_sig = Imprint::try_from(expected.as_slice()).unwrap();

    // Intermediate Known Answer Tests (KATs) matching reference/blincs.py.
    let e: [u8; N] = ref_sig.as_bytes()[..N].try_into().unwrap();
    let r: [u8; N] = ref_sig.as_bytes()[N..2 * N].try_into().unwrap();
    assert_eq!(to_hex(&e), "c59c076073bef65dd74facc7453fdcdc");
    assert_eq!(to_hex(&r), "8538feb0b1803987e8a2344e0991d9b2");
    let ck = derive_key(CTX_CONTENT, sk.id().as_bytes());
    let k_msg = derive_msg_key(&ck, &e, REF_CTX);
    assert_eq!(to_hex(&k_msg), "1c28a56af15ce2bb6792393b0b477388d924a2236ca3aedb061fb93d5e52bd8e");
    let short = content_from_slice(&ck, &e, REF_CTX, msg);
    assert_eq!(to_hex(&short[N..]), "ad7606a939db70dcc963a91e0fa003d59fc4462e163c16dd2138c4cd0cc66fab");
    let pk = PublicKey::from_seed(sk.id().as_bytes()[..N].try_into().unwrap());
    let root: [u8; N] = sk.id().as_bytes()[N..].try_into().unwrap();
    let d = compute_message_digest(&pk, &r, &root, &short, REF_CTX);
    assert_eq!(to_hex(&d), "6e13239c0efaa15bda213d2b03ca8b8d726cc1f9e6e0c6c686fdac69f6af9c68");
    let (fors_idx, leaf_addr) = parse_digest(&d);
    assert_eq!(fors_idx.as_slice(), &d[..FORS_TREES]);
    assert_eq!(leaf_addr.as_u64(), 0x6c6c6e0e6);

    let rust_sig = sk.imprint_with_draw(&draw, REF_CTX, msg);
    assert_eq!(rust_sig.as_bytes().as_slice(), expected.as_slice());

    let reader_sig = sk.imprint_reader_with_draw(&draw, REF_CTX, Cursor::new(msg)).unwrap();
    assert_eq!(reader_sig, rust_sig);

    let vk = SignetId::try_from(sk.id().as_bytes().as_slice()).unwrap();
    assert_eq!(vk, SignetId::from_bytes(sk.id().as_bytes()));
    assert!(SignetId::try_from(&vk.as_bytes()[..SIGNET_ID_LEN - 1]).is_err());
    assert!(SignetId::try_from([vk.as_bytes().as_slice(), &[0u8]].concat().as_slice()).is_err());
    vk.verify(REF_CTX, msg, &ref_sig).unwrap();
    vk.verify_reader(REF_CTX, Cursor::new(msg), &ref_sig).unwrap();
    assert_eq!(vk.verify(REF_CTX, b"hello, BLINCS!", &ref_sig), Err(InvalidImprint));
    assert_eq!(vk.verify(Context::EMPTY, msg, &ref_sig), Err(InvalidImprint));
}

#[test]
fn verify_alone_initializes_blake3_in_fresh_process() {
    let vk_bytes: [u8; SIGNET_ID_LEN] = from_hex(REF_VK_HEX).try_into().unwrap();
    let sig_bytes = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-imprint-1.bin")).unwrap();
    let vk = SignetId::from_bytes(&vk_bytes);
    let sig = Imprint::try_from(sig_bytes.as_slice()).unwrap();
    vk.verify(REF_CTX, b"hello, BLINCS", &sig).unwrap();
}

#[test]
fn context_validation_framing_and_error_contracts() {
    assert_eq!(Context::EMPTY.as_bytes(), b"");
    let max_bytes = [0x5au8; MAX_CONTEXT_LEN];
    let max_ctx = Context::try_new(&max_bytes).unwrap();
    assert_eq!(max_ctx.as_bytes().len(), MAX_CONTEXT_LEN);
    assert_eq!(Context::try_from(max_bytes.as_slice()).unwrap(), max_ctx);

    let over_bytes = [0x5au8; MAX_CONTEXT_LEN + 1];
    let err = Context::try_new(&over_bytes).unwrap_err();
    assert_eq!(err, ContextTooLong { len: 256 });
    assert!(err.to_string().contains("256"));
    assert_eq!(Context::try_from(over_bytes.as_slice()).unwrap_err(), err);
    assert!(catch_unwind(|| Context::new(&over_bytes)).is_err());

    // Distinct contexts and length-framing boundaries cannot cross-verify, and derive_msg_key itself binds ctx.
    let sk = Signet::from_seed(&[0x31u8; SEED_LEN]);
    let vk = sk.id();
    let ck = derive_key(CTX_CONTENT, vk.as_bytes());
    assert_ne!(derive_msg_key(&ck, &[0u8; N], Context::EMPTY), derive_msg_key(&ck, &[0u8; N], Context::new(b"a")));
    assert_ne!(derive_msg_key(&ck, &[0u8; N], Context::new(b"a")), derive_msg_key(&ck, &[0u8; N], Context::new(b"b")));
    let sig_ab_c = sk.imprint_with_draw(&[1u8; 32], Context::new(b"ab"), b"c");
    vk.verify(Context::new(b"ab"), b"c", &sig_ab_c).unwrap();
    assert_eq!(vk.verify(Context::new(b"a"), b"bc", &sig_ab_c), Err(InvalidImprint));
    assert_eq!(vk.verify(Context::new(b"abc"), b"", &sig_ab_c), Err(InvalidImprint));
    assert_eq!(vk.verify(Context::EMPTY, b"abc", &sig_ab_c), Err(InvalidImprint));

    // Error Display / Error::source / From conversions on InvalidImprint and VerifyError.
    assert!(InvalidImprint.to_string().contains("invalid"));
    let ve_inv: VerifyError = InvalidImprint.into();
    assert!(matches!(ve_inv, VerifyError::Invalid));
    assert!(ve_inv.source().is_none());
    assert!(ve_inv.to_string().contains("invalid"));

    let ve_io: VerifyError = io::Error::new(ErrorKind::BrokenPipe, "pipe").into();
    assert!(matches!(ve_io, VerifyError::Io(_)));
    assert!(ve_io.source().is_some());
    assert!(ve_io.to_string().contains("pipe"));

    assert!(matches!(vk.verify_reader(Context::new(b"wrong"), Cursor::new(b"c"), &sig_ab_c), Err(VerifyError::Invalid)));
    assert!(matches!(vk.verify_reader(Context::new(b"ab"), FailingReader::default(), &sig_ab_c), Err(VerifyError::Io(e)) if e.kind() == ErrorKind::BrokenPipe));
}

#[test]
fn verify_short_rejects_mismatched_salt_against_short() {
    let sk = Signet::from_seed(&[0x23u8; SEED_LEN]);
    let vk = sk.id();
    let sig = sk.imprint_with_draw(&[0x44u8; 32], TEST_CTX, b"salt-check");
    let ck = derive_key(CTX_CONTENT, vk.as_bytes());
    let salt: [u8; N] = sig.as_bytes()[..N].try_into().unwrap();
    let short = content_from_slice(&ck, &salt, TEST_CTX, b"salt-check");
    vk.verify_short(TEST_CTX, &short, &sig).unwrap();

    // Corrupt only imprint.salt() (sig[0]) while keeping short intact: D and all trees still match,
    // so ONLY the explicit ct_eq_n(imprint.salt(), short[..N]) check in verify_short rejects this.
    let mut bad_raw = *sig.as_bytes();
    bad_raw[0] ^= 0x01;
    assert_eq!(vk.verify_short(TEST_CTX, &short, &Imprint::from_bytes(&bad_raw)), Err(InvalidImprint));
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
    let expected_idx: [u8; FORS_TREES] = core::array::from_fn(|t| u8::try_from((t * 13 + 29) & 0xff).unwrap());
    d[..FORS_TREES].copy_from_slice(&expected_idx);

    let expected_addr = (1u64 << (HYPER_BITS - 1)) | 0x0123_4567;
    let raw_addr = expected_addr | (0x1fff_ffff_u64 << HYPER_BITS);
    d[20..28].copy_from_slice(&raw_addr.to_le_bytes());
    d[28..32].copy_from_slice(&[0xff; 4]);

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
    let base = sk.imprint_with_draw(&[7u8; 32], REF_CTX, msg);
    vk.verify(REF_CTX, msg, &base).unwrap();

    let flip = |offset: usize| -> bool {
        let mut raw = *base.as_bytes();
        raw[offset] ^= 1;
        vk.verify(REF_CTX, msg, &Imprint::from_bytes(&raw)).is_ok()
    };

    // Mutate one byte in EVERY 16-byte wire field across the entire 7,392-byte imprint (462 fields):
    // salt (0..16), randomizer (16..32), every FORS secret & sibling, and every WOTS chain & Merkle sibling.
    for field in 0..(IMPRINT_LEN / N) {
        let off = field * N + (field % N);
        assert!(!flip(off), "accepted flip in 16-byte wire field {field} (offset {off})");
    }
    assert_eq!(Layer::TOP.sig_offset() + LAYER_LEN, IMPRINT_LEN);

    let mut bad_vk = *vk.as_bytes();
    bad_vk[0] ^= 1;
    assert_eq!(SignetId::from_bytes(&bad_vk).verify(REF_CTX, msg, &base), Err(InvalidImprint));
    let mut bad_root = *vk.as_bytes();
    bad_root[31] ^= 1;
    assert_eq!(SignetId::from_bytes(&bad_root).verify(REF_CTX, msg, &base), Err(InvalidImprint));

    // A valid imprint from a different signet must be rejected.
    let other_sk = Signet::from_seed(&[0x99u8; SEED_LEN]);
    let other_sig = other_sk.imprint_with_draw(&[7u8; 32], REF_CTX, msg);
    other_sk.id().verify(REF_CTX, msg, &other_sig).unwrap();
    assert_eq!(vk.verify(REF_CTX, msg, &other_sig), Err(InvalidImprint));

    assert!(Imprint::try_from(&base.as_bytes()[..IMPRINT_LEN - 1]).is_err());
    let mut too_long = base.as_bytes().to_vec();
    too_long.push(0);
    assert!(Imprint::try_from(too_long.as_slice()).is_err());
}

#[test]
fn arbitrary_imprints_never_panic_and_are_rejected() {
    let vk_bytes: [u8; SIGNET_ID_LEN] = from_hex(REF_VK_HEX).try_into().unwrap();
    let vk = SignetId::from_bytes(&vk_bytes);
    let mut raw = [0u8; IMPRINT_LEN];
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for round in 0..1000u32 {
        // Fill with deterministic SplitMix64 pseudorandom bytes (plus boundary all-0 and all-ff patterns).
        if round == 0 {
            raw.fill(0x00);
        } else if round == 1 {
            raw.fill(0xff);
        } else {
            for chunk in raw.as_chunks_mut::<8>().0 {
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
            }
        }
        let imp = Imprint::from_bytes(&raw);
        assert_eq!(vk.verify(REF_CTX, b"fuzz-target", &imp), Err(InvalidImprint));
    }
}

#[test]
fn streaming_boundaries_and_fragmented_readers_match_slices() {
    let seed = [0x11u8; SEED_LEN];
    let sk = Signet::from_seed(&seed);
    let vk = sk.id();
    let draw = [0x22u8; 32];

    for &len in &[0usize, 1, 63, 64, 65, 1024, 16_383, 16_384, 16_385, 65_535, 65_536, 65_537, 256 * 1024, 512 * 1024, 1024 * 1024 + 19] {
        let msg: Vec<u8> = (0..len).map(|i| u8::try_from((i.wrapping_mul(37) ^ (i >> 8)) & 0xff).unwrap()).collect();
        let sig = sk.imprint_with_draw(&draw, TEST_CTX, &msg);
        vk.verify(TEST_CTX, &msg, &sig).unwrap();

        let frag_sign = FragmentedReader::new(&msg, 7717, 5);
        let sig_reader = sk.imprint_reader_with_draw(&draw, TEST_CTX, frag_sign).unwrap();
        assert_eq!(sig_reader, sig, "reader signature differed for len {len}");

        let frag_ver = FragmentedReader::new(&msg, 11113, 3);
        vk.verify_reader(TEST_CTX, frag_ver, &sig).unwrap();

        let mut longer = msg.clone();
        longer.push(0);
        assert_eq!(vk.verify(TEST_CTX, &longer, &sig), Err(InvalidImprint));
        if !msg.is_empty() {
            let mut flipped = msg.clone();
            flipped[len - 1] ^= 1;
            assert_eq!(vk.verify(TEST_CTX, &flipped, &sig), Err(InvalidImprint));
        }
    }

    let ck = derive_key(CTX_CONTENT, vk.as_bytes());
    let err = content_from_reader(&ck, &[0u8; N], TEST_CTX, FailingReader::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    assert_eq!(sk.imprint_reader_with_draw(&draw, TEST_CTX, FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);
    let sig = sk.imprint_with_draw(&draw, TEST_CTX, b"x");
    assert!(matches!(vk.verify_reader(TEST_CTX, FailingReader::default(), &sig), Err(VerifyError::Io(e)) if e.kind() == ErrorKind::BrokenPipe));

    let err_mid = content_from_reader(&ck, &[0u8; N], TEST_CTX, FailAfterReader { remaining: 90_000, failed: false }).unwrap_err();
    assert_eq!(err_mid.kind(), ErrorKind::BrokenPipe);
}

#[test]
fn concurrent_signing_threads_produce_identical_signatures() {
    let sk = Arc::new(Signet::from_seed(&[0x55u8; SEED_LEN]));
    let vk = sk.id();
    let expected: Vec<Imprint> = (0u8..8).map(|i| sk.imprint_with_draw(&[i; 32], TEST_CTX, &[i; 128])).collect();

    let handles: Vec<_> = (0u8..8)
        .map(|i| {
            let sk = Arc::clone(&sk);
            thread::spawn(move || sk.imprint_with_draw(&[i; 32], TEST_CTX, &[i; 128]))
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        let sig = h.join().unwrap();
        assert_eq!(sig, expected[i]);
        vk.verify(TEST_CTX, &[u8::try_from(i).unwrap(); 128], &sig).unwrap();
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

    assert_eq!(to_hex(&file_id), "a927779e28c7d4d6e9b90fce92b7d968");
    assert_eq!(to_hex(&next_seed), "fe3349e18bfbb00aa7c01e353a77116c60a815f9c4c2d2c0975b378013860ceb");
    assert_eq!(to_hex(&run_key), "c8957425119b74d75e27985c4a1dbc9854fa0ad485361642b13fb927e17770c2");
    assert_eq!(to_hex(&keygen_key), "a10872041d434e01fd6c8761bfc3f25e84a697c255c1dbd26959cec5c5ad1cc6");

    // Distinct seeds/framing produce distinct pools.
    assert_ne!(mix_pool(&[&s1], &system, clock), pool);
    assert_ne!(mix_pool(&[&[0x01u8], &[0x02, 0x03]], &system, clock), mix_pool(&[&[0x01u8, 0x02], &[0x03]], &system, clock));

    let r = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&r.draw()), "2654e875d07988376ff03a027fc5168c708341b72c01a97e29f143bc9429caea");
    assert_eq!(to_hex(&r.draw()), "c64abdd2cdeae926fc81a698156cf71371339af227026256f9a90d389eaef652");
    let rk = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&rk.draw_for_keygen()), "2bae1e739a4b6fd15f275edf493a4c96cc18e3924749d0c1a06780f9a4084f12");
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
    assert!(is_seed_filename("signet-r2-0123456789abcdef0123456789abcdef"));
    assert!(!is_seed_filename("signet-r2-0123456789ABCDEF0123456789abcdef"));
    assert!(!is_seed_filename("signet-r2-0123456789abcdef0123456789abcde"));
    assert!(!is_seed_filename("other-r2-0123456789abcdef0123456789abcdef"));

    Randomness::create(&dir).unwrap();
    assert_eq!(Randomness::create(&dir).unwrap_err().kind(), ErrorKind::AlreadyExists);

    let list_files = |d: &PathBuf| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = fs::read_dir(d)
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                let name = e.file_name().into_string().unwrap();
                if name == ".stage" {
                    return None;
                }
                Some((name, fs::read(e.path()).unwrap()))
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

    // Umask-tolerant permission check: group/other bits must be zero (owner-only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(fs::metadata(dir.join(&init_files[0].0)).unwrap().permissions().mode() & 0o077, 0);
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

    // Staging directory has no leftover temp files after normal publish.
    assert_eq!(fs::read_dir(dir.join(".stage")).unwrap().count(), 0);

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
    assert_eq!(fs::read_dir(dir.join(".stage")).unwrap().count(), 0);

    // read_os_randomness returns fresh, non-constant 32-byte OS entropy.
    let os_a = read_os_randomness().unwrap();
    let os_b = read_os_randomness().unwrap();
    assert_ne!(os_a, os_b);
    assert_ne!(os_a, [0u8; 32]);
    assert_ne!(os_a, [1u8; 32]);

    // read_seed_if_present & remove_if_present ignore NotFound (concurrent deletion) but propagate other I/O errors (ENOTDIR).
    let missing = dir.join("signet-r2-00000000000000000000000000000000");
    assert_eq!(read_seed_if_present(&missing).unwrap(), None);
    remove_if_present(&missing).unwrap();
    let existing_file = dir.join(&list_files(&dir)[0].0);
    let impossible_child = existing_file.join("child");
    assert!(read_seed_if_present(&impossible_child).is_err());
    assert!(remove_if_present(&impossible_child).is_err());

    // write_next_seed re-hashes pool with CTX_MIX on AlreadyExists without clobbering the colliding file,
    // and returns non-AlreadyExists errors immediately (without looping).
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
    assert_eq!(write_next_seed(&dir.join("no-such-subdir"), pool).unwrap_err().kind(), ErrorKind::NotFound);

    // read_exact_seed accepts exact 32 bytes and rejects empty, 31-byte, and 33-byte files.
    let mut frag32 = FragmentedReader::new(&[0x55u8; SEED_FILE_LEN], 5, 2);
    assert_eq!(read_exact_seed(&mut frag32).unwrap(), [0x55u8; SEED_FILE_LEN]);
    let mut frag0 = FragmentedReader::new(b"", 5, 2);
    assert_eq!(read_exact_seed(&mut frag0).unwrap_err().kind(), ErrorKind::InvalidData);
    let mut frag31 = FragmentedReader::new(&[0x55u8; SEED_FILE_LEN - 1], 5, 2);
    assert_eq!(read_exact_seed(&mut frag31).unwrap_err().kind(), ErrorKind::InvalidData);
    let mut frag33 = FragmentedReader::new(&[0x55u8; SEED_FILE_LEN + 1], 7, 3);
    assert_eq!(read_exact_seed(&mut frag33).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(read_exact_seed(&mut FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);

    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn hostile_directory_and_unexpected_files_are_rejected_without_deletion() {
    let base = std::env::temp_dir().join(format!("signet-hostile-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    // Regular file (exact 32 bytes so only directory/symlink/filename checks reject it!) is not a directory.
    let reg = base.join("regular.bin");
    let reg_bytes = [0x33u8; 32];
    fs::write(&reg, reg_bytes).unwrap();
    assert_eq!(Randomness::initialize(&reg).unwrap_err().kind(), ErrorKind::InvalidInput);

    // Empty private directory is rejected.
    let empty_dir = base.join("empty.d");
    fs::create_dir_all(&empty_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&empty_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(Randomness::initialize(&empty_dir).unwrap_err().kind(), ErrorKind::InvalidData);

    // Non-private (0755) directory is rejected with PermissionDenied.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let pub_dir = base.join("public.d");
        Randomness::create(&pub_dir).unwrap();
        fs::set_permissions(&pub_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(Randomness::initialize(&pub_dir).unwrap_err().kind(), ErrorKind::PermissionDenied);
    }

    // Directory containing an unrelated 32-byte file is rejected without touching it.
    let mixed_dir = base.join("mixed.d");
    Randomness::create(&mixed_dir).unwrap();
    let unrelated = mixed_dir.join("notes.txt");
    let keep = [0x44u8; 32];
    fs::write(&unrelated, keep).unwrap();
    assert_eq!(Randomness::initialize(&mixed_dir).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(fs::read(&unrelated).unwrap(), keep.to_vec());

    // Directory containing an empty (0-byte), truncated (31-byte), or oversized (33-byte) seed file
    // is rejected without touching or retiring the valid sibling seed file.
    for (tag, bad_bytes) in [("zero", vec![]), ("short", vec![0x66u8; 31]), ("over", vec![0x77u8; 33])] {
        let d = base.join(format!("badsize-{tag}.d"));
        Randomness::create(&d).unwrap();
        let bad_seed = d.join("signet-r2-ffffffffffffffffffffffffffffffff");
        fs::write(&bad_seed, &bad_bytes).unwrap();
        assert_eq!(Randomness::initialize(&d).unwrap_err().kind(), ErrorKind::InvalidData);
        assert!(bad_seed.exists());
        assert_eq!(fs::read_dir(&d).unwrap().count(), 3); // original seed + bad seed + .stage
    }

    // Symlink to directory, symlink inside directory, or symlinked .stage is rejected.
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
        symlink(&reg, sym_inside.join("signet-r2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
        assert_eq!(Randomness::initialize(&sym_inside).unwrap_err().kind(), ErrorKind::InvalidData);

        let sym_stage = base.join("sym-stage.d");
        Randomness::create(&sym_stage).unwrap();
        fs::remove_dir(sym_stage.join(".stage")).unwrap();
        symlink(&empty_dir, sym_stage.join(".stage")).unwrap();
        assert_eq!(Randomness::initialize(&sym_stage).unwrap_err().kind(), ErrorKind::InvalidData);
    }

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn monotonic_clock_advances_and_is_nontrivial() {
    ensure_init();
    let c1 = read_monotonic_clock();
    thread::sleep(std::time::Duration::from_millis(2));
    let c2 = read_monotonic_clock();
    assert!(c1.len() >= 8 && c2.len() >= 8);
    assert_ne!(c1, c2);
    let p1 = mix_pool(&[&[0x10u8; 32]], &[0x20u8; 32], &c1);
    let p2 = mix_pool(&[&[0x10u8; 32]], &[0x20u8; 32], &c2);
    assert_ne!(p1, p2);
}

#[test]
fn signet_generate_produces_distinct_valid_signets() {
    ensure_init();
    // Pure keygen combiner KAT: depends on BOTH local draw and OS bytes independently.
    let local_a = [0x11u8; 32];
    let local_b = [0x22u8; 32];
    let os_a = [0x33u8; 32];
    let os_b = [0x44u8; 32];
    let s_aa = generate_seed(&local_a, &os_a);
    let s_ba = generate_seed(&local_b, &os_a);
    let s_ab = generate_seed(&local_a, &os_b);
    assert_ne!(s_aa, s_ba);
    assert_ne!(s_aa, s_ab);
    assert_ne!(s_ba, s_ab);
    let mut expected_input = [0u8; 64];
    expected_input[..32].copy_from_slice(&local_a);
    expected_input[32..].copy_from_slice(&os_a);
    assert_eq!(s_aa, derive_key(crate::params::CTX_GENERATE_SIGNET, &expected_input));

    let dir = temp_state_dir("generate");
    Randomness::create(&dir).unwrap();
    let rng = Randomness::initialize(&dir).unwrap();

    let s1 = Signet::generate(&rng).unwrap();
    let s2 = Signet::generate(&rng).unwrap();
    assert_ne!(s1.seed(), s2.seed());
    assert_ne!(s1.id(), s2.id());
    assert_eq!(Signet::from_seed(s1.seed()).id(), s1.id());

    let imp1 = s1.imprint(&rng, TEST_CTX, b"release-1");
    s1.id().verify(TEST_CTX, b"release-1", &imp1).unwrap();
    assert_eq!(s2.id().verify(TEST_CTX, b"release-1", &imp1), Err(InvalidImprint));

    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn fors_batched_root_is_index_independent_at_extreme_addresses() {
    ensure_init();
    let secret = SecretKey::derive(&[0x77u8; SEED_LEN]);
    let public = PublicKey::from_seed(&[0x88u8; N]);
    let pub_h = public.hasher(false);
    let mut ws = SignWorkspace::new(true);

    for raw_addr in [0u64, 1, (1u64 << HYPER_BITS) - 1] {
        let addr = LeafAddr::from_digest_word(raw_addr);
        let idx_zero = [0u8; FORS_TREES];
        let idx_max = [255u8; FORS_TREES];
        let idx_mix: [u8; FORS_TREES] = core::array::from_fn(|t| if t % 2 == 0 { 0 } else { 255 });

        let (mut sig_z, mut sig_m, mut sig_x) = ([0u8; FORS_LEN], [0u8; FORS_LEN], [0u8; FORS_LEN]);
        let r_z = build_all_fors(&secret, &public, addr, &idx_zero, &mut ws, &mut sig_z);
        let r_m = build_all_fors(&secret, &public, addr, &idx_max, &mut ws, &mut sig_m);
        let r_x = build_all_fors(&secret, &public, addr, &idx_mix, &mut ws, &mut sig_x);

        // Changing FORS indices at the same leaf address must change openings while preserving the FORS root!
        assert_eq!(r_z, r_m);
        assert_eq!(r_z, r_x);
        assert_ne!(sig_z, sig_m);
        assert_ne!(sig_z, sig_x);

        assert_eq!(fors_verify(&pub_h, addr, &idx_zero, &sig_z), r_z);
        assert_eq!(fors_verify(&pub_h, addr, &idx_max, &sig_m), r_m);
        assert_eq!(fors_verify(&pub_h, addr, &idx_mix, &sig_x), r_x);
    }
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

    let sig = sk.imprint_with_draw(&[1u8; 32], TEST_CTX, b"dbg");
    let sd = format!("{sig:?}");
    assert!(sd.contains(SUITE_NAME) && sd.contains("7392 bytes") && sd.contains(&to_hex(&sig.as_bytes()[..N])));
}

#[test]
fn create_alone_initializes_blake3_in_fresh_process() {
    let dir = temp_state_dir("create-only");
    Randomness::create(&dir).unwrap();
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 2); // 32-byte seed + .stage
    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn initialize_alone_initializes_blake3_in_fresh_process() {
    let dir = temp_state_dir("init-only");
    fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(dir.join("signet-r2-0123456789abcdef0123456789abcdef"), [0x42u8; 32]).unwrap();
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

    let sig = sk.imprint_reader_with_draw(&[1u8; 32], TEST_CTX, Cursor::new(&secret_msg)).unwrap();

    let mut snoop_small = SnoopingReader { data: b"second", pos: 0, saw_nonzero: false };
    let sig2 = sk.imprint_reader_with_draw(&[2u8; 32], TEST_CTX, &mut snoop_small).unwrap();
    assert!(!snoop_small.saw_nonzero, "small sign_reader observed previous caller's bytes");
    vk.verify(TEST_CTX, b"second", &sig2).unwrap();

    let big_data = vec![0x55u8; 200 * 1024];
    let mut snoop_big_sign = SnoopingReader { data: &big_data, pos: 0, saw_nonzero: false };
    let sig_big = sk.imprint_reader_with_draw(&[3u8; 32], TEST_CTX, &mut snoop_big_sign).unwrap();
    assert!(!snoop_big_sign.saw_nonzero, "stream sign_reader observed nonzero buffer bytes");
    vk.verify(TEST_CTX, &big_data, &sig_big).unwrap();

    vk.verify_reader(TEST_CTX, Cursor::new(&secret_msg), &sig).unwrap();
    assert!(matches!(vk.verify_reader(TEST_CTX, DirtyThenFail::default(), &sig), Err(VerifyError::Io(_))));
    let mut snoop_ver = SnoopingReader { data: &big_data, pos: 0, saw_nonzero: false };
    vk.verify_reader(TEST_CTX, &mut snoop_ver, &sig_big).unwrap();
    assert!(!snoop_ver.saw_nonzero, "stream verify_reader observed nonzero buffer bytes");

    // A reader that dirties tail bytes on partial read or Interrupted retry never sees them on the next read.
    struct DirtyTailRetry {
        step: usize,
        saw_nonzero: bool,
    }
    impl Read for DirtyTailRetry {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.iter().any(|&b| b != 0) {
                self.saw_nonzero = true;
            }
            self.step += 1;
            match self.step {
                1 => {
                    buf.fill(0xCC);
                    Err(io::Error::new(ErrorKind::Interrupted, "retry after dirtying"))
                }
                2 => {
                    buf.fill(0xDD);
                    buf[..3].copy_from_slice(b"abc");
                    Ok(3)
                }
                3 => {
                    buf[..3].copy_from_slice(b"def");
                    Ok(3)
                }
                _ => Ok(0),
            }
        }
    }
    let mut dtr = DirtyTailRetry { step: 0, saw_nonzero: false };
    let sig_dtr = sk.imprint_reader_with_draw(&[4u8; 32], TEST_CTX, &mut dtr).unwrap();
    assert!(!dtr.saw_nonzero, "fill_buf leaked dirty tail across Interrupted/partial read");
    vk.verify(TEST_CTX, b"abcdef", &sig_dtr).unwrap();
}

#[test]
fn reentrant_reader_can_sign_and_verify_without_borrowing_panic() {
    let sk = Signet::from_seed(&[0x44u8; SEED_LEN]);
    let vk = sk.id();
    let inner_sig = sk.imprint_with_draw(&[9u8; 32], TEST_CTX, b"inner");

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
            let nested = self.sk.imprint_reader_with_draw(&[8u8; 32], TEST_CTX, Cursor::new(b"nested")).unwrap();
            self.vk.verify_reader(TEST_CTX, Cursor::new(b"nested"), &nested).unwrap();
            self.vk.verify(TEST_CTX, b"inner", self.inner_sig).unwrap();
            let msg = b"outer";
            buf[..msg.len()].copy_from_slice(msg);
            Ok(msg.len())
        }
    }

    let outer =
        sk.imprint_reader_with_draw(&[7u8; 32], TEST_CTX, ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 0, done: false }).unwrap();
    vk.verify(TEST_CTX, b"outer", &outer).unwrap();
    vk.verify_reader(TEST_CTX, ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 0, done: false }, &outer).unwrap();

    let mut expected_big = vec![0x41u8; 32 * 1024];
    expected_big.extend_from_slice(b"outer");
    let outer_big = sk
        .imprint_reader_with_draw(&[6u8; 32], TEST_CTX, ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 32 * 1024, done: false })
        .unwrap();
    vk.verify(TEST_CTX, &expected_big, &outer_big).unwrap();
    vk.verify_reader(TEST_CTX, ReentrantReader { sk: &sk, vk, inner_sig: &inner_sig, prefix_remaining: 32 * 1024, done: false }, &outer_big).unwrap();
}

#[test]
fn checked_constructors_reject_out_of_range_values() {
    let max_t = tweak(TweakKind::Node, 0, (1u64 << 48) - 1, 0, 0, 0);
    assert_eq!(&max_t[2..8], &[0xff; 6]);
    assert!(catch_unwind(|| tweak(TweakKind::Node, 0, 1u64 << 48, 0, 0, 0)).is_err());

    // Exact per-layer hypertree bounds: L0 < 2^30 .. L5 < 2^5, L6 == 0 (all 32 leaves).
    for (layer, max_trees) in [
        (Layer::L0, 1u64 << 30),
        (Layer::L1, 1u64 << 25),
        (Layer::L2, 1u64 << 20),
        (Layer::L3, 1u64 << 15),
        (Layer::L4, 1u64 << 10),
        (Layer::L5, 1u64 << 5),
        (Layer::L6, 1),
    ] {
        let _ = Pos::new(layer, max_trees - 1, 31);
        assert!(catch_unwind(|| Pos::new(layer, max_trees, 0)).is_err());
        assert!(catch_unwind(|| Pos::new(layer, 0, 32)).is_err());
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
    let sig = thread::spawn(move || sk_t.imprint(&rng_t, TEST_CTX, b"fresh thread message")).join().unwrap();
    vk.verify(TEST_CTX, b"fresh thread message", &sig).unwrap();
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

    assert!(catch_unwind(|| content_from_reader(&ck, &[0u8; N], TEST_CTX, OversizedReader { prefix: 0 })).is_err());
    assert!(catch_unwind(|| content_from_reader(&ck, &[0u8; N], TEST_CTX, OversizedReader { prefix: 32_768 })).is_err());
    assert!(catch_unwind(|| read_exact_seed(&mut OversizedReader { prefix: 0 })).is_err());
}

#[test]
fn all_public_operations_fit_within_128kib_stack_budget() {
    let handle = thread::Builder::new()
        .name("signet-stack-budget".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            let dir = temp_state_dir("stack-128k");
            Randomness::create(&dir).unwrap();
            let rng = Randomness::initialize(&dir).unwrap();
            let sk = Signet::generate(&rng).unwrap();
            let vk = SignetId::from_bytes(sk.id().as_bytes());

            let small = b"bounded stack budget check";
            let s_small = sk.imprint(&rng, TEST_CTX, small);
            vk.verify(TEST_CTX, small, &s_small).unwrap();
            let s_small_r = sk.imprint_reader(&rng, TEST_CTX, Cursor::new(small)).unwrap();
            vk.verify_reader(TEST_CTX, Cursor::new(small), &s_small_r).unwrap();

            let big = vec![0xA5u8; 100 * 1024];
            let s_big = sk.imprint_reader(&rng, TEST_CTX, Cursor::new(&big)).unwrap();
            vk.verify_reader(TEST_CTX, Cursor::new(&big), &s_big).unwrap();
            vk.verify(TEST_CTX, &big, &s_big).unwrap();

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
        let ctx_bytes = from_hex(&extract(block, "ctx_hex"));
        let ctx = Context::try_new(&ctx_bytes).unwrap();
        let draw: [u8; 32] = from_hex(&extract(block, "draw_hex")).try_into().unwrap();
        let expected_sig = from_hex(&extract(block, "imprint_hex"));
        assert_eq!(expected_sig.len(), IMPRINT_LEN);

        let sig_slice = sk.imprint_with_draw(&draw, ctx, msg);
        assert_eq!(sig_slice.as_bytes().as_slice(), expected_sig.as_slice(), "slice mismatch on {expected_name}");
        let sig_reader = sk.imprint_reader_with_draw(&draw, ctx, Cursor::new(msg)).unwrap();
        assert_eq!(sig_reader, sig_slice, "reader mismatch on {expected_name}");
        vk.verify(ctx, msg, &sig_slice).unwrap();
        vk.verify_reader(ctx, Cursor::new(msg), &sig_slice).unwrap();

        let mut bad = *sig_slice.as_bytes();
        bad[IMPRINT_LEN - 1] ^= 1;
        assert_eq!(vk.verify(ctx, msg, &Imprint::from_bytes(&bad)), Err(InvalidImprint));
    }
}

#[test]
fn stateful_lifecycle_and_trait_contracts() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Signet>();
    assert_send_sync::<SignetId>();
    assert_send_sync::<Imprint>();
    assert_send_sync::<Randomness>();
    assert_send_sync::<Context<'static>>();
    assert_send_sync::<InvalidImprint>();
    assert_send_sync::<ContextTooLong>();
    assert_send_sync::<VerifyError>();

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

    let s1a = sk1.imprint(&r1, TEST_CTX, b"alpha");
    let s1b = sk1.imprint(&r1, TEST_CTX, b"alpha");
    assert_ne!(s1a, s1b, "distinct draws must yield distinct signatures");
    let s1a_clone = s1a.clone();
    assert_eq!(s1a, s1a_clone);
    assert_eq!(Imprint::try_from(s1a.as_bytes().as_slice()).unwrap(), s1a);

    let s2 = sk2.imprint_reader(&r2, TEST_CTX, Cursor::new(b"beta")).unwrap();
    vk1.verify(TEST_CTX, b"alpha", &s1a).unwrap();
    vk1_rt.verify_reader(TEST_CTX, Cursor::new(b"alpha"), &s1b).unwrap();
    vk2.verify(TEST_CTX, b"beta", &s2).unwrap();
    assert_eq!(vk1.verify(TEST_CTX, b"beta", &s2), Err(InvalidImprint));
    assert_eq!(vk2.verify(TEST_CTX, b"alpha", &s1a), Err(InvalidImprint));

    let _ = fs::remove_dir_all(d1.parent().unwrap());
    let _ = fs::remove_dir_all(d2.parent().unwrap());
}

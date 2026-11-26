include!("../tools/require_nextest.rs");

use crate::content::{content_from_slice, content_with, derive_msg_key};
use crate::few_time::{build_all_fors, fors_verify, parse_digest};
use crate::one_time::{Pos, SignWorkspace, advance_chains, digits};
use crate::params::{
    CHAIN_STEPS, CHAINS, CTX_CONTENT, FORS_LEN, FORS_TREES, HYPER_BITS, IMPRINT_LEN, LAYER_LEN, Layer, LeafAddr, MAX_CONTEXT_LEN, MSG_CHAINS, N, PublicKey,
    SUITE_NAME, SecretKey, TweakKind, derive_key, ensure_init, tweak,
};
use crate::randomness::{SEED_FILE_LEN, expand_pool, mix_pool, read_exact_seed, read_monotonic_clock, read_os_randomness};
use crate::{
    Context, ContextTooLong, Imprint, InvalidImprint, Randomness, SEED_LEN, SIGNET_ID_LEN, Signet, SignetId, VerifyError, compute_message_digest, generate_seed,
};
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read, Write};
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
    base.join("signet.salt")
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

    let reader_sig = sk
        .imprint_with_draw_stream(&draw, REF_CTX, |sink| {
            io::copy(&mut Cursor::new(msg), sink)?;
            Ok::<(), io::Error>(())
        })
        .unwrap();
    assert_eq!(reader_sig, rust_sig);

    let vk = SignetId::try_from(sk.id().as_bytes().as_slice()).unwrap();
    assert_eq!(vk, SignetId::from_bytes(sk.id().as_bytes()));
    assert!(SignetId::try_from(&vk.as_bytes()[..SIGNET_ID_LEN - 1]).is_err());
    assert!(SignetId::try_from([vk.as_bytes().as_slice(), &[0u8]].concat().as_slice()).is_err());
    vk.verify(REF_CTX, msg, &ref_sig).unwrap();
    vk.verify_with(REF_CTX, &ref_sig, |sink| {
        io::copy(&mut Cursor::new(msg), sink)?;
        Ok::<(), io::Error>(())
    })
    .unwrap();
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
    assert!(matches!(ve_io, VerifyError::Source(_)));
    assert!(ve_io.source().is_some());
    assert!(ve_io.to_string().contains("pipe"));

    assert!(matches!(
        vk.verify_with(Context::new(b"wrong"), &sig_ab_c, |sink| {
            sink.update(b"c");
            Ok::<(), io::Error>(())
        }),
        Err(VerifyError::Invalid)
    ));
    assert!(matches!(
        vk.verify_with(Context::new(b"ab"), &sig_ab_c, |sink| {
            io::copy(&mut FailingReader::default(), sink)?;
            Ok::<(), io::Error>(())
        }),
        Err(VerifyError::Source(e)) if e.kind() == ErrorKind::BrokenPipe
    ));
    // Verify custom non-io::Error producer error types work cleanly too.
    assert!(matches!(vk.verify_with(Context::new(b"ab"), &sig_ab_c, |_sink| Err("custom failure")), Err(VerifyError::Source("custom failure"))));
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
fn streaming_imprint_with_and_verify_with_match_slices() {
    let seed = [0x11u8; SEED_LEN];
    let sk = Signet::from_seed(&seed);
    let vk = sk.id();
    let draw = [0x22u8; 32];

    for &len in &[0usize, 1, 63, 64, 65, 1024, 16_383, 16_384, 16_385, 65_535, 65_536, 65_537, 256 * 1024, 512 * 1024, 1024 * 1024 + 19] {
        let msg: Vec<u8> = (0..len).map(|i| u8::try_from((i.wrapping_mul(37) ^ (i >> 8)) & 0xff).unwrap()).collect();
        let sig = sk.imprint_with_draw(&draw, TEST_CTX, &msg);
        vk.verify(TEST_CTX, &msg, &sig).unwrap();

        // Push-side `Sink::update` in fragmented chunks matches slice byte for byte.
        let sig_upd = sk
            .imprint_with_draw_stream(&draw, TEST_CTX, |sink| {
                for chunk in msg.chunks(7717) {
                    sink.update(chunk);
                }
                Ok::<(), io::Error>(())
            })
            .unwrap();
        assert_eq!(sig_upd, sig, "Sink::update signature differed for len {len}");

        // `std::io::Write` via `io::copy` with a fragmented reader matches too.
        let mut frag_sign = FragmentedReader::new(&msg, 7717, 5);
        let sig_copy = sk
            .imprint_with_draw_stream(&draw, TEST_CTX, |sink| {
                io::copy(&mut frag_sign, sink)?;
                sink.flush()?;
                Ok::<(), io::Error>(())
            })
            .unwrap();
        assert_eq!(sig_copy, sig, "io::copy signature differed for len {len}");

        let mut frag_ver = FragmentedReader::new(&msg, 11113, 3);
        vk.verify_with(TEST_CTX, &sig, |sink| {
            io::copy(&mut frag_ver, sink)?;
            Ok::<(), io::Error>(())
        })
        .unwrap();

        let mut longer = msg.clone();
        longer.push(0);
        assert_eq!(vk.verify(TEST_CTX, &longer, &sig), Err(InvalidImprint));
        if !msg.is_empty() {
            let mut flipped = msg.clone();
            flipped[len - 1] ^= 1;
            assert_eq!(vk.verify(TEST_CTX, &flipped, &sig), Err(InvalidImprint));
        }
    }

    // Producer errors abort cleanly without producing an imprint or accepting verification.
    let ck = derive_key(CTX_CONTENT, vk.as_bytes());
    let err = content_with(&ck, &[0u8; N], TEST_CTX, |sink| {
        io::copy(&mut FailingReader::default(), sink)?;
        Ok::<(), io::Error>(())
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    let err_sign = sk
        .imprint_with_draw_stream(&draw, TEST_CTX, |sink| {
            io::copy(&mut FailingReader::default(), sink)?;
            Ok::<(), io::Error>(())
        })
        .unwrap_err();
    assert_eq!(err_sign.kind(), ErrorKind::BrokenPipe);
    let sig = sk.imprint_with_draw(&draw, TEST_CTX, b"x");
    assert!(matches!(
        vk.verify_with(TEST_CTX, &sig, |sink| {
            io::copy(&mut FailingReader::default(), sink)?;
            Ok::<(), io::Error>(())
        }),
        Err(VerifyError::Source(e)) if e.kind() == ErrorKind::BrokenPipe
    ));
    let err_mid = content_with(&ck, &[0u8; N], TEST_CTX, |sink| {
        io::copy(&mut FailAfterReader { remaining: 90_000, failed: false }, sink)?;
        Ok::<(), io::Error>(())
    })
    .unwrap_err();
    assert_eq!(err_mid.kind(), ErrorKind::BrokenPipe);

    // Sticky u64::MAX overflow poisoning on both Sink::update and Sink::write (and Debug impl).
    assert!(matches!(
        vk.verify_with(TEST_CTX, &sig, |sink| {
            let dbg = format!("{sink:?}");
            assert!(dbg.contains("Sink"));
            sink.set_total_for_test(u64::MAX - 1);
            sink.update(b"x");
            sink.update(b"yz"); // overflows -> sticky poison
            sink.update(b""); // remains poisoned
            assert!(sink.write(b"a").is_err());
            Ok::<(), io::Error>(())
        }),
        Err(VerifyError::Invalid)
    ));
    assert!(matches!(
        vk.verify_with(TEST_CTX, &sig, |sink| {
            sink.set_total_for_test(u64::MAX);
            sink.write_all(b"x")
        }),
        Err(VerifyError::Source(e)) if e.kind() == ErrorKind::InvalidData
    ));
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
    let prior = [0x01u8; 32];
    let system = [0x02u8; 32];
    let pid = 4242u32;
    let clock = b"clock-reading";
    let pool = mix_pool(Some(&prior), &system, pid, clock);
    let (next_seed, run_key, keygen_key) = expand_pool(&pool);

    assert_eq!(to_hex(&next_seed), "e25f6194f016297e9ede065cdda5791ac021a69fbc0912e318ecb321d70f7d24");
    assert_eq!(to_hex(&run_key), "f3454e55d82b6e1350a46c01a4be23a55f9f6ebb51baadf364ee91fa11c3d84c");
    assert_eq!(to_hex(&keygen_key), "9f080816264c88adc6207059744e0d64f739a1b984e7db047fea9ffe15e47615");

    // Prior salt, PID, system randomness, and clock all affect the mixed pool independently.
    assert_ne!(mix_pool(None, &system, pid, clock), pool);
    assert_ne!(mix_pool(Some(&prior), &system, pid + 1, clock), pool);
    assert_ne!(mix_pool(Some(&prior), &[0x03u8; 32], pid, clock), pool);
    assert_ne!(mix_pool(Some(&prior), &system, pid, b"other-clock"), pool);

    let r = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&r.draw()), "5f2db2b96c8a6873291819498bec87e7c5d514877f21f55452125372f93f034f");
    assert_ne!(r.draw(), r.draw());
    let rk = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&rk.draw_for_keygen()), "1a79f68394d9592a5586ea8ca3259bb52edc4bba803668782c604a9f0060259e");

    // read_exact_seed retries Interrupted, accepts exact 32 bytes, rejects 0/31/33 bytes, propagates errors.
    let mut frag32 = FragmentedReader::new(&[0x55u8; SEED_FILE_LEN], 5, 2);
    assert_eq!(read_exact_seed(&mut frag32).unwrap(), [0x55u8; SEED_FILE_LEN]);
    let mut frag0 = FragmentedReader::new(b"", 5, 2);
    assert_eq!(read_exact_seed(&mut frag0).unwrap_err().kind(), ErrorKind::InvalidData);
    let mut frag31 = FragmentedReader::new(&[0x55u8; SEED_FILE_LEN - 1], 5, 2);
    assert_eq!(read_exact_seed(&mut frag31).unwrap_err().kind(), ErrorKind::InvalidData);
    let mut frag33 = FragmentedReader::new(&[0x55u8; SEED_FILE_LEN + 1], 7, 3);
    assert_eq!(read_exact_seed(&mut frag33).unwrap_err().kind(), ErrorKind::InvalidData);
    assert_eq!(read_exact_seed(&mut FailingReader::default()).unwrap_err().kind(), ErrorKind::BrokenPipe);
}

#[test]
#[should_panic(expected = "randomness draw counter exhausted")]
fn randomness_draw_panics_on_counter_exhaustion() {
    ensure_init();
    let r = Randomness::from_keys_at([1u8; 32], [2u8; 32], u64::MAX);
    let _ = r.draw();
}

#[test]
fn randomness_state_file_lifecycle_and_concurrency() {
    let state = temp_state_dir("lifecycle");
    assert_eq!(Randomness::initialize(&state).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(!state.exists());

    Randomness::create(&state).unwrap();
    assert_eq!(Randomness::create(&state).unwrap_err().kind(), ErrorKind::AlreadyExists);

    let init_bytes = fs::read(&state).unwrap();
    assert_eq!(init_bytes.len(), SEED_FILE_LEN);
    assert_ne!(init_bytes.as_slice(), &[0u8; 32]);

    // Umask-tolerant permission check: group/other bits must be zero (owner-only 0600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o077, 0);
    }

    // Separate create() produces distinct initial state.
    let state_other = temp_state_dir("lifecycle-other");
    Randomness::create(&state_other).unwrap();
    assert_ne!(init_bytes, fs::read(&state_other).unwrap());
    let _ = fs::remove_dir_all(state_other.parent().unwrap());

    // Sequential initializations atomically rotate the 32-byte state file with no leftover temp files.
    let rng1 = Randomness::initialize(&state).unwrap();
    let after1 = fs::read(&state).unwrap();
    assert_eq!(after1.len(), SEED_FILE_LEN);
    assert_ne!(after1, init_bytes);

    let rng2 = Randomness::initialize(&state).unwrap();
    let after2 = fs::read(&state).unwrap();
    assert_eq!(after2.len(), SEED_FILE_LEN);
    assert_ne!(after2, after1);
    assert_ne!(rng1.draw(), rng2.draw());
    assert_eq!(fs::read_dir(state.parent().unwrap()).unwrap().count(), 1);

    // Concurrent lock-free startups across 8 threads x 10 rounds (= 80 overlapping atomic renames)
    // all succeed cleanly with 80 distinct draws and leave a single valid 32-byte state file.
    let shared = Arc::new(state.clone());
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
    assert_eq!(fs::read(&state).unwrap().len(), SEED_FILE_LEN);
    assert_eq!(fs::read_dir(state.parent().unwrap()).unwrap().count(), 1);

    // read_os_randomness returns fresh, non-constant 32-byte OS entropy.
    let os_a = read_os_randomness().unwrap();
    let os_b = read_os_randomness().unwrap();
    assert_ne!(os_a, os_b);
    assert_ne!(os_a, [0u8; 32]);
    assert_ne!(os_a, [1u8; 32]);

    let _ = fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn hostile_state_path_and_bad_files_are_rejected_without_clobbering() {
    let base = std::env::temp_dir().join(format!("signet-hostile-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    // Directory is rejected without modification.
    let dir = base.join("a-dir");
    fs::create_dir_all(&dir).unwrap();
    assert_eq!(Randomness::initialize(&dir).unwrap_err().kind(), ErrorKind::InvalidInput);

    // Non-private (0644) state file is rejected with PermissionDenied without modifying it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let pub_file = base.join("public.salt");
        Randomness::create(&pub_file).unwrap();
        let before = fs::read(&pub_file).unwrap();
        fs::set_permissions(&pub_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(Randomness::initialize(&pub_file).unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&pub_file).unwrap(), before);
    }

    // Empty (0 B), truncated (31 B), and oversized (33 B) private files are rejected untouched.
    for (tag, bad_bytes) in [("zero", vec![]), ("short", vec![0x66u8; 31]), ("over", vec![0x77u8; 33])] {
        let f = base.join(format!("badsize-{tag}.salt"));
        fs::write(&f, &bad_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(Randomness::initialize(&f).unwrap_err().kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read(&f).unwrap(), bad_bytes);
    }

    // Symlink to a valid state file is rejected without touching target.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real_file = base.join("real.salt");
        Randomness::create(&real_file).unwrap();
        let before = fs::read(&real_file).unwrap();
        let sym = base.join("link.salt");
        symlink(&real_file, &sym).unwrap();
        assert_eq!(Randomness::initialize(&sym).unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(fs::read(&real_file).unwrap(), before);
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
    let p1 = mix_pool(Some(&[0x10u8; 32]), &[0x20u8; 32], 1, &c1);
    let p2 = mix_pool(Some(&[0x10u8; 32]), &[0x20u8; 32], 1, &c2);
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
    let state = temp_state_dir("create-only");
    Randomness::create(&state).unwrap();
    assert_eq!(fs::read(&state).unwrap().len(), SEED_FILE_LEN);
    let _ = fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn initialize_alone_initializes_blake3_in_fresh_process() {
    let state = temp_state_dir("init-only");
    fs::write(&state, [0x42u8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let rng = Randomness::initialize(&state).unwrap();
    let _ = rng.draw();
    let _ = fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn signing_key_alone_initializes_blake3_in_fresh_process() {
    let sk = Signet::from_seed(&[3u8; SEED_LEN]);
    assert_eq!(sk.id().as_bytes().len(), SIGNET_ID_LEN);
}

#[test]
fn reentrant_producer_can_sign_and_verify_without_borrowing_panic() {
    let sk = Signet::from_seed(&[0x44u8; SEED_LEN]);
    let vk = sk.id();
    let inner_sig = sk.imprint_with_draw(&[9u8; 32], TEST_CTX, b"inner");

    let produce = |prefix_len: usize, sink: &mut crate::Sink| -> io::Result<()> {
        if prefix_len > 0 {
            sink.update(&vec![0x41u8; prefix_len]);
        }
        let nested = sk.imprint_with_draw_stream(&[8u8; 32], TEST_CTX, |s| {
            s.update(b"nested");
            Ok::<(), io::Error>(())
        })?;
        vk.verify_with(TEST_CTX, &nested, |s| {
            s.update(b"nested");
            Ok::<(), io::Error>(())
        })
        .unwrap();
        vk.verify(TEST_CTX, b"inner", &inner_sig).unwrap();
        sink.update(b"outer");
        Ok(())
    };

    let outer = sk.imprint_with_draw_stream(&[7u8; 32], TEST_CTX, |s| produce(0, s)).unwrap();
    vk.verify(TEST_CTX, b"outer", &outer).unwrap();
    vk.verify_with(TEST_CTX, &outer, |s| produce(0, s)).unwrap();

    let mut expected_big = vec![0x41u8; 32 * 1024];
    expected_big.extend_from_slice(b"outer");
    let outer_big = sk.imprint_with_draw_stream(&[6u8; 32], TEST_CTX, |s| produce(32 * 1024, s)).unwrap();
    vk.verify(TEST_CTX, &expected_big, &outer_big).unwrap();
    vk.verify_with(TEST_CTX, &outer_big, |s| produce(32 * 1024, s)).unwrap();
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
}

#[test]
fn public_sign_with_shared_randomness_works_on_fresh_thread() {
    let state = temp_state_dir("fresh-thread-sign");
    Randomness::create(&state).unwrap();
    let rng = Arc::new(Randomness::initialize(&state).unwrap());
    let sk = Arc::new(Signet::from_seed(&[0x77u8; SEED_LEN]));
    let vk = sk.id();

    let rng_t = Arc::clone(&rng);
    let sk_t = Arc::clone(&sk);
    let sig = thread::spawn(move || sk_t.imprint(&rng_t, TEST_CTX, b"fresh thread message")).join().unwrap();
    vk.verify(TEST_CTX, b"fresh thread message", &sig).unwrap();
    let _ = fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn all_public_operations_fit_within_128kib_stack_budget() {
    let handle = thread::Builder::new()
        .name("signet-stack-budget".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            let state = temp_state_dir("stack-128k");
            Randomness::create(&state).unwrap();
            let rng = Randomness::initialize(&state).unwrap();
            let sk = Signet::generate(&rng).unwrap();
            let vk = SignetId::from_bytes(sk.id().as_bytes());

            let small = b"bounded stack budget check";
            let s_small = sk.imprint(&rng, TEST_CTX, small);
            vk.verify(TEST_CTX, small, &s_small).unwrap();
            let s_small_r = sk
                .imprint_with(&rng, TEST_CTX, |sink| {
                    io::copy(&mut Cursor::new(small), sink)?;
                    Ok::<(), io::Error>(())
                })
                .unwrap();
            vk.verify_with(TEST_CTX, &s_small_r, |sink| {
                io::copy(&mut Cursor::new(small), sink)?;
                Ok::<(), io::Error>(())
            })
            .unwrap();

            let big = vec![0xA5u8; 100 * 1024];
            let s_big = sk
                .imprint_with(&rng, TEST_CTX, |sink| {
                    io::copy(&mut Cursor::new(&big), sink)?;
                    Ok::<(), io::Error>(())
                })
                .unwrap();
            vk.verify_with(TEST_CTX, &s_big, |sink| {
                io::copy(&mut Cursor::new(&big), sink)?;
                Ok::<(), io::Error>(())
            })
            .unwrap();
            vk.verify(TEST_CTX, &big, &s_big).unwrap();

            let _ = fs::remove_dir_all(state.parent().unwrap());
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
        let sig_stream = sk
            .imprint_with_draw_stream(&draw, ctx, |sink| {
                sink.update(msg);
                Ok::<(), io::Error>(())
            })
            .unwrap();
        assert_eq!(sig_stream, sig_slice, "stream mismatch on {expected_name}");
        vk.verify(ctx, msg, &sig_slice).unwrap();
        vk.verify_with(ctx, &sig_slice, |sink| {
            sink.update(msg);
            Ok::<(), io::Error>(())
        })
        .unwrap();

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

    let s2 = sk2
        .imprint_with(&r2, TEST_CTX, |sink| {
            sink.update(b"beta");
            Ok::<(), io::Error>(())
        })
        .unwrap();
    vk1.verify(TEST_CTX, b"alpha", &s1a).unwrap();
    vk1_rt
        .verify_with(TEST_CTX, &s1b, |sink| {
            sink.update(b"alpha");
            Ok::<(), io::Error>(())
        })
        .unwrap();
    vk2.verify(TEST_CTX, b"beta", &s2).unwrap();
    assert_eq!(vk1.verify(TEST_CTX, b"beta", &s2), Err(InvalidImprint));
    assert_eq!(vk2.verify(TEST_CTX, b"alpha", &s1a), Err(InvalidImprint));

    let _ = fs::remove_dir_all(d1.parent().unwrap());
    let _ = fs::remove_dir_all(d2.parent().unwrap());
}

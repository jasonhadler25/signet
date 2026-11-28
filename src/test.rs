include!("../tools/require_nextest.rs");

use crate::coding::{decode_wots_c, hex_unrank};
use crate::content::{content_from_slice, content_with, derive_msg_key};
use crate::engine::{CORE_PACKED_WIDTH, Packed, STACK_PACKED_CAP, core_pad_width, sort_chain_queue};
use crate::few_time::{
    count_octopus_sibs, extract_upors_codewords, parse_select_digest, parse_select_fast, select_ancestor_lower_bound, verify_upors_selection,
};
use crate::one_time::verify_wots_msg;
use crate::params::{
    CTX_CONTENT, HYPER_BITS, IMPRINT_LEN, Layer, LeafAddr, MAX_CONTEXT_LEN, N, PublicKey, SUITE_NAME, TOP_LAYER_LEN, TweakKind, UPORS_C, UPORS_CTR_LEN,
    UPORS_HEIGHT, UPORS_K, UPORS_LEN, UPORS_M_MAX, UPORS_N, UPORS_SELECT_MAX_DRAWS, UPORS_STEPS, UPORS_SUM, WOTS_N, WOTS_STEPS, WOTS_SUM, derive_key,
    ensure_init, read_bits, tweak,
};
use crate::randomness::{SEED_FILE_LEN, expand_pool, mix_pool, read_exact_seed, read_monotonic_clock, read_os_randomness};
use crate::{
    Context, ContextTooLong, Imprint, InvalidImprint, Randomness, SEED_LEN, SIGNET_ID_LEN, Signet, SignetId, VerifyError, compute_message_digest, generate_seed,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

const REF_VK_HEX: &str = "7ee7fe20dac820b17625cad3a38a8af696a69a74992f01a7c9ed3680699d2c5c";
const REF_CTX: Context<'static> = Context::new(b"BLINCS-48-X reference vector v1");
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
    assert_eq!(SUITE_NAME, "BLINCS-48-X");
    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let draw = [7u8; 32];
    let msg = b"hello, BLINCS";

    let sk = Signet::from_seed(&seed);
    assert_eq!(sk.seed(), &seed);
    assert_eq!(to_hex(sk.id().as_bytes()), REF_VK_HEX);

    let expected = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/reference-imprint-1.bin")).unwrap();
    assert_eq!(expected.len(), IMPRINT_LEN);
    let ref_sig = Imprint::try_from(expected.as_slice()).unwrap();

    // Intermediate Known Answer Tests (KATs) matching blincs/SPEC.md & reference/blincs.py.
    let e: [u8; N] = ref_sig.as_bytes()[..N].try_into().unwrap();
    let r: [u8; N] = ref_sig.as_bytes()[N..2 * N].try_into().unwrap();
    assert_eq!(to_hex(&e), "9a70dfb49286d13de2a56ed4374946eb");
    assert_eq!(to_hex(&r), "32b08c4c9d15504265fa2984b9b7cf25");
    let ck = derive_key(CTX_CONTENT, sk.id().as_bytes());
    let k_msg = derive_msg_key(&ck, &e, REF_CTX);
    assert_eq!(to_hex(&k_msg), "28b5bf0bad61349ba7f2cc3ba730cd3b1fd1a8a58fff9acc8115f154fe044847");
    let short = content_from_slice(&ck, &e, REF_CTX, msg);
    assert_eq!(to_hex(&short[N..]), "7d978bc5d7a7df9bd2ff34dd4288dbf51963eb8da05365a9cc53ea2d05e2e09a");
    let pk = PublicKey::from_seed(sk.id().as_bytes()[..N].try_into().unwrap());
    let root: [u8; N] = sk.id().as_bytes()[N..].try_into().unwrap();
    let d_seed = compute_message_digest(&pk, &r, &root, &short, REF_CTX);
    assert_eq!(to_hex(&d_seed), "2151d28e0fd8b76f3d514feb22bc966bb26fab87dee126eb3917d320072f30f9");

    let ctr_ft = u32::from_le_bytes(ref_sig.as_bytes()[2 * N..2 * N + UPORS_CTR_LEN].try_into().unwrap());
    assert_eq!(ctr_ft, 5530);
    let eng = pk.engine(false);
    let sel = verify_upors_selection(&eng, &d_seed, ctr_ft).unwrap();
    assert_eq!(sel.leaf_addr.as_u64(), 0xbbce_641c_7560);
    assert_eq!(sel.sibs, 45);
    let cws = extract_upors_codewords(&eng, &sel.h_sel).unwrap();
    for cw in &cws {
        assert_eq!(cw.iter().map(|&x| usize::from(x)).sum::<usize>(), UPORS_SUM);
    }

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

    let mut bad_raw = *sig.as_bytes();
    bad_raw[0] ^= 0x01;
    assert_eq!(vk.verify_short(TEST_CTX, &short, &Imprint::from_bytes(&bad_raw)), Err(InvalidImprint));
}

#[test]
fn hex_and_sperner_unranking_and_fast_select_parser_are_exact() {
    // 1. Exhaustive bijection check for hex_unrank across all 376 codewords in L_42(3, 24).
    let mut seen = BTreeSet::new();
    let mut prev: Option<[u8; UPORS_N]> = None;
    for idx in 0..u16::try_from(UPORS_C).unwrap() {
        let cw = hex_unrank(idx);
        assert!(cw.iter().all(|&d| d <= UPORS_STEPS));
        assert_eq!(cw.iter().map(|&d| usize::from(d)).sum::<usize>(), UPORS_SUM);
        if let Some(p) = prev {
            assert!(p < cw, "hex_unrank must be strictly lexicographic");
        }
        prev = Some(cw);
        assert!(seen.insert(cw));
    }
    assert_eq!(seen.len(), UPORS_C);
    assert!(catch_unwind(|| hex_unrank(u16::try_from(UPORS_C).unwrap())).is_err());

    // 2. WOTS+C direct 6-bit decoding: exact bounds (d_i < 60), z = 2 zero bits, constant sum 679,
    //    every single one of the 21 6-bit lanes tested at boundary 59 vs 60, plus 100,000-digest differential parity vs naive spec!
    let pack_wots_c = |z: u128, ds: &[u8; WOTS_N]| -> [u8; 32] {
        let mut lo = z & 3;
        for (i, &d) in ds.iter().enumerate() {
            lo |= u128::from(d) << (2 + 6 * i);
        }
        let mut h = [0u8; 32];
        h[..16].copy_from_slice(&lo.to_le_bytes());
        h
    };
    let naive_decode_wots_c = |h: &[u8; 32]| -> Option<[u8; WOTS_N]> {
        let lo = u128::from_le_bytes(h[..16].try_into().unwrap());
        if (lo & 3) != 0 {
            return None;
        }
        let mut digits = [0u8; WOTS_N];
        let mut sum = 0usize;
        for (i, slot) in digits.iter_mut().enumerate() {
            let d = u8::try_from((lo >> (2 + 6 * i)) & 63).unwrap();
            if d > WOTS_STEPS {
                return None;
            }
            *slot = d;
            sum += usize::from(d);
        }
        if sum == WOTS_SUM { Some(digits) } else { None }
    };
    let mut base_vec = [32u8; WOTS_N];
    for x in &mut base_vec[11..20] {
        *x = 33;
    }
    base_vec[20] = 30;
    assert_eq!(base_vec.iter().map(|&x| usize::from(x)).sum::<usize>(), WOTS_SUM);
    assert_eq!(decode_wots_c(&pack_wots_c(0, &base_vec)), Some(base_vec));
    for z in 1u128..=3 {
        assert_eq!(decode_wots_c(&pack_wots_c(z, &base_vec)), None);
    }
    let mut wrong_sum = base_vec;
    wrong_sum[0] += 1;
    assert_eq!(decode_wots_c(&pack_wots_c(0, &wrong_sum)), None);
    wrong_sum[0] -= 2;
    assert_eq!(decode_wots_c(&pack_wots_c(0, &wrong_sum)), None);
    // Test EVERY SINGLE 6-bit lane i in 0..21 at exact boundary 59 (valid) and 60, 61, 62, 63 (invalid),
    // AND every bit 0..=5 of every lane (killing every SWAR shift/mask mutation!).
    for lane in 0..WOTS_N {
        let o1 = (lane + 1) % WOTS_N;
        let o2 = (lane + 2) % WOTS_N;
        let mut v59 = base_vec;
        let diff = 59 - v59[lane];
        v59[lane] = 59;
        v59[o1] -= diff / 2;
        v59[o2] -= diff - diff / 2;
        assert_eq!(v59.iter().map(|&x| usize::from(x)).sum::<usize>(), WOTS_SUM);
        assert_eq!(decode_wots_c(&pack_wots_c(0, &v59)), Some(v59));
        for bad_d in 60u8..=63 {
            let mut vbad = v59;
            vbad[lane] = bad_d;
            vbad[o1] -= bad_d - 59;
            assert_eq!(vbad.iter().map(|&x| usize::from(x)).sum::<usize>(), WOTS_SUM);
            assert_eq!(decode_wots_c(&pack_wots_c(0, &vbad)), None, "accepted bad digit {bad_d} in lane {lane}");
        }
        // Also test values 56, 52, 44, 28 (each missing exactly 1 of bits 2, 3, 4, 5) to kill every SWAR shift mutation!
        for ok_d in [56u8, 52, 44, 28] {
            let mut vok = base_vec;
            let delta = i32::from(ok_d) - i32::from(vok[lane]);
            vok[lane] = ok_d;
            vok[o1] = u8::try_from(i32::from(vok[o1]) - delta / 2).unwrap();
            vok[o2] = u8::try_from(i32::from(vok[o2]) - (delta - delta / 2)).unwrap();
            assert_eq!(vok.iter().map(|&x| usize::from(x)).sum::<usize>(), WOTS_SUM);
            assert_eq!(decode_wots_c(&pack_wots_c(0, &vok)), Some(vok));
        }
    }
    // 100,000 random digests: decode_wots_c == naive_decode_wots_c!
    let mut wstate = 0xfeed_face_cafe_babe_u64;
    let mut w_hits = 0usize;
    for _ in 0..100_000usize {
        let mut d = [0u8; 32];
        for chunk in d.as_chunks_mut::<8>().0 {
            wstate = wstate.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = wstate;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
        }
        let fast = decode_wots_c(&d);
        let slow = naive_decode_wots_c(&d);
        assert_eq!(fast, slow, "decode_wots_c diverged from naive reference");
        if fast.is_some() {
            w_hits += 1;
        }
    }
    assert!(w_hits >= 10, "expected >= 10 WOTS+C hits in 100,000 digests, got {w_hits}");

    // 3. LeafAddr 48-bit masking & read_bits tail check.
    let expected_addr = (1u64 << (HYPER_BITS - 1)) | 0x0123_4567_89ab;
    assert_eq!(LeafAddr::from_word(expected_addr | (0xffff_u64 << HYPER_BITS)).as_u64(), expected_addr);
    let splits = LeafAddr::from_word(expected_addr).split_layers();
    assert_eq!(splits[5].0, 0);
    let mut tail = [0u8; 32];
    tail[30] = 0b1010_0101;
    tail[31] = 0b1101_0011;
    assert_eq!(read_bits(&tail, 240, 16), 0b1101_0011_1010_0101);
    assert_eq!(read_bits(&tail, 250, 6), 0b11_0100);

    // 4. Differential parity: fast bit-fold `select_ancestor_lower_bound` + `parse_select_fast` vs naive reference over 100,000 digests.
    let naive_lb = |d: &[u8; 32]| -> u32 {
        let mut s = [0u16; UPORS_K];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = u16::try_from(read_bits(d, i * UPORS_HEIGHT, UPORS_HEIGHT)).unwrap();
        }
        let count_distinct = |shift: u32| -> u32 {
            let mut vals: [u16; UPORS_K] = core::array::from_fn(|i| s[i] >> shift);
            vals.sort_unstable();
            let mut uniq = 1u32;
            for i in 1..UPORS_K {
                if vals[i] != vals[i - 1] {
                    uniq += 1;
                }
            }
            uniq
        };
        5 * count_distinct(5) + count_distinct(6) + count_distinct(7) + count_distinct(8) + count_distinct(9) + count_distinct(10)
    };
    let naive_parse = |d: &[u8; 32]| -> Option<(LeafAddr, [u16; UPORS_K], usize)> {
        let mut leaves = [0u16; UPORS_K];
        let mut found = 0usize;
        for i in 0..UPORS_SELECT_MAX_DRAWS {
            let x = u16::try_from(read_bits(d, i * UPORS_HEIGHT, UPORS_HEIGHT)).unwrap();
            if !leaves[..found].contains(&x) {
                leaves[found] = x;
                found += 1;
                if found == UPORS_K {
                    break;
                }
            }
        }
        if found < UPORS_K {
            return None;
        }
        leaves.sort_unstable();
        let sibs = count_octopus_sibs(&leaves);
        if sibs > UPORS_M_MAX {
            return None;
        }
        let leaf_addr = LeafAddr::from_word(read_bits(d, UPORS_SELECT_MAX_DRAWS * UPORS_HEIGHT, HYPER_BITS));
        Some((leaf_addr, leaves, sibs))
    };
    let mut state = 0x1234_5678_9abc_def0_u64;
    let mut accepted = 0usize;
    for _ in 0..100_000usize {
        let mut d = [0u8; 32];
        for chunk in d.as_chunks_mut::<8>().0 {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
        }
        let lb = select_ancestor_lower_bound(&d);
        assert_eq!(lb, naive_lb(&d), "select_ancestor_lower_bound diverged from exact formula");
        let fast = parse_select_fast(&d);
        let slow = naive_parse(&d);
        assert_eq!(fast, slow, "fast bit-fold parse_select_fast diverged from naive reference");
        assert_eq!(parse_select_digest(&d), slow);
        if fast.is_some() {
            accepted += 1;
        }
    }
    assert!(accepted >= 5, "expected at least 5 accepted selections in 100,000 random digests");

    // Verify exact `lb == 52` valid selection (`> 52` boundary) and NEON PAD11 width table.
    let pack_leaves = |vals: &[u16; UPORS_K]| -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, &v) in vals.iter().enumerate() {
            let bit = i * UPORS_HEIGHT;
            for b in 0..UPORS_HEIGHT {
                if ((v >> b) & 1) != 0 {
                    d[(bit + b) / 8] |= 1u8 << ((bit + b) % 8);
                }
            }
        }
        d
    };
    let leaves_lb52: [u16; UPORS_K] = [128, 129, 160, 161, 480, 832, 864, 1984, 2016];
    let d_lb52 = pack_leaves(&leaves_lb52);
    assert_eq!(select_ancestor_lower_bound(&d_lb52), 52);
    assert!(parse_select_fast(&d_lb52).is_some());
    assert!((8..=STACK_PACKED_CAP).contains(&CORE_PACKED_WIDTH));
    for a in 0..=STACK_PACKED_CAP {
        #[cfg(target_arch = "aarch64")]
        let expected = if (7..CORE_PACKED_WIDTH).contains(&a) { CORE_PACKED_WIDTH } else { a };
        #[cfg(not(target_arch = "aarch64"))]
        let expected = a;
        assert_eq!(core_pad_width(a), expected);
    }

    // Exact boundary tests for `parse_select_digest` & `parse_select_fast`:
    //   - all-zero digest (< 9 distinct leaves) -> None
    assert_eq!(parse_select_fast(&[0u8; 32]), None);
    assert_eq!(parse_select_digest(&[0u8; 32]), None);
    //   - crafted exact sibs == 45 (accepted) vs sibs == 46 (rejected)
    let leaves_45: [u16; UPORS_K] = [395, 402, 414, 927, 1217, 1218, 1510, 1518, 1529];
    let leaves_46: [u16; UPORS_K] = [201, 222, 429, 431, 442, 446, 514, 1938, 1961];
    assert_eq!(count_octopus_sibs(&leaves_45), UPORS_M_MAX);
    assert_eq!(count_octopus_sibs(&leaves_46), UPORS_M_MAX + 1);
    assert!(parse_select_fast(&pack_leaves(&leaves_45)).is_some());
    assert!(parse_select_fast(&pack_leaves(&leaves_46)).is_none());
    assert!(parse_select_digest(&pack_leaves(&leaves_45)).is_some());
    assert!(parse_select_digest(&pack_leaves(&leaves_46)).is_none());

    // Exact `v == 376` (`UPORS_C`) rejection boundary in `extract_upors_codewords`:
    // Find a deterministic `h_sel` whose first 9 valid 9-bit draws encounter `v == 376` and verify it is skipped.
    ensure_init();
    let pk = PublicKey::from_seed(&[0x5au8; N]);
    let mut h_sel = [0xa5u8; 32];
    let mut hit_376 = false;
    for ctr in 0u32..2000 {
        h_sel[..4].copy_from_slice(&ctr.to_le_bytes());
        let mut msg = [0u8; 48];
        msg[..16].copy_from_slice(&tweak(TweakKind::FewCode, crate::params::UPORS_LAYER_U8, 0, 0, 0, 0));
        msg[16..48].copy_from_slice(&h_sel);
        let blk = pk.keyed(&msg);
        let mut valid_before_376 = 0usize;
        let mut saw_376 = false;
        for j in 0..28usize {
            let v = u16::try_from(read_bits(&blk, j * 9, 9)).unwrap();
            if usize::from(v) == UPORS_C {
                saw_376 = true;
                break;
            }
            if usize::from(v) < UPORS_C {
                valid_before_376 += 1;
            }
        }
        if saw_376 && valid_before_376 < UPORS_K {
            let cws = extract_upors_codewords(&pk.engine(false), &h_sel).unwrap();
            assert!(cws.iter().all(|cw| cw.iter().map(|&x| usize::from(x)).sum::<usize>() == UPORS_SUM));
            hit_376 = true;
            break;
        }
    }
    assert!(hit_376, "expected to find a deterministic FewCode block containing exact v == 376");
}

#[test]
fn every_signature_region_and_canonical_padding_are_checked() {
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

    // Mutate one byte in EVERY 16-byte block PLUS every counter byte and last byte across all 3,990 B!
    for off in (0..IMPRINT_LEN).step_by(N).chain([32usize, 35, 1188, 1190, 1639, 1641, 2090, 2092, 2541, 2543, 2992, 2994, 3443, 3445, IMPRINT_LEN - 1]) {
        assert!(!flip(off), "accepted flip at offset {off}");
    }
    assert_eq!(Layer::TOP.sig_offset() + TOP_LAYER_LEN, IMPRINT_LEN);

    // Explicit canonical trailing zero-padding test using edge vector `empty` (sibs = 43/45 -> 32 B trailing zeros).
    let edge_json = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/edge-vectors.json")).unwrap();
    let block = edge_json.split("\"name\": \"empty\"").nth(1).unwrap();
    let pat = "\"imprint_hex\": \"";
    let s = block.find(pat).unwrap() + pat.len();
    let e = block[s..].find('"').unwrap();
    let pad_sig = from_hex(&block[s..s + e]);
    let pad_ctx_pat = "\"ctx_hex\": \"";
    let cs = block.find(pad_ctx_pat).unwrap() + pad_ctx_pat.len();
    let ce = block[cs..].find('"').unwrap();
    let pad_ctx_bytes = from_hex(&block[cs..cs + ce]);
    let pad_ctx = Context::try_new(&pad_ctx_bytes).unwrap();
    vk.verify(pad_ctx, b"", &Imprint::try_from(pad_sig.as_slice()).unwrap()).unwrap();
    // Flip a byte inside the trailing 2 zero-padded sibling slots (offsets 2*N + UPORS_LEN - 32 .. 2*N + UPORS_LEN): MUST REJECT!
    for tail_off in [2 * N + UPORS_LEN - 32, 2 * N + UPORS_LEN - 16, 2 * N + UPORS_LEN - 1] {
        assert_eq!(pad_sig[tail_off], 0);
        let mut mutated = pad_sig.clone();
        mutated[tail_off] = 1;
        assert_eq!(
            vk.verify(pad_ctx, b"", &Imprint::try_from(mutated.as_slice()).unwrap()),
            Err(InvalidImprint),
            "canonical zero-padding check missed byte {tail_off}"
        );
    }

    // Explicit verify_wots_msg 2-zero-bit / sum check.
    let pk = PublicKey::from_seed(&[0x55u8; N]);
    let pub_e = pk.engine(false);
    let mut rejected_ctr = 0usize;
    for ctr in 0u32..32 {
        if verify_wots_msg(&pub_e, Layer::L0, 0, 0, &[0x11u8; N], ctr).is_none() {
            rejected_ctr += 1;
        }
    }
    assert!(rejected_ctr >= 25);

    let mut bad_vk = *vk.as_bytes();
    bad_vk[0] ^= 1;
    assert_eq!(SignetId::from_bytes(&bad_vk).verify(REF_CTX, msg, &base), Err(InvalidImprint));
    let mut bad_root = *vk.as_bytes();
    bad_root[31] ^= 1;
    assert_eq!(SignetId::from_bytes(&bad_root).verify(REF_CTX, msg, &base), Err(InvalidImprint));

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

        let sig_upd = sk
            .imprint_with_draw_stream(&draw, TEST_CTX, |sink| {
                for chunk in msg.chunks(7717) {
                    sink.update(chunk);
                }
                Ok::<(), io::Error>(())
            })
            .unwrap();
        assert_eq!(sig_upd, sig, "Sink::update signature differed for len {len}");

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

    assert!(matches!(
        vk.verify_with(TEST_CTX, &sig, |sink| {
            let dbg = format!("{sink:?}");
            assert!(dbg.contains("Sink"));
            sink.set_total_for_test(u64::MAX - 1);
            sink.update(b"x");
            sink.update(b"yz");
            sink.update(b"");
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

    assert_eq!(to_hex(&next_seed), "97b8baab73eac1d7054392950f031281019b65b801470471fe558ab838bb18d8");
    assert_eq!(to_hex(&run_key), "0c098f138cdb2414e1d302cc2239c6083666a0a0df0a09b5e016f3425ebcb663");
    assert_eq!(to_hex(&keygen_key), "6c6e05e84a6afff9374640a0f0db963b696a501e88f175967efd5b8c8a74b8e7");

    assert_ne!(mix_pool(None, &system, pid, clock), pool);
    assert_ne!(mix_pool(Some(&prior), &system, pid + 1, clock), pool);
    assert_ne!(mix_pool(Some(&prior), &[0x03u8; 32], pid, clock), pool);
    assert_ne!(mix_pool(Some(&prior), &system, pid, b"other-clock"), pool);

    let r = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&r.draw()), "7a6fcaeaa30742062cee1f2be0ac3aafb1ec114b1f14c44a87899e34cfd43d26");
    assert_ne!(r.draw(), r.draw());
    let rk = Randomness::from_keys_at(run_key, keygen_key, 0);
    assert_eq!(to_hex(&rk.draw_for_keygen()), "70b5ece1669e05c593c9e0a7a7cb56efbd4f5f0135f12a758f21ec5354a0589b");

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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o077, 0);
    }

    let state_other = temp_state_dir("lifecycle-other");
    Randomness::create(&state_other).unwrap();
    assert_ne!(init_bytes, fs::read(&state_other).unwrap());
    let _ = fs::remove_dir_all(state_other.parent().unwrap());

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

    let dir = base.join("a-dir");
    fs::create_dir_all(&dir).unwrap();
    assert_eq!(Randomness::initialize(&dir).unwrap_err().kind(), ErrorKind::InvalidInput);

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
    assert!(sd.contains(SUITE_NAME) && sd.contains("3990 bytes") && sd.contains(&to_hex(&sig.as_bytes()[..N])));
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

    assert_eq!(Layer::L0.trees(), 1u64 << 41);
    assert_eq!(Layer::L1.trees(), 1u64 << 34);
    assert_eq!(Layer::L2.trees(), 1u64 << 27);
    assert_eq!(Layer::L3.trees(), 1u64 << 20);
    assert_eq!(Layer::L4.trees(), 1u64 << 13);
    assert_eq!(Layer::L5.trees(), 1);
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

#[test]
fn hash_engine_primitives_match_reference_and_boundaries() {
    ensure_init();
    let pk = PublicKey::from_seed(&[0x3cu8; N]);
    let core = pk.engine(false);
    let bulk = pk.engine(true);

    // 1. sort_chain_queue sorts strictly non-increasing by remaining steps.
    let mut q = [(3u8, 0u8), (19, 1), (0, 2), (7, 3), (19, 4), (1, 5)];
    sort_chain_queue(&mut q);
    assert!(q.windows(2).all(|w| w[0].0 >= w[1].0));
    assert_eq!(q[0].0, 19);
    assert_eq!(q[5].0, 0);

    // 2. hash_short & hash_short_n match PublicKey::keyed across 0..=64 bytes.
    for len in [0usize, 1, 16, 32, 36, 48, 52, 64] {
        let data: Vec<u8> = (0..len).map(|i| u8::try_from((i * 29 + 7) & 0xff).unwrap()).collect();
        let want = pk.keyed(&data);
        assert_eq!(core.hash_short(&data), want);
        assert_eq!(core.hash_short_n(&data), want[..N]);
        assert_eq!(bulk.hash_short(&data), want);
    }

    // 3. hash_packed_48_bulk & hash_packed_48_stack match scalar keyed hash for counts 1..=STACK_PACKED_CAP.
    let mut p48 = Packed::<48>::new(STACK_PACKED_CAP);
    let mut stack48 = [[0u8; 48]; STACK_PACKED_CAP];
    for i in 0..STACK_PACKED_CAP {
        for j in 0..48 {
            let b = u8::try_from((i * 41 + j * 13 + 3) & 0xff).unwrap();
            p48[i][j] = b;
            stack48[i][j] = b;
        }
    }
    let mut scratch = [[0u8; 32]; 1024];
    for count in [1usize, 2, 6, 7, 9, STACK_PACKED_CAP] {
        let mut out_bulk = vec![[0u8; N]; count];
        let mut out_stack = vec![[0u8; N]; count];
        bulk.hash_packed_48_bulk(&p48, count, &mut scratch, &mut out_bulk);
        core.hash_packed_48_stack(&stack48, count, &mut out_stack);
        for i in 0..count {
            let want = pk.keyed(&stack48[i]);
            assert_eq!(out_bulk[i], want[..N]);
            assert_eq!(out_stack[i], want[..N]);
        }
    }

    // 4. advance_chains_fixed, advance_chains_staged, and advance_chains_varlen match scalar chain evaluation.
    let scalar_chain = |init: [u8; 32], steps: u8| -> [u8; N] {
        let mut cur = init;
        let mut step = u32::from_le_bytes(init[12..16].try_into().unwrap());
        for _ in 0..steps {
            let h = pk.keyed(&cur);
            step += 1;
            cur[12..16].copy_from_slice(&step.to_le_bytes());
            cur[16..32].copy_from_slice(&h[..N]);
        }
        cur[16..32].try_into().unwrap()
    };

    const TOTAL: usize = 27;
    let mut p32 = Packed::<32>::new(TOTAL);
    let mut init32 = [[0u8; 32]; TOTAL];
    for i in 0..TOTAL {
        let tw = tweak(TweakKind::Chain, 0, 7, u16::try_from(i).unwrap(), 0, 0);
        p32[i][..16].copy_from_slice(&tw);
        for j in 0..N {
            p32[i][16 + j] = u8::try_from((i * 17 + j * 31 + 5) & 0xff).unwrap();
        }
        init32[i] = p32[i];
    }

    let mut fixed_out = [[0u8; N]; TOTAL];
    bulk.advance_chains_fixed(&mut p32, TOTAL, 4, &mut scratch, &mut fixed_out);
    for i in 0..TOTAL {
        assert_eq!(fixed_out[i], scalar_chain(init32[i], 4));
    }

    for i in 0..TOTAL {
        p32[i] = init32[i];
    }
    let mut staged_out = [[0u8; N]; TOTAL];
    bulk.advance_chains_staged(&mut p32, 16, TOTAL, 3, 6, &mut scratch, &mut staged_out);
    for i in 0..TOTAL {
        let expected_steps = if i < 16 { 6 } else { 3 };
        assert_eq!(staged_out[i], scalar_chain(init32[i], expected_steps));
    }

    // Variable-length chains: 0 chains, 1 chain, mixed zero/nonzero steps, > CORE_PACKED_WIDTH with backfill + swap-remove.
    let mut empty_out: [[u8; N]; 0] = [];
    core.advance_chains_varlen::<TOTAL>(&[], &[], &mut empty_out);

    let mut one_init = [init32[0]];
    one_init[0][12..16].copy_from_slice(&5u32.to_le_bytes());
    let mut one_out = [[0u8; N]; 1];
    core.advance_chains_varlen::<TOTAL>(&one_init, &[3], &mut one_out);
    assert_eq!(one_out[0], scalar_chain(one_init[0], 3));

    let var_steps: [u8; TOTAL] = core::array::from_fn(|i| u8::try_from((i * 5) % 11).unwrap());
    let mut var_init = init32;
    for (i, slot) in var_init.iter_mut().enumerate() {
        let start = u32::try_from(i % 7).unwrap();
        slot[12..16].copy_from_slice(&start.to_le_bytes());
    }
    let mut var_out = [[0u8; N]; TOTAL];
    core.advance_chains_varlen::<TOTAL>(&var_init, &var_steps, &mut var_out);
    for i in 0..TOTAL {
        assert_eq!(var_out[i], scalar_chain(var_init[i], var_steps[i]));
    }

    // 5. grind_counter finds exact smallest counter across batch boundary and returns None when exhausted.
    let mut tmpl = [0u8; 36];
    tmpl[..16].copy_from_slice(&tweak(TweakKind::OneTimeMsg, 0, 1, 2, 0, 0));
    let mut target_block = tmpl;
    let target_ctr = 1029u32;
    target_block[32..36].copy_from_slice(&target_ctr.to_le_bytes());
    let target_digest = pk.keyed(&target_block);
    let found = bulk.grind_counter(&tmpl, 8, 2048, &mut scratch, |d| (*d == target_digest).then_some(42u8));
    assert_eq!(found, Some((target_ctr, target_digest, 42u8)));
    assert_eq!(bulk.grind_counter::<u8>(&tmpl, 8, 1024, &mut scratch, |d| (*d == target_digest).then_some(1)), None);
}

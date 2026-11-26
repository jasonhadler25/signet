//! Freestanding `#![no_std]`, zero-allocator, zero-import `wasm32-unknown-unknown` harness
//! that links `signet-verify` and exposes slice + streaming verification to a WASM host (Node 24).

#![no_std]

use core::panic::PanicInfo;
use signet_verify::{Context, IMPRINT_LEN, ImprintRef, MAX_CONTEXT_LEN, SIGNET_ID_LEN, SignetId};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// Fixed static scratch buffers in WASM linear memory (no heap allocator!).
// Single-threaded freestanding WASM exports access them via safe atomic-free slices?
// Wait: `#![forbid(unsafe_code)]` forbids `static mut`, so we can pass bytes via safe `Sync`
// `core::sync::atomic::AtomicU8` arrays! ZERO `unsafe` even in the WASM harness!!
use core::sync::atomic::{AtomicU8, Ordering};

const MAX_MSG_LEN: usize = 20_480;

static ID_BUF: [AtomicU8; SIGNET_ID_LEN] = [const { AtomicU8::new(0) }; SIGNET_ID_LEN];
static SIG_BUF: [AtomicU8; IMPRINT_LEN] = [const { AtomicU8::new(0) }; IMPRINT_LEN];
static CTX_BUF: [AtomicU8; MAX_CONTEXT_LEN + 1] = [const { AtomicU8::new(0) }; MAX_CONTEXT_LEN + 1];
static MSG_BUF: [AtomicU8; MAX_MSG_LEN] = [const { AtomicU8::new(0) }; MAX_MSG_LEN];

#[unsafe(no_mangle)]
pub extern "C" fn set_id_byte(idx: usize, val: u8) {
    if idx < ID_BUF.len() {
        ID_BUF[idx].store(val, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn set_sig_byte(idx: usize, val: u8) {
    if idx < SIG_BUF.len() {
        SIG_BUF[idx].store(val, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn set_ctx_byte(idx: usize, val: u8) {
    if idx < CTX_BUF.len() {
        CTX_BUF[idx].store(val, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn set_msg_byte(idx: usize, val: u8) {
    if idx < MSG_BUF.len() {
        MSG_BUF[idx].store(val, Ordering::Relaxed);
    }
}

/// Return codes: 0 = Ok, 1 = InvalidImprint, 2 = ContextTooLong, 3 = MsgTooBigForHarness.
#[unsafe(no_mangle)]
pub extern "C" fn verify_both(ctx_len: usize, msg_len: usize, chunk_size: usize) -> u32 {
    if msg_len > MAX_MSG_LEN || ctx_len > CTX_BUF.len() {
        return 3;
    }
    let mut id_bytes = [0u8; SIGNET_ID_LEN];
    for (dst, src) in id_bytes.iter_mut().zip(ID_BUF.iter()) {
        *dst = src.load(Ordering::Relaxed);
    }
    let mut sig_bytes = [0u8; IMPRINT_LEN];
    for (dst, src) in sig_bytes.iter_mut().zip(SIG_BUF.iter()) {
        *dst = src.load(Ordering::Relaxed);
    }
    let mut ctx_bytes = [0u8; MAX_CONTEXT_LEN + 1];
    for i in 0..ctx_len {
        ctx_bytes[i] = CTX_BUF[i].load(Ordering::Relaxed);
    }
    let mut msg_bytes = [0u8; MAX_MSG_LEN];
    for i in 0..msg_len {
        msg_bytes[i] = MSG_BUF[i].load(Ordering::Relaxed);
    }

    let Ok(ctx) = Context::try_new(&ctx_bytes[..ctx_len]) else {
        return 2;
    };
    let id = SignetId::from_bytes(&id_bytes);
    let sig = ImprintRef::from_bytes(&sig_bytes);

    let oneshot_ok = id.verify(ctx, &msg_bytes[..msg_len], sig).is_ok();
    let step = if chunk_size == 0 { 1 } else { chunk_size };
    let mut verifier = id.verifier(ctx, sig);
    let mut stream_ok = verifier.update(b"").is_ok();
    if stream_ok {
        for chunk in msg_bytes[..msg_len].chunks(step) {
            if verifier.update(chunk).is_err() {
                stream_ok = false;
                break;
            }
        }
    }
    let final_ok = stream_ok && verifier.finalize().is_ok();

    if oneshot_ok != final_ok {
        return 99;
    }
    if oneshot_ok { 0 } else { 1 }
}

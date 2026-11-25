use crate::Context;
use crate::params::{MAX_CONTEXT_LEN, N, SHORT_LEN, ensure_init, keyed};
use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience};
use std::io::{self, ErrorKind, Read};

const READER_BUF_LEN: usize = 16_384;

const _: () = {
    assert!(READER_BUF_LEN.is_multiple_of(1024));
};

fn pack_short(salt: &[u8; N], message_hash: &[u8; 32]) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..].copy_from_slice(message_hash);
    short
}

/// Derive the per-imprint, per-context message key `K_msg = Keyed(K_content, e || u8(len(ctx)) || ctx)`.
pub(crate) fn derive_msg_key(content_key: &[u8; 32], salt: &[u8; N], ctx: Context<'_>) -> [u8; 32] {
    let ctx_bytes = ctx.as_bytes();
    let mut buf = [0u8; N + 1 + MAX_CONTEXT_LEN];
    buf[..N].copy_from_slice(salt);
    buf[N] = u8::try_from(ctx_bytes.len()).unwrap();
    buf[N + 1..N + 1 + ctx_bytes.len()].copy_from_slice(ctx_bytes);
    keyed(content_key, &buf[..N + 1 + ctx_bytes.len()])
}

pub(crate) fn checked_add_stream_len(total: u64, n: usize) -> io::Result<u64> {
    let n_u64 = u64::try_from(n).map_err(|_| io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX"))?;
    total.checked_add(n_u64).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX"))
}

/// Zero `buf[filled..]` and fill it from `reader`, retrying `Interrupted` and tracking `total`.
pub(crate) fn fill_buf(reader: &mut impl Read, buf: &mut [u8], mut filled: usize, total: &mut u64) -> io::Result<(usize, bool)> {
    buf[filled..].fill(0);
    while filled < buf.len() {
        let slice = &mut buf[filled..];
        match reader.read(slice) {
            Ok(0) => return Ok((filled, true)),
            Ok(n) => {
                assert!(n <= slice.len(), "Read implementation returned more bytes than buffer length");
                *total = checked_add_stream_len(*total, n)?;
                filled += n;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok((filled, false))
}

/// Compute `short = e || Keyed(Keyed(K_content, e || len(ctx) || ctx), message)` in one single-threaded pass.
pub(crate) fn content_from_slice(content_key: &[u8; 32], salt: &[u8; N], ctx: Context<'_>, message: &[u8]) -> [u8; SHORT_LEN] {
    ensure_init();
    let msg_key = derive_msg_key(content_key, salt, ctx);
    let message_hash = if message.len() <= READER_BUF_LEN {
        *TreeHasher::new(Mode::Keyed(&msg_key)).on_this_core().hash(message).as_bytes()
    } else {
        *TreeHasher::new(Mode::Keyed(&msg_key)).hash(message).as_bytes()
    };
    pack_short(salt, &message_hash)
}

/// Compute `short = e || Keyed(Keyed(K_content, e || len(ctx) || ctx), stream)` in one single-threaded streaming pass.
///
/// Uses a local zero-initialized 16 KiB stack buffer; inputs shorter than 16 KiB hash directly via
/// `TreeHasher::on_this_core`, and longer streams feed `convenience::Hasher` in 16 KiB chunks.
pub(crate) fn content_from_reader(content_key: &[u8; 32], salt: &[u8; N], ctx: Context<'_>, mut reader: impl Read) -> io::Result<[u8; SHORT_LEN]> {
    ensure_init();
    let msg_key = derive_msg_key(content_key, salt, ctx);
    let mut total_bytes = 0u64;
    let mut buf = [0u8; READER_BUF_LEN];

    let (filled, hit_eof) = fill_buf(&mut reader, &mut buf, 0, &mut total_bytes)?;
    if hit_eof {
        let message_hash = *TreeHasher::new(Mode::Keyed(&msg_key)).on_this_core().hash(&buf[..filled]).as_bytes();
        return Ok(pack_short(salt, &message_hash));
    }

    let mut hasher = convenience::Hasher::new(Mode::Keyed(&msg_key), None);
    hasher.update(&buf[..filled]);
    loop {
        let (filled, hit_eof) = fill_buf(&mut reader, &mut buf, 0, &mut total_bytes)?;
        hasher.update(&buf[..filled]);
        if hit_eof {
            break;
        }
    }
    Ok(pack_short(salt, hasher.finalize().as_bytes()))
}

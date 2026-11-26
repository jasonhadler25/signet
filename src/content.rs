use crate::Context;
use crate::params::{MAX_CONTEXT_LEN, N, SHORT_LEN, ensure_init, keyed};
use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience};
use std::fmt;
use std::io::{self, ErrorKind, Write};

const SMALL_SLICE_LIMIT: usize = 16_384;

fn pack_short(salt: &[u8; N], message_hash: &[u8; 32]) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..].copy_from_slice(message_hash);
    short
}

/// Derive the per-imprint, per-context message key `K_msg = Keyed(K_content, e || u8(len(ctx)) || ctx)`.
pub(crate) fn derive_msg_key(content_key: &[u8; 32], salt: &[u8; N], ctx: Context<'_>) -> [u8; 32] {
    let mut buf = [0u8; N + 1 + MAX_CONTEXT_LEN];
    buf[..N].copy_from_slice(salt);
    let ctx_len = ctx.write_framed(&mut buf[N..]);
    keyed(content_key, &buf[..N + ctx_len])
}

/// Streaming byte sink passed to [`crate::Signet::imprint_with`] and [`crate::SignetId::verify_with`].
///
/// Feed message bytes via [`Sink::update`] or [`std::io::Write`] (including `std::io::copy`).
/// The underlying keyed-BLAKE3 salt and message key are initialized before the caller's closure
/// runs and are never exposed through this type.
pub struct Sink {
    hasher: convenience::Hasher,
    total_bytes: u64,
    overflowed: bool,
}

impl fmt::Debug for Sink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sink").field("total_bytes", &self.total_bytes).field("overflowed", &self.overflowed).finish()
    }
}

impl Sink {
    fn new(msg_key: &[u8; 32]) -> Self {
        Self { hasher: convenience::Hasher::new(Mode::Keyed(msg_key), None), total_bytes: 0, overflowed: false }
    }

    pub(crate) fn is_overflowed(&self) -> bool {
        self.overflowed
    }

    /// Feed a slice of message bytes into the salted single-pass BLAKE3 stream.
    ///
    /// If the cumulative byte count would exceed `u64::MAX`, the sink enters a sticky overflowed
    /// state and ignores subsequent writes.
    pub fn update(&mut self, bytes: &[u8]) {
        if self.overflowed {
            return;
        }
        match u64::try_from(bytes.len()).ok().and_then(|n| self.total_bytes.checked_add(n)) {
            Some(total) => {
                self.total_bytes = total;
                self.hasher.update(bytes);
            }
            None => self.overflowed = true,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_total_for_test(&mut self, total: u64) {
        self.total_bytes = total;
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.overflowed {
            return Err(io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX"));
        }
        let n = u64::try_from(buf.len()).map_err(|_| {
            self.overflowed = true;
            io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX")
        })?;
        self.total_bytes = self.total_bytes.checked_add(n).ok_or_else(|| {
            self.overflowed = true;
            io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX")
        })?;
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compute `short = e || Keyed(Keyed(K_content, e || len(ctx) || ctx), message)` in one single-threaded pass.
pub(crate) fn content_from_slice(content_key: &[u8; 32], salt: &[u8; N], ctx: Context<'_>, message: &[u8]) -> [u8; SHORT_LEN] {
    ensure_init();
    let msg_key = derive_msg_key(content_key, salt, ctx);
    let message_hash = if message.len() <= SMALL_SLICE_LIMIT {
        *TreeHasher::new(Mode::Keyed(&msg_key)).on_this_core().hash(message).as_bytes()
    } else {
        *TreeHasher::new(Mode::Keyed(&msg_key)).hash(message).as_bytes()
    };
    pack_short(salt, &message_hash)
}

/// Compute `short` by streaming bytes from a fallible producer into a fresh [`Sink`].
/// Returns `Ok(None)` if the sink overflowed `u64::MAX`, `Ok(Some(short))` on normal completion,
/// or `Err(e)` if `produce` returned an error.
pub(crate) fn content_with<E>(
    content_key: &[u8; 32],
    salt: &[u8; N],
    ctx: Context<'_>,
    produce: impl FnOnce(&mut Sink) -> Result<(), E>,
) -> Result<Option<[u8; SHORT_LEN]>, E> {
    ensure_init();
    let msg_key = derive_msg_key(content_key, salt, ctx);
    let mut sink = Sink::new(&msg_key);
    produce(&mut sink)?;
    if sink.is_overflowed() {
        return Ok(None);
    }
    Ok(Some(pack_short(salt, sink.hasher.finalize().as_bytes())))
}

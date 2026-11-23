use crate::params::{N, SHORT_LEN, first_n, keyed};
use blake3_servil_core::throughput::TreeHasher;
use blake3_servil_core::{Mode, convenience};
use std::io::{self, ErrorKind, Read};

const READ_BUF_LEN: usize = 65_536;

/// Per-signature content salt `e = Keyed(K_salt, draw)[..16]` (SPEC.md, "Content").
#[inline]
pub(crate) fn derive_salt(salt_key: &[u8; 32], draw: &[u8; 32]) -> [u8; N] {
    first_n(&keyed(salt_key, draw))
}

#[inline]
fn pack_short(salt: &[u8; N], message_hash: &[u8; 32]) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..].copy_from_slice(message_hash);
    short
}

/// Compute `short = e || Keyed(Keyed(K_content, e), message)` in one pass for an in-memory slice.
pub(crate) fn content_from_slice(content_key: &[u8; 32], salt: &[u8; N], message: &[u8]) -> [u8; SHORT_LEN] {
    let msg_key = keyed(content_key, salt);
    let message_hash = *TreeHasher::new(Mode::Keyed(&msg_key)).hash(message).as_bytes();
    pack_short(salt, &message_hash)
}

/// Compute `short = e || Keyed(Keyed(K_content, e), stream)` in one streaming pass over `reader`.
pub(crate) fn content_from_reader(content_key: &[u8; 32], salt: &[u8; N], mut reader: impl Read) -> io::Result<[u8; SHORT_LEN]> {
    let msg_key = keyed(content_key, salt);
    let mut hasher = convenience::Hasher::new(Mode::Keyed(&msg_key), None);
    let mut buf = [0u8; READ_BUF_LEN];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let message_hash = *hasher.finalize().as_bytes();
    Ok(pack_short(salt, &message_hash))
}

use crate::params::{N, SHORT_LEN, ensure_init, first_n, keyed};
use blake3_servil::throughput::{Event, Limits, Pipeline, ROOM_LEN, TreeHasher, block_on, update_multithreaded};
use blake3_servil::{Mode, convenience};
use std::io::{self, ErrorKind, Read};

const MT_SLICE_THRESHOLD: usize = 524_288;
const PIPELINE_ROOMS: usize = 32;

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

/// Compute `short = e || Keyed(Keyed(K_content, e), message)` in one pass for an in-memory slice,
/// automatically spreading slices `>= 512 KiB` across all CPU cores via `blake3-servil`.
pub(crate) fn content_from_slice(content_key: &[u8; 32], salt: &[u8; N], message: &[u8]) -> [u8; SHORT_LEN] {
    ensure_init();
    let msg_key = keyed(content_key, salt);
    let message_hash = if message.len() >= MT_SLICE_THRESHOLD {
        let mut hasher = convenience::Hasher::new(Mode::Keyed(&msg_key), Some(message.len() as u64));
        update_multithreaded(&mut hasher, message);
        *hasher.finalize().as_bytes()
    } else {
        *TreeHasher::new(Mode::Keyed(&msg_key)).hash(message).as_bytes()
    };
    pack_short(salt, &message_hash)
}

/// Compute `short = e || Keyed(Keyed(K_content, e), stream)` in one streaming pass over `reader`.
///
/// Streams `<= 64 KiB` hash directly on the calling core with zero heap allocation; longer streams
/// feed directly into `blake3-servil`'s zero-copy multi-core `Pipeline`.
pub(crate) fn content_from_reader(content_key: &[u8; 32], salt: &[u8; N], mut reader: impl Read) -> io::Result<[u8; SHORT_LEN]> {
    ensure_init();
    let msg_key = keyed(content_key, salt);

    // Fast path for small streams (<= 64 KiB): fresh zeroed stack buffer, zero Pipeline setup.
    let mut first = [0u8; ROOM_LEN];
    let mut filled = 0usize;
    while filled < first.len() {
        match reader.read(&mut first[filled..]) {
            Ok(0) => {
                let message_hash = *TreeHasher::new(Mode::Keyed(&msg_key)).on_this_core().hash(&first[..filled]).as_bytes();
                return Ok(pack_short(salt, &message_hash));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    // Multi-core zero-copy streaming via `blake3-servil::throughput::Pipeline`.
    let mut pipe: Pipeline<()> = Pipeline::new(Mode::Keyed(&msg_key), Limits { messages: 1, rooms: PIPELINE_ROOMS });
    let mut msg = block_on(pipe.message((), None));
    {
        let mut room = block_on(pipe.room());
        room.bytes_mut()[..ROOM_LEN].copy_from_slice(&first);
        pipe.commit(&mut msg, &mut room, ROOM_LEN);
    }

    loop {
        let mut room = block_on(pipe.room());
        let mut room_filled = 0usize;
        let mut hit_eof = false;
        while room_filled < ROOM_LEN {
            match reader.read(&mut room.bytes_mut()[room_filled..]) {
                Ok(0) => {
                    hit_eof = true;
                    break;
                }
                Ok(n) => room_filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    pipe.abort(msg);
                    while pipe.next_event().is_none() {
                        block_on(pipe.ready());
                    }
                    return Err(e);
                }
            }
        }
        assert!(room_filled > 0 || hit_eof);
        if room_filled > 0 {
            pipe.commit(&mut msg, &mut room, room_filled);
        }
        if hit_eof {
            break;
        }
    }

    pipe.end(msg);
    let message_hash = loop {
        if let Some(Event::Hashed { hash, .. }) = pipe.next_event() {
            break *hash.as_bytes();
        }
        block_on(pipe.ready());
    };
    Ok(pack_short(salt, &message_hash))
}

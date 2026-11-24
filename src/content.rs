use crate::params::{N, SHORT_LEN, ensure_init, keyed};
use blake3_servil::throughput::{Event, Limits, Pipeline, ROOM_LEN, TreeHasher, block_on, update_multithreaded};
use blake3_servil::{Mode, convenience};
use std::io::{self, ErrorKind, Read};

const MT_SLICE_THRESHOLD: usize = 524_288;
const SMALL_READER_BUF: usize = 16_384;
const PIPELINE_ROOMS: usize = 32;

const _: () = {
    assert!(SMALL_READER_BUF <= ROOM_LEN && SMALL_READER_BUF.is_multiple_of(1024));
};

fn pack_short(salt: &[u8; N], message_hash: &[u8; 32]) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..].copy_from_slice(message_hash);
    short
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

/// Compute `short = e || Keyed(Keyed(K_content, e), message)` in one pass for an in-memory slice,
/// automatically spreading slices `>= 512 KiB` across all CPU cores via `blake3-servil`.
pub(crate) fn content_from_slice(content_key: &[u8; 32], salt: &[u8; N], message: &[u8]) -> [u8; SHORT_LEN] {
    ensure_init();
    let msg_key = keyed(content_key, salt);
    let message_hash = if message.len() >= MT_SLICE_THRESHOLD {
        let len = u64::try_from(message.len()).expect("message length exceeds u64");
        let mut hasher = convenience::Hasher::new(Mode::Keyed(&msg_key), Some(len));
        update_multithreaded(&mut hasher, message);
        *hasher.finalize().as_bytes()
    } else {
        *TreeHasher::new(Mode::Keyed(&msg_key)).hash(message).as_bytes()
    };
    pack_short(salt, &message_hash)
}

/// Compute `short = e || Keyed(Keyed(K_content, e), stream)` in one streaming pass over `reader`.
///
/// Streams shorter than 16 KiB hash on the calling core with zero heap allocation; longer streams
/// feed into `blake3-servil`'s zero-copy multi-core `Pipeline`, zeroing each room slice before read.
pub(crate) fn content_from_reader(content_key: &[u8; 32], salt: &[u8; N], mut reader: impl Read) -> io::Result<[u8; SHORT_LEN]> {
    ensure_init();
    let msg_key = keyed(content_key, salt);
    let mut total_bytes = 0u64;

    let mut first = [0u8; SMALL_READER_BUF];
    let (filled, hit_eof) = fill_buf(&mut reader, &mut first, 0, &mut total_bytes)?;
    if hit_eof {
        let message_hash = *TreeHasher::new(Mode::Keyed(&msg_key)).on_this_core().hash(&first[..filled]).as_bytes();
        return Ok(pack_short(salt, &message_hash));
    }

    let mut pipe: Pipeline<()> = Pipeline::new(Mode::Keyed(&msg_key), Limits { messages: 1, rooms: PIPELINE_ROOMS });
    let mut msg = block_on(pipe.message((), None));
    let mut seeded = true;

    loop {
        let mut room = block_on(pipe.room());
        let start = if seeded {
            seeded = false;
            room.bytes_mut()[..SMALL_READER_BUF].copy_from_slice(&first);
            SMALL_READER_BUF
        } else {
            0
        };
        let (room_filled, hit_eof) = match fill_buf(&mut reader, room.bytes_mut(), start, &mut total_bytes) {
            Ok(v) => v,
            Err(e) => {
                pipe.abort(msg);
                while pipe.next_event().is_none() {
                    block_on(pipe.ready());
                }
                return Err(e);
            }
        };
        if room_filled > 0 {
            pipe.commit(&mut msg, &mut room, room_filled);
        }
        if hit_eof {
            break;
        }
    }

    pipe.end(msg);
    let message_hash = loop {
        match pipe.next_event() {
            Some(Event::Hashed { hash, .. }) => break *hash.as_bytes(),
            Some(_) => panic!("unexpected Pipeline event after end"),
            None => block_on(pipe.ready()),
        }
    };
    Ok(pack_short(salt, &message_hash))
}

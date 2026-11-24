use crate::params::{ContentKey, N, SHORT_LEN, ensure_init};
use blake3_servil::convenience;
use blake3_servil::throughput::{Event, Limits, Pipeline, ROOM_LEN, TreeHasher, block_on, update_multithreaded};
use std::io::{self, ErrorKind, Read};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

const MT_SLICE_THRESHOLD: usize = 524_288;
const SMALL_READER_BUF: usize = 16_384;
const PIPELINE_ROOMS: usize = 32;

const _: () = {
    assert!(SMALL_READER_BUF <= ROOM_LEN);
    assert!(SMALL_READER_BUF.is_multiple_of(1024));
};

#[inline]
fn pack_short(salt: &[u8; N], message_hash: &[u8; 32]) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..].copy_from_slice(message_hash);
    short
}

#[inline]
pub(crate) fn checked_add_stream_len(total: u64, n: usize) -> io::Result<u64> {
    let n_u64 = u64::try_from(n).map_err(|_| io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX"))?;
    total.checked_add(n_u64).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "stream length exceeds u64::MAX"))
}

/// Compute `short = e || Keyed(Keyed(K_content, e), message)` in one pass for an in-memory slice,
/// automatically spreading slices `>= 512 KiB` across all CPU cores via `blake3-servil`.
pub(crate) fn content_from_slice(content_key: &ContentKey, salt: &[u8; N], message: &[u8]) -> [u8; SHORT_LEN] {
    ensure_init();
    let msg_key = content_key.message_key(salt);
    let message_hash = if message.len() >= MT_SLICE_THRESHOLD {
        let len = u64::try_from(message.len()).expect("message length exceeds u64");
        let mut hasher = convenience::Hasher::new(msg_key.mode(), Some(len));
        update_multithreaded(&mut hasher, message);
        *hasher.finalize().as_bytes()
    } else {
        *TreeHasher::new(msg_key.mode()).hash(message).as_bytes()
    };
    pack_short(salt, &message_hash)
}

/// Compute `short = e || Keyed(Keyed(K_content, e), stream)` in one streaming pass over `reader`.
///
/// Streams shorter than 16 KiB hash directly on the calling core with zero heap allocation; longer
/// streams feed into `blake3-servil`'s zero-copy multi-core `Pipeline`, zeroing each newly acquired
/// room slice before exposing it to `reader.read`.
pub(crate) fn content_from_reader(content_key: &ContentKey, salt: &[u8; N], mut reader: impl Read) -> io::Result<[u8; SHORT_LEN]> {
    ensure_init();
    let msg_key = content_key.message_key(salt);

    // Fast path for small streams (< 16 KiB): fresh zeroed stack buffer, zero Pipeline setup.
    let mut first = [0u8; SMALL_READER_BUF];
    let mut filled = 0usize;
    while filled < first.len() {
        let buf = &mut first[filled..];
        match reader.read(buf) {
            Ok(0) => {
                let message_hash = *TreeHasher::new(msg_key.mode()).on_this_core().hash(&first[..filled]).as_bytes();
                return Ok(pack_short(salt, &message_hash));
            }
            Ok(n) => {
                assert!(n <= buf.len(), "Read implementation returned more bytes than buffer length");
                filled += n;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    // Multi-core zero-copy streaming via `blake3-servil::throughput::Pipeline`.
    let mut total_bytes = u64::try_from(SMALL_READER_BUF).unwrap();
    let mut pipe: Pipeline<()> = Pipeline::new(msg_key.mode(), Limits { messages: 1, rooms: PIPELINE_ROOMS });
    let mut msg = block_on(pipe.message((), None));
    let mut seeded = true;

    loop {
        let mut room = block_on(pipe.room());
        let mut room_filled = if seeded {
            seeded = false;
            room.bytes_mut()[..SMALL_READER_BUF].copy_from_slice(&first);
            SMALL_READER_BUF
        } else {
            0
        };
        // Zero the exposed tail of every acquired room before passing `&mut [u8]` to `reader.read`.
        room.bytes_mut()[room_filled..].fill(0);

        let mut hit_eof = false;
        while room_filled < ROOM_LEN {
            let buf = &mut room.bytes_mut()[room_filled..];
            let read_res = match catch_unwind(AssertUnwindSafe(|| reader.read(buf))) {
                Ok(r) => r,
                Err(payload) => {
                    pipe.abort(msg);
                    while pipe.next_event().is_none() {
                        block_on(pipe.ready());
                    }
                    resume_unwind(payload);
                }
            };
            match read_res {
                Ok(0) => {
                    hit_eof = true;
                    break;
                }
                Ok(n) => {
                    assert!(n <= buf.len(), "Read implementation returned more bytes than buffer length");
                    total_bytes = match checked_add_stream_len(total_bytes, n) {
                        Ok(next) => next,
                        Err(e) => {
                            pipe.abort(msg);
                            while pipe.next_event().is_none() {
                                block_on(pipe.ready());
                            }
                            return Err(e);
                        }
                    };
                    room_filled += n;
                }
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
        match pipe.next_event() {
            Some(Event::Hashed { hash, .. }) => break *hash.as_bytes(),
            Some(_) => panic!("unexpected Pipeline event after end"),
            None => block_on(pipe.ready()),
        }
    };
    Ok(pack_short(salt, &message_hash))
}

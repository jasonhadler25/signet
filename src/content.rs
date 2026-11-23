use crate::params::{CHUNK_LEN, N, SHORT_LEN, first_n, keyed};
use blake3_servil_core::Mode;
use blake3_servil_core::throughput::{self, Block, TreeHasher};
use std::io::{self, ErrorKind, Read};

#[inline]
fn chunk_key(content_key: &[u8; 32], salt: &[u8; N], index: u64, prev_x: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; N + 8 + 32];
    input[..N].copy_from_slice(salt);
    input[N..N + 8].copy_from_slice(&index.to_le_bytes());
    input[N + 8..].copy_from_slice(prev_x);
    keyed(content_key, &input)
}

#[inline]
fn pack_short(salt: &[u8; N], last_x: &[u8; 32], total_len: u64) -> [u8; SHORT_LEN] {
    let mut short = [0u8; SHORT_LEN];
    short[..N].copy_from_slice(salt);
    short[N..N + 32].copy_from_slice(last_x);
    short[N + 32..].copy_from_slice(&total_len.to_le_bytes());
    short
}

#[inline]
fn hash_slice_two_pass(content_key: &[u8; 32], salt: &[u8; N], index: u64, prev_x: &[u8; 32], chunk: &[u8]) -> [u8; 32] {
    let k = chunk_key(content_key, salt, index, prev_x);
    let chunk_salt = *TreeHasher::new(Mode::Keyed(&k)).hash(chunk).as_bytes();
    *TreeHasher::new(Mode::Keyed(&chunk_salt)).hash(chunk).as_bytes()
}

#[inline]
fn hash_blocks_two_pass(content_key: &[u8; 32], salt: &[u8; N], index: u64, prev_x: &[u8; 32], blocks: &[Block], len: usize) -> [u8; 32] {
    let k = chunk_key(content_key, salt, index, prev_x);
    let chunk_salt = *throughput::hash(Mode::Keyed(&k), blocks, len).as_bytes();
    *throughput::hash(Mode::Keyed(&chunk_salt), blocks, len).as_bytes()
}

/// Content salt `e = Keyed(Keyed(K_salt, draw), M_0)[..16]` from an in-memory first chunk.
pub(crate) fn derive_salt_slice(salt_key: &[u8; 32], draw: &[u8; 32], first_chunk: &[u8]) -> [u8; N] {
    let ke = keyed(salt_key, draw);
    first_n(TreeHasher::new(Mode::Keyed(&ke)).hash(first_chunk).as_bytes())
}

/// Content salt `e` from a block-aligned first chunk buffer.
pub(crate) fn derive_salt_blocks(salt_key: &[u8; 32], draw: &[u8; 32], blocks: &[Block], len: usize) -> [u8; N] {
    let ke = keyed(salt_key, draw);
    first_n(throughput::hash(Mode::Keyed(&ke), blocks, len).as_bytes())
}

/// Read up to `CHUNK_LEN` bytes into `blocks`, retrying `Interrupted` and looping past short reads until
/// the buffer is full or EOF is reached.
fn read_chunk(reader: &mut impl Read, blocks: &mut [Block]) -> io::Result<usize> {
    let buf = &mut Block::bytes_mut(blocks)[..CHUNK_LEN];
    let mut filled = 0;
    while filled < CHUNK_LEN {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Compute `short = e || x_last || len` for an in-memory slice (SPEC.md, "Content").
pub(crate) fn content_from_slice(content_key: &[u8; 32], salt: &[u8; N], message: &[u8]) -> [u8; SHORT_LEN] {
    let mut x = [0u8; 32];
    if message.is_empty() {
        x = hash_slice_two_pass(content_key, salt, 0, &x, &[]);
    } else {
        for (i, chunk) in message.chunks(CHUNK_LEN).enumerate() {
            x = hash_slice_two_pass(content_key, salt, i as u64, &x, chunk);
        }
    }
    pack_short(salt, &x, message.len() as u64)
}

/// Read a stream in 256 KiB chunks, deriving `salt` after the first chunk when `derive_salt` is provided
/// (signing) or using a fixed `salt` (verifying).
pub(crate) fn content_from_reader(
    content_key: &[u8; 32],
    salt_choice: Result<[u8; N], (&[u8; 32], &[u8; 32])>,
    mut reader: impl Read,
    blocks: &mut [Block],
) -> io::Result<([u8; N], [u8; SHORT_LEN])> {
    let n0 = read_chunk(&mut reader, blocks)?;
    let salt = match salt_choice {
        Ok(e) => e,
        Err((salt_key, draw)) => derive_salt_blocks(salt_key, draw, blocks, n0),
    };
    let mut x = hash_blocks_two_pass(content_key, &salt, 0, &[0u8; 32], blocks, n0);
    let mut total_len = n0 as u64;
    if n0 == CHUNK_LEN {
        let mut index = 1u64;
        loop {
            let n = read_chunk(&mut reader, blocks)?;
            if n == 0 {
                break;
            }
            x = hash_blocks_two_pass(content_key, &salt, index, &x, blocks, n);
            total_len = total_len.checked_add(n as u64).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "message exceeds 2^64 - 1 bytes"))?;
            if n < CHUNK_LEN {
                break;
            }
            index += 1;
        }
    }
    Ok((salt, pack_short(&salt, &x, total_len)))
}

use crate::params::{CHAINS, CHUNK_LEN, FEW_LEAVES, N, TREE_LEAVES};
use blake3_servil_core::throughput::{Batch, Block};
use std::cell::RefCell;

pub(crate) const GRIND: usize = 256;

/// Reusable buffers for signing, kept once per thread for the life of the process.
pub(crate) struct SignWorkspace {
    pub b16: Batch<'static>,
    pub b32: Batch<'static>,
    pub b48: Batch<'static>,
    pub b400: Batch<'static>,
    pub b_pick: Batch<'static>,
    pub b_wmsg: Batch<'static>,
    pub out: Vec<[u8; 32]>,
    pub chunk: Vec<Block>,
}

impl SignWorkspace {
    fn new() -> Self {
        Self {
            b16: Batch::new(16, FEW_LEAVES),
            b32: Batch::new(32, FEW_LEAVES),
            b48: Batch::new(48, FEW_LEAVES / 2),
            b400: Batch::new(16 + N * CHAINS, TREE_LEAVES),
            b_pick: Batch::new(52, GRIND),
            b_wmsg: Batch::new(36, GRIND),
            out: vec![[0u8; 32]; FEW_LEAVES],
            chunk: vec![Block::ZERO; CHUNK_LEN / 64],
        }
    }
}

/// Reusable buffers for verifying, kept once per thread.
pub(crate) struct VerifyWorkspace {
    pub b32: Batch<'static>,
    pub out: [[u8; 32]; CHAINS],
    pub chunk: Vec<Block>,
}

impl VerifyWorkspace {
    fn new() -> Self {
        Self { b32: Batch::new(32, CHAINS), out: [[0u8; 32]; CHAINS], chunk: Vec::new() }
    }

    pub fn chunk_buf(&mut self) -> &mut [Block] {
        if self.chunk.is_empty() {
            self.chunk = vec![Block::ZERO; CHUNK_LEN / 64];
        }
        &mut self.chunk
    }
}

thread_local! {
    static SIGN_WS: RefCell<SignWorkspace> = RefCell::new(SignWorkspace::new());
    static VERIFY_WS: RefCell<VerifyWorkspace> = RefCell::new(VerifyWorkspace::new());
}

pub(crate) fn with_sign_workspace<R>(f: impl FnOnce(&mut SignWorkspace) -> R) -> R {
    SIGN_WS.with(|cell| f(&mut cell.borrow_mut()))
}

pub(crate) fn with_verify_workspace<R>(f: impl FnOnce(&mut VerifyWorkspace) -> R) -> R {
    VERIFY_WS.with(|cell| f(&mut cell.borrow_mut()))
}

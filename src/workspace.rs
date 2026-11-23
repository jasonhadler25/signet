use crate::params::{CHAINS, FORS_LEAVES, FORS_TREES, LOWER_LEAVES, N};
use blake3_servil::throughput::Batch;
use std::cell::RefCell;

/// Maximum WOTS+ leaves batched in one worker chunk (used by both top-tree keygen and lower layers).
pub(crate) const WOTS_CHUNK_LEAVES: usize = LOWER_LEAVES;

/// Maximum slot count needed in `b16` / `b32` / `out` by one worker: max(64 * 35 = 2240, 1024).
const MAX_BATCH: usize = WOTS_CHUNK_LEAVES * CHAINS;
const MAX_PAIR: usize = FORS_LEAVES / 2;

/// Reusable scratch buffers for one signing/keygen worker thread, kept for the life of the thread.
/// Note: `b32` and `out` hold intermediate leaf secrets and are not wiped on drop.
pub(crate) struct WorkerScratch {
    pub b16: Batch<'static>,
    pub b32: Batch<'static>,
    pub b48: Batch<'static>,
    pub b_pk: Batch<'static>,
    pub out: Vec<[u8; 32]>,
}

impl WorkerScratch {
    pub(crate) fn new() -> Self {
        Self {
            b16: Batch::new(16, MAX_BATCH),
            b32: Batch::new(32, MAX_BATCH),
            b48: Batch::new(48, MAX_PAIR),
            b_pk: Batch::new(16 + N * CHAINS, WOTS_CHUNK_LEAVES),
            out: vec![[0u8; 32]; MAX_BATCH],
        }
    }
}

/// Reusable scratch buffers for verifying, kept once per thread.
pub(crate) struct VerifyWorkspace {
    pub b32: Batch<'static>,
    pub b48: Batch<'static>,
    pub out: [[u8; 32]; CHAINS],
}

impl VerifyWorkspace {
    fn new() -> Self {
        Self { b32: Batch::new(32, CHAINS), b48: Batch::new(48, FORS_TREES), out: [[0u8; 32]; CHAINS] }
    }
}

thread_local! {
    static CALLER_SCRATCH: RefCell<WorkerScratch> = RefCell::new(WorkerScratch::new());
    static VERIFY_WS: RefCell<VerifyWorkspace> = RefCell::new(VerifyWorkspace::new());
}

pub(crate) fn with_caller_scratch<R>(f: impl FnOnce(&mut WorkerScratch) -> R) -> R {
    CALLER_SCRATCH.with(|cell| f(&mut cell.borrow_mut()))
}

pub(crate) fn with_verify_workspace<R>(f: impl FnOnce(&mut VerifyWorkspace) -> R) -> R {
    VERIFY_WS.with(|cell| f(&mut cell.borrow_mut()))
}

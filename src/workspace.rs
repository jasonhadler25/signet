use crate::params::{CHAINS, FORS_LEAVES, FORS_TREES, N};
use blake3_servil::throughput::Batch;
use std::cell::RefCell;

/// Maximum WOTS+ leaves batched in one worker chunk (4,096 / 64 = 64 top-tree chunks).
pub(crate) const WOTS_CHUNK_LEAVES: usize = 64;

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

/// Borrow this thread's signing scratch, falling back to a temporary scratch if TLS is already torn down.
pub(crate) fn with_caller_scratch<R>(f: impl FnOnce(&mut WorkerScratch) -> R) -> R {
    let mut f = Some(f);
    match CALLER_SCRATCH.try_with(|cell| f.take().unwrap()(&mut cell.borrow_mut())) {
        Ok(r) => r,
        Err(_) => {
            let mut tmp = WorkerScratch::new();
            f.take().unwrap()(&mut tmp)
        }
    }
}

/// Borrow this thread's verifier workspace, falling back to a temporary workspace if TLS is already torn down.
pub(crate) fn with_verify_workspace<R>(f: impl FnOnce(&mut VerifyWorkspace) -> R) -> R {
    let mut f = Some(f);
    match VERIFY_WS.try_with(|cell| f.take().unwrap()(&mut cell.borrow_mut())) {
        Ok(r) => r,
        Err(_) => {
            let mut tmp = VerifyWorkspace::new();
            f.take().unwrap()(&mut tmp)
        }
    }
}

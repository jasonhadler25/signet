//! Crash-only parallel task runner and reusable per-thread scratch workspaces.

use crate::params::{CHAINS, FORS_LEAVES, FORS_TREES, N, ensure_init};
use blake3_servil::throughput::Batch;
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::abort;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

/// Maximum WOTS+ leaves batched in one worker chunk (4,096 / 64 = 64 top-tree chunks).
pub(crate) const WOTS_CHUNK_LEAVES: usize = 64;

const MAX_BATCH: usize = WOTS_CHUNK_LEAVES * CHAINS;
const MAX_PAIR: usize = FORS_LEAVES / 2;
const MAX_WORKERS: usize = 63;

/// Reusable scratch buffers for one signing/keygen thread (not wiped on drop).
pub(crate) struct WorkerScratch {
    pub b16: Batch<'static>,
    pub b32: Batch<'static>,
    pub b48: Batch<'static>,
    pub b_pk: Batch<'static>,
    pub out: Vec<[u8; 32]>,
}

impl WorkerScratch {
    fn new() -> Self {
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

type TaskFn = dyn Fn(usize, bool, &mut WorkerScratch) + Send + Sync;

struct Wave {
    total: usize,
    next: AtomicUsize,
    task: Arc<TaskFn>,
}

impl Wave {
    fn drain(&self, use_sme2: bool, ws: &mut WorkerScratch) {
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id >= self.total {
                break;
            }
            (self.task)(id, use_sme2, ws);
        }
    }
}

struct PoolState {
    generation: u64,
    active: Option<Arc<Wave>>,
    remaining_workers: usize,
}

fn drain_or_abort(wave: &Wave, use_sme2: bool, ws: &mut WorkerScratch) {
    if catch_unwind(AssertUnwindSafe(|| wave.drain(use_sme2, ws))).is_err() {
        abort();
    }
}

/// Persistent crash-only worker pool: caller runs full-width/SME2, workers stay `on_this_core()`.
struct Pool {
    pid: u32,
    n_workers: usize,
    dispatch: Mutex<()>,
    state: Arc<(Mutex<PoolState>, Condvar, Condvar)>,
}

impl Pool {
    fn new() -> Self {
        let target = thread::available_parallelism().map(|n| n.get()).unwrap_or(1).saturating_sub(1).min(MAX_WORKERS);
        let state = Arc::new((Mutex::new(PoolState { generation: 0, active: None, remaining_workers: 0 }), Condvar::new(), Condvar::new()));

        let mut spawned = 0usize;
        for idx in 0..target {
            let shared = Arc::clone(&state);
            let res = thread::Builder::new().name(format!("blincs-worker-{idx}")).spawn(move || {
                if catch_unwind(AssertUnwindSafe(move || {
                    ensure_init();
                    let mut ws = WorkerScratch::new();
                    let mut seen_gen = 0u64;
                    let (lock, wake, done) = &*shared;
                    loop {
                        let wave = {
                            let mut guard = lock.lock().unwrap();
                            while guard.generation == seen_gen {
                                guard = wake.wait(guard).unwrap();
                            }
                            seen_gen = guard.generation;
                            Arc::clone(guard.active.as_ref().unwrap())
                        };
                        wave.drain(false, &mut ws);
                        let mut guard = lock.lock().unwrap();
                        guard.remaining_workers -= 1;
                        if guard.remaining_workers == 0 {
                            done.notify_one();
                        }
                    }
                }))
                .is_err()
                {
                    abort();
                }
            });
            if res.is_ok() {
                spawned += 1;
            } else {
                break;
            }
        }
        Self { pid: std::process::id(), n_workers: spawned, dispatch: Mutex::new(()), state }
    }

    fn run(&self, wave: Arc<Wave>) {
        if std::process::id() != self.pid {
            abort();
        }
        if self.n_workers == 0 {
            with_caller_scratch(|ws| drain_or_abort(&wave, true, ws));
            return;
        }
        let Ok(_dispatch_guard) = self.dispatch.try_lock() else {
            with_caller_scratch(|ws| drain_or_abort(&wave, true, ws));
            return;
        };

        let (lock, wake, done) = &*self.state;
        {
            let mut guard = lock.lock().unwrap();
            guard.generation += 1;
            guard.active = Some(Arc::clone(&wave));
            guard.remaining_workers = self.n_workers;
            wake.notify_all();
        }
        with_caller_scratch(|ws| drain_or_abort(&wave, true, ws));
        let mut guard = lock.lock().unwrap();
        while guard.remaining_workers > 0 {
            guard = done.wait(guard).unwrap();
        }
        guard.active = None;
    }
}

/// Evaluate `f(id, use_sme2, ws)` for every `id` in `0..total` across CPU cores and collect results in order.
pub(crate) fn parallel_collect<T: Send + 'static>(total: usize, f: impl Fn(usize, bool, &mut WorkerScratch) -> T + Send + Sync + 'static) -> Vec<T> {
    static POOL: OnceLock<Pool> = OnceLock::new();
    let slots: Arc<Vec<Mutex<Option<T>>>> = Arc::new((0..total).map(|_| Mutex::new(None)).collect());
    let out = Arc::clone(&slots);
    let task: Arc<TaskFn> = Arc::new(move |id, sme2, ws| {
        *out[id].lock().unwrap() = Some(f(id, sme2, ws));
    });
    POOL.get_or_init(Pool::new).run(Arc::new(Wave { total, next: AtomicUsize::new(0), task }));
    slots.iter().map(|s| s.lock().unwrap().take().unwrap()).collect()
}

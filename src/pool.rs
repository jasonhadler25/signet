use crate::few_time::{ForsTreeOut, build_fors_tree};
use crate::one_time::{KeyPair, Pos, build_wots_leaves_chunk};
use crate::params::{FORS_TREES, ForsIndex, LAYERS, LOWER_LEAVES, Layer, LeafAddr, N, PublicKey, SecretKey, TOP_LEAVES, TreeIndex, ensure_init};
use crate::workspace::{WOTS_CHUNK_LEAVES, WorkerScratch, with_caller_scratch};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, TryLockError};
use std::thread;

/// Number of WOTS+ leaves processed per dynamic task during a signing wave (128 / 8 = 16 tasks per lower layer).
const SIGN_WOTS_CHUNK: usize = 8;
const LOWER_LAYERS: usize = LAYERS - 1;
const LOWER_CHUNKS_PER_LAYER: usize = LOWER_LEAVES / SIGN_WOTS_CHUNK;
const LOWER_WOTS_TASKS: usize = LOWER_LAYERS * LOWER_CHUNKS_PER_LAYER;
const SIGN_TOTAL_TASKS: usize = LOWER_WOTS_TASKS + FORS_TREES;

const TOP_CHUNKS: usize = TOP_LEAVES / WOTS_CHUNK_LEAVES;

/// Maximum background workers spawned by the persistent pool (`tasks - 1`, since the caller participates).
const MAX_WORKERS: usize = 63;

const _: () = {
    assert!(TOP_LEAVES.is_multiple_of(WOTS_CHUNK_LEAVES));
    assert!(LOWER_LEAVES.is_multiple_of(SIGN_WOTS_CHUNK));
    assert!(TOP_CHUNKS == SIGN_TOTAL_TASKS);
    assert!(MAX_WORKERS == SIGN_TOTAL_TASKS - 1);
};

enum JobKind {
    TopTree {
        secret_key: SecretKey,
        public_key: PublicKey,
        chunks: Vec<Mutex<[[u8; N]; WOTS_CHUNK_LEAVES]>>,
    },
    SignWave {
        secret_key: SecretKey,
        public_key: PublicKey,
        leaf_addr: LeafAddr,
        lower_trees: [TreeIndex; LOWER_LAYERS],
        fors_indices: [ForsIndex; FORS_TREES],
        wots_chunks: Vec<Mutex<[[u8; N]; SIGN_WOTS_CHUNK]>>,
        fors_out: Vec<Mutex<ForsTreeOut>>,
    },
}

impl JobKind {
    fn total(&self) -> usize {
        match self {
            Self::TopTree { .. } => TOP_CHUNKS,
            Self::SignWave { .. } => SIGN_TOTAL_TASKS,
        }
    }
}

struct Job {
    next: AtomicUsize,
    kind: JobKind,
}

impl Job {
    fn execute_one(&self, task_id: usize, use_sme2: bool, ws: &mut WorkerScratch) {
        match &self.kind {
            JobKind::TopTree { secret_key, public_key, chunks } => {
                let start_leaf = u16::try_from(task_id * WOTS_CHUNK_LEAVES).unwrap();
                let mut buf = [[0u8; N]; WOTS_CHUNK_LEAVES];
                build_wots_leaves_chunk(
                    KeyPair { secret: secret_key, public: public_key },
                    Pos::new(Layer::TOP, TreeIndex::ZERO, start_leaf),
                    use_sme2,
                    ws,
                    &mut buf,
                );
                *chunks[task_id].lock().unwrap() = buf;
            }
            JobKind::SignWave { secret_key, public_key, leaf_addr, lower_trees, fors_indices, wots_chunks, fors_out } => {
                if task_id < LOWER_WOTS_TASKS {
                    let layer_idx = task_id / LOWER_CHUNKS_PER_LAYER;
                    let chunk = task_id % LOWER_CHUNKS_PER_LAYER;
                    let start_leaf = u16::try_from(chunk * SIGN_WOTS_CHUNK).unwrap();
                    let mut buf = [[0u8; N]; SIGN_WOTS_CHUNK];
                    build_wots_leaves_chunk(
                        KeyPair { secret: secret_key, public: public_key },
                        Pos::new(Layer::LOWER[layer_idx], lower_trees[layer_idx], start_leaf),
                        use_sme2,
                        ws,
                        &mut buf,
                    );
                    *wots_chunks[task_id].lock().unwrap() = buf;
                } else {
                    let t = task_id - LOWER_WOTS_TASKS;
                    let t_u16 = u16::try_from(t).unwrap();
                    let out = build_fors_tree(secret_key, public_key, *leaf_addr, t_u16, fors_indices[t], use_sme2, ws);
                    *fors_out[t].lock().unwrap() = out;
                }
            }
        }
    }

    fn drain(&self, use_sme2: bool, ws: &mut WorkerScratch) {
        let total = self.kind.total();
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id >= total {
                break;
            }
            self.execute_one(id, use_sme2, ws);
        }
    }
}

struct PoolState {
    generation: u64,
    active: Option<Arc<Job>>,
    remaining_workers: usize,
    failed: bool,
}

/// Persistent crash-only worker pool for coarse tree/FORS waves.
///
/// The calling thread runs with SME2/full vector width while background workers run `on_this_core()`,
/// dynamically claiming tasks via `AtomicUsize` so heterogeneous cores (e.g. 1 SME2 + N NEON) stay balanced.
struct Pool {
    n_workers: usize,
    dispatch: Mutex<()>,
    state: Arc<(Mutex<PoolState>, Condvar, Condvar)>,
}

impl Pool {
    fn new() -> Self {
        let cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let target = cpus.saturating_sub(1).min(MAX_WORKERS);
        let state = Arc::new((Mutex::new(PoolState { generation: 0, active: None, remaining_workers: 0, failed: false }), Condvar::new(), Condvar::new()));

        let mut spawned = 0usize;
        for idx in 0..target {
            let shared = Arc::clone(&state);
            let res = thread::Builder::new().name(format!("blincs-worker-{idx}")).spawn(move || {
                ensure_init();
                let mut ws = WorkerScratch::new();
                let mut seen_gen = 0u64;
                let (lock, wake, done) = &*shared;
                loop {
                    let job = {
                        let mut guard = lock.lock().unwrap();
                        while guard.generation == seen_gen {
                            guard = wake.wait(guard).unwrap();
                        }
                        seen_gen = guard.generation;
                        Arc::clone(guard.active.as_ref().unwrap())
                    };
                    let ok = catch_unwind(AssertUnwindSafe(|| job.drain(false, &mut ws))).is_ok();
                    let mut guard = lock.lock().unwrap();
                    if !ok {
                        guard.failed = true;
                    }
                    guard.remaining_workers -= 1;
                    if guard.remaining_workers == 0 {
                        done.notify_one();
                    }
                    if !ok {
                        break;
                    }
                }
            });
            match res {
                Ok(_) => spawned += 1,
                Err(_) => break,
            }
        }

        Self { n_workers: spawned, dispatch: Mutex::new(()), state }
    }

    fn run(&self, job: Arc<Job>) {
        // If no background workers exist or another caller is already driving the pool (including re-entrant
        // callbacks), run directly on this thread with zero blocking or deadlock.
        if self.n_workers == 0 {
            with_caller_scratch(|ws| job.drain(true, ws));
            return;
        }
        let _dispatch_guard = match self.dispatch.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => {
                with_caller_scratch(|ws| job.drain(true, ws));
                return;
            }
            Err(TryLockError::Poisoned(_)) => panic!("blincs worker pool dispatch lock poisoned"),
        };

        let (lock, wake, done) = &*self.state;
        {
            let mut guard = lock.lock().unwrap();
            assert!(!guard.failed, "blincs worker pool failed in an earlier wave");
            guard.generation += 1;
            guard.active = Some(Arc::clone(&job));
            guard.remaining_workers = self.n_workers;
            wake.notify_all();
        }

        let caller_res = catch_unwind(AssertUnwindSafe(|| with_caller_scratch(|ws| job.drain(true, ws))));

        let worker_failed = {
            let mut guard = lock.lock().unwrap();
            while guard.remaining_workers > 0 {
                guard = done.wait(guard).unwrap();
            }
            guard.active = None;
            guard.failed
        };

        if let Err(payload) = caller_res {
            resume_unwind(payload);
        }
        assert!(!worker_failed, "blincs worker thread panicked during parallel wave");
    }
}

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(Pool::new)
}

/// Build all `TOP_LEAVES` (4,096) WOTS+ leaves of the top hypertree in parallel across all CPU cores.
pub(crate) fn build_top_leaves_parallel(secret_key: &SecretKey, public_key: &PublicKey) -> Vec<[u8; N]> {
    let chunks = (0..TOP_CHUNKS).map(|_| Mutex::new([[0u8; N]; WOTS_CHUNK_LEAVES])).collect();
    let job = Arc::new(Job { next: AtomicUsize::new(0), kind: JobKind::TopTree { secret_key: *secret_key, public_key: *public_key, chunks } });
    pool().run(Arc::clone(&job));

    let mut leaves = Vec::with_capacity(TOP_LEAVES);
    match &job.kind {
        JobKind::TopTree { chunks, .. } => {
            for slot in chunks {
                leaves.extend_from_slice(&*slot.lock().unwrap());
            }
        }
        JobKind::SignWave { .. } => unreachable!(),
    }
    leaves
}

/// Build all 3 lower-layer WOTS+ leaf sets (384 leaves) and all 16 FORS trees (16,384 leaves) in one parallel wave.
pub(crate) fn run_sign_wave(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    leaf_addr: LeafAddr,
    lower_trees: [TreeIndex; LOWER_LAYERS],
    fors_indices: [ForsIndex; FORS_TREES],
) -> ([[[u8; N]; LOWER_LEAVES]; LOWER_LAYERS], [ForsTreeOut; FORS_TREES]) {
    let wots_chunks = (0..LOWER_WOTS_TASKS).map(|_| Mutex::new([[0u8; N]; SIGN_WOTS_CHUNK])).collect();
    let fors_out = (0..FORS_TREES).map(|_| Mutex::new(ForsTreeOut::default())).collect();
    let job = Arc::new(Job {
        next: AtomicUsize::new(0),
        kind: JobKind::SignWave { secret_key: *secret_key, public_key: *public_key, leaf_addr, lower_trees, fors_indices, wots_chunks, fors_out },
    });
    pool().run(Arc::clone(&job));

    let mut lower_leaves = [[[0u8; N]; LOWER_LEAVES]; LOWER_LAYERS];
    let mut fors_trees = [ForsTreeOut::default(); FORS_TREES];
    match &job.kind {
        JobKind::SignWave { wots_chunks, fors_out, .. } => {
            for layer in Layer::LOWER {
                let l = layer.index();
                for chunk in 0..LOWER_CHUNKS_PER_LAYER {
                    let data = *wots_chunks[l * LOWER_CHUNKS_PER_LAYER + chunk].lock().unwrap();
                    lower_leaves[l][chunk * SIGN_WOTS_CHUNK..(chunk + 1) * SIGN_WOTS_CHUNK].copy_from_slice(&data);
                }
            }
            for t in 0..FORS_TREES {
                fors_trees[t] = *fors_out[t].lock().unwrap();
            }
        }
        JobKind::TopTree { .. } => unreachable!(),
    }
    (lower_leaves, fors_trees)
}

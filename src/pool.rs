use crate::few_time::{ForsTreeOut, build_fors_tree};
use crate::one_time::{KeyPair, Pos, build_wots_leaves_chunk};
use crate::params::{FORS_TREES, LAYERS, LOWER_HEIGHT, LOWER_LEAVES, N, TOP_LEAVES};
use crate::workspace::{WOTS_CHUNK_LEAVES, WorkerScratch, with_caller_scratch};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

/// Number of WOTS+ leaves processed per dynamic task during a signing wave (64 / 8 = 8 tasks per lower layer).
const SIGN_WOTS_CHUNK: usize = 8;
const LOWER_LAYERS: usize = LAYERS - 1;
const LOWER_CHUNKS_PER_LAYER: usize = LOWER_LEAVES / SIGN_WOTS_CHUNK;
const LOWER_WOTS_TASKS: usize = LOWER_LAYERS * LOWER_CHUNKS_PER_LAYER;
const SIGN_TOTAL_TASKS: usize = LOWER_WOTS_TASKS + FORS_TREES;

const TOP_CHUNKS: usize = TOP_LEAVES / WOTS_CHUNK_LEAVES;

enum JobKind {
    TopTree {
        secret_key: [u8; 32],
        public_key: [u8; 32],
        chunks: Vec<Mutex<Vec<[u8; N]>>>,
    },
    SignWave {
        secret_key: [u8; 32],
        public_key: [u8; 32],
        leaf_addr: u64,
        lower_trees: [u64; LOWER_LAYERS],
        fors_indices: [u16; FORS_TREES],
        wots_chunks: Vec<Mutex<[[u8; N]; SIGN_WOTS_CHUNK]>>,
        fors_out: Vec<Mutex<ForsTreeOut>>,
    },
}

struct Job {
    total: usize,
    next: AtomicUsize,
    kind: JobKind,
}

impl Job {
    fn execute_one(&self, task_id: usize, use_sme2: bool, ws: &mut WorkerScratch) {
        match &self.kind {
            JobKind::TopTree { secret_key, public_key, chunks } => {
                let start_leaf = (task_id * WOTS_CHUNK_LEAVES) as u16;
                let mut buf = vec![[0u8; N]; WOTS_CHUNK_LEAVES];
                build_wots_leaves_chunk(
                    KeyPair { secret: secret_key, public: public_key },
                    Pos { layer: (LAYERS - 1) as u8, tree: 0, leaf: start_leaf },
                    use_sme2,
                    ws,
                    &mut buf,
                );
                *chunks[task_id].lock().unwrap() = buf;
            }
            JobKind::SignWave { secret_key, public_key, leaf_addr, lower_trees, fors_indices, wots_chunks, fors_out } => {
                if task_id < LOWER_WOTS_TASKS {
                    let layer = task_id / LOWER_CHUNKS_PER_LAYER;
                    let chunk = task_id % LOWER_CHUNKS_PER_LAYER;
                    let start_leaf = (chunk * SIGN_WOTS_CHUNK) as u16;
                    let mut buf = [[0u8; N]; SIGN_WOTS_CHUNK];
                    build_wots_leaves_chunk(
                        KeyPair { secret: secret_key, public: public_key },
                        Pos { layer: layer as u8, tree: lower_trees[layer], leaf: start_leaf },
                        use_sme2,
                        ws,
                        &mut buf,
                    );
                    *wots_chunks[task_id].lock().unwrap() = buf;
                } else {
                    let t = task_id - LOWER_WOTS_TASKS;
                    let out = build_fors_tree(secret_key, public_key, *leaf_addr, t as u16, fors_indices[t], use_sme2, ws);
                    *fors_out[t].lock().unwrap() = out;
                }
            }
        }
    }

    fn drain(&self, use_sme2: bool, ws: &mut WorkerScratch) {
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id >= self.total {
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
}

/// Persistent crash-only worker pool for coarse tree/FORS waves.
///
/// The calling thread runs with SME2/full vector width while background workers run `on_this_core()`,
/// dynamically stealing tasks via `AtomicUsize` so heterogeneous cores (e.g. 1 SME2 + N NEON) stay balanced.
struct Pool {
    n_workers: usize,
    dispatch: Mutex<()>,
    state: Arc<(Mutex<PoolState>, Condvar, Condvar)>,
}

impl Pool {
    fn new() -> Self {
        let cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let n_workers = cpus.saturating_sub(1);
        let state = Arc::new((Mutex::new(PoolState { generation: 0, active: None, remaining_workers: 0 }), Condvar::new(), Condvar::new()));

        for idx in 0..n_workers {
            let shared = Arc::clone(&state);
            thread::Builder::new()
                .name(format!("blincs-worker-{idx}"))
                .spawn(move || {
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
                        job.drain(false, &mut ws);
                        let mut guard = lock.lock().unwrap();
                        guard.remaining_workers -= 1;
                        if guard.remaining_workers == 0 {
                            done.notify_one();
                        }
                    }
                })
                .expect("failed to spawn blincs worker thread");
        }

        Self { n_workers, dispatch: Mutex::new(()), state }
    }

    fn run(&self, job: Arc<Job>) {
        // If no background workers exist or another caller is already driving the pool (including re-entrant
        // callbacks), run directly on this thread with zero blocking or deadlock.
        if self.n_workers == 0 {
            with_caller_scratch(|ws| job.drain(true, ws));
            return;
        }
        let Ok(_dispatch_guard) = self.dispatch.try_lock() else {
            with_caller_scratch(|ws| job.drain(true, ws));
            return;
        };

        let (lock, wake, done) = &*self.state;
        {
            let mut guard = lock.lock().unwrap();
            guard.generation += 1;
            guard.active = Some(Arc::clone(&job));
            guard.remaining_workers = self.n_workers;
            wake.notify_all();
        }

        with_caller_scratch(|ws| job.drain(true, ws));

        let mut guard = lock.lock().unwrap();
        while guard.remaining_workers > 0 {
            guard = done.wait(guard).unwrap();
        }
        guard.active = None;
    }
}

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(Pool::new)
}

/// Build all `TOP_LEAVES` (32,768) WOTS+ leaves of the top hypertree in parallel across all CPU cores.
pub(crate) fn build_top_leaves_parallel(secret_key: &[u8; 32], public_key: &[u8; 32]) -> Vec<[u8; N]> {
    let chunks = (0..TOP_CHUNKS).map(|_| Mutex::new(Vec::new())).collect();
    let job =
        Arc::new(Job { total: TOP_CHUNKS, next: AtomicUsize::new(0), kind: JobKind::TopTree { secret_key: *secret_key, public_key: *public_key, chunks } });
    pool().run(Arc::clone(&job));

    let mut leaves = Vec::with_capacity(TOP_LEAVES);
    if let JobKind::TopTree { chunks, .. } = &job.kind {
        for slot in chunks {
            leaves.extend_from_slice(&slot.lock().unwrap());
        }
    }
    leaves
}

/// Build all 3 lower-layer WOTS+ leaf sets (192 leaves) and all 16 FORS trees (16,384 leaves) in one parallel wave.
pub(crate) fn run_sign_wave(
    secret_key: &[u8; 32],
    public_key: &[u8; 32],
    leaf_addr: u64,
    fors_indices: [u16; FORS_TREES],
) -> ([[[u8; N]; LOWER_LEAVES]; LOWER_LAYERS], [ForsTreeOut; FORS_TREES]) {
    let mut lower_trees = [0u64; LOWER_LAYERS];
    let mut addr = leaf_addr;
    for slot in &mut lower_trees {
        addr >>= LOWER_HEIGHT;
        *slot = addr;
    }

    let wots_chunks = (0..LOWER_WOTS_TASKS).map(|_| Mutex::new([[0u8; N]; SIGN_WOTS_CHUNK])).collect();
    let fors_out = (0..FORS_TREES).map(|_| Mutex::new(ForsTreeOut::default())).collect();
    let job = Arc::new(Job {
        total: SIGN_TOTAL_TASKS,
        next: AtomicUsize::new(0),
        kind: JobKind::SignWave { secret_key: *secret_key, public_key: *public_key, leaf_addr, lower_trees, fors_indices, wots_chunks, fors_out },
    });
    pool().run(Arc::clone(&job));

    let mut lower_leaves = [[[0u8; N]; LOWER_LEAVES]; LOWER_LAYERS];
    let mut fors_trees = [ForsTreeOut::default(); FORS_TREES];
    if let JobKind::SignWave { wots_chunks, fors_out, .. } = &job.kind {
        for layer in 0..LOWER_LAYERS {
            for chunk in 0..LOWER_CHUNKS_PER_LAYER {
                let data = *wots_chunks[layer * LOWER_CHUNKS_PER_LAYER + chunk].lock().unwrap();
                lower_leaves[layer][chunk * SIGN_WOTS_CHUNK..(chunk + 1) * SIGN_WOTS_CHUNK].copy_from_slice(&data);
            }
        }
        for t in 0..FORS_TREES {
            fors_trees[t] = *fors_out[t].lock().unwrap();
        }
    }
    (lower_leaves, fors_trees)
}

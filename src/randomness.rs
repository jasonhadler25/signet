use crate::params::{CTX_MIX, CTX_NEXT_SEED, CTX_RUN_KEY, derive_key, ensure_init, keyed};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const MAGIC: &[u8; 8] = b"BLINCSr1";
pub(crate) const STATE_LEN: usize = 8 + 8 + 32;

/// Pure state-mixing function (SPEC.md, "Signer randomness").
/// Returns `(next_seed_for_file, run_key_for_memory)`.
pub(crate) fn mix(seed: &[u8; 32], count: u64, system: &[u8; 32], clock: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut material = Vec::with_capacity(32 + 8 + 32 + clock.len());
    material.extend_from_slice(seed);
    material.extend_from_slice(&count.to_le_bytes());
    material.extend_from_slice(system);
    material.extend_from_slice(clock);
    let pool = derive_key(CTX_MIX, &material);
    (derive_key(CTX_NEXT_SEED, &pool), derive_key(CTX_RUN_KEY, &pool))
}

fn read_os_randomness() -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Capture the bytes `Instant::now()` feeds to `Hash` (raw seconds and nanoseconds of the system monotonic
/// clock, without unsafe code or external dependencies).
pub(crate) fn read_monotonic_clock() -> Vec<u8> {
    struct Collect(Vec<u8>);
    impl Hasher for Collect {
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
        fn finish(&self) -> u64 {
            0
        }
    }
    let mut c = Collect(Vec::with_capacity(16));
    Instant::now().hash(&mut c);
    assert!(!c.0.is_empty(), "monotonic clock yielded no bytes");
    c.0
}

pub(crate) fn read_exact_or_reject(reader: &mut impl Read) -> io::Result<[u8; STATE_LEN]> {
    let mut buf = [0u8; STATE_LEN + 1];
    let mut filled = 0;
    while filled < buf.len() {
        let slice = &mut buf[filled..];
        match reader.read(slice) {
            Ok(0) => break,
            Ok(n) => {
                assert!(n <= slice.len(), "Read implementation returned more bytes than buffer length");
                filled += n;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if filled != STATE_LEN || &buf[..8] != MAGIC {
        return Err(io::Error::new(ErrorKind::InvalidData, "not a BLINCS randomness state file"));
    }
    let mut state = [0u8; STATE_LEN];
    state.copy_from_slice(&buf[..STATE_LEN]);
    Ok(state)
}

#[derive(Clone, Copy)]
struct RunKey([u8; 32]);

impl RunKey {
    fn draw_at(&self, count: u64) -> [u8; 32] {
        keyed(&self.0, &count.to_le_bytes())
    }
}

/// Per-process signer randomness, backed by a 48-byte persistent state file updated once at startup.
///
/// After [`Randomness::initialize`] returns, drawing per-signature randomness computes a keyed BLAKE3 hash
/// over an in-memory counter (no disk writes, no clock reads, and no system calls by BLINCS itself).
///
/// Keep the state file in a private local directory owned by the signer on a filesystem that supports
/// advisory file locks (`flock`). Provision the file once with [`Randomness::create`] before starting
/// signers. After `fork()` or restoring a live process or VM snapshot, call [`Randomness::initialize`]
/// again so cloned process images do not share the same `(run_key, count)` sequence.
pub struct Randomness {
    run_key: RunKey,
    count: AtomicU64,
}

impl fmt::Debug for Randomness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Randomness { .. }")
    }
}

impl Randomness {
    /// Create and durably sync a new 48-byte BLINCS randomness state file at `path`.
    ///
    /// Fails if `path` already exists, so an existing state file or another file is never overwritten.
    pub fn create(path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        let os_bytes = read_os_randomness()?;
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        let write_res = (|| -> io::Result<()> {
            let mut state = [0u8; STATE_LEN];
            state[..8].copy_from_slice(MAGIC);
            state[8..16].copy_from_slice(&0u64.to_le_bytes());
            state[16..48].copy_from_slice(&os_bytes);
            file.write_all(&state)?;
            file.sync_all()
        })();
        if let Err(e) = write_res {
            let _ = fs::remove_file(path);
            return Err(e);
        }
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Open an existing regular state file at `path`, mix it with OS randomness and the monotonic clock,
    /// write the updated counter and seed in place (without `fsync`), and return the in-memory generator
    /// for this run.
    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {
        ensure_init();
        let mut file = OpenOptions::new().read(true).write(true).open(path.as_ref())?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "BLINCS randomness state path is not a regular file"));
        }
        file.lock()?;
        let state = read_exact_or_reject(&mut file)?;
        let old_count = u64::from_le_bytes(state[8..16].try_into().unwrap());
        let new_count = old_count.checked_add(1).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "randomness state counter exhausted"))?;
        let old_seed: [u8; 32] = state[16..48].try_into().unwrap();
        let os_bytes = read_os_randomness()?;
        let clock_bytes = read_monotonic_clock();
        let (next_seed, run_key) = mix(&old_seed, new_count, &os_bytes, &clock_bytes);
        let mut updated = [0u8; 40];
        updated[..8].copy_from_slice(&new_count.to_le_bytes());
        updated[8..40].copy_from_slice(&next_seed);
        file.seek(SeekFrom::Start(8))?;
        file.write_all(&updated)?;
        Ok(Self { run_key: RunKey(run_key), count: AtomicU64::new(0) })
    }

    #[cfg(test)]
    pub(crate) fn from_run_key_at(run_key: [u8; 32], start: u64) -> Self {
        Self { run_key: RunKey(run_key), count: AtomicU64::new(start) }
    }

    /// Draw a fresh 32-byte per-signature value from memory alone.
    pub(crate) fn draw(&self) -> [u8; 32] {
        let n = self.count.try_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(1)).expect("randomness draw counter exhausted");
        self.run_key.draw_at(n)
    }
}

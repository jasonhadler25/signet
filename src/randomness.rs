use crate::params::{CTX_KEYGEN_KEY, CTX_MIX, CTX_NEXT_SEED, CTX_RUN_KEY, N, derive_key, ensure_init, first_n, keyed};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub(crate) const SEED_FILE_LEN: usize = 32;

/// Fill 32 bytes from the OS cryptographic randomness source (`getrandom(2)` on Linux, `getentropy` on macOS).
pub(crate) fn read_os_randomness() -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(format!("OS randomness failed: {e}")))?;
    Ok(bytes)
}

/// Capture opaque local diversification bytes from the system monotonic clock (`Instant::hash`).
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

/// Pure state-mixing function (`SPEC.md`, "Signer randomness").
/// Mixes optional prior persisted salt, OS randomness, process ID, and monotonic clock bytes.
pub(crate) fn mix_pool(prior_salt: Option<&[u8; SEED_FILE_LEN]>, system: &[u8; 32], pid: u32, clock: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(1 + SEED_FILE_LEN + 32 + 4 + clock.len());
    match prior_salt {
        Some(salt) => {
            material.push(u8::try_from(SEED_FILE_LEN).unwrap());
            material.extend_from_slice(salt);
        }
        None => material.push(0),
    }
    material.extend_from_slice(system);
    material.extend_from_slice(&pid.to_le_bytes());
    material.extend_from_slice(clock);
    derive_key(CTX_MIX, &material)
}

pub(crate) fn expand_pool(pool: &[u8; 32]) -> ([u8; SEED_FILE_LEN], [u8; 32], [u8; 32]) {
    (derive_key(CTX_NEXT_SEED, pool), derive_key(CTX_RUN_KEY, pool), derive_key(CTX_KEYGEN_KEY, pool))
}

pub(crate) fn read_exact_seed(file: &mut impl Read) -> io::Result<[u8; SEED_FILE_LEN]> {
    let mut buf = [0u8; SEED_FILE_LEN + 1];
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                assert!(n <= buf.len() - filled);
                filled += n;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if filled != SEED_FILE_LEN {
        return Err(io::Error::new(ErrorKind::InvalidData, "Signet randomness state file must be exactly 32 bytes"));
    }
    Ok(buf[..SEED_FILE_LEN].try_into().unwrap())
}

fn check_private_regular_file(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Signet randomness state path must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(ErrorKind::PermissionDenied, "Signet randomness state file must be private (mode 0600)"));
        }
    }
    Ok(())
}

fn parent_dir(path: &Path) -> io::Result<&Path> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Signet randomness state path has no parent directory"));
    };
    Ok(if parent.as_os_str().is_empty() { Path::new(".") } else { parent })
}

fn temp_sibling_path(path: &Path) -> io::Result<PathBuf> {
    let parent = parent_dir(path)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("signet-salt");
    let nonce = first_n(&read_os_randomness()?);
    let mut suffix = String::with_capacity(2 * N);
    for &b in &nonce {
        use std::fmt::Write;
        write!(&mut suffix, "{b:02x}").unwrap();
    }
    Ok(parent.join(format!(".{name}.{suffix}.tmp")))
}

fn write_temp_seed(tmp: &Path, seed: &[u8; SEED_FILE_LEN], sync: bool) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    if let Err(e) = f.write_all(seed).and_then(|()| if sync { f.sync_all() } else { Ok(()) }) {
        let _ = fs::remove_file(tmp);
        return Err(e);
    }
    Ok(())
}

/// Lock-free per-process signer randomness backed by a single private 32-byte state file.
///
/// On [`Randomness::initialize`], Signet reads the existing 32-byte file, mixes it with OS
/// randomness (`getrandom`), the process ID, and the monotonic clock, derives an independent
/// successor state and in-memory keys (preserving forward secrecy on disk), and publishes the
/// successor atomically via sibling temp file + POSIX `rename` — with no file locks, no blocking,
/// and no torn reads.
///
/// After `initialize` returns, drawing per-imprint randomness computes a keyed BLAKE3 hash over an
/// in-memory counter (no disk writes, no clock reads, and no system calls).
///
/// Provision the state file once with [`Randomness::create`] before starting signers. In a
/// multithreaded POSIX process, call `exec()` before initializing Signet rather than calling
/// `initialize` directly after `fork()`; after restoring a VM snapshot, ensure genuinely fresh
/// unshared OS entropy before initializing.
pub struct Randomness {
    run_key: [u8; 32],
    keygen_key: [u8; 32],
    count: AtomicU64,
}

impl fmt::Debug for Randomness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Randomness { .. }")
    }
}

impl Randomness {
    /// Create a new private 32-byte randomness state file at `path` (`0600` on Unix) durably.
    ///
    /// Fails with `AlreadyExists` if `path` already exists, never overwriting an existing state
    /// file or unrelated path. Stages the complete 32-byte file, syncs it, publishes atomically
    /// via no-replace `hard_link`, and syncs the parent directory.
    pub fn create(path: impl AsRef<Path>) -> io::Result<()> {
        ensure_init();
        let path = path.as_ref();
        let pool = mix_pool(None, &read_os_randomness()?, std::process::id(), &read_monotonic_clock());
        let (next_seed, _, _) = expand_pool(&pool);

        let tmp = temp_sibling_path(path)?;
        write_temp_seed(&tmp, &next_seed, true)?;
        let link_res = fs::hard_link(&tmp, path);
        let _ = fs::remove_file(&tmp);
        link_res?;

        if let Ok(pf) = File::open(parent_dir(path)?) {
            let _ = pf.sync_all();
        }
        Ok(())
    }

    /// Read the existing 32-byte state file at `path`, mix it with OS randomness (`getrandom`),
    /// the process ID, and the monotonic clock, atomically rotate `path` to a fresh 32-byte
    /// successor via sibling temp file + `rename` (no locks), and return the in-memory generator.
    ///
    /// Rejects missing paths, symlinks, directories, group/world-accessible files (`mode & 0o077 != 0`),
    /// and files whose length is not exactly 32 bytes.
    pub fn initialize(path: impl AsRef<Path>) -> io::Result<Self> {
        ensure_init();
        let path = path.as_ref();
        check_private_regular_file(path)?;
        let mut f = File::open(path)?;
        let prior = read_exact_seed(&mut f)?;
        drop(f);

        let pool = mix_pool(Some(&prior), &read_os_randomness()?, std::process::id(), &read_monotonic_clock());
        let (next_seed, run_key, keygen_key) = expand_pool(&pool);

        let tmp = temp_sibling_path(path)?;
        write_temp_seed(&tmp, &next_seed, false)?;
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        Ok(Self { run_key, keygen_key, count: AtomicU64::new(0) })
    }

    #[cfg(test)]
    pub(crate) fn from_keys_at(run_key: [u8; 32], keygen_key: [u8; 32], start: u64) -> Self {
        Self { run_key, keygen_key, count: AtomicU64::new(start) }
    }

    fn next_counter(&self) -> u64 {
        self.count.try_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(1)).expect("randomness draw counter exhausted")
    }

    /// Draw a fresh 32-byte per-imprint value from memory alone.
    pub(crate) fn draw(&self) -> [u8; 32] {
        ensure_init();
        keyed(&self.run_key, &self.next_counter().to_le_bytes())
    }

    /// Draw a domain-separated 32-byte value for [`crate::Signet::generate`].
    pub(crate) fn draw_for_keygen(&self) -> [u8; 32] {
        ensure_init();
        keyed(&self.keygen_key, &self.next_counter().to_le_bytes())
    }
}

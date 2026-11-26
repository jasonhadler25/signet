use crate::params::{CTX_FILE_ID, CTX_KEYGEN_KEY, CTX_MIX, CTX_NEXT_SEED, CTX_RUN_KEY, N, derive_key, ensure_init, first_n, keyed};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const FILE_PREFIX: &str = "signet-r2-";
const FILE_NAME_LEN: usize = FILE_PREFIX.len() + 2 * N;
const STAGE_DIR_NAME: &str = ".stage";
const STAGE_PREFIX: &str = "tmp-";
pub(crate) const SEED_FILE_LEN: usize = 32;
const MAX_SEED_FILES: usize = 1024;
const MAX_PUBLISH_ATTEMPTS: usize = 64;

/// Fill `out` from the OS cryptographic randomness source (`getrandom(2)` on Linux, `getentropy` on macOS).
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

/// Pure state-mixing function (SPEC.md, "Signer randomness").
/// Returns the 32-byte pool from which `file_id`, `next_seed`, `run_key`, and `keygen_key` derive.
pub(crate) fn mix_pool(seeds: &[&[u8]], system: &[u8; 32], clock: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(seeds.len() * (1 + SEED_FILE_LEN) + 1 + 32 + clock.len());
    for s in seeds {
        assert!(s.len() <= SEED_FILE_LEN);
        material.push(u8::try_from(s.len()).unwrap());
        material.extend_from_slice(s);
    }
    material.push(0xff);
    material.extend_from_slice(system);
    material.extend_from_slice(clock);
    derive_key(CTX_MIX, &material)
}

pub(crate) fn expand_pool(pool: &[u8; 32]) -> ([u8; N], [u8; 32], [u8; 32], [u8; 32]) {
    (first_n(&derive_key(CTX_FILE_ID, pool)), derive_key(CTX_NEXT_SEED, pool), derive_key(CTX_RUN_KEY, pool), derive_key(CTX_KEYGEN_KEY, pool))
}

fn hex_with_prefix(prefix: &str, bytes: &[u8; N]) -> String {
    let mut out = String::with_capacity(prefix.len() + 2 * N);
    out.push_str(prefix);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

pub(crate) fn seed_filename(file_id: &[u8; N]) -> String {
    hex_with_prefix(FILE_PREFIX, file_id)
}

pub(crate) fn is_seed_filename(name: &str) -> bool {
    name.len() == FILE_NAME_LEN && name.starts_with(FILE_PREFIX) && name.as_bytes()[FILE_PREFIX.len()..].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Read an exact 32-byte seed file, failing closed on empty, truncated, or oversized files.
pub(crate) fn read_exact_seed(reader: &mut impl Read) -> io::Result<[u8; SEED_FILE_LEN]> {
    let mut buf = [0u8; SEED_FILE_LEN + 1];
    let (filled, _) = crate::content::fill_buf(reader, &mut buf, 0, &mut 0)?;
    if filled != SEED_FILE_LEN {
        return Err(io::Error::new(ErrorKind::InvalidData, "Signet randomness seed file must be exactly 32 bytes"));
    }
    let mut out = [0u8; SEED_FILE_LEN];
    out.copy_from_slice(&buf[..SEED_FILE_LEN]);
    Ok(out)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn check_private_dir(path: &Path, label: &str) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidInput, format!("{label} is not a directory")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(ErrorKind::PermissionDenied, format!("{label} must be private (mode 0700)")));
        }
    }
    Ok(())
}

pub(crate) fn ignore_not_found<T>(res: io::Result<T>) -> io::Result<Option<T>> {
    match res {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn ensure_stage_dir(dir: &Path) -> io::Result<std::path::PathBuf> {
    let stage_dir = dir.join(STAGE_DIR_NAME);
    let _ = create_private_dir(&stage_dir);
    check_private_dir(&stage_dir, "Signet randomness staging path")?;
    Ok(stage_dir)
}

/// Stage a complete 32-byte seed file inside `dir/.stage/` and publish it atomically to `final_path`
/// via `hard_link` (POSIX `link(2)` — never overwrites and never exposes a partial file in `dir`).
fn publish_complete_seed_file(dir: &Path, final_path: &Path, seed: &[u8; SEED_FILE_LEN], sync: bool) -> io::Result<()> {
    let stage_dir = ensure_stage_dir(dir)?;
    let nonce = first_n(&read_os_randomness()?);
    let stage_path = stage_dir.join(hex_with_prefix(STAGE_PREFIX, &nonce));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&stage_path)?;
    if let Err(e) = file.write_all(seed).and_then(|()| if sync { file.sync_all() } else { Ok(()) }) {
        let _ = remove_if_present(&stage_path);
        return Err(e);
    }
    drop(file);

    let link_res = fs::hard_link(&stage_path, final_path);
    let _ = remove_if_present(&stage_path);
    link_res
}

/// Per-process signer randomness, backed by a lock-free seed directory on a private local filesystem.
///
/// Each published seed file is named `signet-r2-<32 hex>` from a pool-derived `file_id`
/// (domain-separated from `next_seed`, `run_key`, and `keygen_key`) and always holds an exact
/// 32-byte seed: new files are written completely inside `dir/.stage/` and published atomically via
/// no-replace `hard_link`, so concurrent initializers never observe a partial seed file.
///
/// On [`Randomness::initialize`], all existing seed files in the directory are read (sorted by
/// filename) and mixed with OS randomness (`getrandom`) and the monotonic clock, a complete
/// successor seed file is published, and the observed predecessors are unlinked without `flock` or
/// lockfiles.
///
/// After `initialize` returns, drawing per-imprint randomness computes a keyed BLAKE3 hash over an
/// in-memory counter (no disk writes, no clock reads, and no system calls by Signet itself).
///
/// Provision the directory once with [`Randomness::create`] before starting signers. In a
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

pub(crate) fn read_seed_if_present(path: &Path) -> io::Result<Option<[u8; SEED_FILE_LEN]>> {
    let Some(mut f) = ignore_not_found(File::open(path))? else {
        return Ok(None);
    };
    Ok(Some(read_exact_seed(&mut f)?))
}

pub(crate) fn write_next_seed(dir: &Path, mut pool: [u8; 32]) -> io::Result<([u8; 32], [u8; 32])> {
    for _ in 0..MAX_PUBLISH_ATTEMPTS {
        let (file_id, next_seed, rk, kk) = expand_pool(&pool);
        match publish_complete_seed_file(dir, &dir.join(seed_filename(&file_id)), &next_seed, false) {
            Ok(()) => return Ok((rk, kk)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => pool = derive_key(CTX_MIX, &pool),
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(ErrorKind::AlreadyExists, "Signet randomness seed filename collision limit exceeded"))
}

pub(crate) fn remove_if_present(path: &Path) -> io::Result<()> {
    ignore_not_found(fs::remove_file(path))?;
    Ok(())
}

fn read_seed_entries(dir: &Path) -> io::Result<Vec<(String, [u8; SEED_FILE_LEN])>> {
    // Re-scan if concurrent rotation unlinks every listed seed before open or shifts entries past
    // the POSIX readdir cursor.
    for _ in 0..16 {
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name =
                entry.file_name().into_string().map_err(|_| io::Error::new(ErrorKind::InvalidData, "unexpected entry in Signet randomness directory"))?;
            let Some(ftype) = ignore_not_found(entry.file_type())? else {
                continue;
            };
            if name == STAGE_DIR_NAME {
                if !ftype.is_dir() {
                    return Err(io::Error::new(ErrorKind::InvalidData, "unexpected .stage entry in Signet randomness directory"));
                }
                continue;
            }
            if !is_seed_filename(&name) || !ftype.is_file() {
                return Err(io::Error::new(ErrorKind::InvalidData, "unexpected entry in Signet randomness directory"));
            }
            if entries.len() >= MAX_SEED_FILES {
                return Err(io::Error::new(ErrorKind::InvalidData, "Signet randomness directory exceeds maximum seed file count"));
            }
            if let Some(bytes) = read_seed_if_present(&entry.path())? {
                entries.push((name, bytes));
            }
        }
        if !entries.is_empty() {
            return Ok(entries);
        }
    }
    Err(io::Error::new(ErrorKind::InvalidData, "Signet randomness directory contains no seed files"))
}

impl Randomness {
    /// Create a new private seed directory at `dir` (`0700` on Unix) and durably publish its
    /// initial 32-byte seed file.
    ///
    /// Fails if `dir` already exists, so an existing seed directory or unrelated path is never
    /// overwritten. Syncs the seed file, `dir`, and `dir`'s parent directory.
    pub fn create(dir: impl AsRef<Path>) -> io::Result<()> {
        ensure_init();
        let dir = dir.as_ref();
        let os_bytes = read_os_randomness()?;
        let clock = read_monotonic_clock();
        let pool = mix_pool(&[], &os_bytes, &clock);
        let (file_id, next_seed, _, _) = expand_pool(&pool);

        create_private_dir(dir)?;
        publish_complete_seed_file(dir, &dir.join(seed_filename(&file_id)), &next_seed, true)?;
        File::open(dir)?.sync_all()?;
        if let Some(parent) = dir.parent() {
            let parent_path = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
            if let Ok(pf) = File::open(parent_path) {
                let _ = pf.sync_all();
            }
        }
        Ok(())
    }

    /// Read all 32-byte seed files in `dir`, mix them with OS randomness (`getrandom`) and the
    /// monotonic clock, publish a complete successor seed file (best-effort, without `fsync`),
    /// unlink the observed predecessors, and return the in-memory generator.
    ///
    /// Requires `dir` to be a private directory (`0700` on Unix) on a trusted local filesystem;
    /// rejects non-directories, non-private permissions, empty directories, symlinks, unexpected
    /// entries, and seed files whose length is not exactly 32 bytes without modifying or deleting
    /// unrelated files.
    pub fn initialize(dir: impl AsRef<Path>) -> io::Result<Self> {
        ensure_init();
        let dir = dir.as_ref();
        check_private_dir(dir, "Signet randomness state path")?;

        let mut entries = read_seed_entries(dir)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let seed_slices: Vec<&[u8]> = entries.iter().map(|(_, b)| b.as_slice()).collect();
        let pool = mix_pool(&seed_slices, &read_os_randomness()?, &read_monotonic_clock());
        let (run_key, keygen_key) = write_next_seed(dir, pool)?;

        for (old_name, _) in &entries {
            remove_if_present(&dir.join(old_name))?;
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

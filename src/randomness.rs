use crate::params::{CTX_FILE_ID, CTX_KEYGEN_KEY, CTX_MIX, CTX_NEXT_SEED, CTX_RUN_KEY, N, derive_key, ensure_init, first_n, keyed};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const FILE_PREFIX: &str = "blincs-r2-";
const FILE_NAME_LEN: usize = FILE_PREFIX.len() + 2 * N;
pub(crate) const SEED_FILE_MAX_LEN: usize = 32;

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
    let mut material = Vec::with_capacity(seeds.len() * (1 + SEED_FILE_MAX_LEN) + 1 + 32 + clock.len());
    for s in seeds {
        assert!(s.len() <= SEED_FILE_MAX_LEN);
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

pub(crate) fn seed_filename(file_id: &[u8; N]) -> String {
    let mut out = String::with_capacity(FILE_NAME_LEN);
    out.push_str(FILE_PREFIX);
    for &b in file_id {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

pub(crate) fn is_seed_filename(name: &str) -> bool {
    name.len() == FILE_NAME_LEN && name.starts_with(FILE_PREFIX) && name.as_bytes()[FILE_PREFIX.len()..].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn read_bounded_seed(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; SEED_FILE_MAX_LEN + 1];
    let (filled, _) = crate::content::fill_buf(reader, &mut buf, 0, &mut 0)?;
    if filled > SEED_FILE_MAX_LEN {
        return Err(io::Error::new(ErrorKind::InvalidData, "BLINCS randomness seed file exceeds 32 bytes"));
    }
    Ok(buf[..filled].to_vec())
}

fn write_new_seed_file(path: &Path, seed: &[u8; 32], sync: bool) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(seed)?;
    if sync {
        file.sync_all()?;
    }
    Ok(())
}

/// Per-process signer randomness, backed by a lock-free content-addressed seed directory.
///
/// Each seed file is named `blincs-r2-<32 hex>` from a domain-separated `file_id` (revealing zero
/// bits of the file's 32-byte `next_seed`, `run_key`, or future salts/signets) and holds up to 32
/// raw seed bytes. On [`Randomness::initialize`], all existing seed files in the directory are read
/// and mixed with OS randomness (`getrandom`) and the monotonic clock, a new file is created
/// atomically via `create_new` (`O_CREAT | O_EXCL`), and the old files are unlinked — with zero
/// `flock`, zero lockfiles, and automatic self-healing across concurrent startups and crashes.
///
/// After `initialize` returns, drawing per-imprint randomness computes a keyed BLAKE3 hash over an
/// in-memory counter (no disk writes, no clock reads, and no system calls by BLINCS itself).
///
/// Provision the directory once with [`Randomness::create`] before starting signers. After `fork()`
/// (without `exec()`) or restoring a live VM snapshot, call [`Randomness::initialize`] again so
/// cloned processes or images do not share the same in-memory draw sequence.
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

pub(crate) fn read_seed_if_present(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(read_bounded_seed(&mut f)?))
}

pub(crate) fn write_next_seed(dir: &Path, mut pool: [u8; 32]) -> io::Result<([u8; 32], [u8; 32])> {
    loop {
        let (file_id, next_seed, rk, kk) = expand_pool(&pool);
        match write_new_seed_file(&dir.join(seed_filename(&file_id)), &next_seed, false) {
            Ok(()) => return Ok((rk, kk)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => pool = derive_key(CTX_MIX, &pool),
            Err(e) => return Err(e),
        }
    }
}

pub(crate) fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn read_seed_entries(dir: &Path) -> io::Result<Vec<(String, Vec<u8>)>> {
    // Re-scan if concurrent lock-free rotation unlinks every listed seed before open or shifts
    // entries past the POSIX readdir cursor.
    for _ in 0..16 {
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name =
                entry.file_name().into_string().map_err(|_| io::Error::new(ErrorKind::InvalidData, "unexpected entry in BLINCS randomness directory"))?;
            if !is_seed_filename(&name) || !entry.file_type()?.is_file() {
                return Err(io::Error::new(ErrorKind::InvalidData, "unexpected entry in BLINCS randomness directory"));
            }
            if let Some(bytes) = read_seed_if_present(&entry.path())? {
                entries.push((name, bytes));
            }
        }
        if !entries.is_empty() {
            return Ok(entries);
        }
    }
    Err(io::Error::new(ErrorKind::InvalidData, "BLINCS randomness directory contains no seed files"))
}

impl Randomness {
    /// Create a new private seed directory at `dir` (`0700` on Unix) and durably write its initial
    /// 32-byte seed file.
    ///
    /// Fails if `dir` already exists, so an existing seed directory or unrelated path is never
    /// overwritten.
    pub fn create(dir: impl AsRef<Path>) -> io::Result<()> {
        ensure_init();
        let dir = dir.as_ref();
        let os_bytes = read_os_randomness()?;
        let clock = read_monotonic_clock();
        let pool = mix_pool(&[], &os_bytes, &clock);
        let (file_id, next_seed, _, _) = expand_pool(&pool);

        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
        write_new_seed_file(&dir.join(seed_filename(&file_id)), &next_seed, true)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// Read all seed files in `dir`, mix them with OS randomness (`getrandom`) and the monotonic
    /// clock, create a fresh seed file atomically (without `fsync`), remove the old files, and
    /// return the in-memory generator.
    pub fn initialize(dir: impl AsRef<Path>) -> io::Result<Self> {
        ensure_init();
        let dir = dir.as_ref();
        let meta = fs::symlink_metadata(dir)?;
        if !meta.file_type().is_dir() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "BLINCS randomness state path is not a directory"));
        }

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

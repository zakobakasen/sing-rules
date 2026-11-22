use ring::digest::{SHA256, digest};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
const LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Cache {
    directory: Option<PathBuf>,
    refresh: bool,
}

impl Cache {
    pub fn new(directory: Option<PathBuf>, refresh: bool) -> Self {
        Self {
            directory: directory.or_else(default_directory),
            refresh,
        }
    }

    pub fn entry(&self, url: &str) -> Option<PathBuf> {
        let directory = self.directory.as_ref()?;
        let hash = digest(&SHA256, url.as_bytes());
        let name: String = hash
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Some(directory.join(name))
    }

    pub fn read(&self, entry: &Path) -> Option<Vec<u8>> {
        if self.refresh {
            return None;
        }
        match read_fresh(entry) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                eprintln!(
                    "warning: reading ruleset cache {}: {error}",
                    entry.display()
                );
                None
            }
        }
    }
}

fn read_fresh(entry: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = fs::File::open(entry)?;
    let modified = file.metadata()?.modified()?;
    if !modified.elapsed().is_ok_and(|age| age < LIFETIME) {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(MAX_DOWNLOAD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is too large",
        ));
    }
    Ok(Some(bytes))
}

pub fn write(entry: &Path, bytes: &[u8]) -> io::Result<()> {
    let directory = entry
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes)?;
    temporary.persist(entry).map_err(|error| error.error)?;
    Ok(())
}

fn default_directory() -> Option<PathBuf> {
    let env_path = |name| {
        env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let base = if cfg!(windows) {
        env_path("LOCALAPPDATA").map(|path| path.join("sing-rules").join("cache"))
    } else if cfg!(target_os = "macos") {
        env_path("HOME").map(|path| path.join("Library").join("Caches").join("sing-rules"))
    } else {
        env_path("XDG_CACHE_HOME")
            .or_else(|| env_path("HOME").map(|path| path.join(".cache")))
            .map(|path| path.join("sing-rules"))
    };
    base.map(|path| path.join("rulesets"))
}

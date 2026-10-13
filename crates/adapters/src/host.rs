//! The ONLY module that touches the host filesystem: host detection and
//! reading local pacman configuration / sync databases (system files, not
//! untrusted input). Every path is injectable through [`HostInfo`] so tests
//! use fixtures.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::HostInfo;

pub const DEFAULT_PACMAN_CONF: &str = "/etc/pacman.conf";
pub const DEFAULT_MIRRORLIST: &str = "/etc/pacman.d/mirrorlist";
pub const DEFAULT_DB_PATH: &str = "/var/lib/pacman";

/// Largest sync DB we are willing to read (extra.db is ~10 MiB today).
const MAX_DB_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONF_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn detect() -> HostInfo {
    let exists = |p: &str| Path::new(p).exists();
    let arch = match std::env::consts::ARCH {
        "x86" => "i686",
        other => other,
    }
    .to_string();
    let os = std::env::consts::OS.to_string();
    let has_pacman = exists(DEFAULT_PACMAN_CONF);
    let in_path = |prog: &str| {
        ["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin"]
            .iter()
            .any(|d| Path::new(d).join(prog).exists())
    };
    HostInfo {
        pacman_db_path: has_pacman.then(|| PathBuf::from(DEFAULT_DB_PATH)),
        pacman_conf: has_pacman.then(|| PathBuf::from(DEFAULT_PACMAN_CONF)),
        mirrorlist: (has_pacman && exists(DEFAULT_MIRRORLIST))
            .then(|| PathBuf::from(DEFAULT_MIRRORLIST)),
        has_apt: os == "linux" && in_path("apt-get"),
        has_dnf: os == "linux" && in_path("dnf"),
        brew_bottle_tag: None,
        arch,
        os,
    }
}

/// Read a small text file (configuration).
pub(crate) fn read_text(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_CONF_BYTES {
        return Err(format!(
            "{}: unexpectedly large ({} bytes)",
            path.display(),
            meta.len()
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Read a sync database and its modification time (seconds since epoch).
pub(crate) fn read_db(path: &Path) -> Result<(Vec<u8>, Option<i64>), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_DB_BYTES {
        return Err(format!(
            "{}: unexpectedly large ({} bytes)",
            path.display(),
            meta.len()
        ));
    }
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((bytes, mtime))
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

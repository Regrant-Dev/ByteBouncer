//! Acquisition: turn the user's target into exact snapshot files in
//! the scan workspace plus an acquisition manifest. Nothing here parses the
//! content of what it copies or downloads.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bytebouncer_core::{AcquisitionManifest, Origin};
use sha2::{Digest, Sha256};

use crate::fetch::{self, FetchRequest};

/// Directory names skipped by default; listed in coverage.
pub const VENDORED_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    ".git",
    ".hg",
    ".svn",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
];

pub struct Limits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_download_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_total_bytes: 4 << 30,
            max_download_bytes: 2 << 30,
        }
    }
}

/// One file to analyze, already copied into the workspace.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub path: PathBuf,
    pub display: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Default)]
pub struct Acquired {
    pub files: Vec<Snapshot>,
    pub manifest: AcquisitionManifest,
    pub skipped: Vec<String>,
    /// Acquisition problems that make the result incomplete.
    pub incomplete: Vec<String>,
    /// Findings produced during acquisition (repository digest/signature checks).
    pub outputs: Vec<bytebouncer_core::AnalysisOutput>,
    /// Informational caveats from resolution (e.g. stale sync databases).
    pub notes: Vec<String>,
}

pub enum Target {
    File(PathBuf),
    Directory(PathBuf),
    Url(String),
}

pub fn classify(target: &str) -> Option<Target> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(Target::Url(target.to_owned()));
    }
    let path = PathBuf::from(target);
    match fs::metadata(&path) {
        Ok(m) if m.is_dir() => Some(Target::Directory(path)),
        Ok(m) if m.is_file() => Some(Target::File(path)),
        _ => None,
    }
}

pub fn acquire(
    target: Target,
    ws: &Path,
    limits: &Limits,
    include_vendored: bool,
    allow_reduced: bool,
) -> Result<Acquired> {
    let snap_dir = ws.join("snapshot");
    fs::create_dir(&snap_dir)?;
    let mut acq = Acquired::default();
    match target {
        Target::File(p) => {
            let name = file_name(&p);
            let dst = snap_dir.join("0");
            let (sha256, size) = copy_hashed(&p, &dst, limits.max_total_bytes)?;
            acq.files.push(Snapshot {
                path: dst,
                display: name,
                sha256,
                size,
            });
        }
        Target::Directory(root) => {
            snapshot_dir(&root, &snap_dir, limits, include_vendored, &mut acq)?
        }
        Target::Url(url) => {
            let dest = snap_dir.join("0");
            let reply = fetch::fetch(&FetchRequest {
                url: url.clone(),
                headers: vec![],
                max_bytes: limits.max_download_bytes,
                dest: dest.clone(),
                timeout_secs: 900,
                allow_reduced,
            })?;
            let display = url_file_name(&reply.final_url).unwrap_or_else(|| "download".into());
            acq.manifest.origins.push(Origin {
                requested_url: url,
                final_url: reply.final_url,
                redirects: reply.redirects,
                sha256: reply.sha256.clone(),
                size: reply.size,
                retrieved_at: jiff::Timestamp::now().to_string(),
            });
            acq.files.push(Snapshot {
                path: dest,
                display,
                sha256: reply.sha256,
                size: reply.size,
            });
        }
    }
    Ok(acq)
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "input".into())
}

pub fn url_file_name(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next()?;
    let name = path.rsplit('/').next()?;
    (!name.is_empty() && !path.ends_with("://")).then(|| name.to_owned())
}

fn snapshot_dir(
    root: &Path,
    snap_dir: &Path,
    limits: &Limits,
    include_vendored: bool,
    acq: &mut Acquired,
) -> Result<()> {
    let root_name = file_name(&fs::canonicalize(root)?);
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let display = format!("{root_name}/{rel}");
            // symlink_metadata: never follow links out of the selected tree.
            let meta = fs::symlink_metadata(&path)?;
            let ft = meta.file_type();
            if ft.is_symlink() {
                let target = fs::read_link(&path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_default();
                acq.skipped
                    .push(format!("{display}: symlink to {target} not followed"));
            } else if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !include_vendored && VENDORED_DIRS.contains(&name.as_str()) {
                    acq.skipped.push(format!(
                        "{display}/: vendored/generated directory excluded (use --include-vendored)"
                    ));
                } else {
                    stack.push(path);
                }
            } else if !ft.is_file() {
                acq.skipped.push(format!("{display}: special file skipped"));
            } else {
                if acq.files.len() >= limits.max_files {
                    acq.incomplete.push(format!(
                        "directory exceeds the {}-file limit; remaining files not inspected",
                        limits.max_files
                    ));
                    return Ok(());
                }
                if total + meta.len() > limits.max_total_bytes {
                    acq.incomplete.push(format!(
                        "directory exceeds the {}-byte limit; remaining files not inspected",
                        limits.max_total_bytes
                    ));
                    return Ok(());
                }
                let dst = snap_dir.join(acq.files.len().to_string());
                let (sha256, size) = copy_hashed(&path, &dst, limits.max_total_bytes - total)?;
                total += size;
                let after = fs::symlink_metadata(&path).ok();
                if after.is_none_or(|a| {
                    a.len() != meta.len() || a.modified().ok() != meta.modified().ok()
                }) {
                    acq.manifest.changed_during_snapshot.push(display.clone());
                }
                acq.files.push(Snapshot {
                    path: dst,
                    display,
                    sha256,
                    size,
                });
            }
        }
    }
    Ok(())
}

/// Copy `src` to a new file `dst`, returning the SHA-256 and size of the copied bytes.
pub fn copy_hashed(src: &Path, dst: &Path, max_bytes: u64) -> Result<(String, u64)> {
    let mut input = fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let mut out = fs::File::create_new(dst).context("creating snapshot")?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > max_bytes {
            bail!("{} exceeds the {max_bytes}-byte input limit", src.display());
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
    }
    out.sync_all()?;
    Ok((hex::encode(hasher.finalize()), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_names() {
        assert_eq!(
            url_file_name("https://x.org/a/b.zip?x=1").as_deref(),
            Some("b.zip")
        );
        assert_eq!(url_file_name("https://x.org/").as_deref(), None);
    }

    #[cfg(unix)]
    #[test]
    fn directory_snapshot_skips_links_and_vendored() {
        let root = std::env::temp_dir().join(format!("bb-acq-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let src = root.join("proj");
        fs::create_dir_all(src.join("node_modules/x")).unwrap();
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join("src/main.sh"), "echo hi").unwrap();
        fs::write(src.join("node_modules/x/i.js"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("passwd")).unwrap();
        let ws = root.join("ws");
        fs::create_dir_all(&ws).unwrap();
        let acq = acquire(
            Target::Directory(src),
            &ws,
            &Limits::default(),
            false,
            false,
        )
        .unwrap();
        let names: Vec<_> = acq.files.iter().map(|f| f.display.as_str()).collect();
        assert_eq!(names, ["proj/src/main.sh"]);
        assert!(acq.skipped.iter().any(|s| s.contains("symlink")));
        assert!(acq.skipped.iter().any(|s| s.contains("node_modules")));
        let _ = fs::remove_dir_all(&root);
    }
}

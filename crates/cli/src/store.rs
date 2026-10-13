//! Report store and scan workspaces (SPEC §3.4, §9.4).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bytebouncer_core::Report;
use directories::ProjectDirs;

fn dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", "ByteBouncer").context("cannot determine home directory")
}

fn reports_dir() -> Result<PathBuf> {
    Ok(dirs()?.data_dir().join("reports"))
}

fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

pub fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

/// A fresh, owner-only workspace for one scan.
pub fn new_workspace(scan_id: &str) -> Result<PathBuf> {
    let base = dirs()?.cache_dir().join("work");
    create_private_dir(&base)?;
    let ws = base.join(scan_id);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&ws)
        .with_context(|| format!("creating workspace {}", ws.display()))?;
    Ok(ws)
}

pub fn save(report: &Report) -> Result<PathBuf> {
    let dir = reports_dir()?.join(&report.scan_id);
    create_private_dir(&dir)?;
    write_private_file(
        &dir.join("report.json"),
        serde_json::to_string_pretty(report)?.as_bytes(),
    )?;
    write_private_file(
        &dir.join("report.md"),
        crate::render::markdown(report).as_bytes(),
    )?;
    write_private_file(
        &dir.join("report.html"),
        crate::html::render(report).as_bytes(),
    )?;
    Ok(dir)
}

/// Open a saved report's HTML page in the desktop's default browser.
pub fn open_html(scan_id: &str) -> Result<()> {
    let path = reports_dir()?.join(scan_id).join("report.html");
    if !path.exists() {
        let report = load(scan_id)?;
        write_private_file(&path, crate::html::render(&report).as_bytes())?;
    }
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("opening {} with {opener}", path.display()))?;
    eprintln!("opened {}", path.display());
    Ok(())
}

pub fn load(prefix: &str) -> Result<Report> {
    if prefix.len() < 8 {
        bail!("report ID prefix must be at least 8 characters");
    }
    let prefix = prefix.to_ascii_uppercase();
    let matches: Vec<PathBuf> = read_report_dirs()?
        .into_iter()
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
        })
        .collect();
    let dir = match matches.as_slice() {
        [one] => one,
        [] => bail!("no report matches {prefix}"),
        _ => bail!(
            "{prefix} matches {} reports; use a longer prefix",
            matches.len()
        ),
    };
    let data = fs::read(dir.join("report.json"))?;
    Ok(serde_json::from_slice(&data)?)
}

/// (scan ID, one-line summary), newest first. ULIDs sort by time.
pub fn list() -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for dir in read_report_dirs()? {
        let id = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let summary = fs::read(dir.join("report.json"))
            .ok()
            .and_then(|d| serde_json::from_slice::<Report>(&d).ok())
            .map(|r| {
                let name = r.artifacts.first().map(|a| a.path.as_str()).unwrap_or("?");
                format!(
                    "{name}  {:?}  {} finding(s)",
                    r.result_state,
                    r.findings.len()
                )
            })
            .unwrap_or_else(|| "(unreadable)".into());
        out.push((id, summary));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(out)
}

fn read_report_dirs() -> Result<Vec<PathBuf>> {
    let dir = reports_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect())
}

/// Remove saved reports older than `days`. Report IDs are ULIDs, so their
/// creation time is encoded in the name.
pub fn prune(days: u64) -> Result<usize> {
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    let mut removed = 0;
    for dir in read_report_dirs()? {
        let Some(name) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Ok(id) = ulid::Ulid::from_string(&name) else {
            continue;
        };
        if id.datetime() < cutoff {
            fs::remove_dir_all(&dir)?;
            removed += 1;
        }
    }
    Ok(removed)
}

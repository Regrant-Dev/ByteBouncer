//! `bytebouncer watch DIR...`: quick-inspect each newly completed download.
//! Partial downloads are ignored until renamed; files are never moved,
//! opened by anything else, or executed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytebouncer_core::{ExitCode, ResultState, Severity};
use notify::{EventKind, RecursiveMode, Watcher};

use crate::config::Config;
use crate::inspect::{Progress, ScanContext};
use crate::{InspectArgs, store};

/// Browser and download-manager temporary suffixes.
const PARTIAL_SUFFIXES: &[&str] = &[
    ".part",
    ".crdownload",
    ".tmp",
    ".download",
    ".partial",
    ".opdownload",
    ".!qb",
    ".aria2",
];
/// A file must stop changing for this long before it is inspected.
const SETTLE: Duration = Duration::from_secs(2);

pub fn is_partial(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.starts_with('.') || PARTIAL_SUFFIXES.iter().any(|s| name.ends_with(s))
}

pub fn run(
    dirs: Vec<PathBuf>,
    template: &InspectArgs,
    config: &Config,
    notify_desktop: bool,
) -> Result<ExitCode> {
    let dirs = if dirs.is_empty() {
        config.watch.directories.clone()
    } else {
        dirs
    };
    if dirs.is_empty() {
        anyhow::bail!(
            "no directories given (pass DIR or set [watch] directories in the config file)"
        );
    }
    let notify_desktop = notify_desktop || config.watch.notify.unwrap_or(false);
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev);
        }
    })?;
    for d in &dirs {
        watcher
            .watch(d, RecursiveMode::NonRecursive)
            .with_context(|| format!("watching {}", d.display()))?;
        eprintln!("watching {}", d.display());
    }
    eprintln!("new files are inspected in quick mode; press Ctrl-C to stop");

    // path → (last change, size at last change)
    let mut pending: HashMap<PathBuf, (Instant, u64)> = HashMap::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => {
                if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for p in ev.paths {
                        if !is_partial(&p) && p.is_file() {
                            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                            pending.insert(p, (Instant::now(), size));
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(p, (t, size))| {
                t.elapsed() >= SETTLE
                    && std::fs::metadata(p)
                        .map(|m| m.len() == *size)
                        .unwrap_or(false)
            })
            .map(|(p, _)| p.clone())
            .collect();
        for p in ready {
            pending.remove(&p);
            inspect_one(&p, template, config, notify_desktop);
        }
    }
    Ok(ExitCode::Ok)
}

fn inspect_one(path: &Path, template: &InspectArgs, config: &Config, notify_desktop: bool) {
    let target = path.display().to_string();
    let mut args = template.clone();
    args.target = target.clone();
    let ctx = ScanContext {
        args: &args,
        config,
        cancel: Default::default(),
        progress: Progress::new(true),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or(target.clone());
    match crate::inspect::scan_target(&ctx, &target) {
        Ok(Some(report)) => {
            let saved = if args.no_save {
                None
            } else {
                store::save(&report).ok()
            };
            let worst = report.findings.iter().map(|f| f.severity).max();
            let headline = match (report.result_state, report.policy.exceeded, worst) {
                (_, true, _) => "POLICY EXCEEDED".to_owned(),
                (ResultState::Incomplete, ..) => "incomplete analysis".to_owned(),
                (ResultState::Unsupported, ..) => "unsupported format".to_owned(),
                (_, _, Some(s)) if s >= Severity::Medium => {
                    format!("{} finding(s), worst {s:?}", report.findings.len())
                }
                (_, _, Some(_)) => format!("{} informational finding(s)", report.findings.len()),
                (_, _, None) => "no findings (not proof of safety)".to_owned(),
            };
            println!("{name}: {headline}  [report {}]", report.scan_id);
            if notify_desktop {
                desktop_notify(
                    &format!("ByteBouncer: {name}"),
                    &format!("{headline}\nbytebouncer report {}", report.scan_id),
                );
            }
            let _ = saved;
        }
        Ok(None) => {}
        Err(e) => println!("{name}: inspection failed: {e:#}"),
    }
}

fn desktop_notify(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("notify-send")
        .args(["--app-name=ByteBouncer", title, body])
        .status();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("osascript")
        .args([
            "-e",
            &format!("display notification {:?} with title {:?}", body, title),
        ])
        .status();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (title, body);
}

#[cfg(test)]
mod tests {
    use super::is_partial;
    use std::path::Path;

    #[test]
    fn partial_downloads_are_ignored() {
        assert!(is_partial(Path::new("/d/app.zip.part")));
        assert!(is_partial(Path::new("/d/app.exe.crdownload")));
        assert!(is_partial(Path::new("/d/.hidden")));
        assert!(!is_partial(Path::new("/d/app.zip")));
    }
}

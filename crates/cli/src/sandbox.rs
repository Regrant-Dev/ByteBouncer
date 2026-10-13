//! Tier 1 sandboxed worker.
//!
//! The parent re-executes its own binary as a hidden `__tier1-worker`
//! subcommand with a cleared environment. The worker opens and reads the
//! snapshot, then confines itself before any parsing happens:
//!
//! - rlimits: address space, CPU time, no file creation, few descriptors
//! - a new user + network namespace (no network interfaces at all)
//! - Landlock: no filesystem access, no exec, no TCP connect/bind
//! - seccomp: a syscall allow-list covering memory, writing results, exit
//!
//! That is the Linux shape; macOS uses rlimits plus a Seatbelt profile
//! applied with `sandbox_init`, and Windows launches the worker inside an
//! AppContainer and Job Object (granted read access to just its batch and
//! input files) because confinement there must be applied at process
//! creation. The mechanisms live in `bytebouncer-sandbox`; see
//! `docs/platforms.md`.
//!
//! Each restriction that could not be applied is reported as missing.
//! Unless the user passed `--allow-reduced-isolation`, the worker refuses
//! to parse anything when a restriction is missing.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytebouncer_analysis::ArtifactAnalysis;
use bytebouncer_analysis::container::{ExportLimits, Exported};
use bytebouncer_analysis::yara::{self, RuleSource};
use serde::{Deserialize, Serialize};

pub const WORKER_SUBCOMMAND: &str = "__tier1-worker";

/// Every restriction a fully isolated Tier 1 worker must have on this platform.
pub const REQUIRED: &[&str] = bytebouncer_sandbox::TIER1_REQUIRED;

const MAX_WORKER_OUTPUT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFile {
    pub path: PathBuf,
    pub display: String,
    pub sha256: String,
}

/// Written to the workspace by the parent; read by the worker before confinement.
#[derive(Debug, Serialize, Deserialize)]
pub struct Batch {
    pub files: Vec<BatchFile>,
    pub user_rules: Vec<RuleSource>,
    /// Deep mode: hand back nested executables within these limits.
    pub export: Option<ExportLimits>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileResult {
    pub display: String,
    pub analysis: ArtifactAnalysis,
    #[serde(default)]
    pub exported: Vec<Exported>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerReply {
    pub active: Vec<String>,
    pub missing: Vec<String>,
    /// None when the worker refused to analyze because isolation was reduced.
    pub results: Option<Vec<FileResult>>,
    pub rule_errors: Vec<String>,
    pub rule_sources: Vec<String>,
    /// Probe mode only: results of attempted escapes, all of which should fail.
    pub probe: Option<Vec<(String, bool)>>,
}

pub enum WorkerResult {
    Done(Box<WorkerReply>),
    TimedOut,
    Cancelled,
    Crashed(String),
}

pub struct WorkerRequest<'a> {
    /// Path of the serialized [`Batch`]; ignored for probes.
    pub batch: &'a Path,
    pub allow_reduced: bool,
    pub probe: bool,
    pub timeout: Duration,
}

/// Only the paths of a [`Batch`], for granting the worker access to them.
#[derive(Deserialize)]
struct BatchPaths {
    files: Vec<BatchPath>,
}

#[derive(Deserialize)]
struct BatchPath {
    path: PathBuf,
}

/// Removes the escape-probe directory when dropped.
struct ProbeDir(PathBuf);

impl Drop for ProbeDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Parent side: spawn the worker and collect its reply.
pub fn run_worker(req: &WorkerRequest, cancel: &Arc<AtomicBool>) -> Result<WorkerResult> {
    let exe = std::env::current_exe().context("locating own executable")?;
    let mut profile = bytebouncer_sandbox::Profile::tier1(req.probe);
    // Probes target a fresh user-owned directory holding a secret file;
    // the worker gets no access to it.
    let probe_dir = if req.probe {
        let dir = std::env::temp_dir().join(format!("bytebouncer-probe-{}", std::process::id()));
        bytebouncer_sandbox::prepare_probe_dir(&dir).context("creating probe directory")?;
        Some(ProbeDir(dir))
    } else {
        // Where confinement starts at process creation (Windows), the
        // worker must be granted read access to its batch and inputs.
        if cfg!(windows) {
            let paths: BatchPaths =
                serde_json::from_slice(&std::fs::read(req.batch).context("reading batch")?)?;
            profile.read_only.push(req.batch.to_path_buf());
            profile
                .read_only
                .extend(paths.files.into_iter().map(|f| f.path));
        }
        None
    };
    let batch_arg = probe_dir.as_ref().map_or(req.batch, |d| d.0.as_path());
    let args = [
        OsStr::new(WORKER_SUBCOMMAND),
        batch_arg.as_os_str(),
        OsStr::new(if req.allow_reduced {
            "reduced-ok"
        } else {
            "strict"
        }),
        OsStr::new(if req.probe { "probe" } else { "analyze" }),
    ];
    let mut child = bytebouncer_sandbox::spawn_worker("tier1", &profile, &exe, &args)
        .context("spawning Tier 1 worker")?;
    drop(child.stdin.take());

    let stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout
            .take(MAX_WORKER_OUTPUT)
            .read_to_end(&mut buf)
            .map(|_| buf)
    });
    let stderr = child.stderr.take().expect("piped stderr");
    let err_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.take(64 * 1024).read_to_string(&mut buf);
        buf
    });

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if cancel.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(WorkerResult::Cancelled);
        }
        if start.elapsed() > req.timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(WorkerResult::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let trace = std::env::var_os("BYTEBOUNCER_SANDBOX_TRACE").is_some();
    if trace {
        eprintln!("bytebouncer: worker exited ({status}), reading its output");
    }
    let out = reader
        .join()
        .expect("reader thread")
        .context("reading worker output")?;
    let err = err_reader.join().unwrap_or_default();
    if trace {
        eprintln!("bytebouncer: worker output read ({} bytes)", out.len());
    }
    if !status.success() {
        return Ok(WorkerResult::Crashed(format!(
            "worker exited with {status}: {}",
            err.trim()
        )));
    }
    match serde_json::from_slice(&out) {
        Ok(reply) => Ok(WorkerResult::Done(Box::new(reply))),
        Err(e) => Ok(WorkerResult::Crashed(format!(
            "malformed worker output: {e}"
        ))),
    }
}

/// Worker side. Never returns.
pub fn worker_main(args: &[String]) -> ! {
    let code = match worker_inner(args) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e:#}");
            1
        }
    };
    std::process::exit(code)
}

fn worker_inner(args: &[String]) -> Result<()> {
    let [batch_path, isolation_mode, action] = args else {
        bail!("worker: bad arguments");
    };
    let allow_reduced = isolation_mode == "reduced-ok";
    let probe = action == "probe";

    // Read everything we need before confinement removes filesystem access.
    let (batch, inputs) = if probe {
        (
            Batch {
                files: vec![],
                user_rules: vec![],
                export: None,
            },
            vec![],
        )
    } else {
        let batch: Batch =
            serde_json::from_slice(&std::fs::read(batch_path).context("reading batch")?)?;
        let inputs = batch
            .files
            .iter()
            .map(|f| std::fs::read(&f.path).with_context(|| format!("reading {}", f.display)))
            .collect::<Result<Vec<_>>>()?;
        (batch, inputs)
    };
    // Rule compilation is pure computation, but do it before confinement so
    // the JIT's memory setup happens outside the allow-list.
    let (rules, rule_errors) = if probe {
        (None, vec![])
    } else {
        let (r, e) = yara::compile(&batch.user_rules);
        (Some(r), e)
    };

    let (active, missing) = confine(probe);
    let mut reply = WorkerReply {
        active,
        missing,
        results: None,
        rule_sources: rules
            .as_ref()
            .map(|r| r.sources.clone())
            .unwrap_or_default(),
        rule_errors,
        probe: None,
    };
    if probe {
        reply.probe = Some(bytebouncer_sandbox::escape_probes(Path::new(batch_path)));
    } else if reply.missing.is_empty() || allow_reduced {
        reply.results = Some(
            batch
                .files
                .iter()
                .zip(&inputs)
                .map(|(f, bytes)| {
                    let (analysis, exported) =
                        bytebouncer_analysis::container::analyze_tree_exporting(
                            bytes,
                            &f.display,
                            &f.sha256,
                            rules.as_ref(),
                            batch.export,
                        );
                    FileResult {
                        display: f.display.clone(),
                        analysis,
                        exported,
                    }
                })
                .collect(),
        );
    }

    let json = serde_json::to_vec(&reply)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&json)?;
    stdout.flush()?;
    Ok(())
}

fn confine(probe: bool) -> (Vec<String>, Vec<String>) {
    let applied = bytebouncer_sandbox::confine_self(&bytebouncer_sandbox::Profile::tier1(probe));
    let missing = REQUIRED
        .iter()
        .filter(|r| !applied.active.iter().any(|a| a == *r))
        .map(|r| r.to_string())
        .collect();
    (applied.active, missing)
}

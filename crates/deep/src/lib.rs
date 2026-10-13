//! Deep mode (SPEC §6.1–6.2): runs analysis tools the user has already
//! installed (capa, ClamAV, Ghidra) inside the kernel sandbox from
//! `bytebouncer-sandbox` and turns their output into evidence-linked findings.
//!
//! Zero setup: nothing is installed, downloaded, or updated. Missing tools
//! are skipped and reported in coverage. Every tool runs with no network,
//! read-only access to the input (and, for ClamAV, its database), and write
//! access only to its own scratch directory. A tool failure, timeout, or
//! cancellation becomes a coverage limitation — never a clean result.

#![forbid(unsafe_code)]

pub mod capa;
pub mod clamav;
pub mod discover;
pub mod ghidra;
pub mod mcp;
pub mod out;
pub mod rea;
pub mod remote_scan;
pub mod retained;
mod runner;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytebouncer_core::{AnalysisOutput, ToolVersion};
use bytebouncer_sandbox::{Applied, Profile};

pub use discover::{ClamDb, DiscoveredTools, GhidraInstall, ToolInstall, discover};
pub use retained::RetainedData;

use out::Builder;
use runner::{RunOutput, RunSpec, Status};

pub const DEEP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Captured stdout bound (capa JSON for large binaries runs to megabytes).
const STDOUT_CAP: usize = 64 << 20;
const STDERR_CAP: usize = 256 << 10;
/// Largest Ghidra export accepted.
const GHIDRA_EXPORT_CAP: u64 = 64 << 20;

#[derive(Debug, Clone)]
pub struct DeepConfig {
    /// Explicit tool locations; `None` means discover.
    pub capa: Option<PathBuf>,
    pub clamscan: Option<PathBuf>,
    pub clamav_db: Option<PathBuf>,
    /// Ghidra installation directory (contains `support/analyzeHeadless`).
    pub ghidra_dir: Option<PathBuf>,
    /// JDK for Ghidra; `None` means discover (JAVA_HOME, Ghidra's saved choice, PATH).
    pub java_home: Option<PathBuf>,
    /// Run tools even if some sandbox restrictions are unavailable.
    pub allow_reduced_isolation: bool,
    pub timeout_per_tool: Duration,
    /// Most relevant functions Ghidra decompiles.
    pub ghidra_max_functions: usize,
}

impl Default for DeepConfig {
    fn default() -> Self {
        Self {
            capa: None,
            clamscan: None,
            clamav_db: None,
            ghidra_dir: None,
            java_home: None,
            allow_reduced_isolation: false,
            timeout_per_tool: Duration::from_secs(600),
            ghidra_max_functions: 20,
        }
    }
}

pub struct DeepInput<'a> {
    /// Snapshot of the artifact inside the scan workspace.
    pub path: &'a Path,
    pub display_path: &'a str,
    pub sha256: &'a str,
    /// Tier 1 format label: `elf-64`, `pe-32`, `mach-o`, `unknown`, …
    pub format: &'a str,
}

#[derive(Debug, Clone, Default)]
pub struct DeepResult {
    pub output: AnalysisOutput,
    pub tools: Vec<ToolVersion>,
    /// Restrictions in force for each tool run.
    pub isolation: Vec<(String, Applied)>,
    /// Wall-clock time of each tool run.
    pub timings: Vec<(String, Duration)>,
    pub retained: RetainedData,
}

fn is_executable_format(format: &str) -> bool {
    format.starts_with("elf") || format.starts_with("pe") || format.starts_with("mach")
}

/// Run every available deep-analysis tool on one artifact. `scratch` must
/// be an empty directory owned by this scan; the caller removes it.
pub fn run_deep(
    tools: &DiscoveredTools,
    input: &DeepInput<'_>,
    scratch: &Path,
    cfg: &DeepConfig,
    cancel: &AtomicBool,
) -> DeepResult {
    let mut b = Builder::new(input.sha256, input.display_path, input.format);
    let mut result = DeepResult::default();
    for note in &tools.notes {
        b.out.coverage.skipped.push(format!("deep: {note}"));
    }
    let input_size = std::fs::metadata(input.path).map(|m| m.len()).unwrap_or(0);
    let executable = is_executable_format(input.format);
    let mut ran_any = false;

    // ClamAV: any file type.
    match (&tools.clamscan, &tools.clamav_db) {
        (Some(clam), Some(db)) if !cancel.load(Ordering::Relaxed) => {
            ran_any = true;
            run_clamav(
                clam,
                db,
                input,
                &scratch.join("clamav"),
                cfg,
                cancel,
                &mut b,
                &mut result,
            );
        }
        _ => {}
    }

    // capa: PE and ELF (and shellcode, which deep mode does not guess).
    if let Some(capa) = &tools.capa {
        if input.format.starts_with("elf") || input.format.starts_with("pe") {
            if !cancel.load(Ordering::Relaxed) {
                ran_any = true;
                run_capa(
                    capa,
                    input,
                    &scratch.join("capa"),
                    cfg,
                    cancel,
                    &mut b,
                    &mut result,
                );
            }
        } else {
            b.out.coverage.unsupported.push(format!(
                "{}: capa does not support format '{}'",
                input.display_path, input.format
            ));
        }
    }

    // Ghidra: native executables.
    if let Some(g) = &tools.ghidra {
        if !executable {
            b.out.coverage.unsupported.push(format!(
                "{}: Ghidra analysis skipped for non-executable format '{}'",
                input.display_path, input.format
            ));
        } else if g.java_home.is_none() {
            // Already explained in tools.notes.
        } else if !cancel.load(Ordering::Relaxed) {
            ran_any = true;
            run_ghidra(
                g,
                input,
                input_size,
                &scratch.join("ghidra"),
                cfg,
                cancel,
                &mut b,
                &mut result,
            );
        }
    }

    if cancel.load(Ordering::Relaxed) {
        b.out
            .coverage
            .limitations
            .push("Deep analysis was cancelled; results are incomplete".into());
    }
    if !ran_any {
        b.out.coverage.limitations.push(
            "Deep mode: no installed analysis tool applied to this artifact; no deep analysis was performed".into(),
        );
    }
    result.output = b.out;
    result
}

/// Profile shared by all tools: the base external-tool profile plus a
/// scratch HOME/TMPDIR and the tool's own environment.
/// Removes a directory when dropped (Ghidra's private project location).
struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(d) = &self.0 {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn tool_profile(
    tool_dirs: Vec<PathBuf>,
    inputs: Vec<PathBuf>,
    scratch: &Path,
    extra_env: &[(OsString, OsString)],
) -> Profile {
    let mut p = Profile::external_tool(tool_dirs, inputs, scratch.to_path_buf());
    p.env.extend(discover::scratch_env(scratch));
    p.env.extend(extra_env.iter().cloned());
    p
}

/// Run a tool and translate sandbox/timeout/cancel problems into coverage.
/// Returns the output only when the tool ran to an exit code.
#[allow(clippy::too_many_arguments)]
fn execute(
    tool: &str,
    program: &Path,
    args: Vec<OsString>,
    profile: Profile,
    scratch: &Path,
    timeout: Duration,
    cfg: &DeepConfig,
    cancel: &AtomicBool,
    b: &mut Builder<'_>,
    result: &mut DeepResult,
) -> Option<RunOutput> {
    let spec = RunSpec {
        program,
        args,
        profile,
        cwd: Some(scratch.to_path_buf()),
        timeout,
        stdout_cap: STDOUT_CAP,
        stderr_cap: STDERR_CAP,
        allow_reduced: cfg.allow_reduced_isolation,
    };
    let out = match runner::run(spec, cancel) {
        Ok(o) => o,
        Err(e) => {
            b.out
                .coverage
                .limitations
                .push(format!("{tool} did not run: {e}"));
            return None;
        }
    };
    result
        .isolation
        .push((tool.to_owned(), out.applied.clone()));
    result.timings.push((tool.to_owned(), out.elapsed));
    if !out.applied.missing.is_empty() {
        b.out.coverage.limitations.push(format!(
            "{tool} ran with reduced isolation (missing: {})",
            out.applied.missing.join(", ")
        ));
    }
    match out.status {
        Status::TimedOut => {
            b.out.coverage.limitations.push(format!(
                "{tool} timed out after {}s and was stopped; its results are missing",
                timeout.as_secs()
            ));
            None
        }
        Status::Cancelled => {
            b.out
                .coverage
                .limitations
                .push(format!("{tool} was cancelled; its results are missing"));
            None
        }
        Status::Signaled => {
            b.out.coverage.limitations.push(format!(
                "{tool} was terminated by a signal (crash or resource limit): {}",
                out.stderr_tail()
            ));
            None
        }
        Status::Exited(_) => Some(out),
    }
}

fn prepare_scratch(dir: &Path, tool: &str, b: &mut Builder<'_>) -> bool {
    match std::fs::create_dir_all(dir) {
        Ok(()) => true,
        Err(e) => {
            b.out
                .coverage
                .limitations
                .push(format!("{tool}: could not create scratch directory: {e}"));
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_clamav(
    clam: &ToolInstall,
    db: &ClamDb,
    input: &DeepInput<'_>,
    scratch: &Path,
    cfg: &DeepConfig,
    cancel: &AtomicBool,
    b: &mut Builder<'_>,
    result: &mut DeepResult,
) {
    if !prepare_scratch(scratch, "ClamAV", b) {
        return;
    }
    let engine = clam.version.clone().unwrap_or_else(|| "unknown".into());
    result.tools.push(ToolVersion {
        name: "clamav".into(),
        version: engine.clone(),
        digest: None,
    });
    result.tools.push(ToolVersion {
        name: "clamav-db".into(),
        version: db.version.clone(),
        digest: None,
    });
    let profile = tool_profile(
        clam.grant_dirs.clone(),
        vec![input.path.to_path_buf(), db.dir.clone()],
        scratch,
        &clam.env,
    );
    let args: Vec<OsString> = vec![
        "--no-summary".into(),
        "--stdout".into(),
        "--allmatch=yes".into(),
        "--database".into(),
        db.dir.clone().into_os_string(),
        format!("--tempdir={}", scratch.join("tmp").display()).into(),
        "--".into(),
        input.path.as_os_str().to_owned(),
    ];
    let Some(out) = execute(
        "ClamAV",
        &clam.path,
        args,
        profile,
        scratch,
        cfg.timeout_per_tool,
        cfg,
        cancel,
        b,
        result,
    ) else {
        return;
    };
    let Status::Exited(code) = out.status else {
        return;
    };
    let mut parsed = clamav::parse(&out.stdout_text());
    if code == 2 && parsed.errors.is_empty() {
        parsed.errors.push(out.stderr_tail());
    }
    clamav::map(&parsed, code, &engine, &db.version, b);
}

#[allow(clippy::too_many_arguments)]
fn run_capa(
    capa: &ToolInstall,
    input: &DeepInput<'_>,
    scratch: &Path,
    cfg: &DeepConfig,
    cancel: &AtomicBool,
    b: &mut Builder<'_>,
    result: &mut DeepResult,
) {
    if !prepare_scratch(scratch, "capa", b) {
        return;
    }
    let mut env = capa.env.clone();
    // Wide virtual terminal so rich-formatted log lines do not wrap.
    env.push(("COLUMNS".into(), "400".into()));
    let profile = tool_profile(
        capa.grant_dirs.clone(),
        vec![input.path.to_path_buf()],
        scratch,
        &env,
    );
    let args: Vec<OsString> = vec!["-j".into(), "--".into(), input.path.as_os_str().to_owned()];
    let Some(out) = execute(
        "capa",
        &capa.path,
        args,
        profile,
        scratch,
        cfg.timeout_per_tool,
        cfg,
        cancel,
        b,
        result,
    ) else {
        result.tools.push(capa_tool_version(capa, None));
        return;
    };
    if out.status != Status::Exited(0) {
        result.tools.push(capa_tool_version(capa, None));
        let Status::Exited(code) = out.status else {
            return;
        };
        b.out
            .coverage
            .limitations
            .push(format!("capa failed (exit {code}): {}", capa_error(&out)));
        return;
    }
    if out.stdout_truncated {
        result.tools.push(capa_tool_version(capa, None));
        b.out.coverage.limitations.push(format!(
            "capa output exceeded {} MiB and was not processed",
            STDOUT_CAP >> 20
        ));
        return;
    }
    match capa::parse(&out.stdout_text()) {
        Ok(report) => {
            result.tools.push(capa_tool_version(capa, Some(&report)));
            capa::map(&report, b);
            result.retained.capa_rules = report.rules;
        }
        Err(e) => {
            result.tools.push(capa_tool_version(capa, None));
            b.out.coverage.limitations.push(format!("capa: {e}"));
        }
    }
}

fn capa_tool_version(capa: &ToolInstall, report: Option<&capa::CapaReport>) -> ToolVersion {
    let version = report
        .map(|r| r.version.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| capa.version.clone())
        .unwrap_or_else(|| "unknown".into());
    let rules = report.map_or("unknown", |r| r.rules_source.as_str());
    ToolVersion {
        name: "capa".into(),
        version: format!(
            "{version} (rules: {})",
            if rules == "embedded" {
                format!("embedded, bundled with capa {version}")
            } else {
                rules.to_owned()
            }
        ),
        digest: None,
    }
}

/// capa logs errors as rich-formatted `ERROR capa: …` lines on stderr,
/// with `file.py:NNN` source tags and wrapped continuation lines.
fn capa_error(out: &RunOutput) -> String {
    parse_capa_error(&out.stderr_text()).unwrap_or_else(|| out.stderr_tail())
}

fn parse_capa_error(stderr: &str) -> Option<String> {
    let mut words = Vec::new();
    let mut in_error = false;
    for line in stderr.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("ERROR") {
            in_error = true;
            words.extend(rest.split_whitespace().map(str::to_owned));
        } else if in_error && !t.is_empty() && !t.starts_with('-') && line.starts_with(' ') {
            words.extend(t.split_whitespace().map(str::to_owned));
        } else if in_error && t.starts_with('-') && words.len() > 3 {
            break;
        }
    }
    let is_tag = |w: &str| {
        w == "capa:"
            || w.starts_with('-')
            || w.split_once(".py:")
                .is_some_and(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
    };
    let text = words
        .iter()
        .filter(|w| !is_tag(w))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    // First sentence is the actual error; the rest is boilerplate advice.
    let first = text.split_inclusive(". ").next().unwrap_or(&text).trim();
    (!first.is_empty()).then(|| runner::bounded(first, 200))
}

#[allow(clippy::too_many_arguments)]
fn run_ghidra(
    g: &GhidraInstall,
    input: &DeepInput<'_>,
    input_size: u64,
    scratch: &Path,
    cfg: &DeepConfig,
    cancel: &AtomicBool,
    b: &mut Builder<'_>,
    result: &mut DeepResult,
) {
    let version = g.version.clone().unwrap_or_else(|| "unknown".into());
    result.tools.push(ToolVersion {
        name: "ghidra".into(),
        version: version.clone(),
        digest: None,
    });
    result.tools.push(ToolVersion {
        name: "bytebouncer-ghidra-export".into(),
        version: format!("{DEEP_VERSION} ({})", ghidra::EXPORT_SCHEMA),
        digest: None,
    });
    let Some(java_home) = &g.java_home else {
        return;
    };
    // analyzeHeadless splits JVM options on spaces.
    if scratch.to_string_lossy().contains(char::is_whitespace) {
        b.out
            .coverage
            .limitations
            .push("Ghidra skipped: scratch path contains whitespace".into());
        return;
    }
    let scripts = scratch.join("scripts");
    // Ghidra rejects project paths with a component starting with '.', which
    // excludes the usual cache location (~/.cache/...). In that case the
    // project lives in a fresh owner-only directory under the system temp dir.
    let dotted = |p: &Path| {
        p.components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
    };
    let private_project = if dotted(scratch) {
        let dir = std::env::temp_dir().join(format!(
            "bytebouncer-ghidra-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        if dotted(&dir) || builder.create(&dir).is_err() {
            b.out.coverage.limitations.push(
                "Ghidra skipped: no project location without a '.'-prefixed path component".into(),
            );
            return;
        }
        Some(dir)
    } else {
        None
    };
    let project = private_project
        .clone()
        .unwrap_or_else(|| scratch.join("project"));
    let _cleanup = RemoveOnDrop(private_project.clone());
    let out_json = scratch.join("export.json");
    let tmp = scratch.join("tmp");
    for d in [&scripts, &project] {
        if !prepare_scratch(d, "Ghidra", b) {
            return;
        }
    }
    if let Err(e) = std::fs::write(
        scripts.join(ghidra::EXPORT_SCRIPT_NAME),
        ghidra::EXPORT_SCRIPT,
    ) {
        b.out
            .coverage
            .limitations
            .push(format!("Ghidra: could not write export script: {e}"));
        return;
    }
    let total = cfg.timeout_per_tool.as_secs().max(5);
    // Leave room for JVM start-up, the export, and decompilation.
    let analysis_secs = (total * 6 / 10).max(3);
    let decompile_secs = (total / 10 / (cfg.ghidra_max_functions.max(1) as u64)).clamp(5, 60);
    let max_chars = 6000.min(ghidra::MAX_DECOMPILED_CHARS);
    let mut env: Vec<(OsString, OsString)> = vec![
        ("JAVA_HOME".into(), java_home.clone().into_os_string()),
        (
            "GHIDRA_HEADLESS_JAVA_OPTIONS".into(),
            format!(
                "-Djava.io.tmpdir={} -Duser.home={} -XX:-UsePerfData",
                tmp.display(),
                scratch.join("home").display()
            )
            .into(),
        ),
    ];
    // Prefer the selected JDK over any other java on PATH.
    env.push((
        "PATH".into(),
        format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            java_home.join("bin").display()
        )
        .into(),
    ));
    let mut profile = tool_profile(
        vec![g.dir.clone(), java_home.clone()],
        vec![input.path.to_path_buf()],
        scratch,
        &env,
    );
    if let Some(dir) = &private_project {
        profile.read_write.push(dir.clone());
    }
    // RLIMIT_CPU counts all JVM threads; wall-clock timeout is the real bound.
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get() as u64);
    profile.limits.cpu_seconds = Some(total.saturating_mul(cpus).max(1800));
    profile.limits.address_space = None;
    // Later PATH entries win in Command::envs; drop the default.
    dedup_env(&mut profile.env);

    let args: Vec<OsString> = vec![
        project.clone().into_os_string(),
        "bytebouncer".into(),
        "-import".into(),
        input.path.as_os_str().to_owned(),
        "-scriptPath".into(),
        scripts.into_os_string(),
        "-postScript".into(),
        ghidra::EXPORT_SCRIPT_NAME.into(),
        out_json.clone().into_os_string(),
        cfg.ghidra_max_functions.to_string().into(),
        max_chars.to_string().into(),
        decompile_secs.to_string().into(),
        "-deleteProject".into(),
        "-analysisTimeoutPerFile".into(),
        analysis_secs.to_string().into(),
    ];
    let Some(out) = execute(
        "Ghidra",
        &g.headless(),
        args,
        profile,
        scratch,
        Duration::from_secs(total),
        cfg,
        cancel,
        b,
        result,
    ) else {
        return;
    };
    // analyzeHeadless exits 0 even when the post-script fails, so the export
    // file is the success signal.
    let export = match std::fs::metadata(&out_json) {
        Ok(m) if m.len() > GHIDRA_EXPORT_CAP => {
            b.out.coverage.limitations.push(format!(
                "Ghidra export exceeded {} MiB and was not processed",
                GHIDRA_EXPORT_CAP >> 20
            ));
            return;
        }
        Ok(_) => std::fs::read_to_string(&out_json),
        Err(e) => Err(e),
    };
    let text = match export {
        Ok(t) => t,
        Err(_) => {
            let Status::Exited(code) = out.status else {
                return;
            };
            b.out.coverage.limitations.push(format!(
                "Ghidra produced no export (exit {code}): {}",
                ghidra_error(&out)
            ));
            return;
        }
    };
    match ghidra::parse(&text) {
        Ok(e) => {
            ghidra::map(&e, &version, cfg.ghidra_max_functions, input_size, b);
            result.retained.absorb_ghidra(e);
        }
        Err(e) => b.out.coverage.limitations.push(format!("Ghidra: {e}")),
    }
}

/// Keep only the last value for each environment variable.
fn dedup_env(env: &mut Vec<(OsString, OsString)>) {
    let mut seen = std::collections::HashSet::new();
    let mut kept: Vec<(OsString, OsString)> = env
        .drain(..)
        .rev()
        .filter(|(k, _)| seen.insert(k.clone()))
        .collect();
    kept.reverse();
    *env = kept;
}

/// The first meaningful Ghidra error line (script compile errors, import failures).
fn ghidra_error(out: &RunOutput) -> String {
    let text = format!("{}\n{}", out.stdout_text(), out.stderr_text());
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| {
            l.starts_with("ERROR")
                || l.contains("REPORT SCRIPT ERROR")
                || l.starts_with("Exception")
        })
        .map(str::to_owned)
        .unwrap_or_else(|| out.stderr_tail());
    runner::bounded(&line, 300)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capa_error_is_readable() {
        let stderr = "WARNING  capa: something\nERROR    capa:  Input file does not appear to be a supported      helpers.py:275\n         file.                                                                  \nERROR    capa:                                                    helpers.py:276\nERROR    capa:  See all supported file formats via capa's help    helpers.py:277\n         --------------------------------------------------------\n";
        assert_eq!(
            parse_capa_error(stderr).as_deref(),
            Some("Input file does not appear to be a supported file.")
        );
        assert_eq!(parse_capa_error("nothing here"), None);
    }

    #[test]
    fn env_dedup_keeps_last() {
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), "a".into()),
            ("HOME".into(), "h".into()),
            ("PATH".into(), "b".into()),
        ];
        dedup_env(&mut env);
        assert_eq!(
            env,
            vec![("HOME".into(), "h".into()), ("PATH".into(), "b".into())]
        );
    }

    #[test]
    fn no_tools_is_an_explicit_limitation() {
        let tools = DiscoveredTools {
            notes: vec!["capa: not installed".into()],
            ..Default::default()
        };
        let dir = std::env::temp_dir().join(format!("bb-deep-none-{}", std::process::id()));
        let input = DeepInput {
            path: Path::new("/bin/sh"),
            display_path: "sh",
            sha256: "abc",
            format: "elf-64",
        };
        let r = run_deep(
            &tools,
            &input,
            &dir,
            &DeepConfig::default(),
            &AtomicBool::new(false),
        );
        assert!(r.output.findings.is_empty());
        assert!(
            r.output
                .coverage
                .skipped
                .iter()
                .any(|s| s.contains("capa: not installed"))
        );
        assert!(
            r.output
                .coverage
                .limitations
                .iter()
                .any(|l| l.contains("no deep analysis was performed"))
        );
    }

    #[test]
    fn missing_tool_binary_is_a_limitation_not_a_panic() {
        let tools = DiscoveredTools {
            capa: Some(ToolInstall {
                path: "/nonexistent/capa".into(),
                version: None,
                grant_dirs: vec![],
                env: vec![],
            }),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join(format!("bb-deep-missing-{}", std::process::id()));
        let input = DeepInput {
            path: Path::new("/bin/sh"),
            display_path: "sh",
            sha256: "abc",
            format: "elf-64",
        };
        let cfg = DeepConfig {
            allow_reduced_isolation: true,
            ..Default::default()
        };
        let r = run_deep(&tools, &input, &dir, &cfg, &AtomicBool::new(false));
        assert!(r.output.findings.is_empty());
        assert!(
            r.output
                .coverage
                .limitations
                .iter()
                .any(|l| l.contains("capa did not run")),
            "{:?}",
            r.output.coverage
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

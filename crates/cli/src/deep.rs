//! Deep mode glue (SPEC §6.2, §9.2 Tier 2): run whichever of capa, ClamAV,
//! and Ghidra are installed, each confined by the Tier 2 sandbox, on the
//! input's executables. Missing tools are reported, never installed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use bytebouncer_analysis::code::CodeMap;
use bytebouncer_analysis::container::Exported;
use bytebouncer_core::{ArtifactRecord, Merger, ToolVersion};
use bytebouncer_deep::rea::{ReaConfig, ReaSession};
use bytebouncer_deep::{DeepConfig, DeepInput, DiscoveredTools, RetainedData};
use bytebouncer_models::{EvidenceSource, ToolSpec};
use serde_json::{Value, json};

use crate::acquire::Snapshot;
use crate::config::Config;
use crate::inspect::ScanContext;

/// Bounded deep-analysis data for one artifact, used by model tools.
pub struct Retained {
    pub artifact: String,
    pub data: RetainedData,
    /// Live REA session (closed when the scan ends).
    pub rea: Option<ReaSession>,
    _scratch: Option<PrivateDir>,
}

/// An owner-only directory under the system temp dir, removed on drop. REA's
/// Ghidra rejects project paths containing '.'-prefixed folders (~/.cache).
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new(tag: &str) -> Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "bytebouncer-{tag}-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&p)?;
        Ok(Self(p))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// How REA will be reached for this scan.
struct ReaPlan {
    program: PathBuf,
    args: Vec<String>,
    sandbox: bool,
    grant_dirs: Vec<PathBuf>,
    staging_dir: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
    open_timeout: Duration,
    max_artifacts: usize,
    label: String,
}

fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        return Some(crate::config::expand_home(Path::new(name)));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn rea_plan(config: &Config, found: &DiscoveredTools) -> Option<ReaPlan> {
    let ghidra = found.ghidra.as_ref();
    let mut ghidra_env: Vec<(OsString, OsString)> = Vec::new();
    let mut grant: Vec<PathBuf> = Vec::new();
    if let Some(g) = ghidra {
        ghidra_env.push(("GHIDRA_INSTALL_DIR".into(), g.dir.clone().into_os_string()));
        grant.push(g.dir.clone());
        if let Some(j) = &g.java_home {
            ghidra_env.push(("JAVA_HOME".into(), j.clone().into_os_string()));
            ghidra_env.push((
                "PATH".into(),
                format!("{}:/usr/local/bin:/usr/bin:/bin", j.join("bin").display()).into(),
            ));
            grant.push(j.clone());
        }
    }
    if let Some(node) = which("node").and_then(|p| p.parent().map(Path::to_path_buf)) {
        grant.push(node);
    }
    match &config.deep.rea {
        Some(c) => {
            let program = which(c.command.first()?)?;
            let sandbox = c.sandbox.unwrap_or(true);
            let mut env: Vec<(OsString, OsString)> = if sandbox { ghidra_env } else { vec![] };
            env.extend(c.env.iter().map(|(k, v)| (k.into(), v.into())));
            if let Some(parent) = program.parent().and_then(Path::parent) {
                grant.push(parent.to_path_buf());
            }
            Some(ReaPlan {
                label: if sandbox {
                    "REA in the Tier 2 sandbox".into()
                } else {
                    format!(
                        "{} (isolation provided by that command, not by ByteBouncer)",
                        program.display()
                    )
                },
                program,
                args: c.command[1..].to_vec(),
                sandbox,
                grant_dirs: grant,
                staging_dir: c.staging_dir.as_deref().map(crate::config::expand_home),
                env,
                open_timeout: Duration::from_secs(c.open_timeout_secs.unwrap_or(900)),
                max_artifacts: c.max_artifacts.unwrap_or(2),
            })
        }
        None => {
            let (bin, dir) = crate::setup::installed().rea?;
            ghidra?;
            grant.push(dir);
            Some(ReaPlan {
                program: bin,
                args: vec!["mcp".into()],
                sandbox: true,
                grant_dirs: grant,
                staging_dir: None,
                env: ghidra_env,
                open_timeout: Duration::from_secs(900),
                max_artifacts: 2,
                label: "REA in the Tier 2 sandbox".into(),
            })
        }
    }
}

fn deep_config(config: &Config, allow_reduced: bool) -> DeepConfig {
    let d = &config.deep;
    let mut cfg = DeepConfig {
        capa: d.capa.clone(),
        clamscan: d.clamscan.clone(),
        clamav_db: d.clamav_db.clone(),
        ghidra_dir: d.ghidra_dir.clone(),
        java_home: d.java_home.clone(),
        allow_reduced_isolation: allow_reduced,
        ..DeepConfig::default()
    };
    // Tools installed with `bytebouncer setup` fill in anything not configured.
    let installed = crate::setup::installed();
    cfg.ghidra_dir = cfg.ghidra_dir.or(installed.ghidra_dir);
    cfg.java_home = cfg.java_home.or(installed.java_home);
    cfg.capa = cfg.capa.or(installed.capa);
    if let Some(t) = d.timeout_per_tool_secs {
        cfg.timeout_per_tool = Duration::from_secs(t);
    }
    if let Some(n) = d.ghidra_max_functions {
        cfg.ghidra_max_functions = n;
    }
    cfg
}

/// Largest file handed to Ghidra/REA/capa.
const DEEP_MAX_BYTES: u64 = 400 << 20;

fn is_executable(format: &str) -> bool {
    ["elf", "pe", "mach"].iter().any(|p| format.starts_with(p))
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    ctx: &ScanContext,
    ws: &Path,
    files: &[Snapshot],
    exported: &[Exported],
    artifacts: &[ArtifactRecord],
    merger: &mut Merger,
    tools: &mut Vec<ToolVersion>,
    incomplete: &mut Vec<String>,
    retained: &mut Vec<Retained>,
) -> Result<()> {
    let cfg = deep_config(ctx.config, ctx.args.allow_reduced_isolation);
    let mut found = bytebouncer_deep::discover(&cfg);
    let rea = rea_plan(ctx.config, &found);
    if rea.is_some() {
        // REA drives Ghidra itself; don't analyze the same file twice.
        found.ghidra = None;
        found.notes.retain(|n| !n.starts_with("Ghidra"));
    }
    let mut rea_opened = 0;
    let mut remote = None;
    if let Some(sc) = &ctx.config.deep.scan {
        match start_remote_scan(sc) {
            Ok(r) => {
                // The remote server replaces local capa/ClamAV.
                found.capa = None;
                found.clamscan = None;
                found
                    .notes
                    .retain(|n| !n.starts_with("capa") && !n.starts_with("ClamAV"));
                remote = Some(r);
            }
            Err(e) => merger
                .coverage
                .limitations
                .push(format!("Remote capa/ClamAV unavailable: {e}")),
        }
    }
    if rea.is_none()
        && remote.is_none()
        && found.capa.is_none()
        && found.clamscan.is_none()
        && found.ghidra.is_none()
    {
        merger.coverage.limitations.push(
            "Deep mode: no capa, ClamAV, or Ghidra installation found, so no deep analysis was performed (see `bytebouncer doctor`)".into(),
        );
        return Ok(());
    }

    // Candidates: top-level executables, then nested ones exported by Tier 1.
    let dir = ws.join("deep");
    std::fs::create_dir_all(&dir)?;
    let mut candidates: Vec<(PathBuf, String, String, String)> = Vec::new();
    for f in files {
        if let Some(a) = artifacts.iter().find(|a| a.path == f.display)
            && (is_executable(&a.format)
                || found.clamscan.is_some()
                || remote.as_ref().is_some_and(|r| r.has_clamav))
        {
            candidates.push((
                f.path.clone(),
                f.display.clone(),
                f.sha256.clone(),
                a.format.clone(),
            ));
        }
    }
    for (i, e) in exported.iter().enumerate() {
        let path = dir.join(format!("nested-{i}"));
        std::fs::write(&path, &e.data)?;
        candidates.push((path, e.path.clone(), e.sha256.clone(), e.format.clone()));
    }
    // Decompiling enormous binaries would consume the whole budget without
    // finishing; say so instead (the code map and AI still cover them).
    candidates.retain(|(path, display, _, _)| {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size > DEEP_MAX_BYTES {
            merger.coverage.limitations.push(format!(
                "{display}: {} MB is too large for deep decompilation; covered by quick-mode analysis and the code map only",
                size >> 20
            ));
            false
        } else {
            true
        }
    });
    let max = ctx.args.deep_max_artifacts;
    if candidates.len() > max {
        incomplete.push(format!(
            "Deep mode analyzed {max} of {} candidate artifacts (raise --deep-max-artifacts to cover more)",
            candidates.len()
        ));
        candidates.truncate(max);
    }

    for (i, (path, display, sha256, format)) in candidates.iter().enumerate() {
        if ctx.cancel.load(Ordering::SeqCst) {
            return Ok(());
        }
        ctx.progress.phase(&format!(
            "deep analysis {}/{}: {display}",
            i + 1,
            candidates.len()
        ));
        let scratch = dir.join(format!("scratch-{i}"));
        std::fs::create_dir_all(&scratch)?;
        let input = DeepInput {
            path,
            display_path: display,
            sha256,
            format,
        };
        let mut result = bytebouncer_deep::run_deep(&found, &input, &scratch, &cfg, &ctx.cancel);
        if let Some(r) = remote.as_mut() {
            ctx.progress
                .phase(&format!("  capa/ClamAV via {}", r.label));
            let mut b = bytebouncer_deep::out::Builder::new(sha256, display, format);
            r.scan(
                path,
                display,
                sha256,
                is_executable(format),
                &mut b,
                tools,
                &mut result.retained,
            );
            merger.add(b.out);
        }
        for (tool, applied) in &result.isolation {
            if applied.missing.is_empty() {
                merger.coverage.analyzed.push(format!(
                    "{display}: {tool} ran in the Tier 2 sandbox ({})",
                    applied.active.join(", ")
                ));
            } else {
                merger.coverage.limitations.push(format!(
                    "{display}: {tool} ran with REDUCED isolation (missing {})",
                    applied.missing.join(", ")
                ));
            }
        }
        for (tool, t) in &result.timings {
            ctx.progress
                .phase(&format!("  {tool}: {:.1}s", t.as_secs_f64()));
        }
        for t in result.tools {
            if !tools.iter().any(|x| x.name == t.name) {
                tools.push(t);
            }
        }
        // The local-tool runner doesn't know REA or a scan server will cover this file.
        let rea_will_run = rea
            .as_ref()
            .is_some_and(|p| is_executable(format) && rea_opened < p.max_artifacts);
        if rea_will_run || remote.is_some() {
            result
                .output
                .coverage
                .limitations
                .retain(|l| !l.starts_with("Deep mode: no installed analysis tool"));
        }
        merger.add(result.output);
        let mut session = None;
        let mut scratch_guard = None;
        if let Some(plan) = rea
            .as_ref()
            .filter(|p| is_executable(format) && rea_opened < p.max_artifacts)
        {
            rea_opened += 1;
            ctx.progress
                .phase(&format!("  REA: opening {display} via {}", plan.label));
            match open_rea(
                plan,
                path,
                display,
                sha256,
                format,
                ctx.args.allow_reduced_isolation,
            ) {
                Ok((s, out, applied, guard)) => {
                    match applied {
                        Some(a) if a.missing.is_empty() => merger.coverage.analyzed.push(format!(
                            "{display}: REA ran in the Tier 2 sandbox ({})",
                            a.active.join(", ")
                        )),
                        Some(a) => merger.coverage.limitations.push(format!(
                            "{display}: REA ran with REDUCED isolation (missing {})",
                            a.missing.join(", ")
                        )),
                        None => merger
                            .coverage
                            .analyzed
                            .push(format!("{display}: REA via {}", plan.label)),
                    }
                    if !tools.iter().any(|x| x.name == "rea") {
                        tools.push(ToolVersion {
                            name: "rea".into(),
                            version: s.version.clone(),
                            digest: None,
                        });
                    }
                    merger.add(out);
                    session = Some(s);
                    scratch_guard = guard;
                }
                Err(e) => merger
                    .coverage
                    .limitations
                    .push(format!("{display}: REA analysis failed: {e}")),
            }
        }
        retained.push(Retained {
            artifact: display.clone(),
            data: result.retained,
            rea: session,
            _scratch: scratch_guard,
        });
        let _ = std::fs::remove_dir_all(&scratch);
    }
    Ok(())
}

fn start_remote_scan(
    sc: &crate::config::ScanServerConfig,
) -> Result<bytebouncer_deep::remote_scan::RemoteScan> {
    let program = which(
        sc.command
            .first()
            .ok_or_else(|| anyhow::anyhow!("[deep.scan] command is empty"))?,
    )
    .ok_or_else(|| anyhow::anyhow!("[deep.scan] command not found"))?;
    bytebouncer_deep::remote_scan::RemoteScan::start(
        bytebouncer_deep::remote_scan::RemoteScanConfig {
            label: format!("{} (isolation provided by that command)", program.display()),
            program,
            args: sc.command[1..].to_vec(),
            env: sc.env.iter().map(|(k, v)| (k.into(), v.into())).collect(),
            staging_dir: sc.staging_dir.as_deref().map(crate::config::expand_home),
            timeout: Duration::from_secs(sc.timeout_secs.unwrap_or(900)),
        },
    )
    .map_err(anyhow::Error::msg)
}

type ReaOpened = (
    ReaSession,
    bytebouncer_core::AnalysisOutput,
    Option<bytebouncer_sandbox::Applied>,
    Option<PrivateDir>,
);

fn open_rea(
    plan: &ReaPlan,
    input: &Path,
    display: &str,
    sha256: &str,
    format: &str,
    allow_reduced: bool,
) -> Result<ReaOpened> {
    let mut env = plan.env.clone();
    let (sandbox, guard) = if plan.sandbox {
        let dir = PrivateDir::new("rea")?;
        let home = dir.0.clone();
        for var in [
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
        ] {
            env.push((var.into(), home.clone().into_os_string()));
        }
        env.push((
            "JAVA_TOOL_OPTIONS".into(),
            format!("-Djava.io.tmpdir={0} -Duser.home={0}", home.display()).into(),
        ));
        let mut profile = bytebouncer_sandbox::Profile::external_tool(
            plan.grant_dirs.clone(),
            vec![input.to_path_buf()],
            home,
        );
        profile.limits.address_space = None;
        profile.limits.cpu_seconds = Some(3600 * 8);
        (Some(profile), Some(dir))
    } else {
        (None, None)
    };
    let cfg = ReaConfig {
        program: plan.program.clone(),
        args: plan.args.clone(),
        env,
        sandbox,
        staging_dir: plan.staging_dir.clone(),
        open_timeout: plan.open_timeout,
        call_timeout: Duration::from_secs(300),
        allow_reduced,
        label: plan.label.clone(),
    };
    let mut b = bytebouncer_deep::out::Builder::new(sha256, display, format);
    let (session, applied) =
        ReaSession::open(cfg, input, display, sha256, &mut b).map_err(anyhow::Error::msg)?;
    Ok((session, b.out, applied, guard))
}

/// Read-only model tools over every artifact's retained deep data (Ghidra,
/// capa) and the built-in code maps. Deep tools accept an optional
/// `artifact` to narrow the query.
struct DeepTools<'a>(&'a [Retained], &'a [CodeMap]);

impl EvidenceSource for DeepTools<'_> {
    fn tools(&self) -> Vec<ToolSpec> {
        let mut specs: Vec<ToolSpec> = if self.1.is_empty() {
            vec![]
        } else {
            bytebouncer_analysis::code::tools::tool_specs()
                .into_iter()
                .map(|(name, description, parameters)| ToolSpec {
                    name: name.into(),
                    description: description.into(),
                    parameters,
                })
                .collect()
        };
        if self.0.is_empty() {
            return specs;
        }
        let rea_names: Vec<&str> = self
            .0
            .iter()
            .filter(|r| r.rea.is_some())
            .map(|r| r.artifact.as_str())
            .collect();
        if let Some(first) = self.0.iter().find_map(|r| r.rea.as_ref()) {
            specs.extend(
                first
                    .tool_specs()
                    .into_iter()
                    .map(|(name, description, mut schema)| {
                        if rea_names.len() > 1
                            && let Some(props) =
                                schema.get_mut("properties").and_then(Value::as_object_mut)
                        {
                            props.insert(
                                "artifact".into(),
                                json!({"type": "string", "enum": rea_names}),
                            );
                        }
                        ToolSpec {
                            name,
                            description,
                            parameters: schema,
                        }
                    }),
            );
        }
        let names: Vec<&str> = self.0.iter().map(|r| r.artifact.as_str()).collect();
        specs.extend(RetainedData::tool_specs()
            .into_iter()
            .map(|(name, description, mut schema)| {
                if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
                    props.insert("artifact".into(), json!({"type": "string", "enum": names}));
                }
                ToolSpec {
                    name: name.into(),
                    description: format!("{description} (deep-analysis data; optional `artifact` selects one input)"),
                    parameters: schema,
                }
            }));
        specs
    }

    fn call(&self, name: &str, args: &Value) -> Result<Value, String> {
        if name.starts_with("code_") {
            return bytebouncer_analysis::code::tools::call(self.1, name, args);
        }
        if name.starts_with("rea_") {
            let wanted = args.get("artifact").and_then(Value::as_str);
            let mut inner = args.clone();
            if let Some(o) = inner.as_object_mut() {
                o.remove("artifact");
            }
            let session = self
                .0
                .iter()
                .filter_map(|r| r.rea.as_ref())
                .find(|s| wanted.is_none_or(|w| w == s.artifact()))
                .ok_or("no REA session for that artifact")?;
            return session.model_call(name, &inner);
        }
        let wanted = args.get("artifact").and_then(Value::as_str);
        let mut inner = args.clone();
        if let Some(o) = inner.as_object_mut() {
            o.remove("artifact");
        }
        let mut results = Vec::new();
        for r in self
            .0
            .iter()
            .filter(|r| wanted.is_none_or(|w| w == r.artifact))
        {
            match r.data.call(name, &inner) {
                Ok(v) => results.push(json!({"artifact": r.artifact, "result": v})),
                Err(e) if wanted.is_some() => return Err(e),
                Err(_) => {}
            }
        }
        if results.is_empty() {
            return Err(format!("no deep-analysis data answered `{name}`"));
        }
        Ok(Value::Array(results))
    }

    fn drain_new_evidence(&self) -> Vec<bytebouncer_core::Evidence> {
        self.0
            .iter()
            .filter_map(|r| r.rea.as_ref())
            .flat_map(|s| s.drain_new_evidence())
            .collect()
    }
}

pub fn evidence_source<'a>(
    retained: &'a [Retained],
    code: &'a [CodeMap],
) -> Box<dyn EvidenceSource + 'a> {
    Box::new(DeepTools(retained, code))
}

pub fn doctor(config: &Config) {
    let found = bytebouncer_deep::discover(&deep_config(config, false));
    match rea_plan(config, &found) {
        Some(plan) => println!(
            "\nREA (Ghidra over MCP): {} {} — {}",
            plan.program.display(),
            plan.args.join(" "),
            plan.label
        ),
        None if crate::setup::installed().rea.is_some() => {
            println!(
                "\nREA: installed, but needs Ghidra (`bytebouncer setup ghidra` or [deep] ghidra_dir)"
            )
        }
        None => println!(
            "\nREA: not configured (`bytebouncer setup rea`, or [deep.rea] command for a VM connector)"
        ),
    }
    println!("\nDeep mode tools (optional; run in the Tier 2 sandbox):");
    let show = |name: &str, path: Option<String>, version: Option<String>| match path {
        Some(p) => println!(
            "  found   {name}: {p} ({})",
            version.unwrap_or_else(|| "version unknown".into())
        ),
        None => println!("  -       {name}: not installed"),
    };
    show(
        "capa",
        found.capa.as_ref().map(|t| t.path.display().to_string()),
        found.capa.as_ref().and_then(|t| t.version.clone()),
    );
    show(
        "clamscan",
        found
            .clamscan
            .as_ref()
            .map(|t| t.path.display().to_string()),
        found.clamscan.as_ref().and_then(|t| t.version.clone()),
    );
    show(
        "clamav db",
        found
            .clamav_db
            .as_ref()
            .map(|d| d.dir.display().to_string()),
        found.clamav_db.as_ref().map(|d| d.version.clone()),
    );
    show(
        "ghidra",
        found.ghidra.as_ref().map(|g| g.dir.display().to_string()),
        found.ghidra.as_ref().and_then(|g| g.version.clone()),
    );
    for note in &found.notes {
        println!("          {note}");
    }
}

//! The `inspect` pipeline: acquire → provenance → Tier 1 (cached, batched)
//! → optional lookups → optional deep mode → optional model synthesis →
//! policy → report.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytebouncer_analysis::ArtifactAnalysis;
use bytebouncer_analysis::container::{ExportLimits, Exported};
use bytebouncer_analysis::yara::RuleSource;
use bytebouncer_core::{
    AcquisitionManifest, ArtifactRecord, Budget, ExitCode, Isolation, IsolationTier, Merger,
    Report, ResultState, ScanMode, ToolVersion,
};

use crate::acquire::{self, Acquired, Snapshot, Target};
use crate::cache::Tier1Cache;
use crate::config::Config;
use crate::lookup::{self, Verdict};
use crate::provenance::{self, Checker};
use crate::sandbox::{self, Batch, BatchFile, WorkerRequest, WorkerResult};
use crate::{InspectArgs, OutputFormat, render, store};

/// Tier 1 batches: bounded so the worker's read-everything-first step stays small.
const BATCH_MAX_FILES: usize = 256;
const BATCH_MAX_BYTES: u64 = 512 << 20;
/// Bounds for nested files extracted to disk because they are too large to
/// expand in memory.
const SPILL_MAX_FILES: usize = 16;
const SPILL_MAX_FILE_BYTES: u64 = 4 << 30;
const SPILL_MAX_TOTAL_BYTES: u64 = 8 << 30;

pub struct Progress {
    quiet: bool,
    start: Instant,
}

impl Progress {
    pub fn new(quiet: bool) -> Self {
        Self {
            quiet: quiet || !std::io::stderr().is_terminal(),
            start: Instant::now(),
        }
    }

    pub fn phase(&self, msg: &str) {
        if !self.quiet {
            eprintln!("[{:>5.1}s] {msg}", self.start.elapsed().as_secs_f64());
        }
    }
}

/// Everything a scan needs besides the target.
pub struct ScanContext<'a> {
    pub args: &'a InspectArgs,
    pub config: &'a Config,
    pub cancel: Arc<AtomicBool>,
    pub progress: Progress,
}

pub fn run(args: &InspectArgs, config: &Config) -> Result<ExitCode> {
    if let Some(h) = &args.expect_sha256
        && (h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        eprintln!("error: --expect-sha256 must be 64 hex characters");
        return Ok(ExitCode::InvalidRequest);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = cancel.clone();
        // A second handler registration (e.g. from `watch`) is harmless to ignore.
        let _ = ctrlc::set_handler(move || cancel.store(true, Ordering::SeqCst));
    }
    let ctx = ScanContext {
        args,
        config,
        cancel,
        progress: Progress::new(args.quiet),
    };
    match scan_target(&ctx, &args.target) {
        Ok(Some(report)) => emit(&ctx, report),
        Ok(None) => {
            eprintln!("cancelled");
            Ok(ExitCode::Cancelled)
        }
        Err(e) if e.downcast_ref::<InvalidRequest>().is_some() => {
            eprintln!("error: {e}");
            Ok(ExitCode::InvalidRequest)
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub struct InvalidRequest(pub String);

impl std::fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidRequest {}

fn emit(ctx: &ScanContext, report: Report) -> Result<ExitCode> {
    if let Err(e) = report.validate_evidence_links() {
        bail!("internal error: report failed evidence validation: {e}");
    }
    if !ctx.args.no_save {
        let dir = store::save(&report)?;
        if ctx.args.open {
            store::open_html(&report.scan_id)?;
        }
        ctx.progress.phase(&format!(
            "report saved: {} ({})",
            report.scan_id,
            dir.display()
        ));
    }
    if let Some(path) = &ctx.args.output {
        store::write_private_file(path, serde_json::to_string_pretty(&report)?.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
    }
    match ctx.args.format {
        OutputFormat::Text => print!("{}", render::brief(&report, !ctx.args.no_save)),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Html => print!("{}", crate::html::render(&report)),
    }
    Ok(report.exit_code())
}

/// Scan one target string. `Ok(None)` means cancelled.
pub fn scan_target(ctx: &ScanContext, target: &str) -> Result<Option<Report>> {
    let scan_id = ulid::Ulid::new().to_string();
    let started_at = jiff::Timestamp::now().to_string();
    let started = Instant::now();
    let workspace = store::new_workspace(&scan_id)?;
    let result = scan_in_workspace(ctx, target, &workspace);
    let cleanup_ok = std::fs::remove_dir_all(&workspace).is_ok();
    let Some(mut report) = result? else {
        return Ok(None);
    };
    report.scan_id = scan_id;
    report.started_at = started_at;
    report.finished_at = jiff::Timestamp::now().to_string();
    report.budget.wall_clock_seconds_limit = ctx.args.timeout;
    report.budget.wall_clock_millis_used = started.elapsed().as_millis() as u64;
    report.cleanup_ok = cleanup_ok;
    if !cleanup_ok {
        report
            .coverage
            .limitations
            .push(format!("Workspace cleanup failed: {}", workspace.display()));
    }
    Ok(Some(report))
}

fn scan_in_workspace(ctx: &ScanContext, target: &str, ws: &Path) -> Result<Option<Report>> {
    let args = ctx.args;
    let mut merger = Merger::default();
    let mut incomplete: Vec<String> = Vec::new();
    let mut tools: Vec<ToolVersion> = vec![ToolVersion {
        name: "bytebouncer".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        digest: None,
    }];

    // 1. Acquisition.
    ctx.progress.phase(&format!("acquiring {target}"));
    let mut acquired = match acquire::classify(target) {
        Some(t) => {
            let is_url = matches!(t, Target::Url(_));
            let limits = acquire::Limits::default();
            let acq = acquire::acquire(
                t,
                ws,
                &limits,
                args.include_vendored,
                args.allow_reduced_isolation,
            );
            match acq {
                Ok(a) => a,
                Err(e) if is_url => {
                    let mut a = Acquired::default();
                    a.incomplete.push(format!("download failed: {e:#}"));
                    a
                }
                Err(e) => return Err(e),
            }
        }
        None => crate::packages::acquire_package(ctx, target, ws)?,
    };
    if ctx.cancel.load(Ordering::SeqCst) {
        return Ok(None);
    }
    incomplete.append(&mut acquired.incomplete);
    merger.coverage.skipped.append(&mut acquired.skipped);
    merger.coverage.limitations.append(&mut acquired.notes);
    for out in std::mem::take(&mut acquired.outputs) {
        merger.add(out);
    }
    let mut manifest = std::mem::take(&mut acquired.manifest);
    let mut files = std::mem::take(&mut acquired.files);
    if files.len() == 1 {
        ctx.progress.phase(&format!(
            "acquired {} ({} bytes, sha256 {})",
            files[0].display,
            files[0].size,
            &files[0].sha256[..16]
        ));
    } else {
        ctx.progress
            .phase(&format!("acquired {} files", files.len()));
    }

    // 2. Provenance.
    if args.expect_sha256.is_some() && files.len() != 1 {
        return Err(InvalidRequest(
            "--expect-sha256 applies to a single file; use --checksums-file for several".into(),
        )
        .into());
    }
    provenance_checks(ctx, ws, &files, &mut manifest, &mut merger);

    // 3. Tier 1, with cache.
    let user_rules = load_user_rules(ctx.config, &args.rules)?;
    let cache = Tier1Cache::new(!args.no_cache, &user_rules);
    tools.push(ToolVersion {
        name: "yara-x rules".into(),
        version: "bundled+user".into(),
        digest: Some(cache.rules_digest().into()),
    });
    let mut artifacts: Vec<ArtifactRecord> = Vec::new();
    let mut cache_hits = Vec::new();
    let mut isolation = Isolation {
        tier: IsolationTier::Tier1Sandbox,
        active: vec![],
        missing: vec![],
        reduced: false,
    };
    let mut pending: Vec<Snapshot> = Vec::new();
    // (input snapshot path, analysis) so oversized nested files can be
    // extracted from the right input later.
    let mut analyses: Vec<(PathBuf, ArtifactAnalysis)> = Vec::new();
    let mode: ScanMode = args.mode.into();
    // Deep mode needs nested executables from the worker, which the cache
    // does not keep, so it always re-runs Tier 1.
    let export = (mode == ScanMode::Deep).then_some(ExportLimits {
        per_file: 256 << 20,
        total: 1 << 30,
        count: 64,
    });
    let mut exported: Vec<Exported> = Vec::new();
    for f in &files {
        let cached = if export.is_some() {
            None
        } else {
            cache.get(&f.sha256, &f.display)
        };
        match cached {
            Some(a) => {
                cache_hits.push(format!("tier1:{}", &f.sha256[..16]));
                analyses.push((f.path.clone(), a));
            }
            None => pending.push(f.clone()),
        }
    }
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut batch_no = 0;
    let mut spilled_seen = 0usize;
    let mut spill_count = 0usize;
    let mut spill_bytes = 0u64;
    let mut spilled_parents: Vec<(String, String)> = Vec::new();
    loop {
        while !pending.is_empty() {
            let mut take = 0;
            let mut bytes = 0;
            while take < pending.len()
                && take < BATCH_MAX_FILES
                && (take == 0 || bytes + pending[take].size <= BATCH_MAX_BYTES)
            {
                bytes += pending[take].size;
                take += 1;
            }
            let batch_files: Vec<Snapshot> = pending.drain(..take).collect();
            batch_no += 1;
            ctx.progress.phase(&format!(
                "tier 1 analysis: batch {batch_no} ({} file(s))",
                batch_files.len()
            ));
            let batch_path = ws.join(format!("batch-{batch_no}.json"));
            let batch = Batch {
                files: batch_files
                    .iter()
                    .map(|f| BatchFile {
                        path: f.path.clone(),
                        display: f.display.clone(),
                        sha256: f.sha256.clone(),
                    })
                    .collect(),
                user_rules: user_rules.clone(),
                export,
            };
            std::fs::write(&batch_path, serde_json::to_vec(&batch)?)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let req = WorkerRequest {
                batch: &batch_path,
                allow_reduced: args.allow_reduced_isolation,
                probe: false,
                timeout: remaining,
            };
            match sandbox::run_worker(&req, &ctx.cancel)? {
                WorkerResult::Cancelled => return Ok(None),
                WorkerResult::TimedOut => {
                    incomplete.push(format!(
                        "Tier 1 analysis exceeded the {}s budget",
                        args.timeout
                    ));
                    for f in batch_files.iter().chain(pending.iter()) {
                        merger
                            .coverage
                            .skipped
                            .push(format!("{}: not analyzed (budget exhausted)", f.display));
                    }
                    pending.clear();
                }
                WorkerResult::Crashed(msg) => {
                    incomplete.push(format!("Tier 1 worker failed on batch {batch_no}: {msg}"));
                    for f in &batch_files {
                        merger
                            .coverage
                            .skipped
                            .push(format!("{}: not analyzed (worker failure)", f.display));
                    }
                }
                WorkerResult::Done(reply) => {
                    isolation.reduced |= !reply.missing.is_empty();
                    isolation.active = reply.active;
                    isolation.missing = reply.missing;
                    merger.coverage.limitations.extend(reply.rule_errors);
                    match reply.results {
                        None => {
                            incomplete.push(format!(
                            "Analysis refused: sandbox restrictions unavailable ({}). Re-run with --allow-reduced-isolation to proceed anyway.",
                            isolation.missing.join(", ")
                        ));
                            break;
                        }
                        Some(results) => {
                            for (f, r) in batch_files.iter().zip(results) {
                                cache.put(&f.sha256, &r.analysis);
                                exported.extend(r.exported);
                                analyses.push((f.path.clone(), r.analysis));
                            }
                        }
                    }
                }
            }
        }
        // Nested files too large for memory: extract each in its own sandboxed
        // worker and analyze it as an input (docs/design-large-entries.md).
        let mut requests = Vec::new();
        for (input, a) in analyses.iter_mut().skip(spilled_seen) {
            requests.extend(a.spill.drain(..).map(|r| (input.clone(), r)));
        }
        spilled_seen = analyses.len();
        if requests.is_empty() || ctx.cancel.load(Ordering::SeqCst) {
            break;
        }
        let spill_dir = ws.join("spill");
        std::fs::create_dir_all(&spill_dir)?;
        for (input, req) in requests {
            if spill_count >= SPILL_MAX_FILES
                || req.size > SPILL_MAX_FILE_BYTES
                || spill_bytes + req.size > SPILL_MAX_TOTAL_BYTES
            {
                incomplete.push(format!(
                    "{} ({} bytes) not analyzed: over the large-file extraction limits",
                    req.display, req.size
                ));
                continue;
            }
            spill_count += 1;
            ctx.progress.phase(&format!(
                "extracting large nested file {} ({} MB)",
                req.display,
                req.size >> 20
            ));
            let dest = spill_dir.join(spill_count.to_string());
            let display = req.display.clone();
            let container = req.container.clone();
            match crate::spill::extract(&crate::spill::ExtractRequest {
                input,
                request: req,
                dest: dest.clone(),
                max_bytes: SPILL_MAX_FILE_BYTES,
                allow_reduced: args.allow_reduced_isolation,
            }) {
                Ok(r) => {
                    spill_bytes += r.size;
                    merger.coverage.analyzed.push(format!("{display}: too large for in-memory expansion; extracted in a sandboxed worker and analyzed separately"));
                    spilled_parents.push((display.clone(), container));
                    let snap = Snapshot {
                        path: dest,
                        display,
                        sha256: r.sha256,
                        size: r.size,
                    };
                    files.push(snap.clone());
                    pending.push(snap);
                }
                Err(e) => incomplete.push(format!("{display}: extraction failed: {e:#}")),
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    let mut code_maps = Vec::new();
    for (_, a) in analyses {
        code_maps.extend(a.code);
        incomplete.extend(a.incomplete);
        let mut arts = a.artifacts;
        if let Some(first) = arts.first_mut()
            && let Some((_, container)) = spilled_parents.iter().find(|(d, _)| d == &first.path)
        {
            first.parent = Some(container.clone());
        }
        artifacts.extend(arts);
        for out in a.outputs {
            merger.add(out);
        }
    }
    if ctx.cancel.load(Ordering::SeqCst) {
        return Ok(None);
    }

    // 4. Opt-in reputation lookups (hash only).
    let mut external_lookups = Vec::new();
    for service in &args.lookup {
        let key_env = match service {
            lookup::Service::Malwarebazaar => ctx.config.lookup.malwarebazaar_key_env.as_deref(),
            lookup::Service::Virustotal => ctx.config.lookup.virustotal_key_env.as_deref(),
        };
        for f in files.iter().take(20) {
            ctx.progress.phase(&format!(
                "looking up {} on {}",
                &f.sha256[..16],
                service.name()
            ));
            external_lookups.push(format!(
                "{}: sha256 {} at {}",
                service.name(),
                f.sha256,
                jiff::Timestamp::now()
            ));
            match lookup::query(*service, &f.sha256, key_env) {
                Ok(Verdict::Hit { summary, severity }) => merger.add(lookup::hit_output(
                    *service, &f.sha256, &f.display, summary, severity,
                )),
                Ok(Verdict::NotFound) => merger.coverage.analyzed.push(format!(
                    "{}: not known to {} (absence is not evidence of safety)",
                    f.display,
                    service.name()
                )),
                Err(e) => merger
                    .coverage
                    .limitations
                    .push(format!("{} lookup failed: {e:#}", service.name())),
            }
        }
    }

    // 5. Deep mode (locally installed tools, Tier 2 sandbox).
    let mut retained = Vec::new();
    if mode == ScanMode::Deep {
        crate::deep::run(
            ctx,
            ws,
            &files,
            &exported,
            &artifacts,
            &mut merger,
            &mut tools,
            &mut incomplete,
            &mut retained,
        )?;
        if ctx.cancel.load(Ordering::SeqCst) {
            return Ok(None);
        }
    }

    for a in &artifacts {
        if a.format == "unknown" {
            merger.coverage.unsupported.push(format!(
                "{}: file type not recognized; only string extraction and rules ran",
                a.path
            ));
        }
    }
    incomplete.extend(
        manifest
            .unresolved
            .iter()
            .map(|u| format!("unresolved: {u}")),
    );
    merger
        .coverage
        .limitations
        .extend(incomplete.iter().cloned());

    let mut report = Report {
        schema_version: bytebouncer_core::SCHEMA_VERSION.into(),
        scan_id: String::new(),
        started_at: String::new(),
        finished_at: String::new(),
        mode,
        result_state: ResultState::NoFindingsDetected,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        artifacts,
        isolation,
        findings: merger.findings,
        evidence: merger.evidence,
        coverage: merger.coverage,
        policy: Default::default(),
        sample_executed: false,
        network_observation: false,
        external_lookups,
        cleanup_ok: false,
        acquisition: manifest,
        tools,
        model: None,
        budget: Budget::default(),
        cache_hits,
        model_notes: Default::default(),
    };
    if let (Some(a), Some(exp)) = (report.artifacts.first_mut(), &args.expect_sha256) {
        a.expected_sha256 = Some(exp.to_ascii_lowercase());
    }

    // 6. Optional model synthesis over the validated evidence.
    if let Some(model) = &args.model {
        crate::synth::run(ctx, model, &mut report, &retained, &code_maps)?;
    }

    report.result_state = if !incomplete.is_empty() || report.budget.exhausted {
        ResultState::Incomplete
    } else if report.artifacts.is_empty()
        || (!report.coverage.unsupported.is_empty() && report.findings.is_empty())
    {
        ResultState::Unsupported
    } else if report.findings.is_empty() {
        ResultState::NoFindingsDetected
    } else {
        ResultState::FindingsDetected
    };
    report.policy = ctx.config.policy.to_policy()?.evaluate(&report.findings);
    Ok(Some(report))
}

fn provenance_checks(
    ctx: &ScanContext,
    ws: &Path,
    files: &[Snapshot],
    manifest: &mut AcquisitionManifest,
    merger: &mut Merger,
) {
    let args = ctx.args;
    let sums = args
        .checksums_file
        .as_deref()
        .map(|src| load_text(ctx, ws, src, "checksums"));
    let mut minisign_keys = ctx.config.keys.minisign.clone();
    minisign_keys.extend(args.minisign_key.iter().cloned());
    let mut keyrings = ctx.config.keys.pgp_keyrings.clone();
    keyrings.extend(args.pgp_keyring.iter().cloned());

    // Arch packages: the system's own pacman keyring is the trust root.
    let pacman_keyring = PathBuf::from("/etc/pacman.d/gnupg/pubring.gpg");
    for f in files {
        let mut keyrings = keyrings.clone();
        if f.display.contains(".pkg.tar") && std::fs::File::open(&pacman_keyring).is_ok() {
            keyrings.push(pacman_keyring.clone());
        }
        let keyrings = &keyrings;
        let mut c = Checker::new(&f.sha256, &f.display);
        if let Some(exp) = &args.expect_sha256 {
            c.expect_sha256(&exp.to_ascii_lowercase(), "--expect-sha256");
        }
        match &sums {
            Some(Ok(text)) => {
                match provenance::expected_for(&provenance::parse_checksums(text), &f.display) {
                    Some(exp) => c.expect_sha256(&exp, "checksums file"),
                    None => c
                        .out
                        .coverage
                        .limitations
                        .push(format!("{}: no entry in the checksums file", f.display)),
                }
            }
            Some(Err(e)) => c
                .out
                .coverage
                .limitations
                .push(format!("checksums file unavailable: {e:#}")),
            None => {}
        }
        for (kind, path) in find_signatures(ctx, ws, f) {
            match kind {
                SigKind::Minisign => match (std::fs::read_to_string(&path), std::fs::read(&f.path))
                {
                    (Ok(text), Ok(data)) => c.minisign(&data, &text, &minisign_keys),
                    (Err(e), _) | (_, Err(e)) => c
                        .out
                        .coverage
                        .limitations
                        .push(format!("minisign check skipped: {e}")),
                },
                SigKind::OpenPgp => c.openpgp(
                    &f.path,
                    &path,
                    keyrings,
                    &ws.join("gpgv"),
                    args.allow_reduced_isolation,
                ),
            }
        }
        manifest.signatures.append(&mut c.checks);
        merger.add(c.out);
    }
}

#[derive(Clone, Copy)]
enum SigKind {
    Minisign,
    OpenPgp,
}

/// Candidate signature files for an artifact, copied into the workspace.
fn find_signatures(ctx: &ScanContext, ws: &Path, f: &Snapshot) -> Vec<(SigKind, PathBuf)> {
    let kind_of = |name: &str| {
        if name.ends_with(".minisig") {
            SigKind::Minisign
        } else {
            SigKind::OpenPgp
        }
    };
    let dir = ws.join("signatures");
    let _ = std::fs::create_dir_all(&dir);
    let mut found = Vec::new();
    if let Some(sig) = &ctx.args.signature {
        if let Ok(bytes) = load_bytes(ctx, ws, sig) {
            let dst = dir.join("explicit");
            if std::fs::write(&dst, bytes).is_ok() {
                found.push((kind_of(sig), dst));
            }
        }
        return found;
    }
    // Auto-discovery only for a single local file or URL target.
    let target = &ctx.args.target;
    let is_url = target.starts_with("http://") || target.starts_with("https://");
    if !(is_url || Path::new(target).is_file()) || f.display.contains('/') {
        return found;
    }
    for ext in [".minisig", ".sig", ".asc"] {
        let candidate = format!("{target}{ext}");
        let bytes = if is_url {
            fetch_small(ctx, ws, &candidate).ok()
        } else {
            std::fs::read(&candidate).ok()
        };
        if let Some(b) = bytes.filter(|b| !b.is_empty() && b.len() < 64 * 1024) {
            let dst = dir.join(format!("auto{ext}"));
            if std::fs::write(&dst, b).is_ok() {
                ctx.progress
                    .phase(&format!("found detached signature {candidate}"));
                found.push((kind_of(ext), dst));
            }
        }
    }
    found
}

fn fetch_small(ctx: &ScanContext, ws: &Path, url: &str) -> Result<Vec<u8>> {
    let fetcher = crate::fetch::WorkerFetcher {
        scratch: ws.join("fetch"),
        allow_reduced: ctx.args.allow_reduced_isolation,
        counter: Default::default(),
    };
    Ok(fetcher.get(url, &[], 1 << 20)?.0)
}

fn load_bytes(ctx: &ScanContext, ws: &Path, src: &str) -> Result<Vec<u8>> {
    if src.starts_with("http://") || src.starts_with("https://") {
        fetch_small(ctx, ws, src)
    } else {
        std::fs::read(src).with_context(|| format!("reading {src}"))
    }
}

fn load_text(ctx: &ScanContext, ws: &Path, src: &str, what: &str) -> Result<String> {
    let bytes = load_bytes(ctx, ws, src).with_context(|| format!("loading {what}"))?;
    String::from_utf8(bytes).with_context(|| format!("{what} is not text"))
}

fn load_user_rules(config: &Config, extra: &[PathBuf]) -> Result<Vec<RuleSource>> {
    let mut sources = Vec::new();
    for dir in config.rules.directories.iter().chain(extra) {
        let paths: Vec<PathBuf> = if dir.is_file() {
            vec![dir.clone()]
        } else {
            match std::fs::read_dir(dir) {
                Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
                Err(e) => bail!("rule directory {}: {e}", dir.display()),
            }
        };
        let mut paths: Vec<_> = paths
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "yar" || e == "yara"))
            .collect();
        paths.sort();
        for p in paths {
            let text =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            sources.push(RuleSource {
                name: p.display().to_string(),
                text,
            });
        }
    }
    Ok(sources)
}

pub fn doctor(config: &Config) -> Result<ExitCode> {
    let cancel = Arc::new(AtomicBool::new(false));
    let req = WorkerRequest {
        batch: Path::new("/dev/null"),
        allow_reduced: true,
        probe: true,
        timeout: Duration::from_secs(10),
    };
    println!("ByteBouncer {} — host check\n", env!("CARGO_PKG_VERSION"));
    let caps = bytebouncer_sandbox::host_capabilities();
    println!(
        "Platform: {} (Landlock ABI {})\n",
        caps.platform, caps.landlock_abi
    );
    println!("Tier 1 sandbox (quick mode):");
    let reply = match sandbox::run_worker(&req, &cancel)? {
        WorkerResult::Done(reply) => reply,
        WorkerResult::Crashed(msg) => {
            println!("  worker crashed: {msg}");
            return Ok(ExitCode::InternalFailure);
        }
        WorkerResult::TimedOut | WorkerResult::Cancelled => {
            println!("  worker did not finish");
            return Ok(ExitCode::InternalFailure);
        }
    };
    for r in sandbox::REQUIRED {
        let ok = reply.active.iter().any(|a| a == r);
        println!("  {} {r}", if ok { "ok     " } else { "MISSING" });
    }
    println!("\nEscape probes (all should be blocked):");
    let mut all_blocked = true;
    for (name, blocked) in reply.probe.unwrap_or_default() {
        all_blocked &= blocked;
        println!("  {} {name}", if blocked { "blocked" } else { "ALLOWED" });
    }
    crate::deep::doctor(config);
    Ok(if reply.missing.is_empty() && all_blocked {
        ExitCode::Ok
    } else {
        ExitCode::Incomplete
    })
}

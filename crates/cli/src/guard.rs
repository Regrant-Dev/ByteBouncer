//! Shared install gate: native download -> private snapshot -> review ->
//! digest verification -> local-only native install. Parsers never run as root.

mod offline;
mod plan;

use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context, Result, bail};
use bytebouncer_core::{ExitCode, Report};
use sha2::{Digest, Sha256};

use crate::{InspectArgs, Mode, approve, config::Config, inspect, integration, render, store};
use plan::{Manager, Plan};

#[derive(clap::Args, Clone)]
pub struct Args {
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    /// Model profile for analysis (deep mode also exposes read-only REA tools)
    #[arg(long)]
    pub model: Option<String>,
    #[arg(long)]
    pub allow_hosted_model: bool,
    #[arg(long)]
    pub allow_reduced_isolation: bool,
    /// Install without a prompt ONLY if the scan is complete and policy passes
    #[arg(long)]
    pub yes: bool,
    /// Native command, for example: -- pacman -Syu
    #[arg(last = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
}

struct Workspace(PathBuf);

/// Preserve native query statuses (notably pacman -T) for AUR helpers.
#[derive(Debug)]
pub struct NativeExit(pub u8);

impl std::fmt::Display for NativeExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "package manager exited with status {}", self.0)
    }
}

impl std::error::Error for NativeExit {}

impl Workspace {
    fn new() -> Result<Self> {
        Ok(Self(store::new_workspace(&format!(
            "guard-{}",
            ulid::Ulid::new()
        ))?))
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!(
                "ByteBouncer: cannot remove temporary files in {}: {e}",
                self.0.display()
            );
        }
    }
}

pub fn run(args: &Args, config: &Config, config_path: Option<&Path>) -> Result<ExitCode> {
    if !cfg!(target_os = "linux") {
        bail!(
            "automatic package-manager guarding currently supports Linux; use inspect on this platform"
        );
    }
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return unprivileged(args, config_path);
    }
    let normalized;
    let args = if args.command.first().is_some_and(|p| p == "pacman")
        && args.command.iter().any(|a| a == "-")
    {
        use std::io::Read;
        if std::io::stdin().is_terminal() {
            bail!("pacman '-' targets must be piped into guard");
        }
        let mut input = String::new();
        std::io::stdin()
            .take(1_048_577)
            .read_to_string(&mut input)?;
        if input.len() > 1_048_576 {
            bail!("package list on stdin is too large");
        }
        let targets: Vec<_> = input.split_whitespace().map(str::to_owned).collect();
        if targets.is_empty()
            || targets
                .iter()
                .any(|t| t.starts_with('-') || t.contains('\0'))
        {
            bail!("invalid package list on stdin");
        }
        let mut command = Vec::new();
        for word in &args.command {
            if word == "-" {
                command.extend(targets.iter().cloned());
            } else {
                command.push(word.clone());
            }
        }
        normalized = Args {
            command,
            ..args.clone()
        };
        &normalized
    } else {
        args
    };
    let program = args.command.first().context("missing native command")?;
    let ws = Workspace::new()?;
    let downloads = ws.0.join("downloads");
    let payload = ws.0.join("payload");
    std::fs::create_dir(&downloads)?;
    std::fs::create_dir(&payload)?;
    let connector = if program == "dnf" && is_dnf5() {
        "dnf5"
    } else {
        program
    };
    let plan = match plan::plan(connector, &args.command[1..], &downloads) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::InvalidRequest);
        }
    };
    match plan {
        Plan::Passthrough => native(
            program,
            &args.command[1..],
            requires_root(program, &args.command[1..]),
        ),
        Plan::Helper => helper(args, config_path),
        Plan::Recipe => recipe(args, config, &payload, config_path),
        Plan::Packages {
            manager,
            download,
            local,
            install_options,
        } => {
            require_interaction(args.yes)?;
            if !download.is_empty() {
                eprintln!(
                    "ByteBouncer: downloading the transaction and its dependencies; installation is paused."
                );
                let code = native(program, &download, manager != Manager::Dnf5)?;
                if code != ExitCode::Ok {
                    return Ok(code);
                }
            }
            stage_packages(manager, &downloads, &payload)?;
            for p in &local {
                stage_file(Path::new(p), &payload)?;
            }
            let files = package_files(manager, &payload)?;
            if files.is_empty() {
                eprintln!("ByteBouncer: no incoming packages; nothing to install.");
                return Ok(ExitCode::Ok);
            }
            let stored = if manager == Manager::Dnf5 {
                inventory(&downloads)?
            } else {
                BTreeMap::new()
            };
            let Some(reviewed) = review(&payload, args, config)? else {
                return Ok(ExitCode::Cancelled);
            };
            // Do not install the unscanned download directory. Only these exact
            // snapshots are passed to the native manager; no repository fetch
            // is allowed at handoff.
            verify_files(&payload, &reviewed)?;
            if manager == Manager::Dnf5 && inventory(&downloads)? != stored {
                bail!("stored transaction changed during review; installation stopped");
            }
            if manager == Manager::Dnf5 {
                for (path, sha) in &stored {
                    if plan::is_package(manager, path)
                        && reviewed.get(Path::new(
                            path.file_name().context("stored package has no filename")?,
                        )) != Some(sha)
                    {
                        bail!(
                            "stored package {} does not match the reviewed copy; installation stopped",
                            path.display()
                        );
                    }
                }
            }
            for path in &files {
                let sig = downloads.join(format!(
                    "{}.sig",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ));
                if sig.is_file() {
                    std::fs::copy(&sig, PathBuf::from(format!("{}.sig", path.display())))?;
                }
            }
            for original in &local {
                let signature = PathBuf::from(format!("{original}.sig"));
                if signature.is_file() {
                    std::fs::copy(
                        &signature,
                        payload.join(signature.file_name().context("signature has no filename")?),
                    )?;
                }
            }
            let files: Vec<_> = files.iter().map(|p| p.display().to_string()).collect();
            let final_args = if manager == Manager::Pacman && !download.is_empty() {
                let config_file = ws.0.join("pacman-offline.conf");
                store::write_private_file(
                    &config_file,
                    offline::pacman_config(&std::fs::read_to_string(offline::pacman_source(
                        &args.command[1..],
                    ))?)?
                    .as_bytes(),
                )?;
                offline::pacman_args(&args.command[1..], &payload, &config_file)
            } else {
                plan::install_args(
                    manager,
                    if manager == Manager::Dnf5 {
                        &downloads
                    } else {
                        &payload
                    },
                    &files,
                    &install_options,
                    &args.command[1..],
                )
            };
            let installer = program;
            eprintln!(
                "ByteBouncer: handing {} reviewed package(s) to {installer}.",
                files.len()
            );
            native(installer, &final_args, true)
        }
    }
}

fn require_interaction(yes: bool) -> Result<()> {
    if !yes
        && !std::io::stdin().is_terminal()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_err()
    {
        bail!(
            "guard needs a terminal to wait for your decision; --yes permits only complete scans that pass policy"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn unprivileged(args: &Args, config_path: Option<&Path>) -> Result<ExitCode> {
    let uid: u32 = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok())
        .filter(|uid| *uid != 0).context("do not run guard as root; run it as your normal user (native package-manager commands use sudo)")?;
    // AUR helpers may sudo their pacman callback. Return to the invoking user
    // before loading models, scanning files or asking for approval.
    let mut cmd = Command::new("sudo");
    cmd.args(["--set-home", "--user", &format!("#{uid}"), "--"])
        .arg(std::env::current_exe()?);
    if let Some(path) = config_path {
        cmd.arg("--config").arg(path);
    }
    cmd.arg("guard")
        .args(forward_options(args))
        .arg("--")
        .args(&args.command);
    status(&mut cmd)
}

pub(crate) fn forward_options(args: &Args) -> Vec<String> {
    let mut options = Vec::new();
    if let Some(mode) = args.mode {
        options.extend([
            "--mode".into(),
            if matches!(mode, Mode::Deep) {
                "deep"
            } else {
                "quick"
            }
            .into(),
        ]);
    }
    if let Some(model) = &args.model {
        options.extend(["--model".into(), model.clone()]);
    }
    if args.allow_hosted_model {
        options.push("--allow-hosted-model".into());
    }
    if args.allow_reduced_isolation {
        options.push("--allow-reduced-isolation".into());
    }
    if args.yes {
        options.push("--yes".into());
    }
    options
}

fn requires_root(program: &str, args: &[String]) -> bool {
    match program {
        "pacman" => {
            let flags: String = args
                .iter()
                .filter(|a| a.starts_with('-') && !a.starts_with("--"))
                .flat_map(|a| a.chars().skip(1))
                .collect();
            flags.contains('R')
                || flags.contains('D')
                || ((flags.contains('S') || flags.contains('F'))
                    && (flags.contains('y') || flags.contains('c')))
                || args.iter().any(|a| {
                    matches!(
                        a.as_str(),
                        "--remove" | "--database" | "--refresh" | "--clean"
                    )
                })
        }
        "apt" | "apt-get" | "dnf" | "dnf5" => args.iter().any(|a| {
            matches!(
                a.as_str(),
                "update"
                    | "remove"
                    | "purge"
                    | "autoremove"
                    | "autopurge"
                    | "clean"
                    | "autoclean"
                    | "makecache"
            )
        }),
        _ => false,
    }
}

fn native(program: &str, args: &[String], root: bool) -> Result<ExitCode> {
    let mut cmd = if root {
        let mut cmd = Command::new("sudo");
        cmd.arg("--").arg(program);
        cmd
    } else {
        Command::new(program)
    };
    cmd.args(args);
    status(&mut cmd)
}

fn status(cmd: &mut Command) -> Result<ExitCode> {
    if cancellation().load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(ExitCode::Cancelled);
    }
    let result = cmd.status().with_context(|| format!("starting {cmd:?}"))?;
    if result.success() {
        return Ok(ExitCode::Ok);
    }
    #[cfg(unix)]
    let code = {
        use std::os::unix::process::ExitStatusExt;
        result
            .code()
            .unwrap_or_else(|| 128 + result.signal().unwrap_or(0))
    };
    #[cfg(not(unix))]
    let code = result.code().unwrap_or(1);
    Err(NativeExit(code as u8).into())
}

fn helper(args: &Args, config_path: Option<&Path>) -> Result<ExitCode> {
    let proxies = Workspace::new()?;
    let pacman = integration::write_proxy(&proxies.0, "pacman", args, config_path)?;
    let makepkg = integration::write_proxy(&proxies.0, "makepkg", args, config_path)?;
    let program = &args.command[0];
    let mut native_args = vec![
        "--pacman".into(),
        pacman.display().to_string(),
        "--makepkg".into(),
        makepkg.display().to_string(),
    ];
    native_args.extend_from_slice(&args.command[1..]);
    eprintln!(
        "ByteBouncer: {program} build recipes and pacman installations will wait for review."
    );
    native(program, &native_args, false)
}

fn stage_file(source: &Path, destination: &Path) -> Result<()> {
    let name = source.file_name().context("input has no file name")?;
    let target = destination.join(name);
    if target.exists() {
        if digest(source)? != digest(&target)? {
            bail!(
                "different packages have the same file name: {}",
                name.to_string_lossy()
            );
        }
    } else {
        let metadata = std::fs::symlink_metadata(source)?;
        if !metadata.file_type().is_file() {
            bail!("not a regular file: {}", source.display());
        }
        std::fs::copy(source, &target).with_context(|| format!("staging {}", source.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn stage_packages(manager: Manager, source: &Path, destination: &Path) -> Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && plan::is_package(manager, &entry.path()) {
            stage_file(&entry.path(), destination)?;
        } else if entry.file_type()?.is_dir() {
            stage_packages(manager, &entry.path(), destination)?;
        }
    }
    Ok(())
}

fn is_dnf5() -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .find_map(|dir| std::fs::canonicalize(dir.join("dnf")).ok())
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().starts_with("dnf5"))
            })
            .unwrap_or(false)
    })
}

fn inventory(directory: &Path) -> Result<Reviewed> {
    fn visit(root: &Path, directory: &Path, files: &mut Reviewed) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if files.len() > 20_000 {
                bail!("stored transaction has too many files");
            }
            if entry.file_type()?.is_dir() {
                visit(root, &entry.path(), files)?;
            } else if entry.file_type()?.is_file() {
                files.insert(
                    entry.path().strip_prefix(root)?.to_owned(),
                    digest(&entry.path())?,
                );
            } else {
                bail!(
                    "unexpected link in stored transaction: {}",
                    entry.path().display()
                );
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(directory, directory, &mut files)?;
    Ok(files)
}

fn package_files(manager: Manager, path: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && plan::is_package(manager, &entry.path()) {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn digest(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut sha = Sha256::new();
    std::io::copy(&mut file, &mut sha)?;
    Ok(hex::encode(sha.finalize()))
}

type Reviewed = BTreeMap<PathBuf, String>;

fn cancellation() -> &'static Arc<AtomicBool> {
    static CANCEL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    CANCEL.get_or_init(|| {
        let cancel = Arc::new(AtomicBool::new(false));
        let handler_cancel = cancel.clone();
        let _ = ctrlc::set_handler(move || {
            handler_cancel.store(true, std::sync::atomic::Ordering::SeqCst)
        });
        cancel
    })
}

fn verify_files(payload: &Path, reviewed: &Reviewed) -> Result<()> {
    for (name, expected) in reviewed {
        let path = payload.join(name);
        if !std::fs::symlink_metadata(&path)?.file_type().is_file() || digest(&path)? != *expected {
            bail!(
                "{} changed after review; installation stopped",
                path.display()
            );
        }
    }
    Ok(())
}

fn reviewed_files(payload: &Path, report: &Report) -> Result<Reviewed> {
    let reviewed = inventory(payload)?;
    for (path, actual) in &reviewed {
        if !report
            .artifacts
            .iter()
            .any(|a| a.parent.is_none() && a.sha256 == *actual)
        {
            bail!(
                "{} was not covered by the scan; installation stopped",
                path.display()
            );
        }
    }
    if reviewed.is_empty() {
        bail!("empty transaction snapshot");
    }
    Ok(reviewed)
}

fn review(payload: &Path, args: &Args, config: &Config) -> Result<Option<Reviewed>> {
    let mut scan_args = InspectArgs::defaults_for(&payload.display().to_string());
    scan_args.mode = match args.mode {
        Some(mode) => mode,
        None => match config.guard.mode.as_deref() {
            None | Some("quick") => Mode::Quick,
            Some("deep") => Mode::Deep,
            Some(other) => bail!("guard.mode must be quick or deep, not {other}"),
        },
    };
    scan_args.model = args.model.clone().or_else(|| config.guard.model.clone());
    scan_args.allow_hosted_model = args.allow_hosted_model;
    scan_args.allow_reduced_isolation = args.allow_reduced_isolation;
    scan_args.include_vendored = true;
    // Deep review should attempt every executable in the staged transaction.
    scan_args.deep_max_artifacts = usize::MAX;
    let cancel = cancellation().clone();
    loop {
        let ctx = inspect::ScanContext {
            args: &scan_args,
            config,
            cancel: cancel.clone(),
            progress: inspect::Progress::new(false),
        };
        let Some(mut report) = inspect::scan_target(&ctx, &scan_args.target)? else {
            return Ok(None);
        };
        report.coverage.limitations.push(format!("Install guard for {:?}. This report describes static analysis before native installation/build execution; package acquisition and repository trust checks are delegated to the native package manager.", args.command));
        report
            .validate_evidence_links()
            .map_err(anyhow::Error::msg)?;
        store::save(&report)?;
        display(&render::markdown(&report));
        let reviewed = reviewed_files(payload, &report)?;
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        if args.yes {
            if report.exit_code() != ExitCode::Ok {
                eprintln!(
                    "ByteBouncer: --yes cannot override an incomplete scan or exceeded policy."
                );
                return Err(NativeExit(report.exit_code() as u8).into());
            }
            approve::approve(&report.scan_id, None)?;
            return Ok(Some(reviewed));
        }
        loop {
            let choice = ask(
                "ByteBouncer: [c] continue, [d] deep/REA scan, [r] read report, [o] open report, [x] cancel [x]: ",
                &cancel,
            )?;
            match choice.trim().to_ascii_lowercase().as_str() {
                "c" | "continue" => {
                    let reason = if report.exit_code() != ExitCode::Ok {
                        let reason = ask(
                            "Scan is incomplete or policy was exceeded. Enter a reason to approve anyway (empty cancels): ",
                            &cancel,
                        )?;
                        if reason.trim().is_empty() {
                            return Ok(None);
                        }
                        Some(reason)
                    } else {
                        None
                    };
                    approve::approve(&report.scan_id, reason)?;
                    return Ok(Some(reviewed));
                }
                "d" | "deep" => {
                    scan_args.mode = Mode::Deep;
                    break;
                }
                "r" | "read" => display(&render::markdown(&report)),
                "o" | "open" => {
                    if let Err(e) = store::open_html(&report.scan_id) {
                        eprintln!("cannot open report: {e}");
                    }
                }
                "" | "x" | "cancel" | "q" => return Ok(None),
                _ => eprintln!("Choose c, d, r, o or x."),
            }
        }
    }
}

fn display(message: &str) {
    if !std::io::stderr().is_terminal()
        && let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty")
    {
        let _ = tty.write_all(message.as_bytes());
        let _ = tty.flush();
    } else {
        eprint!("{message}");
        let _ = std::io::stderr().flush();
    }
}

fn ask(prompt: &str, cancel: &AtomicBool) -> Result<String> {
    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(String::new());
    }
    display(prompt);
    let mut answer = String::new();
    let tty = std::fs::OpenOptions::new().read(true).open("/dev/tty").ok();
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = tty
            .as_ref()
            .map(|file| file.as_raw_fd())
            .unwrap_or(libc::STDIN_FILENO);
        loop {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(String::new());
            }
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll points to one initialized descriptor for this call.
            let ready = unsafe { libc::poll(&mut poll, 1, 100) };
            if ready > 0 {
                break;
            }
            if ready < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    if let Some(tty) = tty {
        std::io::BufReader::new(tty).read_line(&mut answer)?;
    } else if std::io::stdin().is_terminal() {
        std::io::stdin().read_line(&mut answer)?;
    }
    Ok(answer.trim().to_owned())
}

fn recipe(
    args: &Args,
    config: &Config,
    payload: &Path,
    config_path: Option<&Path>,
) -> Result<ExitCode> {
    let mut recipe = PathBuf::from("PKGBUILD");
    let mut words = args.command[1..].iter();
    while let Some(word) = words.next() {
        if word == "--help" || word == "--version" || word == "-h" || word == "-V" {
            return native("makepkg", &args.command[1..], false);
        }
        if word == "-p" {
            recipe = PathBuf::from(words.next().context("makepkg -p needs a recipe path")?);
        } else if let Some(path) = word.strip_prefix("-p") {
            recipe = PathBuf::from(path);
        }
    }
    let recipe = std::fs::canonicalize(&recipe)
        .with_context(|| format!("reading {} before makepkg", recipe.display()))?;
    let directory = recipe.parent().context("recipe has no directory")?;
    // Recipes, .install files and patches are untrusted data until the user
    // accepts them. Do not run makepkg even for metadata before this gate.
    stage_recipe(directory, payload, 0)?;
    let approvals = approve::approvals_dir()?;
    let previous = inventory(payload)?;
    let accepted = !previous.is_empty()
        && previous
            .values()
            .all(|sha| approve::lookup(&approvals, sha).is_some());
    let reviewed = if accepted {
        eprintln!("ByteBouncer: these exact build inputs were already approved.");
        previous
    } else {
        require_interaction(args.yes)?;
        eprintln!(
            "ByteBouncer: reviewing build recipes before makepkg can execute them. Downloaded sources/build execution are outside this recipe review."
        );
        let Some(reviewed) = review(payload, args, config)? else {
            return Ok(ExitCode::Cancelled);
        };
        reviewed
    };
    verify_files(directory, &reviewed)?;
    let proxies = Workspace::new()?;
    let pacman = integration::write_proxy(&proxies.0, "pacman", args, config_path)?;
    let mut cmd = Command::new("makepkg");
    cmd.env("PACMAN", pacman).args(&args.command[1..]);
    status(&mut cmd)
}

fn stage_recipe(source: &Path, destination: &Path, depth: usize) -> Result<()> {
    if depth > 32 {
        bail!("build recipe directory is too deeply nested");
    }
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if entry.file_type()?.is_dir() {
            if [".git", "src", "pkg", "target"]
                .iter()
                .any(|skip| name == *skip)
            {
                continue;
            }
            let child = destination.join(&name);
            std::fs::create_dir(&child)?;
            stage_recipe(&entry.path(), &child, depth + 1)?;
        } else if entry.file_type()?.is_file() {
            if !plan::is_package(Manager::Pacman, &entry.path()) {
                stage_file(&entry.path(), destination)?;
            }
        } else {
            bail!(
                "build inputs contain a link or special file: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_payload_is_rejected_even_with_same_file_name() {
        let path =
            std::env::temp_dir().join(format!("bytebouncer-guard-hash-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path).unwrap();
        let file = path.join("a.deb");
        std::fs::write(&file, b"reviewed bytes").unwrap();
        let reviewed = BTreeMap::from([(PathBuf::from("a.deb"), digest(&file).unwrap())]);
        assert!(verify_files(&path, &reviewed).is_ok());
        std::fs::write(&file, b"replacement").unwrap();
        assert!(verify_files(&path, &reviewed).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}

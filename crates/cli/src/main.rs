//! ByteBouncer CLI.

mod acquire;
mod approve;
mod cache;
mod compare;
mod config;
mod deep;
mod fetch;
mod guard;
mod hook;
mod html;
mod inspect;
mod install;
mod integration;
mod lookup;
mod mcp;
mod overview;
mod packages;
mod provenance;
mod render;
mod sandbox;
mod setup;
mod spill;
mod store;
mod synth;
mod watch;

use std::path::PathBuf;
use std::process::ExitCode as ProcessExit;

use bytebouncer_core::{ExitCode, ScanMode};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "bytebouncer",
    version,
    about = "Know what you're letting in.",
    long_about = "Inspect software before installing or running it. Inspection never installs \
        or executes the input. The guard and install commands can hand approved packages \
        to your native package manager.\n\n\
        Exit code 0 means the requested analysis completed and no policy threshold \
        was exceeded. It is NOT proof that the software is safe."
)]
struct Cli {
    /// Use this config file instead of the default location
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Download packages, scan the exact files, and wait before installing (Linux)
    Guard(guard::Args),
    /// Print shell functions that automatically guard package-manager commands
    Integration(integration::Args),
    /// Inspect a file, directory, URL, or package request without installing or running it
    Inspect(Box<InspectArgs>),
    /// Show, list, or prune saved reports
    Report {
        /// Report ID or unique prefix (8+ characters)
        id: Option<String>,
        #[arg(long)]
        list: bool,
        /// Delete reports older than this many days
        #[arg(long, value_name = "DAYS")]
        prune: Option<u64>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
        format: ReportFormat,
        /// Open the report's HTML page in your browser
        #[arg(long)]
        open: bool,
    },
    /// Compare two saved reports (e.g. before and after an update)
    Compare { old: String, new: String },
    /// Watch directories and quick-inspect each new file
    Watch {
        /// Directories to watch (default: [watch] directories in the config)
        dirs: Vec<PathBuf>,
        /// Show a desktop notification for each result
        #[arg(long)]
        notify: bool,
        #[arg(long)]
        allow_reduced_isolation: bool,
    },
    /// Inspect model profiles from the config file
    Models {
        #[command(subcommand)]
        action: ModelsAction,
    },
    /// Check sandbox support and installed deep-mode tools on this host
    Doctor,
    /// Approve the exact artifacts in a report (used by the pacman hook and `install`)
    Approve {
        report: String,
        /// Required to approve an incomplete report or one that exceeded the policy
        #[arg(long, value_name = "REASON")]
        r#override: Option<String>,
        /// Treat REPORT as a SHA-256 and remove its approval instead
        #[arg(long, conflicts_with = "override")]
        revoke: bool,
    },
    /// Re-download an approved package request, verify it byte-for-byte, and hand it to the package manager
    Install {
        report: String,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_reduced_isolation: bool,
    },
    /// pacman PreTransaction hook: check approvals (runs as root; never analyzes)
    #[command(name = "pacman-hook")]
    PacmanHook {
        /// Print the .hook file to install in /etc/pacman.d/hooks/
        #[arg(long)]
        print_hook: bool,
    },
    /// Serve inspection tools over MCP (stdio)
    Mcp,
    /// Optionally install deep-mode tools into ByteBouncer's own folder (verified downloads)
    Setup {
        #[arg(value_enum)]
        tool: setup::Tool,
        /// Remove a tool installed by `setup` instead
        #[arg(long)]
        remove: bool,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_reduced_isolation: bool,
    },
}

#[derive(Subcommand)]
enum ModelsAction {
    /// List configured model profiles
    List,
    /// Check that a profile's endpoint is reachable
    Probe { name: String },
}

#[derive(clap::Args, Clone)]
pub struct InspectArgs {
    /// What to inspect: a path, an http(s) URL, or a package request — quoted
    /// ("pacman -S firefox") or after `--` (-- yay -S foo)
    #[arg(required = true, num_args = 1.., value_name = "TARGET")]
    pub words: Vec<String>,
    #[arg(skip)]
    pub target: String,
    #[arg(long, value_enum, default_value_t = Mode::Quick)]
    pub mode: Mode,
    /// Output format printed to the terminal
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Also write the JSON report to this path
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Publisher-supplied SHA-256; a mismatch fails the default policy
    #[arg(long, value_name = "HEX")]
    pub expect_sha256: Option<String>,
    /// SHA256SUMS-style file (path or URL) to check artifacts against
    #[arg(long, value_name = "PATH|URL")]
    pub checksums_file: Option<String>,
    /// Detached signature (path or URL): .minisig, .sig, or .asc
    #[arg(long, value_name = "PATH|URL")]
    pub signature: Option<String>,
    /// Trusted minisign public key (repeatable)
    #[arg(long, value_name = "KEY")]
    pub minisign_key: Vec<String>,
    /// Trusted OpenPGP keyring file (repeatable)
    #[arg(long, value_name = "PATH")]
    pub pgp_keyring: Vec<PathBuf>,
    /// Look up the SHA-256 (never the file) on a reputation service (repeatable)
    #[arg(long, value_enum)]
    pub lookup: Vec<lookup::Service>,
    /// Extra YARA rule file or directory (repeatable)
    #[arg(long, value_name = "PATH")]
    pub rules: Vec<PathBuf>,
    /// Model profile for synthesis ("default" uses default_model from the config)
    #[arg(long, value_name = "NAME")]
    pub model: Option<String>,
    /// Question to focus the model's investigation
    #[arg(long, value_name = "TEXT", requires = "model")]
    pub ask: Option<String>,
    /// Reasoning effort for the model on this scan (overrides the config), e.g. low, medium, high
    #[arg(long, value_name = "LEVEL", requires = "model")]
    pub effort: Option<String>,
    /// Allow sending selected evidence to a hosted (non-local) model endpoint
    #[arg(long)]
    pub allow_hosted_model: bool,
    #[arg(long, default_value_t = 40, value_name = "N")]
    pub model_max_tool_calls: u32,
    /// Total model token budget (prompt + output, summed over all turns)
    #[arg(long, default_value_t = 1_000_000, value_name = "N")]
    pub model_max_tokens: u64,
    #[arg(long, default_value_t = 600, value_name = "SECS")]
    pub model_timeout: u64,
    /// Deep mode: most executables to hand to capa/ClamAV/Ghidra
    #[arg(long, default_value_t = 10, value_name = "N")]
    pub deep_max_artifacts: usize,
    /// Proceed even if some sandbox restrictions are unavailable
    #[arg(long)]
    pub allow_reduced_isolation: bool,
    /// Include node_modules, vendor, target, .git, … when inspecting directories
    #[arg(long)]
    pub include_vendored: bool,
    /// For package requests, also acquire and inspect declared dependencies
    #[arg(long)]
    pub include_dependencies: bool,
    /// Do not save the report to the report store
    #[arg(long, conflicts_with = "open")]
    pub no_save: bool,
    /// Open the finished report in your browser
    #[arg(long)]
    pub open: bool,
    /// Do not reuse or store cached analysis results
    #[arg(long)]
    pub no_cache: bool,
    /// No progress output on stderr
    #[arg(long, short)]
    pub quiet: bool,
    /// Wall-clock budget for analysis, in seconds
    #[arg(long, default_value_t = 300, value_name = "SECS")]
    pub timeout: u64,
}

impl InspectArgs {
    fn finish(mut self) -> Self {
        self.target = self.words.join(" ");
        self
    }

    /// Defaults for scans started by `watch`.
    pub fn defaults_for(target: &str) -> Self {
        match Cli::try_parse_from(["bytebouncer", "inspect", target]).map(|c| c.command) {
            Ok(Command::Inspect(a)) => a.finish(),
            _ => unreachable!("default inspect arguments parse"),
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Mode {
    Quick,
    Deep,
}

impl From<Mode> for ScanMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Quick => ScanMode::Quick,
            Mode::Deep => ScanMode::Deep,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Html,
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Markdown,
    Json,
    Html,
}

fn main() -> ProcessExit {
    // Behave like other CLI tools when output is piped into `head` and the
    // pipe closes: exit quietly instead of panicking on a write error.
    #[cfg(unix)]
    // SAFETY: restoring the default disposition of SIGPIPE before any threads start.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some(sandbox::WORKER_SUBCOMMAND) => sandbox::worker_main(&args[2..]),
        Some(fetch::WORKER_SUBCOMMAND) => fetch::worker_main(),
        Some(spill::WORKER_SUBCOMMAND) => spill::worker_main(),
        _ => {}
    }

    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) if e.downcast_ref::<guard::NativeExit>().is_some() => {
            return ProcessExit::from(e.downcast_ref::<guard::NativeExit>().unwrap().0);
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::InternalFailure
        }
    };
    ProcessExit::from(code as u8)
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let config = match config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            return Ok(ExitCode::InvalidRequest);
        }
    };
    match cli.command {
        Command::Guard(args) => guard::run(&args, &config, cli.config.as_deref()),
        Command::Integration(args) => integration::run(&args, cli.config.as_deref()),
        Command::Inspect(args) => inspect::run(&args.finish(), &config),
        Command::Report {
            id,
            list,
            prune,
            format,
            open,
        } => {
            if let Some(days) = prune {
                let n = store::prune(days)?;
                println!("removed {n} report(s) older than {days} day(s)");
                return Ok(ExitCode::Ok);
            }
            if list || id.is_none() {
                for (id, summary) in store::list()? {
                    println!("{id}  {summary}");
                }
                return Ok(ExitCode::Ok);
            }
            let report = store::load(id.as_deref().unwrap_or_default())?;
            if open {
                store::open_html(&report.scan_id)?;
                return Ok(ExitCode::Ok);
            }
            match format {
                ReportFormat::Markdown => print!("{}", render::markdown(&report)),
                ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
                ReportFormat::Html => print!("{}", html::render(&report)),
            }
            Ok(ExitCode::Ok)
        }
        Command::Compare { old, new } => {
            print!(
                "{}",
                compare::compare(&store::load(&old)?, &store::load(&new)?)
            );
            Ok(ExitCode::Ok)
        }
        Command::Watch {
            dirs,
            notify,
            allow_reduced_isolation,
        } => {
            let mut template = InspectArgs::defaults_for("placeholder");
            template.allow_reduced_isolation = allow_reduced_isolation;
            watch::run(dirs, &template, &config, notify)
        }
        Command::Models { action } => {
            match action {
                ModelsAction::List => {
                    if config.models.is_empty() {
                        println!(
                            "no model profiles configured; add [models.NAME] to {}",
                            config::config_path()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default()
                        );
                    }
                    for (name, p) in &config.models {
                        let default = if config.default_model.as_deref() == Some(name) {
                            " (default)"
                        } else {
                            ""
                        };
                        println!("{name}{default}: {} at {}", p.model, p.base_url);
                    }
                }
                ModelsAction::Probe { name } => synth::probe(&config, &name)?,
            }
            Ok(ExitCode::Ok)
        }
        Command::Doctor => inspect::doctor(&config),
        Command::Approve {
            report,
            r#override,
            revoke,
        } => {
            if revoke {
                let removed = approve::revoke(&report)?;
                println!(
                    "{}",
                    if removed {
                        "approval removed"
                    } else {
                        "no approval for that SHA-256"
                    }
                );
                return Ok(ExitCode::Ok);
            }
            match approve::approve(&report, r#override) {
                Ok(list) => {
                    for a in list {
                        println!("approved {}  {}", a.sha256, a.artifact);
                    }
                    Ok(ExitCode::Ok)
                }
                Err(e) => {
                    eprintln!("error: {e:#}");
                    Ok(ExitCode::PolicyExceeded)
                }
            }
        }
        Command::Install {
            report,
            yes,
            allow_reduced_isolation,
        } => install::run(&report, yes, allow_reduced_isolation),
        Command::PacmanHook { print_hook } => {
            if print_hook {
                print!("{}", hook::HOOK_FILE);
                return Ok(ExitCode::Ok);
            }
            let code = hook::run()?;
            Ok(if code == 0 {
                ExitCode::Ok
            } else {
                ExitCode::PolicyExceeded
            })
        }
        Command::Mcp => mcp::serve(&config),
        Command::Setup {
            tool,
            remove,
            yes,
            allow_reduced_isolation,
        } => {
            if remove {
                setup::remove(tool)
            } else {
                setup::run(tool, yes, allow_reduced_isolation)
            }
        }
    }
}

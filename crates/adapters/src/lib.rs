//! Package-manager adapters.
//!
//! Two jobs, both side-effect free:
//!
//! 1. [`parse_command_str`] / [`parse_argv`] turn familiar package-manager
//!    syntax (`pacman -S curl`, `brew install --cask firefox`, …) into a
//!    [`PackageRequest`]. Anything with shell meaning, any unknown flag, and any
//!    operation whose meaning cannot be preserved is rejected.
//! 2. [`resolve`] turns a request into immutable artifacts to fetch
//!    ([`ResolvedPackage`] / `SourceRef`), recipe files retrieved as data, and
//!    an explicit list of what could not be resolved safely.
//!
//! This crate never executes a recipe, never installs anything and never
//! performs network I/O itself: every request goes through the caller's
//! [`Fetcher`], and every host command through the caller's [`HostCommands`].
//! The only direct I/O is reading the local pacman configuration and sync
//! databases (system files) in [`host`], with paths injectable via [`HostInfo`].

#![forbid(unsafe_code)]

mod apt;
mod aur;
mod brew;
mod choco;
mod dnf;
pub mod host;
mod pacman;
mod parse;
pub mod pkgbuild;
mod scoop;
mod tarball;
mod util;
mod winget;

use std::path::PathBuf;

pub use bytebouncer_core::{Manager, PackageRequest, ResolvedPackage, SourceRef};
pub use choco::chocolatey_script_sources;
pub use parse::{ParseError, parse_argv, parse_command_str};
pub use util::compare_versions;

/// Bytes returned by a [`Fetcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub final_url: String,
    pub redirects: u32,
}

/// Why a fetch failed. `Status` lets resolvers tell "not found" from outages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("HTTP status {code}: {message}")]
    Status { code: u16, message: String },
    #[error("response exceeds the {limit}-byte limit")]
    TooLarge { limit: u64 },
    #[error("network error: {0}")]
    Network(String),
    /// The caller's policy refused the request (host not allowed, budget…).
    #[error("fetch refused: {0}")]
    Denied(String),
}

/// Caller-provided network access (the CLI routes this through its sandboxed
/// fetch worker; tests use recorded fixtures).
pub trait Fetcher {
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<Fetched, FetchError>;
}

/// Caller-provided, read-only host commands (`apt-get --print-uris`,
/// `dnf download --url`, …). Implementations must not run anything that
/// modifies the system; this crate only ever asks for query commands.
pub trait HostCommands {
    fn run_readonly(&self, program: &str, args: &[&str]) -> Result<String, String>;
}

/// A [`HostCommands`] that refuses everything, for hosts/tests without them.
pub struct NoHostCommands;

impl HostCommands for NoHostCommands {
    fn run_readonly(&self, program: &str, _args: &[&str]) -> Result<String, String> {
        Err(format!("host command `{program}` is not available"))
    }
}

/// Facts about the host that change resolution. See [`HostInfo::detect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    /// pacman `DBPath` (default `/var/lib/pacman`); sync DBs live in `<dbpath>/sync/`.
    pub pacman_db_path: Option<PathBuf>,
    /// Usually `/etc/pacman.conf`.
    pub pacman_conf: Option<PathBuf>,
    /// Replaces `/etc/pacman.d/mirrorlist` wherever pacman.conf includes it.
    pub mirrorlist: Option<PathBuf>,
    /// Machine architecture in pacman/uname spelling (`x86_64`, `aarch64`, …).
    pub arch: String,
    /// Operating system (`linux`, `macos`, `windows`).
    pub os: String,
    pub has_apt: bool,
    pub has_dnf: bool,
    /// Homebrew bottle tag to prefer (`x86_64_linux`, `arm64_sequoia`, …).
    /// When `None` it is derived from `os`/`arch` on Linux; on macOS the
    /// codename is unknown and every bottle is listed in notes instead.
    pub brew_bottle_tag: Option<String>,
}

impl HostInfo {
    /// A host description with nothing available (useful for tests).
    pub fn minimal(arch: &str, os: &str) -> Self {
        HostInfo {
            pacman_db_path: None,
            pacman_conf: None,
            mirrorlist: None,
            arch: arch.to_string(),
            os: os.to_string(),
            has_apt: false,
            has_dnf: false,
            brew_bottle_tag: None,
        }
    }

    /// Detect the current host by checking well-known paths. Reads no file
    /// contents.
    pub fn detect() -> Self {
        host::detect()
    }
}

/// A recipe/manifest file retrieved as DATA (never executed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeFile {
    pub package: String,
    /// Path inside the recipe set, e.g. `PKGBUILD`, `wget.rb`, `7zip.json`.
    pub path: String,
    pub bytes: Vec<u8>,
    /// Where the bytes came from (URL, or `<snapshot url>#<path>`).
    pub origin: String,
}

/// Extra request headers the caller must send to fetch `url` (e.g. the
/// anonymous ghcr.io bearer token Homebrew bottles need). Core's `SourceRef`
/// has no header field, so this side table is keyed by URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHeaders {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// A structured, security-relevant fact noticed while resolving (top-level
/// PKGBUILD commands, .SRCINFO disagreements, lifecycle scripts…). These are
/// observations for the analysis stage, not verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub package: String,
    pub file: Option<String>,
    /// Stable identifier, e.g. `pkgbuild.top_level_command`.
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    pub packages: Vec<ResolvedPackage>,
    pub recipe_files: Vec<RecipeFile>,
    /// Steps that could not be resolved safely; each makes the scan incomplete.
    pub unresolved: Vec<String>,
    pub notes: Vec<String>,
    /// `(file_name, detached signature bytes)` published inside repository
    /// metadata (pacman `%PGPSIG%`).
    pub embedded_signatures: Vec<(String, Vec<u8>)>,
    pub source_headers: Vec<SourceHeaders>,
    pub observations: Vec<Observation>,
}

impl Resolution {
    fn observe(
        &mut self,
        package: &str,
        file: Option<&str>,
        kind: &str,
        detail: impl Into<String>,
    ) {
        self.observations.push(Observation {
            package: package.to_string(),
            file: file.map(str::to_string),
            kind: kind.to_string(),
            detail: detail.into(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("{0}")]
    ManagerUnavailable(String),
    #[error("host configuration: {0}")]
    HostConfig(String),
    #[error("fetching {url}: {error}")]
    Fetch { url: String, error: FetchError },
    #[error("{0}")]
    RateLimited(String),
    #[error("malformed response from {url}: {message}")]
    Malformed { url: String, message: String },
    #[error("unsupported request: {0}")]
    Unsupported(String),
}

/// Resolve a parsed request into artifacts, recipe files and unresolved steps.
///
/// Default dependency scope is the named packages only: declared dependencies
/// are listed in `ResolvedPackage::dependencies` but not resolved. Per-package
/// problems (not found, dynamic sources…) land in `unresolved`; only failures
/// that make the whole request meaningless return `Err`.
pub fn resolve(
    req: &PackageRequest,
    fetcher: &dyn Fetcher,
    host: &dyn HostCommands,
    info: &HostInfo,
) -> Result<Resolution, ResolveError> {
    if req.operation != "install" {
        return Err(ResolveError::Unsupported(format!(
            "operation `{}` (only `install` is supported)",
            req.operation
        )));
    }
    let mut res = Resolution::default();
    match req.manager {
        Manager::Pacman => pacman::resolve(req, info, &mut res)?,
        Manager::Aur => aur::resolve(req, fetcher, info, &mut res)?,
        Manager::Apt => apt::resolve(req, host, info, &mut res)?,
        Manager::Dnf => dnf::resolve(req, host, info, &mut res)?,
        Manager::Homebrew => brew::resolve(req, fetcher, info, &mut res)?,
        Manager::Winget => winget::resolve(req, fetcher, info, &mut res)?,
        Manager::Scoop => scoop::resolve(req, fetcher, info, &mut res)?,
        Manager::Chocolatey => choco::resolve(req, fetcher, &mut res)?,
    }
    res.notes.push(
        "dependency scope: named packages only; declared dependencies are listed but were not resolved or inspected"
            .to_string(),
    );
    Ok(res)
}

/// Shared helper: fetch, turning transport problems into `ResolveError` and
/// 404 into `Ok(None)`.
pub(crate) fn fetch_opt(
    fetcher: &dyn Fetcher,
    url: &str,
    headers: &[(&str, &str)],
    max_bytes: u64,
) -> Result<Option<Fetched>, ResolveError> {
    match fetcher.get(url, headers, max_bytes) {
        Ok(f) => Ok(Some(f)),
        Err(FetchError::Status { code: 404, .. }) | Err(FetchError::Status { code: 410, .. }) => {
            Ok(None)
        }
        Err(error) => Err(ResolveError::Fetch {
            url: url.to_string(),
            error,
        }),
    }
}

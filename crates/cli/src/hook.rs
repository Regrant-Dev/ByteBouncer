//! pacman PreTransaction hook. Runs as root, so it never
//! analyzes anything: it only checks that each package pacman is about to
//! install has an approval record for its exact SHA-256, created earlier by
//! the user with `bytebouncer approve`. Default mode warns; `enforce` aborts
//! the transaction. Configuration lives in a root-owned file.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bytebouncer_adapters::{FetchError, Fetched, Fetcher, HostInfo, NoHostCommands};
use bytebouncer_core::{Manager, PackageRequest};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::approve;

pub const HOOK_CONFIG: &str = "/etc/bytebouncer/pacman-hook.toml";

pub const HOOK_FILE: &str = "\
# ByteBouncer approval check. Install as /etc/pacman.d/hooks/00-bytebouncer.hook
# and configure /etc/bytebouncer/pacman-hook.toml (see `bytebouncer pacman-hook --help`).
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = Checking ByteBouncer approvals...
When = PreTransaction
Exec = /usr/bin/bytebouncer pacman-hook
NeedsTargets
AbortOnFail
";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookConfig {
    /// `warn` (default) or `enforce`.
    mode: Option<String>,
    /// The approving user's approvals directory, e.g.
    /// /home/alice/.local/share/bytebouncer/approvals
    approvals_dir: PathBuf,
    /// Extra package cache directories to search (pacman's CacheDir is always used).
    #[serde(default)]
    cache_dirs: Vec<PathBuf>,
}

/// Sync-DB lookups never need the network.
struct Offline;

impl Fetcher for Offline {
    fn get(&self, url: &str, _: &[(&str, &str)], _: u64) -> Result<Fetched, FetchError> {
        Err(FetchError::Denied(format!(
            "{url}: the pacman hook never uses the network"
        )))
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).ok()?;
    Some(hex::encode(h.finalize()))
}

/// Find the package file pacman will install for `name`: the sync DB says
/// which file name and digest to expect.
fn expected_file(name: &str, info: &HostInfo, cache_dirs: &[PathBuf]) -> Option<(PathBuf, String)> {
    let req = PackageRequest {
        manager: Manager::Pacman,
        operation: "install".into(),
        packages: vec![name.into()],
        options: vec![],
        raw: format!("pacman -S {name}"),
    };
    let res = bytebouncer_adapters::resolve(&req, &Offline, &NoHostCommands, info).ok()?;
    let src = res.packages.first()?.sources.first()?.clone();
    let expected = src.expected_sha256?;
    cache_dirs
        .iter()
        .map(|d| d.join(&src.file_name))
        .find(|p| p.is_file())
        .map(|p| (p, expected))
}

pub fn run() -> Result<i32> {
    // The override exists for testing; whoever controls root's environment
    // already controls the transaction.
    let path = std::env::var("BYTEBOUNCER_HOOK_CONFIG").unwrap_or_else(|_| HOOK_CONFIG.into());
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let cfg: HookConfig = toml::from_str(&text).with_context(|| format!("parsing {path}"))?;
    let enforce = match cfg.mode.as_deref() {
        None | Some("warn") => false,
        Some("enforce") => true,
        Some(other) => anyhow::bail!("{HOOK_CONFIG}: mode must be warn or enforce, not {other}"),
    };
    let info = HostInfo::detect();
    let mut cache_dirs = vec![PathBuf::from("/var/cache/pacman/pkg")];
    cache_dirs.extend(cfg.cache_dirs);

    let mut problems = 0;
    for line in std::io::stdin().lock().lines() {
        let name = line?.trim().to_owned();
        if name.is_empty() {
            continue;
        }
        let verdict = match expected_file(&name, &info, &cache_dirs) {
            None => Err(format!(
                "{name}: package file not found in the cache or sync DB (local/AUR package?)"
            )),
            Some((path, expected)) => match sha256_file(&path) {
                Some(actual) if actual != expected => Err(format!(
                    "{name}: cached file does not match the sync DB digest"
                )),
                None => Err(format!("{name}: cannot read {}", path.display())),
                Some(actual) => match approve::lookup(&cfg.approvals_dir, &actual) {
                    Some(a) => Ok(format!("{name}: approved (report {})", a.report_id)),
                    None => Err(format!(
                        "{name}: not approved; run `bytebouncer inspect \"pacman -S {name}\"` and `bytebouncer approve <report>`"
                    )),
                },
            },
        };
        match verdict {
            Ok(msg) => println!("  {msg}"),
            Err(msg) => {
                problems += 1;
                println!("  {}: {msg}", if enforce { "BLOCKED" } else { "warning" });
            }
        }
    }
    Ok(if enforce && problems > 0 { 1 } else { 0 })
}

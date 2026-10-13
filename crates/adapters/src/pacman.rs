//! pacman: resolve repository packages from the local sync databases.
//! File reads go through [`crate::host`]; everything else here is pure.

use std::collections::BTreeMap;
use std::path::PathBuf;

use bytebouncer_core::{PackageRequest, ResolvedPackage};

use crate::host;
use crate::tarball::{self, Limits};
use crate::util::{self, source_ref};
use crate::{HostInfo, Resolution, ResolveError};

/// Sync DBs older than this get a staleness warning.
const STALE_DAYS: i64 = 7;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoConf {
    pub name: String,
    pub servers: Vec<String>,
    pub includes: Vec<String>,
    pub sig_level: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacmanConf {
    pub db_path: Option<String>,
    pub architecture: Option<String>,
    pub repos: Vec<RepoConf>,
}

/// Parse pacman.conf: `[options]` keys we need and every enabled repository
/// section in order. `Include` inside `[options]` is not followed.
pub fn parse_pacman_conf(text: &str) -> PacmanConf {
    let mut conf = PacmanConf::default();
    let mut section: Option<String> = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.trim().to_string();
            if name != "options" {
                conf.repos.push(RepoConf {
                    name: name.clone(),
                    ..Default::default()
                });
            }
            section = Some(name);
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (line, ""),
        };
        match section.as_deref() {
            Some("options") => match key {
                "DBPath" => conf.db_path = Some(value.to_string()),
                "Architecture" => {
                    conf.architecture = value.split_whitespace().next().map(str::to_string)
                }
                _ => {}
            },
            Some(_) => {
                if let Some(repo) = conf.repos.last_mut() {
                    match key {
                        "Server" => repo.servers.push(value.to_string()),
                        "Include" => repo.includes.push(value.to_string()),
                        "SigLevel" => repo.sig_level = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
            None => {}
        }
    }
    conf
}

pub fn parse_mirrorlist(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let (k, v) = l.split_once('=')?;
            (k.trim() == "Server").then(|| v.trim().to_string())
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbPackage {
    pub name: String,
    pub base: Option<String>,
    pub version: String,
    pub filename: String,
    pub sha256: Option<String>,
    pub pgpsig: Option<String>,
    pub arch: String,
    pub depends: Vec<String>,
    pub provides: Vec<String>,
    pub groups: Vec<String>,
    pub csize: Option<u64>,
}

/// Parse one `desc` entry (`%KEY%` header followed by value lines).
pub fn parse_desc(text: &str) -> DbPackage {
    let mut fields: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut key: Option<&str> = None;
    for line in text.lines() {
        if line.len() > 2 && line.starts_with('%') && line.ends_with('%') {
            key = Some(&line[1..line.len() - 1]);
            fields.entry(key.unwrap_or_default()).or_default();
        } else if line.is_empty() {
            key = None;
        } else if let Some(k) = key {
            fields.entry(k).or_default().push(line);
        }
    }
    let one = |k: &str| fields.get(k).and_then(|v| v.first()).map(|s| s.to_string());
    let many = |k: &str| {
        fields
            .get(k)
            .map(|v| v.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    };
    DbPackage {
        name: one("NAME").unwrap_or_default(),
        base: one("BASE"),
        version: one("VERSION").unwrap_or_default(),
        filename: one("FILENAME").unwrap_or_default(),
        sha256: one("SHA256SUM").and_then(|s| util::hex_digest(&s, 64)),
        pgpsig: one("PGPSIG"),
        arch: one("ARCH").unwrap_or_default(),
        depends: many("DEPENDS"),
        provides: many("PROVIDES"),
        groups: many("GROUPS"),
        csize: one("CSIZE").and_then(|s| s.parse().ok()),
    }
}

/// Parse a sync DB archive (`name-ver-rel/desc` entries).
pub fn parse_sync_db(bytes: &[u8]) -> Result<Vec<DbPackage>, String> {
    let limits = Limits {
        max_entries: 2_000_000,
        max_total: 512 * 1024 * 1024,
        max_file: 4 * 1024 * 1024,
        max_stream: 2 * 1024 * 1024 * 1024,
    };
    let contents = tarball::read_tar(bytes, limits, &|p| p.ends_with("/desc"))?;
    Ok(contents
        .files
        .iter()
        .map(|(_, b)| parse_desc(&String::from_utf8_lossy(b)))
        .filter(|p| !p.name.is_empty())
        .collect())
}

pub struct SyncRepo {
    pub name: String,
    pub server: Option<String>,
    pub sig_level: Option<String>,
    pub packages: Vec<DbPackage>,
}

pub struct SyncDbs {
    pub repos: Vec<SyncRepo>,
}

pub enum Lookup<'a> {
    Found(&'a SyncRepo, &'a DbPackage),
    ViaProvides(&'a SyncRepo, &'a DbPackage),
    Ambiguous(Vec<String>),
    Group(Vec<String>),
    NotFound,
}

fn provides_name(p: &str) -> &str {
    p.split(['=', '<', '>']).next().unwrap_or(p)
}

impl SyncDbs {
    /// Load configuration and every enabled repo's sync DB. Returns `Ok(None)`
    /// when the host has no pacman configuration at all.
    pub fn load(info: &HostInfo, res: &mut Resolution) -> Result<Option<SyncDbs>, ResolveError> {
        let Some(conf_path) = info.pacman_conf.clone() else {
            return Ok(None);
        };
        let conf_text = host::read_text(&conf_path).map_err(ResolveError::HostConfig)?;
        let conf = parse_pacman_conf(&conf_text);
        let arch = match conf.architecture.as_deref() {
            Some(a) if a != "auto" => a.to_string(),
            _ => info.arch.clone(),
        };
        let db_root = info
            .pacman_db_path
            .clone()
            .or_else(|| conf.db_path.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(host::DEFAULT_DB_PATH));
        let now = host::now_unix();
        let mut repos = Vec::new();
        for rc in &conf.repos {
            let mut servers = rc.servers.clone();
            for inc in &rc.includes {
                let path = match &info.mirrorlist {
                    Some(m) if inc == host::DEFAULT_MIRRORLIST => m.clone(),
                    _ => PathBuf::from(inc),
                };
                match host::read_text(&path) {
                    Ok(t) => servers.extend(parse_mirrorlist(&t)),
                    Err(e) => res.notes.push(format!("pacman: cannot read include {e}")),
                }
            }
            let server = servers.first().map(|s| {
                s.replace("$repo", &rc.name)
                    .replace("$arch", &arch)
                    .trim_end_matches('/')
                    .to_string()
            });
            let db_file = db_root.join("sync").join(format!("{}.db", rc.name));
            let (bytes, mtime) = match host::read_db(&db_file) {
                Ok(v) => v,
                Err(e) => {
                    res.notes.push(format!(
                        "pacman: repository [{}] has no readable sync DB ({e}); run `pacman -Sy` yourself if this is unexpected",
                        rc.name
                    ));
                    continue;
                }
            };
            let packages = parse_sync_db(&bytes)
                .map_err(|e| ResolveError::HostConfig(format!("{}: {e}", db_file.display())))?;
            if let Some(m) = mtime {
                let age = (now - m) / 86_400;
                let stale = if age >= STALE_DAYS {
                    " — STALE: the mirror may no longer serve these files; refresh with `pacman -Sy` (ByteBouncer never does)"
                } else {
                    ""
                };
                res.notes.push(format!(
                    "pacman: sync DB {}.db last updated {} ({age} days ago){stale}",
                    rc.name,
                    util::ymd(m)
                ));
            }
            repos.push(SyncRepo {
                name: rc.name.clone(),
                server,
                sig_level: rc.sig_level.clone(),
                packages,
            });
        }
        Ok(Some(SyncDbs { repos }))
    }

    pub fn lookup(&self, repo: Option<&str>, name: &str) -> Lookup<'_> {
        let repos: Vec<&SyncRepo> = self
            .repos
            .iter()
            .filter(|r| repo.is_none_or(|n| r.name == n))
            .collect();
        for r in &repos {
            if let Some(p) = r.packages.iter().find(|p| p.name == name) {
                return Lookup::Found(r, p);
            }
        }
        let mut providers = Vec::new();
        for r in &repos {
            for p in &r.packages {
                if p.provides.iter().any(|pr| provides_name(pr) == name) {
                    providers.push((*r, p));
                }
            }
        }
        match providers.len() {
            1 => return Lookup::ViaProvides(providers[0].0, providers[0].1),
            n if n > 1 => {
                return Lookup::Ambiguous(
                    providers
                        .iter()
                        .map(|(r, p)| format!("{}/{}", r.name, p.name))
                        .collect(),
                );
            }
            _ => {}
        }
        let members: Vec<String> = repos
            .iter()
            .flat_map(|r| r.packages.iter().map(move |p| (r, p)))
            .filter(|(_, p)| p.groups.iter().any(|g| g == name))
            .map(|(r, p)| format!("{}/{}", r.name, p.name))
            .collect();
        if !members.is_empty() {
            return Lookup::Group(members);
        }
        Lookup::NotFound
    }
}

/// Append a resolved repo package to the resolution.
pub fn push_db_package(repo: &SyncRepo, pkg: &DbPackage, res: &mut Resolution) {
    let mut sources = Vec::new();
    if pkg.filename.is_empty() || pkg.filename.contains('/') {
        res.unresolved.push(format!(
            "pacman: {}/{} has no usable %FILENAME% in the sync DB",
            repo.name, pkg.name
        ));
    } else if let Some(server) = &repo.server {
        let url = format!("{server}/{}", pkg.filename);
        let mut s = source_ref(&url, Some(&pkg.filename));
        s.expected_sha256 = pkg.sha256.clone();
        s.signature_url = Some(format!("{url}.sig"));
        if s.expected_sha256.is_none() {
            res.notes.push(format!(
                "pacman: {} has no %SHA256SUM% in the sync DB; rely on its signature",
                pkg.name
            ));
        }
        sources.push(s);
    } else {
        res.unresolved.push(format!(
            "pacman: repository [{}] has no Server configured; cannot locate {}",
            repo.name, pkg.filename
        ));
    }
    match pkg.pgpsig.as_deref().map(util::b64_decode) {
        Some(Some(sig)) => res
            .embedded_signatures
            .push((format!("{}.sig", pkg.filename), sig)),
        Some(None) => res.notes.push(format!(
            "pacman: {} has an undecodable %PGPSIG% in the sync DB",
            pkg.name
        )),
        None => {}
    }
    if let Some(level) = &repo.sig_level {
        res.notes
            .push(format!("pacman: [{}] SigLevel = {level}", repo.name));
    }
    res.packages.push(ResolvedPackage {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        arch: Some(pkg.arch.clone()),
        repository: Some(repo.name.clone()),
        sources,
        recipe_files: Vec::new(),
        dependencies: pkg.depends.clone(),
    });
}

pub fn split_repo(spec: &str) -> (Option<&str>, &str) {
    match spec.split_once('/') {
        Some((r, n)) => (Some(r), n),
        None => (None, spec),
    }
}

/// Outcome of trying one name against the sync repos (shared with AUR).
pub enum RepoOutcome {
    Resolved,
    NotFound,
}

pub fn resolve_one(dbs: &SyncDbs, spec: &str, res: &mut Resolution) -> RepoOutcome {
    let (repo, name) = split_repo(spec);
    match dbs.lookup(repo, name) {
        Lookup::Found(r, p) => {
            push_db_package(r, p, res);
            RepoOutcome::Resolved
        }
        Lookup::ViaProvides(r, p) => {
            res.notes.push(format!(
                "pacman: `{name}` is provided by {}/{}; pacman would install that package",
                r.name, p.name
            ));
            push_db_package(r, p, res);
            RepoOutcome::Resolved
        }
        Lookup::Ambiguous(list) => {
            res.unresolved.push(format!(
                "pacman: `{name}` is provided by several packages ({}); pacman would ask — request one explicitly",
                list.join(", ")
            ));
            RepoOutcome::Resolved
        }
        Lookup::Group(members) => {
            res.unresolved.push(format!(
                "pacman: `{name}` is a package group ({} members: {}); request members explicitly",
                members.len(),
                util::excerpt(&members.join(", "), 400)
            ));
            RepoOutcome::Resolved
        }
        Lookup::NotFound => RepoOutcome::NotFound,
    }
}

pub fn resolve(
    req: &PackageRequest,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let Some(dbs) = SyncDbs::load(info, res)? else {
        return Err(ResolveError::ManagerUnavailable(
            "pacman is not configured on this host (no pacman.conf)".to_string(),
        ));
    };
    if dbs.repos.is_empty() {
        return Err(ResolveError::HostConfig(
            "no pacman sync databases could be read".to_string(),
        ));
    }
    for spec in &req.packages {
        let (repo, _) = split_repo(spec);
        if let Some(r) = repo
            && !dbs.repos.iter().any(|x| x.name == r)
        {
            res.unresolved.push(format!(
                "pacman: repository `{r}` is not enabled in pacman.conf"
            ));
            continue;
        }
        if let RepoOutcome::NotFound = resolve_one(&dbs, spec, res) {
            res.unresolved
                .push(format!("pacman: target not found in sync DBs: {spec}"));
        }
    }
    Ok(())
}

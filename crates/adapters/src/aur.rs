//! yay/paru: sync repositories first (like the helpers), then the AUR. AUR
//! recipe files are retrieved as DATA (snapshot tarball) and the PKGBUILD is
//! read statically with [`crate::pkgbuild`]. Nothing is sourced or built.

use std::collections::BTreeMap;

use bytebouncer_core::{PackageRequest, ResolvedPackage, SourceRef};
use serde_json::Value as Json;

use crate::pacman::{self, RepoOutcome, SyncDbs};
use crate::pkgbuild::{self, Expanded, Pkgbuild, SrcInfo};
use crate::tarball::{self, Limits};
use crate::util::{self, excerpt, percent_encode};
use crate::{Fetcher, HostInfo, RecipeFile, Resolution, ResolveError, fetch_opt};

pub const AUR_BASE: &str = "https://aur.archlinux.org";
const MAX_RPC: u64 = 4 * 1024 * 1024;
const MAX_SNAPSHOT: u64 = 32 * 1024 * 1024;

const VCS_PREFIXES: &[&str] = &[
    "git+", "git://", "hg+", "svn+", "svn://", "bzr+", "bzr://", "fossil+",
];
const CHECKSUM_ALGOS: &[&str] = &[
    "sha256sums",
    "sha512sums",
    "b2sums",
    "sha384sums",
    "sha224sums",
    "sha1sums",
    "md5sums",
    "cksums",
];

pub fn resolve(
    req: &PackageRequest,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let dbs = SyncDbs::load(info, res)?;
    if dbs.is_none() {
        res.notes.push(
            "aur: no local pacman configuration; skipped the sync-repository lookup that yay/paru perform first"
                .to_string(),
        );
    }
    for spec in &req.packages {
        let (repo, name) = pacman::split_repo(spec);
        if repo != Some("aur") {
            if let Some(dbs) = &dbs
                && let RepoOutcome::Resolved = pacman::resolve_one(dbs, spec, res)
            {
                continue;
            }
            if let Some(r) = repo {
                res.unresolved
                    .push(format!("{spec}: not found in repository `{r}`"));
                continue;
            }
        }
        resolve_aur(name, fetcher, info, res)?;
    }
    Ok(())
}

fn resolve_aur(
    name: &str,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let rpc_url = format!("{AUR_BASE}/rpc/v5/info?arg%5B%5D={}", percent_encode(name));
    let Some(f) = fetch_opt(fetcher, &rpc_url, &[], MAX_RPC)? else {
        res.unresolved
            .push(format!("aur: RPC returned 404 for {name}"));
        return Ok(());
    };
    let json: Json = serde_json::from_slice(&f.bytes).map_err(|e| ResolveError::Malformed {
        url: rpc_url.clone(),
        message: e.to_string(),
    })?;
    if json["type"] == "error" {
        res.unresolved.push(format!(
            "aur: RPC error for {name}: {}",
            excerpt(json["error"].as_str().unwrap_or("unknown"), 200)
        ));
        return Ok(());
    }
    let Some(meta) = json["results"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["Name"] == name))
    else {
        res.unresolved.push(format!(
            "aur: target not found in sync repositories or the AUR: {name}"
        ));
        return Ok(());
    };
    let base = meta["PackageBase"].as_str().unwrap_or(name).to_string();
    let rpc_version = meta["Version"].as_str().unwrap_or("").to_string();
    if !meta["OutOfDate"].is_null() {
        res.notes
            .push(format!("aur: {name} is flagged out-of-date"));
    }
    if meta["Maintainer"].is_null() {
        res.notes
            .push(format!("aur: {name} is orphaned (no maintainer)"));
    }
    if let Some(m) = meta["LastModified"].as_i64() {
        res.notes.push(format!(
            "aur: {name} {rpc_version} (base {base}) last modified {}; votes {}, popularity {}",
            util::ymd(m),
            meta["NumVotes"],
            meta["Popularity"]
        ));
    }

    let snapshot_url = match meta["URLPath"].as_str() {
        Some(p) if p.starts_with("/cgit/aur.git/snapshot/") && !p.contains("..") => {
            format!("{AUR_BASE}{p}")
        }
        _ => format!(
            "{AUR_BASE}/cgit/aur.git/snapshot/{}.tar.gz",
            percent_encode(&base)
        ),
    };
    let Some(snap) = fetch_opt(fetcher, &snapshot_url, &[], MAX_SNAPSHOT)? else {
        res.unresolved
            .push(format!("aur: snapshot not found: {snapshot_url}"));
        return Ok(());
    };
    let limits = Limits {
        max_entries: 2_000,
        max_total: 24 * 1024 * 1024,
        max_file: 16 * 1024 * 1024,
        max_stream: 256 * 1024 * 1024,
    };
    let contents = match tarball::read_tar(&snap.bytes, limits, &|_| true) {
        Ok(c) => c,
        Err(e) => {
            res.unresolved
                .push(format!("aur: cannot read snapshot {snapshot_url}: {e}"));
            return Ok(());
        }
    };
    for s in &contents.skipped {
        res.notes
            .push(format!("aur: {base} snapshot entry skipped: {s}"));
    }
    let prefix = format!("{base}/");
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (path, bytes) in contents.files {
        let rel = path.strip_prefix(&prefix).unwrap_or(&path).to_string();
        files.insert(rel, bytes);
    }
    let recipe_paths: Vec<String> = files.keys().cloned().collect();
    for (path, bytes) in &files {
        res.recipe_files.push(RecipeFile {
            package: name.to_string(),
            path: path.clone(),
            bytes: bytes.clone(),
            origin: format!("{snapshot_url}#{path}"),
        });
    }

    let Some(pkgbuild_bytes) = files.get("PKGBUILD") else {
        res.unresolved
            .push(format!("aur: {base} snapshot has no PKGBUILD"));
        return Ok(());
    };
    let text = String::from_utf8_lossy(pkgbuild_bytes);
    let pb = match pkgbuild::parse_pkgbuild(&text) {
        Ok(pb) => pb,
        Err(e) => {
            res.unresolved.push(format!("aur: {base}: {e}"));
            res.observe(name, Some("PKGBUILD"), "pkgbuild.parse_error", e);
            return Ok(());
        }
    };
    let srcinfo = files
        .get(".SRCINFO")
        .map(|b| pkgbuild::parse_srcinfo(&String::from_utf8_lossy(b)));
    if srcinfo.is_none() {
        res.notes.push(format!(
            "aur: {base} snapshot has no .SRCINFO to cross-check"
        ));
    }

    let arch = info.arch.as_str();
    for cmd in &pb.top_level_commands {
        res.observe(
            name,
            Some("PKGBUILD"),
            "pkgbuild.top_level_command",
            format!(
                "runs whenever the PKGBUILD is sourced (even by `makepkg --printsrcinfo`): {cmd}"
            ),
        );
    }
    if !pb.top_level_commands.is_empty() {
        res.notes.push(format!(
            "aur: {base}: PKGBUILD has {} top-level command(s) that execute when it is sourced; extracted values assume they do not change variables",
            pb.top_level_commands.len()
        ));
    }
    if !pb.functions.is_empty() {
        res.notes.push(format!(
            "aur: {base}: PKGBUILD functions (run during build, not inspected here): {}",
            pb.functions.join(", ")
        ));
    }
    if pb.functions.iter().any(|f| f == "pkgver") {
        res.notes.push(format!(
            "aur: {base}: defines pkgver(), so the built version is computed at build time"
        ));
    }

    // Identity.
    let version = pkg_version(&pb);
    let version = match version {
        Ok(v) => {
            if !rpc_version.is_empty() && v != rpc_version {
                res.notes.push(format!(
                    "aur: {base}: PKGBUILD version {v} differs from AUR metadata {rpc_version}"
                ));
            }
            v
        }
        Err(e) => {
            res.notes.push(format!(
                "aur: {base}: PKGBUILD version is not literal ({e}); using AUR metadata {rpc_version}"
            ));
            rpc_version.clone()
        }
    };
    let arches = pb.literal_array("arch");
    let pkg_arch = if arches.iter().any(|a| a == "any") {
        Some("any".to_string())
    } else if arches.iter().any(|a| a == arch) {
        Some(arch.to_string())
    } else {
        res.unresolved.push(format!(
            "aur: {base}: PKGBUILD arch=({}) does not include host architecture {arch}",
            arches.join(" ")
        ));
        None
    };
    let pkgnames = pb.literal_array("pkgname");
    if pkgnames.len() > 1 {
        res.notes.push(format!(
            "aur: {base} is a split package ({}); per-package metadata inside package_*() functions is not extracted",
            pkgnames.join(", ")
        ));
    }

    // install scriptlet
    if let Some(install) = pb.scalar("install") {
        match install {
            Ok(f) if files.contains_key(&f) => res.notes.push(format!(
                "aur: {base}: install scriptlet `{f}` runs as root on install (included as a recipe file)"
            )),
            Ok(f) => res.unresolved.push(format!(
                "aur: {base}: install scriptlet `{f}` is not in the snapshot"
            )),
            Err(e) => res
                .unresolved
                .push(format!("aur: {base}: install= is not literal: {e}")),
        }
    }

    // Dependencies.
    let mut dependencies = Vec::new();
    for key in ["depends".to_string(), format!("depends_{arch}")] {
        collect_list(&pb, &key, &mut dependencies, res, &base);
    }
    if dependencies.is_empty() {
        dependencies = json_strs(&meta["Depends"]);
    }
    let mut make = Vec::new();
    for key in [
        "makedepends".to_string(),
        format!("makedepends_{arch}"),
        "checkdepends".to_string(),
    ] {
        collect_list(&pb, &key, &mut make, res, &base);
    }
    if !make.is_empty() {
        res.notes.push(format!(
            "aur: {base}: build-time dependencies (not inspected): {}",
            make.join(", ")
        ));
    }

    // Sources.
    let sources = collect_sources(&pb, arch, &files, srcinfo.as_ref(), &base, res);
    if let Some(keys) = pb.array("validpgpkeys") {
        let keys: Vec<String> = keys.into_iter().filter_map(Result::ok).collect();
        if !keys.is_empty() {
            res.notes.push(format!(
                "aur: {base}: validpgpkeys (not auto-trusted): {}",
                keys.join(", ")
            ));
        }
    }
    let other_arches: Vec<&String> = pb
        .vars
        .keys()
        .filter(|k| k.starts_with("source_") && **k != format!("source_{arch}"))
        .collect();
    if !other_arches.is_empty() {
        res.notes.push(format!(
            "aur: {base}: sources for other architectures not considered: {}",
            other_arches
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if let Some(si) = &srcinfo {
        cross_check(&pb, si, arch, name, &base, res);
    }

    res.packages.push(ResolvedPackage {
        name: name.to_string(),
        version,
        arch: pkg_arch,
        repository: Some("aur".to_string()),
        sources,
        recipe_files: recipe_paths,
        dependencies,
    });
    Ok(())
}

fn pkg_version(pb: &Pkgbuild) -> Result<String, String> {
    let ver = pb.scalar("pkgver").ok_or("pkgver missing")??;
    let rel = pb.scalar("pkgrel").ok_or("pkgrel missing")??;
    match pb.scalar("epoch") {
        Some(Ok(e)) if !e.is_empty() && e != "0" => Ok(format!("{e}:{ver}-{rel}")),
        Some(Err(e)) => Err(e),
        _ => Ok(format!("{ver}-{rel}")),
    }
}

fn collect_list(pb: &Pkgbuild, key: &str, out: &mut Vec<String>, res: &mut Resolution, base: &str) {
    for v in pb.array(key).unwrap_or_default() {
        match v {
            Ok(s) => {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            Err(e) => res
                .unresolved
                .push(format!("aur: {base}: {key} entry is not literal: {e}")),
        }
    }
}

fn json_strs(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn checksum_at(pb: &Pkgbuild, algo: &str, suffix: &str, i: usize) -> Option<Expanded> {
    let key = if suffix.is_empty() {
        algo.to_string()
    } else {
        format!("{algo}_{suffix}")
    };
    pb.array(&key).and_then(|a| a.get(i).cloned())
}

fn collect_sources(
    pb: &Pkgbuild,
    arch: &str,
    files: &BTreeMap<String, Vec<u8>>,
    srcinfo: Option<&SrcInfo>,
    base: &str,
    res: &mut Resolution,
) -> Vec<SourceRef> {
    let mut out: Vec<SourceRef> = Vec::new();
    for suffix in ["", arch] {
        let key = if suffix.is_empty() {
            "source".to_string()
        } else {
            format!("source_{suffix}")
        };
        let Some(entries) = pb.array(&key) else {
            continue;
        };
        // Checksum array length sanity.
        for algo in CHECKSUM_ALGOS {
            let ck = if suffix.is_empty() {
                algo.to_string()
            } else {
                format!("{algo}_{suffix}")
            };
            if let Some(a) = pb.array(&ck)
                && a.len() != entries.len()
            {
                res.notes.push(format!(
                    "aur: {base}: {ck} has {} entries but {key} has {}",
                    a.len(),
                    entries.len()
                ));
            }
        }
        let srcinfo_vals = srcinfo.map(|s| s.base_values(&key)).unwrap_or_default();
        for (i, entry) in entries.iter().enumerate() {
            let entry = match entry {
                Ok(e) => e.clone(),
                Err(reason) => {
                    let hint = srcinfo_vals
                        .get(i)
                        .map(|v| format!("; .SRCINFO claims `{}` (not trusted)", excerpt(v, 120)))
                        .unwrap_or_default();
                    res.unresolved.push(format!(
                        "aur: {base}: {key}[{i}] cannot be determined statically: {reason}{hint}"
                    ));
                    continue;
                }
            };
            let (fname, location) = match entry.split_once("::") {
                Some((n, u)) => (Some(n.to_string()), u.to_string()),
                None => (None, entry.clone()),
            };
            let lower = location.to_ascii_lowercase();
            if VCS_PREFIXES.iter().any(|p| lower.starts_with(p)) {
                res.unresolved.push(format!(
                    "aur: {base}: {key}[{i}] `{}`: VCS sources not supported in this version",
                    excerpt(&location, 160)
                ));
                continue;
            }
            if location.contains("://") {
                if !util::is_http_url(&location) {
                    res.unresolved.push(format!(
                        "aur: {base}: {key}[{i}] `{}`: unsupported download protocol",
                        excerpt(&location, 160)
                    ));
                    continue;
                }
                let mut s = util::source_ref(&location, fname.as_deref());
                let mut weak = Vec::new();
                for algo in CHECKSUM_ALGOS {
                    let Some(v) = checksum_at(pb, algo, suffix, i) else {
                        continue;
                    };
                    match v {
                        Ok(v) if v == "SKIP" => {}
                        Ok(v) => match *algo {
                            "sha256sums" => match util::hex_digest(&v, 64) {
                                Some(h) => s.expected_sha256 = Some(h),
                                None => res.notes.push(format!(
                                    "aur: {base}: malformed sha256 `{}` for {key}[{i}]",
                                    excerpt(&v, 80)
                                )),
                            },
                            "sha512sums" => s.expected_sha512 = util::hex_digest(&v, 128),
                            other => weak.push(format!("{other}={}", excerpt(&v, 140))),
                        },
                        Err(e) => res.unresolved.push(format!(
                            "aur: {base}: {algo} for {key}[{i}] is not literal: {e}"
                        )),
                    }
                }
                if s.expected_sha256.is_none() && s.expected_sha512.is_none() {
                    let extra = if weak.is_empty() {
                        "no checksum (SKIP or missing)".to_string()
                    } else {
                        format!("only {}", weak.join(", "))
                    };
                    res.notes.push(format!(
                        "aur: {base}: {} has no SHA-256/512 to verify against ({extra})",
                        s.file_name
                    ));
                } else if !weak.is_empty() {
                    res.notes.push(format!(
                        "aur: {base}: {} also declares {} (recorded, not used)",
                        s.file_name,
                        weak.join(", ")
                    ));
                }
                out.push(s);
            } else {
                // Local file shipped in the AUR repository.
                let local = fname.unwrap_or(location);
                if files.contains_key(&local) {
                    continue; // already a recipe file
                }
                res.unresolved.push(format!(
                    "aur: {base}: local source `{}` is not in the AUR snapshot",
                    excerpt(&local, 120)
                ));
            }
        }
    }
    // Pair detached signatures with the artifact they sign.
    let sig_ext = [".sig", ".asc", ".sign"];
    let urls: Vec<String> = out.iter().map(|s| s.url.clone()).collect();
    let mut keep = Vec::new();
    for s in out {
        let target = sig_ext
            .iter()
            .find_map(|e| s.url.strip_suffix(e))
            .filter(|t| urls.iter().any(|u| u == t));
        match target {
            Some(_) => keep.push((s, true)),
            None => keep.push((s, false)),
        }
    }
    let sigs: Vec<(String, String)> = keep
        .iter()
        .filter(|(_, is_sig)| *is_sig)
        .map(|(s, _)| {
            let t = sig_ext
                .iter()
                .find_map(|e| s.url.strip_suffix(e))
                .unwrap_or_default()
                .to_string();
            (t, s.url.clone())
        })
        .collect();
    keep.into_iter()
        .filter(|(_, is_sig)| !is_sig)
        .map(|(mut s, _)| {
            if let Some((_, sig)) = sigs.iter().find(|(t, _)| *t == s.url) {
                s.signature_url = Some(sig.clone());
            }
            s
        })
        .collect()
}

/// Compare what the PKGBUILD statically says with .SRCINFO (which is what
/// the AUR web UI and RPC show). Disagreement is itself suspicious.
fn cross_check(
    pb: &Pkgbuild,
    si: &SrcInfo,
    arch: &str,
    name: &str,
    base: &str,
    res: &mut Resolution,
) {
    let mut keys: Vec<String> = [
        "pkgver",
        "pkgrel",
        "epoch",
        "source",
        "sha256sums",
        "sha512sums",
        "depends",
        "makedepends",
        "install",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    keys.push(format!("source_{arch}"));
    keys.push(format!("sha256sums_{arch}"));
    keys.push(format!("depends_{arch}"));
    for key in keys {
        let si_vals = si.base_values(&key);
        let pb_vals = pb.array(&key);
        let pb_vals: Vec<Expanded> = pb_vals.unwrap_or_default();
        if pb_vals.is_empty() && si_vals.is_empty() {
            continue;
        }
        if key == "pkgver" && pb.functions.iter().any(|f| f == "pkgver") {
            continue;
        }
        if pb_vals.iter().any(|v| v.is_err()) {
            if !si_vals.is_empty() {
                res.notes.push(format!(
                    "aur: {base}: `{key}` is dynamic in PKGBUILD; .SRCINFO claims {} — the claim cannot be verified statically",
                    excerpt(&si_vals.join(" "), 200)
                ));
            }
            continue;
        }
        let pb_lit: Vec<String> = pb_vals.into_iter().filter_map(Result::ok).collect();
        let (a, b) = if key == "epoch" {
            (
                pb_lit.into_iter().filter(|e| e != "0").collect::<Vec<_>>(),
                si_vals.into_iter().filter(|e| e != "0").collect::<Vec<_>>(),
            )
        } else {
            (pb_lit, si_vals)
        };
        if a != b {
            let detail = format!(
                "`{key}` differs: PKGBUILD has [{}], .SRCINFO has [{}]",
                excerpt(&a.join(" "), 200),
                excerpt(&b.join(" "), 200)
            );
            res.notes.push(format!(
                "aur: {base}: SUSPICIOUS .SRCINFO/PKGBUILD mismatch: {detail}"
            ));
            res.observe(name, Some(".SRCINFO"), "srcinfo.mismatch", detail);
        }
    }
}

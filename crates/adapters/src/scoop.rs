//! Scoop: JSON manifests from the official buckets on GitHub. Lifecycle
//! PowerShell (pre_install, post_install, installer/uninstaller scripts…) is
//! recorded as recipe text to inspect; it is never run.

use bytebouncer_core::{PackageRequest, ResolvedPackage, SourceRef};
use serde_json::Value as Json;

use crate::parse::SCOOP_KNOWN_BUCKETS;
use crate::util::{self, excerpt};
use crate::{Fetcher, HostInfo, RecipeFile, Resolution, ResolveError, fetch_opt};

const RAW: &str = "https://raw.githubusercontent.com/ScoopInstaller";
const MAX_JSON: u64 = 2 * 1024 * 1024;

const SCRIPT_FIELDS: &[&str] = &[
    "pre_install",
    "post_install",
    "pre_uninstall",
    "post_uninstall",
];

fn bucket_repo(bucket: &str) -> Option<&'static str> {
    Some(match bucket {
        "main" => "Main",
        "extras" => "Extras",
        "versions" => "Versions",
        "java" => "Java",
        "nerd-fonts" => "Nerd-Fonts",
        "games" => "Games",
        _ => return None,
    })
}

fn host_scoop_arch(info: &HostInfo) -> &'static str {
    match info.arch.as_str() {
        "aarch64" | "arm64" => "arm64",
        "x86" | "i686" | "i386" => "32bit",
        _ => "64bit",
    }
}

fn str_or_list(v: &Json) -> Vec<String> {
    match v {
        Json::String(s) => vec![s.clone()],
        Json::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// A Scoop hash string → (sha256, sha512, weak).
pub fn parse_hash(h: &str) -> (Option<String>, Option<String>, Option<String>) {
    let h = h.trim();
    let lower = h.to_ascii_lowercase();
    if let Some(v) = lower.strip_prefix("sha256:") {
        (util::hex_digest(v, 64), None, None)
    } else if let Some(v) = lower.strip_prefix("sha512:") {
        (None, util::hex_digest(v, 128), None)
    } else if lower.starts_with("md5:") || lower.starts_with("sha1:") {
        (None, None, Some(h.to_string()))
    } else {
        (util::hex_digest(&lower, 64), None, None)
    }
}

/// Split Scoop's `url#/rename.ext` convention.
pub fn split_rename(url: &str) -> (String, Option<String>) {
    match url.split_once('#') {
        Some((u, frag)) => {
            let name = frag
                .strip_prefix('/')
                .filter(|n| !n.is_empty())
                .map(util::sanitize_file_name);
            (u.to_string(), name)
        }
        None => (url.to_string(), None),
    }
}

pub fn resolve(
    req: &PackageRequest,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let want_arch = req
        .options
        .iter()
        .find_map(|o| o.strip_prefix("--arch="))
        .unwrap_or_else(|| host_scoop_arch(info))
        .to_string();
    for spec in &req.packages {
        let (spec_nv, version) = match spec.split_once('@') {
            Some((s, v)) => (s, Some(v)),
            None => (spec.as_str(), None),
        };
        let (bucket, app) = match spec_nv.split_once('/') {
            Some((b, a)) => (Some(b), a),
            None => (None, spec_nv),
        };
        let repos: Vec<&str> = match bucket {
            Some(b) => match bucket_repo(&b.to_ascii_lowercase()) {
                Some(r) => vec![r],
                None => {
                    res.unresolved.push(format!(
                        "scoop: bucket `{b}` is not a known official bucket ({}); third-party buckets are not resolved",
                        SCOOP_KNOWN_BUCKETS.join(", ")
                    ));
                    continue;
                }
            },
            None => vec!["Main", "Extras"],
        };
        let mut found = None;
        for repo in repos {
            let url = format!(
                "{RAW}/{repo}/master/bucket/{}.json",
                util::percent_encode(app)
            );
            if let Some(f) = fetch_opt(fetcher, &url, &[], MAX_JSON)? {
                found = Some((repo, url, f.bytes));
                break;
            }
        }
        let Some((repo, url, bytes)) = found else {
            res.unresolved.push(format!(
                "scoop: no manifest for `{app}` in {}",
                bucket.unwrap_or("main or extras")
            ));
            continue;
        };
        let json: Json = match serde_json::from_slice(&bytes) {
            Ok(j) => j,
            Err(e) => {
                res.unresolved
                    .push(format!("scoop: {app}: manifest is not valid JSON: {e}"));
                continue;
            }
        };
        res.recipe_files.push(RecipeFile {
            package: app.to_string(),
            path: format!("{app}.json"),
            bytes,
            origin: url,
        });
        resolve_manifest(app, repo, &json, version, &want_arch, res);
    }
    Ok(())
}

fn resolve_manifest(
    app: &str,
    repo: &str,
    j: &Json,
    want_version: Option<&str>,
    want_arch: &str,
    res: &mut Resolution,
) {
    let version = j["version"].as_str().unwrap_or("").to_string();
    let mut recipe_files = vec![format!("{app}.json")];
    if let Some(v) = want_version
        && v != version
    {
        res.unresolved.push(format!(
            "scoop: {app}@{v}: the bucket has {version}; scoop would synthesize a manifest from `autoupdate`, which is not supported"
        ));
        return;
    }
    // Architecture block, with arm64 → 64bit fallback like Scoop.
    let arch_block = &j["architecture"];
    let mut arch = want_arch.to_string();
    let mut block = arch_block.get(want_arch);
    if block.is_none() && want_arch == "arm64" && arch_block.get("64bit").is_some() {
        block = arch_block.get("64bit");
        arch = "64bit".to_string();
        res.notes.push(format!(
            "scoop: {app}: no arm64 build; using 64bit (emulated)"
        ));
    }
    if block.is_none() && arch_block.is_object() && j.get("url").is_none() {
        res.unresolved.push(format!(
            "scoop: {app}: no `{want_arch}` architecture in manifest (has: {})",
            arch_block
                .as_object()
                .map(|m| m.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default()
        ));
        return;
    }
    let pick = |k: &str| -> &Json {
        match block.and_then(|b| b.get(k)) {
            Some(v) => v,
            None => &j[k],
        }
    };
    let urls = str_or_list(pick("url"));
    let hashes = str_or_list(pick("hash"));
    if urls.is_empty() {
        res.unresolved
            .push(format!("scoop: {app}: manifest has no url"));
    }
    if !hashes.is_empty() && hashes.len() != urls.len() {
        res.notes.push(format!(
            "scoop: {app}: {} urls but {} hashes",
            urls.len(),
            hashes.len()
        ));
    }
    let mut sources: Vec<SourceRef> = Vec::new();
    for (i, u) in urls.iter().enumerate() {
        let (url, rename) = split_rename(u);
        if !util::is_http_url(&url) {
            res.unresolved.push(format!(
                "scoop: {app}: unsupported url `{}`",
                excerpt(&url, 120)
            ));
            continue;
        }
        let mut s = util::source_ref(&url, rename.as_deref());
        match hashes.get(i) {
            Some(h) => {
                let (s256, s512, weak) = parse_hash(h);
                s.expected_sha256 = s256;
                s.expected_sha512 = s512;
                if let Some(w) = weak {
                    res.notes.push(format!(
                        "scoop: {app}: {} only has `{}` (recorded, not used for verification)",
                        s.file_name,
                        excerpt(&w, 80)
                    ));
                } else if s.expected_sha256.is_none() && s.expected_sha512.is_none() {
                    res.notes
                        .push(format!("scoop: {app}: malformed hash `{}`", excerpt(h, 80)));
                }
            }
            None => res
                .notes
                .push(format!("scoop: {app}: {} has no hash", s.file_name)),
        }
        sources.push(s);
    }

    // Lifecycle scripts (root and architecture-specific).
    let mut scripts: Vec<(String, String)> = Vec::new();
    for (scope, obj) in [("", Some(j)), (arch.as_str(), block)] {
        let Some(obj) = obj else { continue };
        let prefix = if scope.is_empty() {
            String::new()
        } else {
            format!("{scope}.")
        };
        for f in SCRIPT_FIELDS {
            let lines = str_or_list(&obj[*f]);
            if !lines.is_empty() {
                scripts.push((format!("{prefix}{f}"), lines.join("\n")));
            }
        }
        for f in ["installer", "uninstaller"] {
            let lines = str_or_list(&obj[f]["script"]);
            if !lines.is_empty() {
                scripts.push((format!("{prefix}{f}.script"), lines.join("\n")));
            }
            if let Some(file) = obj[f]["file"].as_str() {
                res.observe(
                    app,
                    None,
                    "scoop.installer_file",
                    format!("{prefix}{f} runs `{file}` with args {}", obj[f]["args"]),
                );
            }
        }
    }
    for (field, text) in scripts {
        let path = format!("{app}.{field}.ps1");
        res.observe(
            app,
            Some(&path),
            "scoop.script",
            format!(
                "{field} PowerShell runs during install/uninstall: {}",
                excerpt(&text, 200)
            ),
        );
        res.recipe_files.push(RecipeFile {
            package: app.to_string(),
            path: path.clone(),
            bytes: text.into_bytes(),
            origin: format!("{app}.json#{field}"),
        });
        recipe_files.push(path);
    }
    if !j["psmodule"].is_null() {
        res.observe(
            app,
            None,
            "scoop.psmodule",
            format!("installs a PowerShell module: {}", j["psmodule"]),
        );
    }
    for k in ["env_add_path", "env_set", "persist", "shortcuts", "bin"] {
        if !j[k].is_null() {
            res.notes.push(format!(
                "scoop: {app}: {k} = {}",
                excerpt(&j[k].to_string(), 200)
            ));
        }
    }
    let dependencies = str_or_list(&j["depends"]);
    if !j["suggest"].is_null() {
        res.notes.push(format!(
            "scoop: {app}: suggests {}",
            excerpt(&j["suggest"].to_string(), 200)
        ));
    }
    res.packages.push(ResolvedPackage {
        name: app.to_string(),
        version,
        arch: Some(arch),
        repository: Some(format!("scoop/{}", repo.to_ascii_lowercase())),
        sources,
        recipe_files,
        dependencies,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_renames() {
        let h = "a".repeat(64);
        assert_eq!(parse_hash(&h).0, Some(h.clone()));
        assert_eq!(
            parse_hash(&format!("sha256:{}", h.to_uppercase())).0,
            Some(h.clone())
        );
        assert!(
            parse_hash(&format!("sha512:{}", "b".repeat(128)))
                .1
                .is_some()
        );
        assert!(parse_hash("md5:abcd").2.is_some());
        assert!(parse_hash("sha1:abcd").2.is_some());
        assert_eq!(
            split_rename("https://x/dl?id=1#/setup.exe"),
            (
                "https://x/dl?id=1".to_string(),
                Some("setup.exe".to_string())
            )
        );
        assert_eq!(
            split_rename("https://x/a.zip#/../../evil").1.as_deref(),
            Some(".._.._evil")
        );
    }
}

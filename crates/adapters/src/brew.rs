//! Homebrew: formula/cask JSON API for artifacts and digests; the Ruby
//! formula/cask is retrieved as DATA (it is executable content and is never
//! evaluated). Bottles live on ghcr.io, which needs an anonymous bearer token
//! that we obtain through the caller's fetcher and hand back in
//! `Resolution::source_headers`.

use bytebouncer_core::{PackageRequest, ResolvedPackage, SourceRef};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

use crate::util::{self, excerpt, percent_encode};
use crate::{Fetcher, HostInfo, RecipeFile, Resolution, ResolveError, SourceHeaders, fetch_opt};

pub const API_BASE: &str = "https://formulae.brew.sh/api";
const RAW: &str = "https://raw.githubusercontent.com";
const MAX_JSON: u64 = 8 * 1024 * 1024;
const MAX_RUBY: u64 = 2 * 1024 * 1024;

pub fn resolve(
    req: &PackageRequest,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let want_cask = req.options.iter().any(|o| o == "--cask");
    let want_formula = req.options.iter().any(|o| o == "--formula");
    for spec in &req.packages {
        let parts: Vec<&str> = spec.split('/').collect();
        let (tap, name) = match parts.as_slice() {
            [n] => (None, *n),
            [u, t, n] => (Some(format!("{u}/{t}")), *n),
            _ => {
                res.unresolved
                    .push(format!("brew: cannot interpret `{spec}`"));
                continue;
            }
        };
        let (try_formula, try_cask) = match tap.as_deref() {
            None => (!want_cask, !want_formula),
            Some("homebrew/core") => (true, false),
            Some("homebrew/cask") => (false, true),
            Some(t) => {
                third_party_tap(t, name, want_cask, fetcher, res)?;
                continue;
            }
        };
        if try_formula && formula(name, fetcher, info, res)? {
            continue;
        }
        if try_cask && cask(name, fetcher, info, res)? {
            continue;
        }
        let what = match (try_formula, try_cask) {
            (true, true) => "formula or cask",
            (true, false) => "formula",
            _ => "cask",
        };
        res.unresolved.push(format!(
            "brew: no {what} named `{name}` in the Homebrew API"
        ));
    }
    Ok(())
}

fn host_bottle_tag(info: &HostInfo) -> Option<String> {
    if let Some(t) = &info.brew_bottle_tag {
        return Some(t.clone());
    }
    match (info.os.as_str(), info.arch.as_str()) {
        ("linux", "x86_64") => Some("x86_64_linux".into()),
        ("linux", "aarch64" | "arm64") => Some("arm64_linux".into()),
        _ => None,
    }
}

fn strs(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| match x.as_str() {
                    Some(s) => s.to_string(),
                    None => x.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn fetch_json(fetcher: &dyn Fetcher, url: &str) -> Result<Option<Json>, ResolveError> {
    let Some(f) = fetch_opt(fetcher, url, &[], MAX_JSON)? else {
        return Ok(None);
    };
    serde_json::from_slice(&f.bytes)
        .map(Some)
        .map_err(|e| ResolveError::Malformed {
            url: url.to_string(),
            message: e.to_string(),
        })
}

/// Fetch the Ruby source as data, pinned to the API's tap commit when known,
/// and verify it against the API's `ruby_source_checksum`.
fn fetch_ruby(
    repo: &str,
    json: &Json,
    package: &str,
    fetcher: &dyn Fetcher,
    res: &mut Resolution,
) -> Result<Option<String>, ResolveError> {
    let Some(path) = json["ruby_source_path"].as_str() else {
        res.unresolved.push(format!(
            "brew: {package}: API gives no ruby_source_path; recipe not retrieved"
        ));
        return Ok(None);
    };
    if path.contains("..") || path.starts_with('/') || !path.ends_with(".rb") {
        res.unresolved.push(format!(
            "brew: {package}: suspicious ruby_source_path `{}`",
            excerpt(path, 120)
        ));
        return Ok(None);
    }
    let rev = json["tap_git_head"]
        .as_str()
        .filter(|h| h.len() == 40 && h.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or("HEAD");
    let url = format!("{RAW}/{repo}/{rev}/{path}");
    let Some(f) = fetch_opt(fetcher, &url, &[], MAX_RUBY)? else {
        res.unresolved
            .push(format!("brew: {package}: Ruby source not found at {url}"));
        return Ok(None);
    };
    if let Some(expected) = json["ruby_source_checksum"]["sha256"].as_str() {
        let actual = hex::encode(Sha256::digest(&f.bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            res.notes.push(format!(
                "brew: {package}: Ruby source sha256 {actual} differs from the API's ruby_source_checksum {expected} (the API and repository may be out of sync)"
            ));
        }
    }
    let file = path.rsplit('/').next().unwrap_or(path).to_string();
    res.recipe_files.push(RecipeFile {
        package: package.to_string(),
        path: file.clone(),
        bytes: f.bytes,
        origin: url,
    });
    res.notes.push(format!(
        "brew: {package}: {file} is executable Ruby (retrieved as data, never evaluated); install-time behavior beyond the API fields must be reviewed there"
    ));
    Ok(Some(file))
}

fn formula(
    name: &str,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<bool, ResolveError> {
    let url = format!("{API_BASE}/formula/{}.json", percent_encode(name));
    let Some(j) = fetch_json(fetcher, &url)? else {
        return Ok(false);
    };
    let pkg = j["name"].as_str().unwrap_or(name).to_string();
    let stable = j["versions"]["stable"].as_str().unwrap_or("").to_string();
    let revision = j["revision"].as_u64().unwrap_or(0);
    let version = if revision > 0 {
        format!("{stable}_{revision}")
    } else {
        stable.clone()
    };
    if j["disabled"].as_bool() == Some(true) {
        res.notes
            .push(format!("brew: {pkg} is disabled: {}", j["disable_reason"]));
    }
    if j["deprecated"].as_bool() == Some(true) {
        res.notes.push(format!(
            "brew: {pkg} is deprecated: {}",
            j["deprecation_reason"]
        ));
    }
    let tag = host_bottle_tag(info);
    let mut sources: Vec<SourceRef> = Vec::new();

    // Bottle for this host.
    let files = &j["bottle"]["stable"]["files"];
    let available: Vec<String> = files
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let chosen = tag
        .as_deref()
        .filter(|t| files.get(*t).is_some())
        .or_else(|| files.get("all").map(|_| "all"));
    match chosen {
        Some(t) => {
            let b = &files[t];
            if let Some(burl) = b["url"].as_str() {
                let mut s =
                    util::source_ref(burl, Some(&format!("{pkg}--{version}.{t}.bottle.tar.gz")));
                s.expected_sha256 = b["sha256"].as_str().and_then(|h| util::hex_digest(h, 64));
                if burl.starts_with("https://ghcr.io/v2/") {
                    add_ghcr_token(burl, &pkg, fetcher, res)?;
                }
                sources.push(s);
                res.notes
                    .push(format!("brew: {pkg}: bottle `{t}` selected for this host"));
            }
        }
        None => {
            if available.is_empty() {
                res.notes.push(format!(
                    "brew: {pkg} has no bottles; it would be built from source"
                ));
            } else {
                res.notes.push(format!(
                    "brew: {pkg}: no bottle for this host ({}); available: {} — Homebrew would build from source",
                    tag.as_deref().unwrap_or("unknown macOS tag; set HostInfo::brew_bottle_tag"),
                    available.join(", ")
                ));
            }
        }
    }

    // Source archive (always recorded: it is what a source build uses).
    let st = &j["urls"]["stable"];
    if let Some(surl) = st["url"].as_str() {
        let using = st["using"].as_str().unwrap_or("");
        if using == "git" || surl.ends_with(".git") || !util::is_http_url(surl) {
            res.unresolved.push(format!(
                "brew: {pkg}: source `{}` is a VCS checkout (using: {using}); VCS sources not supported in this version",
                excerpt(surl, 160)
            ));
        } else {
            let mut s = util::source_ref(surl, None);
            s.expected_sha256 = st["checksum"]
                .as_str()
                .and_then(|h| util::hex_digest(h, 64));
            if s.expected_sha256.is_none() {
                res.notes
                    .push(format!("brew: {pkg}: source archive has no checksum"));
            }
            if !using.is_empty() {
                res.notes
                    .push(format!("brew: {pkg}: source download strategy `{using}`"));
            }
            sources.push(s);
        }
    }
    // Patches are build inputs too.
    for p in j["patches"].as_array().into_iter().flatten() {
        if let Some(purl) = p["url"].as_str().filter(|u| util::is_http_url(u)) {
            let mut s = util::source_ref(purl, None);
            s.expected_sha256 = p["sha256"].as_str().and_then(|h| util::hex_digest(h, 64));
            sources.push(s);
        } else {
            res.notes.push(format!(
                "brew: {pkg}: inline/DATA patch (in the Ruby source)"
            ));
        }
    }

    // Dependencies (host-specific variation when present).
    let deps_src = tag
        .as_deref()
        .and_then(|t| j["variations"].get(t))
        .filter(|v| v.get("dependencies").is_some())
        .map(|v| &v["dependencies"])
        .unwrap_or(&j["dependencies"]);
    let dependencies = strs(deps_src);
    let build = strs(&j["build_dependencies"]);
    if !build.is_empty() {
        res.notes.push(format!(
            "brew: {pkg}: build dependencies (not inspected): {}",
            build.join(", ")
        ));
    }
    if j["post_install_defined"].as_bool() == Some(true) {
        res.observe(
            &pkg,
            None,
            "brew.post_install",
            "formula defines post_install (runs Ruby after pouring/building)",
        );
        res.notes.push(format!(
            "brew: {pkg}: defines post_install; review it in the Ruby source"
        ));
    }
    if !j["service"].is_null() {
        res.observe(
            &pkg,
            None,
            "brew.service",
            format!(
                "declares a service: {}",
                excerpt(&j["service"].to_string(), 300)
            ),
        );
    }
    if let Some(c) = j["caveats"].as_str() {
        res.notes
            .push(format!("brew: {pkg}: caveats: {}", excerpt(c, 300)));
    }

    let recipe = fetch_ruby("Homebrew/homebrew-core", &j, &pkg, fetcher, res)?;
    res.packages.push(ResolvedPackage {
        name: pkg,
        version,
        arch: chosen.map(str::to_string),
        repository: Some("homebrew/core".to_string()),
        sources,
        recipe_files: recipe.into_iter().collect(),
        dependencies,
    });
    Ok(true)
}

/// GET the anonymous pull token for a ghcr.io blob URL and record the header.
fn add_ghcr_token(
    blob_url: &str,
    pkg: &str,
    fetcher: &dyn Fetcher,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    // https://ghcr.io/v2/<repo path>/blobs/sha256:…
    let Some(repo) = blob_url
        .strip_prefix("https://ghcr.io/v2/")
        .and_then(|r| r.split_once("/blobs/"))
        .map(|(r, _)| r.to_string())
    else {
        return Ok(());
    };
    let token_url = format!("https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull");
    match fetcher.get(&token_url, &[], 64 * 1024) {
        Ok(f) => {
            let token = serde_json::from_slice::<Json>(&f.bytes)
                .ok()
                .and_then(|j| j["token"].as_str().map(str::to_string));
            match token {
                Some(t) => res.source_headers.push(SourceHeaders {
                    url: blob_url.to_string(),
                    headers: vec![("Authorization".to_string(), format!("Bearer {t}"))],
                }),
                None => res.notes.push(format!(
                    "brew: {pkg}: ghcr.io token response had no token; bottle download needs `Authorization: Bearer <token>` from {token_url}"
                )),
            }
        }
        Err(e) => res.notes.push(format!(
            "brew: {pkg}: could not obtain ghcr.io token ({e}); bottle download needs `Authorization: Bearer <token>` from {token_url}"
        )),
    }
    Ok(())
}

const CASK_HOOK_KEYS: &[&str] = &[
    "preflight",
    "postflight",
    "uninstall_preflight",
    "uninstall_postflight",
    "installer",
    "pkg",
];

fn cask(
    name: &str,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<bool, ResolveError> {
    let url = format!("{API_BASE}/cask/{}.json", percent_encode(name));
    let Some(j) = fetch_json(fetcher, &url)? else {
        return Ok(false);
    };
    let token = j["token"].as_str().unwrap_or(name).to_string();
    let mut version = j["version"].as_str().unwrap_or("").to_string();
    let mut curl = j["url"].as_str().map(str::to_string);
    let mut sha = j["sha256"].as_str().map(str::to_string);
    let mut artifacts = j["artifacts"].clone();

    // Platform variation for this host, if any.
    let variations: Vec<String> = j["variations"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let tag = host_bottle_tag(info);
    let mut chosen_tag = None;
    if let Some(t) = tag.as_deref()
        && let Some(v) = j["variations"].get(t)
    {
        if let Some(u) = v["url"].as_str() {
            curl = Some(u.to_string());
        }
        if let Some(s) = v["sha256"].as_str() {
            sha = Some(s.to_string());
        }
        if let Some(ver) = v["version"].as_str() {
            version = ver.to_string();
        }
        if v.get("artifacts").is_some() {
            artifacts = v["artifacts"].clone();
        }
        chosen_tag = Some(t.to_string());
    } else if !variations.is_empty() {
        res.notes.push(format!(
            "brew: cask {token}: default variant used; platform variations exist: {}",
            variations.join(", ")
        ));
    }
    if info.os != "macos" && j["depends_on"].get("macos").is_some() {
        res.notes.push(format!(
            "brew: cask {token} targets macOS (host is {}); resolved for inspection only",
            info.os
        ));
    }
    if let Some(spec) = j["url_specs"].as_object().filter(|m| !m.is_empty()) {
        res.notes.push(format!(
            "brew: cask {token}: download options {}",
            excerpt(&Json::Object(spec.clone()).to_string(), 200)
        ));
    }

    let mut sources = Vec::new();
    match curl {
        Some(u) if util::is_http_url(&u) => {
            let mut s = util::source_ref(&u, None);
            match sha.as_deref() {
                Some("no_check") | Some(":no_check") | None => {
                    res.unresolved.push(format!(
                        "brew: cask {token}: sha256 :no_check — the download cannot be verified against an expected digest"
                    ));
                }
                Some(h) => s.expected_sha256 = util::hex_digest(h, 64),
            }
            sources.push(s);
        }
        Some(u) => res.unresolved.push(format!(
            "brew: cask {token}: unsupported download `{}`",
            excerpt(&u, 160)
        )),
        None => res
            .unresolved
            .push(format!("brew: cask {token}: no download URL in the API")),
    }

    // Artifacts and lifecycle hooks.
    let mut kinds = Vec::new();
    for a in artifacts.as_array().into_iter().flatten() {
        for (k, v) in a.as_object().into_iter().flatten() {
            if k == "target" {
                continue;
            }
            kinds.push(k.clone());
            let hook = CASK_HOOK_KEYS.iter().any(|h| k.starts_with(h))
                || k.contains("preflight")
                || k.contains("postflight");
            if hook {
                res.observe(
                    &token,
                    None,
                    "brew.cask_hook",
                    format!("`{k}`: {}", excerpt(&v.to_string(), 300)),
                );
            }
            if k == "uninstall" || k == "zap" {
                res.notes.push(format!(
                    "brew: cask {token}: {k} stanza {}",
                    excerpt(&v.to_string(), 300)
                ));
            }
        }
    }
    if !kinds.is_empty() {
        kinds.dedup();
        res.notes.push(format!(
            "brew: cask {token}: artifacts: {}",
            kinds.join(", ")
        ));
    }
    if let Some(c) = j["caveats"].as_str() {
        res.notes
            .push(format!("brew: cask {token}: caveats: {}", excerpt(c, 300)));
    }
    let mut dependencies = strs(&j["depends_on"]["formula"]);
    dependencies.extend(strs(&j["depends_on"]["cask"]));

    let recipe = fetch_ruby("Homebrew/homebrew-cask", &j, &token, fetcher, res)?;
    res.packages.push(ResolvedPackage {
        name: token,
        version,
        arch: chosen_tag,
        repository: Some("homebrew/cask".to_string()),
        sources,
        recipe_files: recipe.into_iter().collect(),
        dependencies,
    });
    Ok(true)
}

/// Third-party tap: the Ruby recipe is fetched as data, but URLs/digests
/// would require evaluating Ruby, so the package itself stays unresolved.
fn third_party_tap(
    tap: &str,
    name: &str,
    want_cask: bool,
    fetcher: &dyn Fetcher,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let (user, repo) = tap.split_once('/').unwrap_or((tap, ""));
    let repo = format!("{user}/homebrew-{repo}");
    let mut candidates = vec![
        format!("Formula/{name}.rb"),
        format!("{name}.rb"),
        format!("Casks/{name}.rb"),
    ];
    if want_cask {
        candidates.rotate_right(1);
    }
    for path in candidates {
        let url = format!("{RAW}/{repo}/HEAD/{path}");
        if let Some(f) = fetch_opt(fetcher, &url, &[], MAX_RUBY)? {
            res.recipe_files.push(RecipeFile {
                package: name.to_string(),
                path: format!("{name}.rb"),
                bytes: f.bytes,
                origin: url,
            });
            res.unresolved.push(format!(
                "brew: {tap}/{name} is from a third-party tap; its download URL and digest are defined in Ruby and are not resolved (recipe retrieved as data)"
            ));
            return Ok(());
        }
    }
    res.unresolved.push(format!(
        "brew: {tap}/{name}: recipe not found in github.com/{repo}"
    ));
    Ok(())
}

//! winget: manifests from github.com/microsoft/winget-pkgs. Versions are
//! listed through the (unauthenticated, rate-limited) GitHub contents API;
//! manifests are fetched from raw.githubusercontent.com and parsed as data
//! with `yaml-rust2` (aliases are not expanded by that parser).

use bytebouncer_core::{PackageRequest, ResolvedPackage, SourceRef};
use serde_json::Value as Json;
use yaml_rust2::{Yaml, YamlLoader};

use crate::util::{self, compare_versions, excerpt};
use crate::{FetchError, Fetcher, HostInfo, RecipeFile, Resolution, ResolveError, fetch_opt};

const API: &str = "https://api.github.com/repos/microsoft/winget-pkgs/contents";
const RAW: &str = "https://raw.githubusercontent.com/microsoft/winget-pkgs/master";
const MAX_LIST: u64 = 4 * 1024 * 1024;
const MAX_YAML: u64 = 1024 * 1024;

/// Installer fields inherited from the manifest root when absent per entry.
const INHERITED: &[&str] = &[
    "InstallerType",
    "Scope",
    "InstallerSwitches",
    "NestedInstallerType",
    "NestedInstallerFiles",
    "InstallerLocale",
    "Platform",
    "MinimumOSVersion",
    "ElevationRequirement",
    "Dependencies",
];

pub fn manifest_dir(id: &str) -> String {
    let first = id
        .chars()
        .next()
        .map(|c| c.to_ascii_lowercase())
        .unwrap_or('_');
    format!("manifests/{first}/{}", id.replace('.', "/"))
}

fn scalar(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Compact one-line rendering of a YAML value for notes.
fn render(y: &Yaml) -> String {
    match y {
        Yaml::Hash(h) => {
            let parts: Vec<String> = h
                .iter()
                .map(|(k, v)| format!("{}={}", scalar(k).unwrap_or_default(), render(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Yaml::Array(a) => format!("[{}]", a.iter().map(render).collect::<Vec<_>>().join(", ")),
        other => scalar(other).unwrap_or_default(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installer {
    pub architecture: String,
    pub installer_type: String,
    pub scope: Option<String>,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub nested_installer_type: Option<String>,
    pub nested_files: Vec<String>,
    pub switches: Option<String>,
    pub dependencies: Vec<String>,
    pub extra_dependencies: Vec<String>,
}

/// Parse an installer manifest (or a singleton manifest) into installers,
/// applying root-level defaults.
pub fn parse_installers(text: &str) -> Result<(Vec<Installer>, Yaml), String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| format!("YAML: {e}"))?;
    let root = docs.into_iter().next().ok_or("empty YAML document")?;
    let mut out = Vec::new();
    for inst in root["Installers"].as_vec().into_iter().flatten() {
        let get = |k: &str| -> &Yaml {
            let v = &inst[k];
            if v.is_badvalue() && INHERITED.contains(&k) {
                &root[k]
            } else {
                v
            }
        };
        let deps = get("Dependencies");
        let dependencies = deps["PackageDependencies"]
            .as_vec()
            .into_iter()
            .flatten()
            .filter_map(|d| scalar(&d["PackageIdentifier"]))
            .collect();
        let mut extra = Vec::new();
        for k in [
            "WindowsFeatures",
            "WindowsLibraries",
            "ExternalDependencies",
        ] {
            for v in deps[k].as_vec().into_iter().flatten() {
                if let Some(s) = scalar(v) {
                    extra.push(format!("{k}:{s}"));
                }
            }
        }
        out.push(Installer {
            architecture: scalar(get("Architecture")).unwrap_or_default(),
            installer_type: scalar(get("InstallerType")).unwrap_or_default(),
            scope: scalar(get("Scope")),
            url: scalar(get("InstallerUrl")),
            sha256: scalar(get("InstallerSha256")).and_then(|h| util::hex_digest(&h, 64)),
            nested_installer_type: scalar(get("NestedInstallerType")),
            nested_files: get("NestedInstallerFiles")
                .as_vec()
                .into_iter()
                .flatten()
                .filter_map(|f| scalar(&f["RelativeFilePath"]))
                .collect(),
            switches: match get("InstallerSwitches") {
                Yaml::BadValue | Yaml::Null => None,
                y => Some(render(y)),
            },
            dependencies,
            extra_dependencies: extra,
        });
    }
    Ok((out, root))
}

fn host_winget_arch(info: &HostInfo) -> &'static str {
    match info.arch.as_str() {
        "aarch64" | "arm64" => "arm64",
        "x86" | "i686" | "i386" => "x86",
        _ => "x64",
    }
}

fn github_error(url: &str, e: FetchError) -> ResolveError {
    match e {
        FetchError::Status {
            code: 403 | 429,
            ref message,
        } => ResolveError::RateLimited(format!(
            "GitHub API refused {url} (HTTP 403/429: {}); the unauthenticated limit is 60 requests/hour — retry later or pass `--version` to skip version listing",
            excerpt(message, 120)
        )),
        error => ResolveError::Fetch {
            url: url.to_string(),
            error,
        },
    }
}

pub fn resolve(
    req: &PackageRequest,
    fetcher: &dyn Fetcher,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let opt = |p: &str| {
        req.options
            .iter()
            .find_map(|o| o.strip_prefix(p).map(str::to_string))
    };
    let want_version = opt("--version=");
    let want_arch = opt("--architecture=").unwrap_or_else(|| host_winget_arch(info).to_string());
    let want_scope = opt("--scope=");
    if !req.options.iter().any(|o| o == "--exact") {
        res.notes.push(
            "winget: identifiers are matched exactly and case-sensitively against the winget-pkgs layout (winget without --exact would match case-insensitively)"
                .to_string(),
        );
    }
    for id in &req.packages {
        let dir = manifest_dir(id);
        let version = match &want_version {
            Some(v) => v.clone(),
            None => {
                let url = format!("{API}/{dir}");
                let headers = [
                    ("Accept", "application/vnd.github+json"),
                    ("User-Agent", "bytebouncer"),
                ];
                let listing = match fetcher.get(&url, &headers, MAX_LIST) {
                    Ok(f) => f,
                    Err(FetchError::Status { code: 404, .. }) => {
                        res.unresolved.push(format!(
                            "winget: package `{id}` not found in winget-pkgs (identifiers are case-sensitive here)"
                        ));
                        continue;
                    }
                    Err(e) => return Err(github_error(&url, e)),
                };
                let json: Json = serde_json::from_slice(&listing.bytes).map_err(|e| {
                    ResolveError::Malformed {
                        url: url.clone(),
                        message: e.to_string(),
                    }
                })?;
                let mut versions: Vec<String> = json
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|e| e["type"] == "dir")
                    .filter_map(|e| e["name"].as_str())
                    .filter(|n| n.chars().next().is_some_and(|c| c.is_ascii_digit()))
                    .map(str::to_string)
                    .collect();
                versions.sort_by(|a, b| compare_versions(a, b));
                match versions.last() {
                    Some(v) => {
                        res.notes.push(format!(
                            "winget: {id}: {} versions listed; selected highest {v}",
                            versions.len()
                        ));
                        v.clone()
                    }
                    None => {
                        res.unresolved.push(format!(
                            "winget: `{id}` has no version directories (it may be a publisher/namespace, not a package id)"
                        ));
                        continue;
                    }
                }
            }
        };
        resolve_version(
            id,
            &dir,
            &version,
            &want_arch,
            want_scope.as_deref(),
            fetcher,
            res,
        )?;
    }
    Ok(())
}

fn fetch_recipe(
    fetcher: &dyn Fetcher,
    id: &str,
    base: &str,
    file: &str,
    res: &mut Resolution,
) -> Result<Option<String>, ResolveError> {
    let url = format!("{base}/{file}");
    let Some(f) = fetch_opt(fetcher, &url, &[], MAX_YAML)? else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(&f.bytes).into_owned();
    res.recipe_files.push(RecipeFile {
        package: id.to_string(),
        path: file.to_string(),
        bytes: f.bytes,
        origin: url,
    });
    Ok(Some(text))
}

fn resolve_version(
    id: &str,
    dir: &str,
    version: &str,
    want_arch: &str,
    want_scope: Option<&str>,
    fetcher: &dyn Fetcher,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let base = format!("{RAW}/{dir}/{}", util::percent_encode(version));
    let mut recipe_files = Vec::new();
    let installer_file = format!("{id}.installer.yaml");
    let text = match fetch_recipe(fetcher, id, &base, &installer_file, res)? {
        Some(t) => {
            recipe_files.push(installer_file);
            t
        }
        None => {
            // Older singleton manifests carry everything in `<id>.yaml`.
            let single = format!("{id}.yaml");
            match fetch_recipe(fetcher, id, &base, &single, res)? {
                Some(t) if t.contains("Installers:") => {
                    recipe_files.push(single);
                    t
                }
                _ => {
                    res.unresolved.push(format!(
                        "winget: {id} {version}: no installer manifest at {base}/"
                    ));
                    return Ok(());
                }
            }
        }
    };
    // Version + default-locale manifests (descriptive data, kept as recipe).
    let version_file = format!("{id}.yaml");
    let mut locale = "en-US".to_string();
    if !recipe_files.contains(&version_file)
        && let Some(t) = fetch_recipe(fetcher, id, &base, &version_file, res)?
    {
        recipe_files.push(version_file);
        if let Some(l) = YamlLoader::load_from_str(&t)
            .ok()
            .and_then(|d| d.into_iter().next())
            .and_then(|d| scalar(&d["DefaultLocale"]))
            .filter(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        {
            locale = l;
        }
    }
    let locale_file = format!("{id}.locale.{locale}.yaml");
    if fetch_recipe(fetcher, id, &base, &locale_file, res)?.is_some() {
        recipe_files.push(locale_file);
    }

    let (installers, root) = match parse_installers(&text) {
        Ok(v) => v,
        Err(e) => {
            res.unresolved.push(format!(
                "winget: {id} {version}: installer manifest unreadable: {e}"
            ));
            return Ok(());
        }
    };
    if let Some(declared) = scalar(&root["PackageIdentifier"])
        && declared != id
    {
        res.notes.push(format!(
            "winget: manifest declares PackageIdentifier `{declared}`, requested `{id}`"
        ));
    }
    for (i, inst) in installers.iter().enumerate() {
        res.notes.push(format!(
            "winget: {id} {version} installer[{i}]: Architecture={} InstallerType={} Scope={} InstallerUrl={} InstallerSha256={}{}{}",
            inst.architecture,
            inst.installer_type,
            inst.scope.as_deref().unwrap_or("-"),
            inst.url.as_deref().unwrap_or("-"),
            inst.sha256.as_deref().unwrap_or("-"),
            inst.switches
                .as_ref()
                .map(|s| format!(" InstallerSwitches={}", excerpt(s, 200)))
                .unwrap_or_default(),
            if inst.nested_files.is_empty() {
                String::new()
            } else {
                format!(
                    " Nested={}:{}",
                    inst.nested_installer_type.as_deref().unwrap_or("?"),
                    inst.nested_files.join("|")
                )
            }
        ));
    }
    let scope_ok = |i: &&Installer| match (want_scope, i.scope.as_deref()) {
        (Some(w), Some(s)) => w.eq_ignore_ascii_case(s),
        _ => true,
    };
    let mut chosen: Vec<&Installer> = installers
        .iter()
        .filter(|i| i.architecture == want_arch || i.architecture == "neutral")
        .filter(scope_ok)
        .collect();
    let mut chosen_arch = want_arch.to_string();
    if chosen.is_empty() && want_arch == "x64" {
        chosen = installers
            .iter()
            .filter(|i| i.architecture == "x86")
            .filter(scope_ok)
            .collect();
        if !chosen.is_empty() {
            chosen_arch = "x86".to_string();
            res.notes.push(format!(
                "winget: {id}: no x64 installer; using x86 (as winget would)"
            ));
        }
    }
    if chosen.is_empty() {
        res.unresolved.push(format!(
            "winget: {id} {version}: no installer for architecture {want_arch}{}",
            want_scope
                .map(|s| format!(" and scope {s}"))
                .unwrap_or_default()
        ));
    }
    if chosen.len() > 1 {
        res.notes.push(format!(
            "winget: {id}: {} installers match {chosen_arch}; all are listed because winget's choice depends on local preferences",
            chosen.len()
        ));
    }
    let mut sources: Vec<SourceRef> = Vec::new();
    let mut dependencies = Vec::new();
    for inst in &chosen {
        let Some(url) = inst.url.as_deref() else {
            res.unresolved.push(format!(
                "winget: {id}: {} installer has no InstallerUrl",
                inst.installer_type
            ));
            continue;
        };
        if inst.installer_type == "msstore" || !util::is_http_url(url) {
            res.unresolved.push(format!(
                "winget: {id}: installer `{}` ({}) is not a direct download",
                excerpt(url, 120),
                inst.installer_type
            ));
            continue;
        }
        if inst.sha256.is_none() {
            res.notes.push(format!(
                "winget: {id}: installer {url} has no InstallerSha256"
            ));
        }
        if !inst.nested_files.is_empty() {
            res.observe(
                id,
                None,
                "winget.nested_installer",
                format!(
                    "{} archive runs nested {} installer(s): {}",
                    inst.installer_type,
                    inst.nested_installer_type.as_deref().unwrap_or("?"),
                    inst.nested_files.join(", ")
                ),
            );
        }
        for d in &inst.dependencies {
            if !dependencies.contains(d) {
                dependencies.push(d.clone());
            }
        }
        for d in &inst.extra_dependencies {
            res.notes.push(format!("winget: {id}: requires {d}"));
        }
        if sources.iter().any(|s| s.url == url) {
            continue;
        }
        let mut s = util::source_ref(url, None);
        s.expected_sha256 = inst.sha256.clone();
        sources.push(s);
    }
    res.packages.push(ResolvedPackage {
        name: id.to_string(),
        version: version.to_string(),
        arch: Some(chosen_arch),
        repository: Some("winget".to_string()),
        sources,
        recipe_files,
        dependencies,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_paths() {
        assert_eq!(
            manifest_dir("Microsoft.PowerToys"),
            "manifests/m/Microsoft/PowerToys"
        );
        assert_eq!(manifest_dir("7zip.7zip"), "manifests/7/7zip/7zip");
    }

    #[test]
    fn root_defaults_are_inherited() {
        let (inst, _) = parse_installers(
            "PackageIdentifier: A.B\nInstallerType: zip\nNestedInstallerType: portable\nNestedInstallerFiles:\n- RelativeFilePath: a.exe\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://x/a.zip\n  InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n- Architecture: arm64\n  InstallerType: exe\n  InstallerUrl: https://x/a.exe\n",
        )
        .unwrap();
        assert_eq!(inst[0].installer_type, "zip");
        assert_eq!(inst[0].nested_files, vec!["a.exe"]);
        assert_eq!(
            inst[0].sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(inst[1].installer_type, "exe");
    }
}

//! apt: ask the host's apt (read-only, no root, no download) which .deb it
//! would fetch: `apt-get --print-uris --quiet download <pkg>` prints
//! `'URL' file size SHA256:hash`. The expected digest comes from apt's
//! signature-verified repository metadata, so trust derives from the host's
//! apt keyring.

use bytebouncer_core::{PackageRequest, ResolvedPackage};

use crate::util::{self, excerpt};
use crate::{HostCommands, HostInfo, Resolution, ResolveError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptUri {
    pub url: String,
    pub file_name: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub weak: Option<String>,
}

/// Parse `apt-get --print-uris` output lines.
pub fn parse_print_uris(out: &str) -> Vec<AptUri> {
    out.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix('\'')?;
            let (url, rest) = rest.split_once('\'')?;
            let mut parts = rest.split_whitespace();
            let file_name = parts.next()?.to_string();
            let size = parts.next().and_then(|s| s.parse().ok());
            let hash = parts.next().unwrap_or("");
            let mut u = AptUri {
                url: url.to_string(),
                file_name: util::sanitize_file_name(&file_name),
                size,
                sha256: None,
                sha512: None,
                weak: None,
            };
            if let Some(h) = hash.strip_prefix("SHA256:") {
                u.sha256 = util::hex_digest(h, 64);
            } else if let Some(h) = hash.strip_prefix("SHA512:") {
                u.sha512 = util::hex_digest(h, 128);
            } else if !hash.is_empty() {
                u.weak = Some(hash.to_string());
            }
            Some(u)
        })
        .collect()
}

/// `name_version_arch.deb` → (name, version, arch), with `%3a` → `:`.
fn split_deb_name(file: &str) -> Option<(String, String, String)> {
    let stem = file.strip_suffix(".deb")?;
    let mut it = stem.splitn(3, '_');
    let name = it.next()?.to_string();
    let version = util::percent_decode(it.next()?);
    let arch = it.next()?.to_string();
    Some((name, version, arch))
}

/// `Depends:` of `apt-cache show --no-all-versions` output.
fn parse_depends(show: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in show.lines() {
        if let Some(d) = line
            .strip_prefix("Depends:")
            .or_else(|| line.strip_prefix("Pre-Depends:"))
        {
            out.extend(
                d.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
        if line.is_empty() && !out.is_empty() {
            break;
        }
    }
    out
}

pub fn resolve(
    req: &PackageRequest,
    host: &dyn HostCommands,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    if !info.has_apt {
        return Err(ResolveError::ManagerUnavailable(
            "apt requests can only be resolved on a host with apt (Debian/Ubuntu); its keyring and sources define what `apt install` means".to_string(),
        ));
    }
    for spec in &req.packages {
        // The parser guarantees `spec` cannot start with `-`.
        let out = match host.run_readonly("apt-get", &["--print-uris", "--quiet", "download", spec])
        {
            Ok(o) => o,
            Err(e) => {
                res.unresolved.push(format!(
                    "apt: `apt-get download --print-uris {spec}` failed: {}",
                    excerpt(&e, 300)
                ));
                continue;
            }
        };
        let uris = parse_print_uris(&out);
        let Some(u) = uris.first() else {
            res.unresolved
                .push(format!("apt: no download URI reported for {spec}"));
            continue;
        };
        let mut s = util::source_ref(&u.url, Some(&u.file_name));
        s.expected_sha256 = u.sha256.clone();
        s.expected_sha512 = u.sha512.clone();
        if let Some(w) = &u.weak {
            res.notes.push(format!(
                "apt: {spec}: apt reported only `{}` (not usable as SHA-256)",
                excerpt(w, 80)
            ));
        }
        let (name, version, arch) = split_deb_name(&u.file_name).unwrap_or_else(|| {
            (
                spec.split(['=', '/', ':'])
                    .next()
                    .unwrap_or(spec)
                    .to_string(),
                String::new(),
                String::new(),
            )
        });
        let name_only = spec.split(['=', '/']).next().unwrap_or(spec);
        let dependencies =
            match host.run_readonly("apt-cache", &["show", "--no-all-versions", name_only]) {
                Ok(show) => parse_depends(&show),
                Err(e) => {
                    res.notes.push(format!(
                        "apt: could not list dependencies of {name_only}: {}",
                        excerpt(&e, 200)
                    ));
                    Vec::new()
                }
            };
        res.packages.push(ResolvedPackage {
            name,
            version,
            arch: (!arch.is_empty()).then_some(arch),
            repository: None,
            sources: vec![s],
            recipe_files: Vec::new(),
            dependencies,
        });
    }
    res.notes.push(
        "apt: URLs and expected digests come from the host's apt metadata, so trust derives from the host's apt keyring and sources.list; the .deb's maintainer scripts are inspected after download"
            .to_string(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_uris() {
        let out = "'http://deb.debian.org/debian/pool/main/c/curl/curl_7.88.1-10%2bdeb12u5_amd64.deb' curl_7.88.1-10+deb12u5_amd64.deb 315460 SHA256:0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9\n";
        let u = parse_print_uris(out);
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].file_name, "curl_7.88.1-10+deb12u5_amd64.deb");
        assert_eq!(u[0].size, Some(315460));
        assert!(u[0].sha256.is_some());
        let (n, v, a) = split_deb_name("libssl3_3.0.11-1~deb12u2_amd64.deb").unwrap();
        assert_eq!(
            (n.as_str(), v.as_str(), a.as_str()),
            ("libssl3", "3.0.11-1~deb12u2", "amd64")
        );
        let (_, v, _) = split_deb_name("bash_1%3a5.2-1_amd64.deb").unwrap();
        assert_eq!(v, "1:5.2-1");
    }
}

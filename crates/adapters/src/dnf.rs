//! dnf: ask the host's dnf (read-only) for the RPM it would fetch.
//!
//! * URL: `dnf download --url --quiet <spec>` (dnf4 with dnf-plugins-core and
//!   dnf5 both print one URL per line and download nothing).
//! * Dependencies: `dnf repoquery --quiet --requires --latest-limit=1 <spec>`
//!   (same syntax on dnf4 and dnf5).
//! * Expected digest: not queried. dnf4's `--queryformat` has no checksum tag
//!   and dnf5's tag set differs between releases, so instead of guessing we
//!   leave `expected_sha256` empty: RPMs carry header digests and an embedded
//!   OpenPGP signature that the inspection stage verifies, and trust derives
//!   from the host's imported RPM keys.

use bytebouncer_core::{PackageRequest, ResolvedPackage};

use crate::util::{self, excerpt};
use crate::{HostCommands, HostInfo, Resolution, ResolveError};

/// Download URLs from `dnf download --url` output (other lines ignored).
pub fn parse_download_urls(out: &str) -> Vec<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| util::is_http_url(l) || l.starts_with("ftp://"))
        .filter(|l| l.ends_with(".rpm") && !l.ends_with(".src.rpm"))
        .map(str::to_string)
        .collect()
}

/// `name-version-release.arch.rpm` → (name, version-release, arch).
pub fn split_rpm_name(file: &str) -> Option<(String, String, String)> {
    let stem = file.strip_suffix(".rpm")?;
    let (nvr, arch) = stem.rsplit_once('.')?;
    let (nv, release) = nvr.rsplit_once('-')?;
    let (name, version) = nv.rsplit_once('-')?;
    Some((
        name.to_string(),
        format!("{version}-{release}"),
        arch.to_string(),
    ))
}

pub fn resolve(
    req: &PackageRequest,
    host: &dyn HostCommands,
    info: &HostInfo,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    if !info.has_dnf {
        return Err(ResolveError::ManagerUnavailable(
            "dnf requests can only be resolved on a host with dnf (Fedora/RHEL); its repositories and keys define what `dnf install` means".to_string(),
        ));
    }
    for spec in &req.packages {
        let out = match host.run_readonly("dnf", &["download", "--url", "--quiet", spec]) {
            Ok(o) => o,
            Err(e) => {
                res.unresolved.push(format!(
                    "dnf: `dnf download --url {spec}` failed: {}",
                    excerpt(&e, 300)
                ));
                continue;
            }
        };
        let urls = parse_download_urls(&out);
        // Prefer the host architecture, then noarch.
        let chosen = urls
            .iter()
            .find(|u| u.ends_with(&format!(".{}.rpm", info.arch)))
            .or_else(|| urls.iter().find(|u| u.ends_with(".noarch.rpm")))
            .or_else(|| urls.first());
        let Some(url) = chosen else {
            res.unresolved
                .push(format!("dnf: no download URL reported for {spec}"));
            continue;
        };
        if urls.len() > 1 {
            res.notes.push(format!(
                "dnf: {spec}: {} candidate URLs; chose {}",
                urls.len(),
                util::url_file_name(url)
            ));
        }
        let s = util::source_ref(url, None);
        let (name, version, arch) = split_rpm_name(&s.file_name)
            .unwrap_or_else(|| (spec.clone(), String::new(), String::new()));
        let dependencies = match host.run_readonly(
            "dnf",
            &[
                "repoquery",
                "--quiet",
                "--requires",
                "--latest-limit=1",
                spec,
            ],
        ) {
            Ok(o) => o
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            Err(e) => {
                res.notes.push(format!(
                    "dnf: could not list requirements of {spec}: {}",
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
        "dnf: no expected digest is taken from dnf; verify the RPM's embedded header digests and OpenPGP signature against the host's RPM keys after download"
            .to_string(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpm_names() {
        assert_eq!(
            split_rpm_name("curl-8.6.0-7.fc40.x86_64.rpm"),
            Some(("curl".into(), "8.6.0-7.fc40".into(), "x86_64".into()))
        );
        assert_eq!(
            split_rpm_name("python3-dnf-plugins-core-4.4.4-1.fc40.noarch.rpm")
                .unwrap()
                .0,
            "python3-dnf-plugins-core"
        );
    }
}

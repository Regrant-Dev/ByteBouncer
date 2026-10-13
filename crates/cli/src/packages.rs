//! Package-manager requests (SPEC §3.1, §5.3). The familiar command is parsed
//! by a finite grammar, never executed. Resolution goes through the sandboxed
//! fetch worker; recipes are fetched as data and inspected like any file.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::Result;
use bytebouncer_adapters::{FetchError, Fetched, Fetcher, HostCommands, HostInfo, Resolution};
use bytebouncer_core::{
    AnalysisOutput, Evidence, EvidenceKind, EvidenceStrength, Finding, Location, OptOut,
    OptOutStatus, Origin, PackageRequest, Producer, Severity, TriState,
};
use sha2::{Digest, Sha512};

use crate::acquire::{Acquired, Snapshot};
use crate::fetch::{self, FetchRequest, WorkerFetcher};
use crate::inspect::{InvalidRequest, ScanContext};
use crate::provenance::Checker;

const MAX_DEPENDENCY_PACKAGES: usize = 200;

impl Fetcher for WorkerFetcher {
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        if fetch::validate_url(url).is_err() {
            return Err(FetchError::Denied(format!(
                "{url}: only http(s) on ports 80/443"
            )));
        }
        match WorkerFetcher::get(self, url, headers, max_bytes) {
            Ok((bytes, reply)) => Ok(Fetched {
                bytes,
                final_url: reply.final_url,
                redirects: reply.redirects,
            }),
            Err(e) => {
                let msg = format!("{e:#}");
                // ureq reports HTTP errors as "http status: NNN".
                match msg
                    .split("status: ")
                    .nth(1)
                    .and_then(|s| s.get(..3))
                    .and_then(|s| s.parse().ok())
                {
                    Some(code) => Err(FetchError::Status { code, message: msg }),
                    None if msg.contains("limit") => Err(FetchError::TooLarge { limit: max_bytes }),
                    None => Err(FetchError::Network(msg)),
                }
            }
        }
    }
}

/// Read-only queries against the host's own package manager (apt/dnf), which
/// is how their repository trust chain is preserved.
struct ReadOnlyHost;

impl HostCommands for ReadOnlyHost {
    fn run_readonly(&self, program: &str, args: &[&str]) -> Result<String, String> {
        if !matches!(program, "apt-get" | "apt-cache" | "dnf") {
            return Err(format!("{program} is not an allowed query command"));
        }
        let first = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .copied()
            .unwrap_or_default();
        let allowed = match program {
            "apt-get" => args.contains(&"--print-uris") && first == "download",
            "apt-cache" => matches!(first, "show" | "policy" | "depends"),
            _ => (first == "download" && args.contains(&"--url")) || first == "repoquery",
        };
        if !allowed {
            return Err(format!("refusing non-query invocation of {program}"));
        }
        let out = Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }
    }
}

fn parse_request(ctx: &ScanContext) -> Result<PackageRequest, InvalidRequest> {
    let words = &ctx.args.words;
    let parsed = if words.len() > 1 {
        bytebouncer_adapters::parse_argv(words)
    } else {
        bytebouncer_adapters::parse_command_str(&ctx.args.target)
    };
    parsed.map_err(|e| {
        InvalidRequest(format!(
            "'{}' is not a file, directory, URL, or supported package request: {e}",
            ctx.args.target
        ))
    })
}

/// Strip version constraints from a declared dependency (`glibc>=2.3` → `glibc`).
fn dependency_name(dep: &str) -> &str {
    dep.split(['<', '>', '=', ':', ' '])
        .next()
        .unwrap_or(dep)
        .trim()
}

pub fn acquire_package(ctx: &ScanContext, _target: &str, ws: &Path) -> Result<Acquired> {
    let req = parse_request(ctx)?;
    ctx.progress.phase(&format!(
        "resolving {:?} request for {} (nothing will be installed)",
        req.manager,
        req.packages.join(", ")
    ));
    let fetcher = WorkerFetcher {
        scratch: ws.join("fetch"),
        allow_reduced: ctx.args.allow_reduced_isolation,
        counter: Default::default(),
    };
    let host = HostInfo::detect();
    let mut acq = Acquired::default();

    let mut res = match bytebouncer_adapters::resolve(&req, &fetcher, &ReadOnlyHost, &host) {
        Ok(r) => r,
        Err(e) => return Err(InvalidRequest(format!("cannot resolve {}: {e}", req.raw)).into()),
    };

    // Optional dependency closure: same manager, deduplicated, bounded.
    if ctx.args.include_dependencies {
        let mut seen: Vec<String> = res.packages.iter().map(|p| p.name.clone()).collect();
        let mut queue: Vec<String> = res
            .packages
            .iter()
            .flat_map(|p| p.dependencies.iter().map(|d| dependency_name(d).to_owned()))
            .collect();
        while let Some(dep) = queue.pop() {
            if dep.is_empty() || seen.contains(&dep) {
                continue;
            }
            if seen.len() >= MAX_DEPENDENCY_PACKAGES {
                acq.incomplete.push(format!("dependency closure exceeds {MAX_DEPENDENCY_PACKAGES} packages; remaining dependencies not inspected"));
                break;
            }
            seen.push(dep.clone());
            let mut sub = req.clone();
            sub.packages = vec![dep.clone()];
            match bytebouncer_adapters::resolve(&sub, &fetcher, &ReadOnlyHost, &host) {
                Ok(r) => {
                    queue.extend(r.packages.iter().flat_map(|p| {
                        p.dependencies.iter().map(|d| dependency_name(d).to_owned())
                    }));
                    acq.manifest.dependencies_included.push(dep);
                    merge_resolution(&mut res, r);
                }
                Err(e) => acq.incomplete.push(format!("dependency {dep}: {e}")),
            }
        }
    } else {
        acq.manifest.dependencies_excluded = res
            .packages
            .iter()
            .flat_map(|p| p.dependencies.iter().cloned())
            .collect();
    }

    let snap_dir = ws.join("snapshot");
    std::fs::create_dir_all(&snap_dir)?;
    let sig_dir = ws.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;
    let pacman_keyring = Path::new("/etc/pacman.d/gnupg/pubring.gpg");
    let mut keyrings = ctx.config.keys.pgp_keyrings.clone();
    keyrings.extend(ctx.args.pgp_keyring.iter().cloned());

    // Recipe files: inspected as data.
    for rf in &res.recipe_files {
        let path = snap_dir.join(acq.files.len().to_string());
        std::fs::write(&path, &rf.bytes)?;
        let sha256 = hex::encode(sha2::Sha256::digest(&rf.bytes));
        acq.files.push(Snapshot {
            path,
            display: format!("{}/recipe/{}", rf.package, rf.path),
            sha256,
            size: rf.bytes.len() as u64,
        });
    }

    // Package artifacts: downloaded through the fetch worker and checked
    // against repository metadata digests and signatures.
    for pkg in &res.packages {
        for src in &pkg.sources {
            if ctx.cancel.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(acq);
            }
            ctx.progress
                .phase(&format!("downloading {} ({})", src.file_name, src.url));
            let dest = snap_dir.join(acq.files.len().to_string());
            let headers = res
                .source_headers
                .iter()
                .find(|h| h.url == src.url)
                .map(|h| h.headers.clone())
                .unwrap_or_default();
            let reply = match fetch::fetch(&FetchRequest {
                url: src.url.clone(),
                headers,
                max_bytes: 2 << 30,
                dest: dest.clone(),
                timeout_secs: 1800,
                allow_reduced: ctx.args.allow_reduced_isolation,
            }) {
                Ok(r) => r,
                Err(e) => {
                    acq.incomplete
                        .push(format!("{}: download failed: {e:#}", src.file_name));
                    continue;
                }
            };
            let display = format!("{}/{}", pkg.name, src.file_name);
            acq.manifest.origins.push(Origin {
                requested_url: src.url.clone(),
                final_url: reply.final_url.clone(),
                redirects: reply.redirects,
                sha256: reply.sha256.clone(),
                size: reply.size,
                retrieved_at: jiff::Timestamp::now().to_string(),
            });

            let mut c = Checker::new(&reply.sha256, &display);
            let source = format!("{:?} repository metadata", req.manager).to_lowercase();
            if let Some(exp) = &src.expected_sha256 {
                c.expect_sha256(&exp.to_ascii_lowercase(), &source);
            }
            if let Some(exp512) = &src.expected_sha512 {
                let actual = hex::encode(Sha512::digest(std::fs::read(&dest)?));
                if !actual.eq_ignore_ascii_case(exp512) {
                    c.expect_sha256(&format!("sha512:{exp512}"), &source);
                } else {
                    c.out
                        .coverage
                        .analyzed
                        .push(format!("{display}: SHA-512 matches {source}"));
                }
            }
            if src.expected_sha256.is_none() && src.expected_sha512.is_none() {
                c.out.coverage.limitations.push(format!(
                    "{display}: repository publishes no SHA-256/512 for this file"
                ));
            }
            // Detached signature: embedded in metadata (pacman %PGPSIG%) or a .sig URL.
            let sig_bytes = res
                .embedded_signatures
                .iter()
                .find(|(n, _)| n == &src.file_name)
                .map(|(_, b)| b.clone())
                .or_else(|| {
                    let url = src.signature_url.as_ref()?;
                    Fetcher::get(&fetcher, url, &[], 64 * 1024)
                        .ok()
                        .map(|f| f.bytes)
                });
            if let Some(sig) = sig_bytes {
                let sig_path = sig_dir.join(format!("{}.sig", acq.files.len()));
                std::fs::write(&sig_path, sig)?;
                let mut rings = keyrings.clone();
                if src.file_name.contains(".pkg.tar") && pacman_keyring.exists() {
                    rings.push(pacman_keyring.to_path_buf());
                }
                c.openpgp(
                    &dest,
                    &sig_path,
                    &rings,
                    &ws.join("gpgv"),
                    ctx.args.allow_reduced_isolation,
                );
            }
            acq.manifest.signatures.append(&mut c.checks);
            acq.outputs.push(c.out);
            acq.files.push(Snapshot {
                path: dest,
                display,
                sha256: reply.sha256,
                size: reply.size,
            });
        }
    }

    // Resolver observations become evidence-backed findings on the recipe file.
    for obs in &res.observations {
        let file = acq
            .files
            .iter()
            .find(|f| {
                obs.file
                    .as_ref()
                    .is_some_and(|name| f.display == format!("{}/recipe/{}", obs.package, name))
            })
            .or_else(|| {
                acq.files
                    .iter()
                    .find(|f| f.display.starts_with(&format!("{}/", obs.package)))
            });
        if let Some(f) = file {
            acq.outputs
                .push(observation_output(obs, &f.sha256, &f.display));
        }
    }

    acq.manifest.request = Some(req);
    acq.manifest.packages = res.packages;
    acq.manifest.unresolved = res.unresolved;
    acq.notes = res.notes;
    Ok(acq)
}

fn merge_resolution(into: &mut Resolution, from: Resolution) {
    into.packages.extend(from.packages);
    into.recipe_files.extend(from.recipe_files);
    into.unresolved.extend(from.unresolved);
    into.notes.extend(from.notes);
    into.embedded_signatures.extend(from.embedded_signatures);
    into.source_headers.extend(from.source_headers);
    into.observations.extend(from.observations);
}

fn observation_output(
    obs: &bytebouncer_adapters::Observation,
    sha256: &str,
    display: &str,
) -> AnalysisOutput {
    let (category, severity, title) = match obs.kind.as_str() {
        "pkgbuild.top_level_command" => (
            "security.capability",
            Severity::Medium,
            "PKGBUILD runs commands at top level (they execute whenever makepkg reads the file)",
        ),
        "srcinfo.mismatch" => (
            "provenance.recipe_mismatch",
            Severity::Medium,
            ".SRCINFO disagrees with the PKGBUILD",
        ),
        "brew.post_install" => (
            "security.persistence",
            Severity::Low,
            "Homebrew formula has a post_install step",
        ),
        "brew.cask_hook" => (
            "security.persistence",
            Severity::Low,
            "Homebrew cask runs pre/postflight or uninstall hooks",
        ),
        "scoop.script" => (
            "security.capability",
            Severity::Info,
            "Scoop manifest runs PowerShell during install",
        ),
        "winget.nested_installer" => (
            "security.downloader",
            Severity::Info,
            "winget installer contains nested installers",
        ),
        _ => (
            "security.capability",
            Severity::Info,
            "Package recipe observation",
        ),
    };
    let mut out = AnalysisOutput::default();
    out.evidence.push(Evidence {
        id: "evidence-001".into(),
        kind: EvidenceKind::ManifestEntry,
        artifact_sha256: sha256.into(),
        artifact_path: display.into(),
        location: Location::default(),
        snippet: Some(bytebouncer_core::evidence::bound_snippet(&obs.detail).0),
        snippet_truncated: obs.detail.len() > bytebouncer_core::evidence::MAX_SNIPPET_BYTES,
        producer: Producer {
            tool: "bytebouncer-adapters".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            rule_id: Some(obs.kind.clone()),
        },
        notes: None,
    });
    out.findings.push(Finding {
        id: "finding-001".into(),
        category: category.into(),
        title: title.into(),
        severity,
        evidence_strength: EvidenceStrength::StaticReference,
        artifact_sha256: sha256.into(),
        evidence_ids: vec!["evidence-001".into()],
        data_types: vec![],
        recipient: None,
        enabled_by_default: TriState::Unknown,
        runtime_observed: false,
        conditions: vec![],
        possible_legitimate_purpose: Some(
            "Common in legitimate package recipes; review the command".into(),
        ),
        opt_out: OptOut {
            status: OptOutStatus::NotEstablished,
        },
        limitations: vec![],
    });
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn dependency_names() {
        assert_eq!(super::dependency_name("glibc>=2.38"), "glibc");
        assert_eq!(super::dependency_name("libfoo.so=1-64"), "libfoo.so");
        assert_eq!(super::dependency_name("python"), "python");
    }
}

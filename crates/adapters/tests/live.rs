//! Live checks against the real endpoints (and this host's pacman DBs).
//! Ignored by default: `cargo test -p bytebouncer-adapters -- --ignored`.

use bytebouncer_adapters::{
    FetchError, Fetched, Fetcher, HostInfo, NoHostCommands, Resolution, parse_command_str, resolve,
};

/// Minimal test-only fetcher. The real CLI routes requests through its
/// sandboxed fetch worker instead.
struct UreqFetcher {
    agent: ureq::Agent,
}

impl UreqFetcher {
    fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .max_redirects(5)
            .http_status_as_error(false)
            .user_agent("bytebouncer-adapters-live-test")
            .build()
            .into();
        UreqFetcher { agent }
    }
}

impl Fetcher for UreqFetcher {
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        use ureq::ResponseExt;
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut resp = req.call().map_err(|e| FetchError::Network(e.to_string()))?;
        let code = resp.status().as_u16();
        let final_url = resp.get_uri().to_string();
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => FetchError::TooLarge { limit: max_bytes },
                e => FetchError::Network(e.to_string()),
            })?;
        if !(200..300).contains(&code) {
            return Err(FetchError::Status {
                code,
                message: String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).into_owned(),
            });
        }
        Ok(Fetched {
            bytes,
            final_url,
            redirects: 0,
        })
    }
}

fn live(cmd: &str, info: &HostInfo) -> Resolution {
    let req = parse_command_str(cmd).unwrap();
    let r = resolve(&req, &UreqFetcher::new(), &NoHostCommands, info)
        .unwrap_or_else(|e| panic!("{cmd}: {e}"));
    eprintln!("=== {cmd}");
    for p in &r.packages {
        eprintln!(
            "  {} {} [{}] repo={:?} deps={}",
            p.name,
            p.version,
            p.arch.as_deref().unwrap_or("-"),
            p.repository,
            p.dependencies.len()
        );
        for s in &p.sources {
            eprintln!(
                "    {} sha256={} sha512={} sig={:?}",
                s.url,
                s.expected_sha256.as_deref().unwrap_or("-"),
                s.expected_sha512.is_some(),
                s.signature_url
            );
        }
    }
    for f in &r.recipe_files {
        eprintln!("  recipe {} ({} bytes)", f.path, f.bytes.len());
    }
    for u in &r.unresolved {
        eprintln!("  UNRESOLVED {u}");
    }
    for o in &r.observations {
        eprintln!("  OBS {} {}", o.kind, o.detail);
    }
    for n in &r.notes {
        eprintln!("  note {n}");
    }
    assert!(!r.packages.is_empty(), "{cmd} resolved nothing");
    r
}

fn windows() -> HostInfo {
    HostInfo::minimal("x86_64", "windows")
}

#[test]
#[ignore = "reads this host's pacman configuration"]
fn live_pacman_curl() {
    let info = HostInfo::detect();
    if info.pacman_conf.is_none() {
        eprintln!("no pacman on this host; skipping");
        return;
    }
    let r = live("pacman -S curl", &info);
    let s = &r.packages[0].sources[0];
    assert!(s.url.ends_with(".pkg.tar.zst"));
    assert!(s.expected_sha256.is_some());
    assert!(!r.embedded_signatures.is_empty());
}

#[test]
#[ignore = "network"]
fn live_aur_yay() {
    let info = HostInfo::detect();
    let r = live("yay -S yay", &info);
    let p = &r.packages[0];
    assert_eq!(p.repository.as_deref(), Some("aur"));
    assert!(p.sources.iter().any(|s| s.expected_sha256.is_some()));
    assert!(r.recipe_files.iter().any(|f| f.path == "PKGBUILD"));
}

#[test]
#[ignore = "network"]
fn live_brew_wget_and_firefox_cask() {
    let r = live("brew install wget", &HostInfo::minimal("x86_64", "linux"));
    assert!(!r.source_headers.is_empty(), "ghcr token");
    assert!(r.recipe_files.iter().any(|f| f.path == "wget.rb"));
    let r = live(
        "brew install --cask firefox",
        &HostInfo::minimal("aarch64", "macos"),
    );
    assert!(r.packages[0].sources[0].expected_sha256.is_some());
}

#[test]
#[ignore = "network (GitHub API, 60 requests/hour unauthenticated)"]
fn live_winget() {
    let r = live("winget install --id 7zip.7zip --exact", &windows());
    assert!(
        r.packages[0]
            .sources
            .iter()
            .all(|s| s.expected_sha256.is_some())
    );
    let r = live("winget install --id Microsoft.PowerToys -e", &windows());
    assert!(!r.packages[0].sources.is_empty());
}

#[test]
#[ignore = "network"]
fn live_scoop_7zip() {
    let r = live("scoop install 7zip", &windows());
    assert!(r.packages[0].sources[0].expected_sha256.is_some());
}

#[test]
#[ignore = "network"]
fn live_choco_7zip() {
    let r = live("choco install 7zip", &windows());
    assert!(r.packages[0].sources[0].expected_sha512.is_some());
}

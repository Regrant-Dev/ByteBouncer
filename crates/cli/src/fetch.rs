//! Fetch worker: downloads one URL into the scan workspace.
//!
//! Runs as a separate confined process that may only make outbound TCP
//! connections to ports 80/443, read system configuration needed for DNS and
//! TLS, and write its destination directory. (Windows: the AppContainer's
//! `internetClient` capability cannot restrict ports, so `port_restriction`
//! is reported missing there and downloads need `--allow-reduced-isolation`.) It hashes what it writes and
//! never parses the downloaded bytes; parsing happens later in Tier 1.
//! Request headers (which may carry tokens) travel over stdin, not argv.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytebouncer_sandbox::{Limits, Network, Profile, Seccomp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const WORKER_SUBCOMMAND: &str = "__fetch-worker";
pub const MAX_REDIRECTS: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub max_bytes: u64,
    pub dest: PathBuf,
    pub timeout_secs: u64,
    pub allow_reduced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchReply {
    pub final_url: String,
    pub redirects: u32,
    pub sha256: String,
    pub size: u64,
    pub isolation_active: Vec<String>,
    pub isolation_missing: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum WorkerOutcome {
    Ok(FetchReply),
    Err(String),
}

/// Only HTTP(S) on default ports: the worker's Landlock rules allow nothing else.
pub fn validate_url(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .context("only http:// and https:// URLs are supported")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        bail!("URLs with embedded credentials are not supported");
    }
    if let Some((_, port)) = authority.rsplit_once(':')
        && !authority.ends_with(']')
        && !matches!(port, "80" | "443")
    {
        bail!("only ports 80 and 443 are allowed for downloads");
    }
    Ok(())
}

/// Parent side: run the fetch worker and wait for it.
pub fn fetch(req: &FetchRequest) -> Result<FetchReply> {
    validate_url(&req.url)?;
    let exe = std::env::current_exe().context("locating own executable")?;
    let dest_dir = req.dest.parent().context("destination has no parent")?;
    let profile = fetch_profile(dest_dir, req.max_bytes);
    let mut child = bytebouncer_sandbox::spawn_worker(
        "fetch",
        &profile,
        &exe,
        &[OsStr::new(WORKER_SUBCOMMAND)],
    )
    .context("spawning fetch worker")?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin
            .write_all(&serde_json::to_vec(req)?)
            .context("sending fetch request")?;
    }
    let out = child.wait_with_output()?;
    match serde_json::from_slice::<WorkerOutcome>(&out.stdout) {
        Ok(WorkerOutcome::Ok(reply)) => Ok(reply),
        Ok(WorkerOutcome::Err(e)) => bail!("download failed: {e}"),
        Err(_) => bail!(
            "fetch worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

/// Worker side. Never returns.
pub fn worker_main() -> ! {
    let outcome = match worker_inner() {
        Ok(reply) => WorkerOutcome::Ok(reply),
        Err(e) => WorkerOutcome::Err(format!("{e:#}")),
    };
    let _ = std::io::stdout().write_all(&serde_json::to_vec(&outcome).unwrap_or_default());
    std::process::exit(0)
}

fn worker_inner() -> Result<FetchReply> {
    let mut input = Vec::new();
    std::io::stdin().take(1 << 20).read_to_end(&mut input)?;
    let req: FetchRequest = serde_json::from_slice(&input).context("bad fetch request")?;
    let dest_dir = req
        .dest
        .parent()
        .context("destination has no parent")?
        .to_path_buf();

    let applied = bytebouncer_sandbox::confine_self(&fetch_profile(&dest_dir, req.max_bytes));
    if !applied.missing.is_empty() && !req.allow_reduced {
        bail!(
            "fetch sandbox restrictions unavailable ({}); re-run with --allow-reduced-isolation",
            applied.missing.join(", ")
        );
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(MAX_REDIRECTS)
        .save_redirect_history(true)
        .timeout_global(Some(Duration::from_secs(req.timeout_secs)))
        .user_agent(concat!("bytebouncer/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut builder = agent.get(&req.url);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    let mut resp = builder.call().context("request failed")?;
    use ureq::ResponseExt;
    let final_url = resp.get_uri().to_string();
    let redirects = resp
        .get_redirect_history()
        .map(|h| h.len().saturating_sub(1) as u32)
        .unwrap_or(0);
    if let Some(len) = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        && len > req.max_bytes
    {
        bail!(
            "response is {len} bytes, over the {}-byte limit",
            req.max_bytes
        );
    }

    let mut reader = resp
        .body_mut()
        .with_config()
        .limit(req.max_bytes + 1)
        .reader();
    let mut file = std::fs::File::create_new(&req.dest).context("creating download file")?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = reader.read(&mut buf).context("reading response body")?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > req.max_bytes {
            bail!("download exceeded the {}-byte limit", req.max_bytes);
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }
    file.sync_all()?;
    Ok(FetchReply {
        final_url,
        redirects,
        sha256: hex::encode(hasher.finalize()),
        size,
        isolation_active: applied.active,
        isolation_missing: applied.missing,
    })
}

/// Built identically by the parent (Windows applies it at launch) and the
/// worker (Linux/macOS apply it in `confine_self`).
fn fetch_profile(dest_dir: &Path, max_bytes: u64) -> Profile {
    // Linux: DNS (resolv.conf, nsswitch, hosts) and NSS modules. macOS: the
    // Seatbelt profile adds the resolver files and services itself. Windows:
    // system DLLs are readable by every AppContainer. TLS roots are compiled in.
    let (read_only, executable): (Vec<PathBuf>, Vec<PathBuf>) = if cfg!(target_os = "linux") {
        (
            vec!["/etc".into(), "/run/systemd/resolve".into()],
            vec!["/usr".into(), "/lib".into(), "/lib64".into()],
        )
    } else {
        (vec![], vec![])
    };
    Profile {
        read_only,
        executable,
        read_write: vec![dest_dir.to_path_buf()],
        network: Network::TcpConnectPorts(vec![80, 443]),
        limits: Limits {
            address_space: None,
            cpu_seconds: Some(600),
            file_size: Some(max_bytes.saturating_add(1)),
            open_files: Some(64),
        },
        seccomp: Seccomp::DenyList,
        env: vec![],
    }
}

/// Fetcher for package adapters: small metadata documents fetched through the worker.
pub struct WorkerFetcher {
    pub scratch: PathBuf,
    pub allow_reduced: bool,
    pub counter: std::cell::Cell<u32>,
}

impl WorkerFetcher {
    pub fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<(Vec<u8>, FetchReply)> {
        let n = self.counter.get() + 1;
        self.counter.set(n);
        let dir = self.scratch.join(format!("meta-{n}"));
        std::fs::create_dir_all(&dir)?;
        let dest = dir.join("body");
        let reply = fetch(&FetchRequest {
            url: url.to_owned(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            max_bytes,
            dest: dest.clone(),
            timeout_secs: 60,
            allow_reduced: self.allow_reduced,
        })?;
        let bytes = std::fs::read(&dest)?;
        let _ = std::fs::remove_dir_all(&dir);
        Ok((bytes, reply))
    }
}

#[cfg(test)]
mod tests {
    use super::validate_url;

    #[test]
    fn url_validation() {
        assert!(validate_url("https://example.com/a.zip").is_ok());
        assert!(validate_url("http://example.com:80/a").is_ok());
        assert!(validate_url("https://example.com:8443/a").is_err());
        assert!(validate_url("ftp://example.com/a").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("https://user:pw@example.com/").is_err());
    }
}

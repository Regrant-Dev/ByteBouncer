//! Extraction worker for nested files too large to analyze in memory
//! (docs/design-large-entries.md). It reads the input snapshot, opens its
//! one output file, then confines itself like a Tier 1 worker (no network,
//! no new file access, no exec) and streams the requested entry into the
//! already-open file, hashing as it writes. The written file is then
//! analyzed as an ordinary input.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bytebouncer_analysis::container::{SpillRequest, extract_spilled};
use bytebouncer_sandbox::{Limits, Network, Profile, Seccomp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const WORKER_SUBCOMMAND: &str = "__extract-worker";

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractRequest {
    pub input: PathBuf,
    pub request: SpillRequest,
    pub dest: PathBuf,
    pub max_bytes: u64,
    pub allow_reduced: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractReply {
    pub sha256: String,
    pub size: u64,
    pub active: Vec<String>,
    pub missing: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum Outcome {
    Ok(ExtractReply),
    Err(String),
}

fn profile(input: &Path, dest_dir: &Path, max_bytes: u64) -> Profile {
    Profile {
        read_only: vec![input.to_path_buf()],
        executable: vec![],
        read_write: vec![dest_dir.to_path_buf()],
        network: Network::Blocked,
        limits: Limits {
            // The input plus any intermediate containers live in memory.
            address_space: Some(8 << 30),
            cpu_seconds: Some(1800),
            file_size: Some(max_bytes.saturating_add(1)),
            open_files: Some(16),
        },
        seccomp: Seccomp::Tier1AllowList,
        env: vec![],
    }
}

/// Parent side: extract one spilled entry to `req.dest`.
pub fn extract(req: &ExtractRequest) -> Result<ExtractReply> {
    let exe = std::env::current_exe().context("locating own executable")?;
    let dest_dir = req.dest.parent().context("destination has no parent")?;
    let mut child = bytebouncer_sandbox::spawn_worker(
        "extract",
        &profile(&req.input, dest_dir, req.max_bytes),
        &exe,
        &[OsStr::new(WORKER_SUBCOMMAND)],
    )
    .context("spawning extraction worker")?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin
            .write_all(&serde_json::to_vec(req)?)
            .context("sending extraction request")?;
    }
    let out = child.wait_with_output()?;
    match serde_json::from_slice::<Outcome>(&out.stdout) {
        Ok(Outcome::Ok(reply)) => Ok(reply),
        Ok(Outcome::Err(e)) => bail!("{e}"),
        Err(_) => bail!(
            "extraction worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

/// Worker side. Never returns.
pub fn worker_main() -> ! {
    let outcome = match worker_inner() {
        Ok(r) => Outcome::Ok(r),
        Err(e) => Outcome::Err(format!("{e:#}")),
    };
    let _ = std::io::stdout().write_all(&serde_json::to_vec(&outcome).unwrap_or_default());
    std::process::exit(0)
}

/// Hashes and counts everything written through it.
struct HashingWriter {
    file: File,
    hasher: Sha256,
    written: u64,
}

impl Write for HashingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn worker_inner() -> Result<ExtractReply> {
    let mut input = Vec::new();
    std::io::stdin().take(1 << 20).read_to_end(&mut input)?;
    let req: ExtractRequest = serde_json::from_slice(&input).context("bad extraction request")?;
    // Everything the worker touches is opened before confinement.
    let bytes = std::fs::read(&req.input).context("reading input snapshot")?;
    let file = File::create_new(&req.dest).context("creating output file")?;
    let dest_dir = req.dest.parent().context("destination has no parent")?;

    let applied = bytebouncer_sandbox::confine_self(&profile(&req.input, dest_dir, req.max_bytes));
    let missing: Vec<String> = bytebouncer_sandbox::tier1_required()
        .iter()
        .filter(|r| !applied.active.iter().any(|a| a == *r))
        .map(|r| r.to_string())
        .collect();
    if !missing.is_empty() && !req.allow_reduced {
        bail!(
            "sandbox restrictions unavailable ({}); re-run with --allow-reduced-isolation",
            missing.join(", ")
        );
    }

    let mut out = HashingWriter {
        file,
        hasher: Sha256::new(),
        written: 0,
    };
    let size = extract_spilled(&bytes, &req.request, &mut out, req.max_bytes)
        .map_err(anyhow::Error::msg)?;
    out.flush()?;
    if size != out.written {
        bail!("extracted {size} bytes but wrote {}", out.written);
    }
    Ok(ExtractReply {
        sha256: hex::encode(out.hasher.finalize()),
        size,
        active: applied.active,
        missing,
    })
}

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bytebouncer_adapters::{FetchError, Fetched, Fetcher, HostCommands};

pub fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

type Request = (String, Vec<(String, String)>);

/// Offline fetcher: exact URL → bytes or HTTP status; anything else is 404.
/// Records every request so tests can assert what was (not) fetched.
#[derive(Default)]
pub struct MockFetcher {
    pub routes: HashMap<String, Result<Vec<u8>, u16>>,
    pub requests: RefCell<Vec<Request>>,
}

impl MockFetcher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, url: &str, body: Vec<u8>) -> Self {
        self.routes.insert(url.to_string(), Ok(body));
        self
    }
    pub fn status(mut self, url: &str, code: u16) -> Self {
        self.routes.insert(url.to_string(), Err(code));
        self
    }
    pub fn requested(&self) -> Vec<String> {
        self.requests
            .borrow()
            .iter()
            .map(|(u, _)| u.clone())
            .collect()
    }
}

impl Fetcher for MockFetcher {
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        self.requests.borrow_mut().push((
            url.to_string(),
            headers
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        ));
        match self.routes.get(url) {
            Some(Ok(b)) if b.len() as u64 > max_bytes => {
                Err(FetchError::TooLarge { limit: max_bytes })
            }
            Some(Ok(b)) => Ok(Fetched {
                bytes: b.clone(),
                final_url: url.to_string(),
                redirects: 0,
            }),
            Some(Err(code)) => Err(FetchError::Status {
                code: *code,
                message: "mock".into(),
            }),
            None => Err(FetchError::Status {
                code: 404,
                message: "not found".into(),
            }),
        }
    }
}

/// Offline host commands: `program args…` (joined by spaces) → output.
#[derive(Default)]
pub struct MockHost {
    pub outputs: HashMap<String, Result<String, String>>,
    pub calls: RefCell<Vec<String>>,
}

impl MockHost {
    pub fn with(mut self, cmd: &str, out: &str) -> Self {
        self.outputs.insert(cmd.to_string(), Ok(out.to_string()));
        self
    }
}

impl HostCommands for MockHost {
    fn run_readonly(&self, program: &str, args: &[&str]) -> Result<String, String> {
        let key = format!("{program} {}", args.join(" "));
        self.calls.borrow_mut().push(key.clone());
        self.outputs
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Err(format!("unexpected command: {key}")))
    }
}

/// Build a `.tar.gz` (or zstd) archive in memory from (path, contents).
pub fn tarball(files: &[(&str, &str)], zstd: bool) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, path, contents.as_bytes())
            .unwrap();
    }
    let raw = builder.into_inner().unwrap();
    if zstd {
        ruzstd::encoding::compress_to_vec(&raw[..], ruzstd::encoding::CompressionLevel::Fastest)
    } else {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&raw).unwrap();
        enc.finish().unwrap()
    }
}

/// A fresh temporary directory for one test, removed when dropped.
pub struct TempDir(PathBuf);

impl std::ops::Deref for TempDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn temp_dir(tag: &str) -> TempDir {
    let d = std::env::temp_dir().join(format!(
        "bytebouncer-adapters-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    TempDir(d)
}

//! capa and ClamAV through an MCP "scan" server that runs them somewhere
//! else, e.g. inside a disposable offline VM. The server exposes exactly
//! `capa_scan {path}` and `clamav_scan {path}` and returns the tools' raw
//! output, which is parsed here exactly like a local run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytebouncer_core::ToolVersion;
use serde_json::{Value, json};

use crate::RetainedData;
use crate::mcp::{Launch, McpServer};
use crate::out::Builder;
use crate::{capa, clamav};

pub struct RemoteScanConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub staging_dir: Option<PathBuf>,
    pub timeout: Duration,
    pub label: String,
}

pub struct RemoteScan {
    server: McpServer,
    staging_dir: Option<PathBuf>,
    timeout: Duration,
    pub label: String,
    pub has_capa: bool,
    pub has_clamav: bool,
}

impl RemoteScan {
    pub fn start(cfg: RemoteScanConfig) -> Result<Self, String> {
        let launch = Launch {
            program: &cfg.program,
            args: &cfg.args,
            env: cfg.env,
            sandbox: None,
            allow_reduced: true,
        };
        let (server, _) = McpServer::start(launch, Duration::from_secs(120))?;
        let has_capa = server.has_tool("capa_scan");
        let has_clamav = server.has_tool("clamav_scan");
        if !has_capa && !has_clamav {
            return Err(format!(
                "'{}' offers neither capa_scan nor clamav_scan",
                server.server_name
            ));
        }
        Ok(Self {
            server,
            staging_dir: cfg.staging_dir,
            timeout: cfg.timeout,
            label: cfg.label,
            has_capa,
            has_clamav,
        })
    }

    /// Scan one artifact; findings and coverage go into `b`.
    #[allow(clippy::too_many_arguments)]
    pub fn scan(
        &mut self,
        input: &Path,
        display: &str,
        sha256: &str,
        executable: bool,
        b: &mut Builder,
        tools: &mut Vec<ToolVersion>,
        retained: &mut RetainedData,
    ) {
        let staged = match &self.staging_dir {
            Some(dir) => {
                let p = dir.join(format!("bytebouncer-scan-{}", &sha256[..16]));
                if let Err(e) = std::fs::create_dir_all(dir).and_then(|_| std::fs::copy(input, &p))
                {
                    b.out
                        .coverage
                        .limitations
                        .push(format!("{display}: remote scan staging failed: {e}"));
                    return;
                }
                Some(p)
            }
            None => None,
        };
        let path = staged.as_deref().unwrap_or(input).display().to_string();

        if self.has_clamav {
            match self
                .server
                .call_tool("clamav_scan", json!({"path": path}), self.timeout)
            {
                Ok(r) => {
                    let code = r["exit_code"].as_i64().unwrap_or(2) as i32;
                    let mut parsed = clamav::parse(r["stdout"].as_str().unwrap_or_default());
                    if code == 2 && parsed.errors.is_empty() {
                        parsed.errors.push(
                            r["stderr_tail"]
                                .as_str()
                                .unwrap_or("clamscan error")
                                .to_owned(),
                        );
                    }
                    let engine = r["clamav_version"]
                        .as_str()
                        .unwrap_or("unknown")
                        .trim_start_matches("ClamAV ")
                        .to_owned();
                    let db = r["db_version"].as_str().unwrap_or("unknown").to_owned();
                    clamav::map(&parsed, code, &engine, &db, b);
                    push_tool(tools, "clamav (remote)", &engine);
                }
                Err(e) => b
                    .out
                    .coverage
                    .limitations
                    .push(format!("{display}: remote ClamAV failed: {e}")),
            }
        }
        if self.has_capa && executable {
            match self
                .server
                .call_tool("capa_scan", json!({"path": path}), self.timeout)
            {
                Ok(r) if r["exit_code"].as_i64() == Some(0) => {
                    match capa::parse(r["stdout"].as_str().unwrap_or_default()) {
                        Ok(report) => {
                            push_tool(tools, "capa (remote)", &report.version);
                            capa::map(&report, b);
                            retained.capa_rules = report.rules;
                        }
                        Err(e) => b
                            .out
                            .coverage
                            .limitations
                            .push(format!("{display}: remote capa output: {e}")),
                    }
                }
                Ok(r) => b.out.coverage.limitations.push(format!(
                    "{display}: remote capa failed (exit {}): {}",
                    r["exit_code"],
                    r["stderr_tail"]
                        .as_str()
                        .unwrap_or_default()
                        .chars()
                        .take(300)
                        .collect::<String>()
                )),
                Err(e) => b
                    .out
                    .coverage
                    .limitations
                    .push(format!("{display}: remote capa failed: {e}")),
            }
        }
        b.out
            .coverage
            .analyzed
            .push(format!("{display}: capa/ClamAV via {}", self.label));
        if let Some(p) = staged {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn push_tool(tools: &mut Vec<ToolVersion>, name: &str, version: &str) {
    if !tools.iter().any(|t| t.name == name) {
        tools.push(ToolVersion {
            name: name.into(),
            version: version.into(),
            digest: None,
        });
    }
}

/// Result payloads a scan server returns (documented shape for implementers).
pub fn result_shape() -> Value {
    json!({
        "capa_scan": {"exit_code": "int", "stdout": "capa -j JSON text", "stderr_tail": "string", "capa_version": "string"},
        "clamav_scan": {"exit_code": "int (0 clean, 1 detected, 2 error)", "stdout": "clamscan --no-summary --stdout output", "stderr_tail": "string", "clamav_version": "string", "db_version": "string"}
    })
}

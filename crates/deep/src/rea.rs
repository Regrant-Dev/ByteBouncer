//! REA backend (https://github.com/morluto/rea): Ghidra-backed investigation
//! over MCP. Works with a local `rea mcp` (run in the Tier 2 sandbox) or with
//! a connector that runs REA elsewhere, e.g. inside a disposable offline VM.
//!
//! ByteBouncer opens the artifact, verifies REA saw the exact same bytes,
//! collects a small set of evidence on its own (where network destinations
//! are used, with decompiled code), and then keeps the session open so the
//! user's model can investigate through a fixed allow-list of read-only REA
//! tools. Every tool result the model fetches is recorded as citable
//! evidence. REA's dynamic tools (Frida, ADB, browser/UI automation,
//! renaming/annotation) are never exposed.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use bytebouncer_core::{
    Evidence, EvidenceKind, EvidenceStrength, Location, Producer, Recipient, Severity,
};
use bytebouncer_sandbox::{Applied, Profile};
use serde_json::{Value, json};

use crate::mcp::{Launch, McpServer};
use crate::out::{Builder, EvidenceSpec, FindingSpec};

/// Read-only REA tools the model may call (prefixed `rea_` for the model).
pub const MODEL_TOOLS: &[&str] = &[
    "binary_overview",
    "list_segments",
    "list_procedures",
    "search_procedures",
    "procedure_info",
    "procedure_address",
    "procedure_callers",
    "procedure_callees",
    "procedure_references",
    "procedure_pseudo_code",
    "procedure_assembly",
    "read_function_instructions",
    "batch_decompile",
    "analyze_function",
    "inspect_native_api",
    "resolve_containing_procedure",
    "list_strings",
    "search_strings",
    "trace_feature",
    "trace_call_path",
    "get_call_graph",
    "xrefs",
    "find_xrefs_to_name",
    "list_names",
    "address_name",
];

/// API names whose presence in decompiled code means "this function talks to the network".
const NETWORK_APIS: &[&str] = &[
    "send(",
    "sendto(",
    "sendmsg(",
    "connect(",
    "WSASend",
    "WinHttpSendRequest",
    "WinHttpWriteData",
    "InternetWriteFile",
    "HttpSendRequest",
    "InternetOpenUrl",
    "URLDownloadToFile",
    "curl_easy_perform",
    "SSL_write",
    "write_all",
    "NSURLSession",
    "CFNetwork",
    "getaddrinfo(",
    "gethostbyname(",
];

const OUTPUT_LIMIT: usize = 8_000;
const MAX_DESTINATIONS: usize = 10;

pub struct ReaConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    /// Tier 2 profile for a local REA; `None` for a connector that isolates itself.
    pub sandbox: Option<Profile>,
    /// Copy inputs here first (connectors that only accept files from certain folders).
    pub staging_dir: Option<PathBuf>,
    pub open_timeout: Duration,
    pub call_timeout: Duration,
    pub allow_reduced: bool,
    /// Label for reports, e.g. "local REA" or "external command".
    pub label: String,
}

/// An open REA session for one artifact. Dropping it closes the server and
/// removes any staged copy.
pub struct ReaSession {
    server: Mutex<McpServer>,
    artifact_path: String,
    sha256: String,
    staged: Option<PathBuf>,
    call_timeout: Duration,
    new_evidence: Mutex<Vec<Evidence>>,
    counter: Mutex<usize>,
    pub version: String,
}

impl Drop for ReaSession {
    fn drop(&mut self) {
        if let Some(p) = &self.staged {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Drop bulky provenance headers REA attaches to every result.
fn strip(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        for k in [
            "subject",
            "provider",
            "analysis_profile",
            "raw_result",
            "environment",
        ] {
            o.remove(k);
        }
    }
    v
}

fn bounded_json(v: &Value) -> Value {
    let text = v.to_string();
    if text.len() <= OUTPUT_LIMIT {
        return v.clone();
    }
    let mut cut = OUTPUT_LIMIT;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    Value::String(format!(
        "{}… [truncated {} bytes]",
        &text[..cut],
        text.len() - cut
    ))
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest
        .split(['/', ':', '?', '#'])
        .next()?
        .to_ascii_lowercase();
    (host.contains('.') && host.len() <= 253).then_some(host)
}

impl ReaSession {
    /// Open `input` in REA and collect automatic evidence into `b`.
    /// Returns the live session (for model tools) and the sandbox report.
    pub fn open(
        cfg: ReaConfig,
        input: &Path,
        display: &str,
        sha256: &str,
        b: &mut Builder,
    ) -> Result<(ReaSession, Option<Applied>), String> {
        // Stage first if the backend only reads certain folders.
        let (path, staged) = match &cfg.staging_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("staging dir {}: {e}", dir.display()))?;
                let name = display.rsplit(['/', '!']).next().unwrap_or("input");
                let safe: String = name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let p = dir.join(format!("bytebouncer-{}-{safe}", &sha256[..16]));
                std::fs::copy(input, &p).map_err(|e| format!("staging input: {e}"))?;
                (p.clone(), Some(p))
            }
            None => (input.to_path_buf(), None),
        };
        let cleanup = |e: String| {
            if let Some(p) = &staged {
                let _ = std::fs::remove_file(p);
            }
            e
        };
        let launch = Launch {
            program: &cfg.program,
            args: &cfg.args,
            env: cfg.env,
            sandbox: cfg.sandbox,
            allow_reduced: cfg.allow_reduced,
        };
        // VM connectors may boot a guest on first use; allow for that.
        let (mut server, applied) =
            McpServer::start(launch, Duration::from_secs(120)).map_err(cleanup)?;
        if !server.has_tool("open_binary") {
            return Err(cleanup(format!(
                "'{}' does not look like a REA server (no open_binary tool)",
                server.server_name
            )));
        }
        let opened = server
            .call_tool(
                "open_binary",
                json!({"path": path.display().to_string()}),
                cfg.open_timeout,
            )
            .map_err(|e| cleanup(format!("REA could not open the file: {e}")))?;
        let reported = opened["result"]["sha256"].as_str().unwrap_or_default();
        if !reported.is_empty() && reported != sha256 {
            return Err(cleanup(format!(
                "REA analyzed different bytes (sha256 {reported}, expected {sha256})"
            )));
        }

        let overview = server
            .call_tool("binary_overview", json!({}), cfg.open_timeout)
            .map(strip);
        let version = server.server_name.clone();
        let session = ReaSession {
            server: Mutex::new(server),
            artifact_path: display.to_owned(),
            sha256: sha256.to_owned(),
            staged: staged.clone(),
            call_timeout: cfg.call_timeout,
            new_evidence: Mutex::new(vec![]),
            counter: Mutex::new(0),
            version,
        };
        match overview {
            Ok(v) => {
                let n = &v["normalized_result"];
                let procs = n["procedure_count"]
                    .as_u64()
                    .or(n["procedures"]["count"].as_u64());
                let strings = n["string_count"]
                    .as_u64()
                    .or(n["strings"]["count"].as_u64());
                b.out.coverage.analyzed.push(format!(
                    "{display}: REA/Ghidra analysis via {}{}",
                    cfg.label,
                    match (procs, strings) {
                        (Some(p), Some(s)) => format!(" ({p} procedures, {s} strings)"),
                        _ => String::new(),
                    }
                ));
            }
            Err(e) => b
                .out
                .coverage
                .limitations
                .push(format!("{display}: REA overview failed: {e}")),
        }
        session.collect_destinations(b);
        Ok((session, applied))
    }

    fn call(&self, name: &str, args: Value) -> Result<Value, String> {
        let mut server = self
            .server
            .lock()
            .map_err(|_| "REA session poisoned".to_string())?;
        server.call_tool(name, args, self.call_timeout).map(strip)
    }

    /// Where network destinations appear in code, with the decompiled function.
    fn collect_destinations(&self, b: &mut Builder) {
        let found = match self.call(
            "search_strings",
            json!({"pattern": "https?://", "mode": "regex"}),
        ) {
            Ok(v) => v,
            Err(e) => {
                b.out
                    .coverage
                    .limitations
                    .push(format!("REA string search failed: {e}"));
                return;
            }
        };
        let mut hosts: Vec<(String, String)> = Vec::new();
        for s in found["normalized_result"].as_array().into_iter().flatten() {
            let value = s["value"].as_str().unwrap_or_default();
            if let Some(h) = host_of(value)
                && !hosts.iter().any(|(x, _)| x == &h)
            {
                hosts.push((h, value.to_owned()));
            }
        }
        if hosts.len() > MAX_DESTINATIONS {
            b.out.coverage.limitations.push(format!(
                "REA: traced {MAX_DESTINATIONS} of {} destinations; the model can trace the rest",
                hosts.len()
            ));
            hosts.truncate(MAX_DESTINATIONS);
        }
        for (host, url) in hosts {
            let Ok(trace) = self.call("trace_feature", json!({"query": host})) else {
                continue;
            };
            let mut functions: Vec<(String, String)> = Vec::new();
            for r in trace["normalized_result"]["references"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let p = &r["containing_procedure"]["procedure"];
                if let (Some(name), Some(addr)) = (p["name"].as_str(), p["address"].as_str())
                    && !functions.iter().any(|(n, _)| n == name)
                {
                    functions.push((name.to_owned(), addr.to_owned()));
                }
            }
            for (fname, addr) in functions.into_iter().take(3) {
                let code = self
                    .call("procedure_pseudo_code", json!({"procedure": addr}))
                    .ok()
                    .and_then(|v| v["normalized_result"].as_str().map(str::to_owned))
                    .unwrap_or_default();
                let apis: Vec<&str> = NETWORK_APIS
                    .iter()
                    .copied()
                    .filter(|a| code.contains(a))
                    .collect();
                let location = Location {
                    function: Some(fname.clone()),
                    address: crate::out::parse_hex_address(&addr),
                    ..Default::default()
                };
                let s_id = b.evidence(EvidenceSpec {
                    kind: EvidenceKind::StringReference,
                    location: location.clone(),
                    snippet: &url,
                    tool: "rea",
                    version: &self.version,
                    rule_id: Some("trace_feature"),
                    notes: None,
                });
                let mut ids = vec![s_id];
                if !code.is_empty() {
                    ids.push(
                        b.evidence(EvidenceSpec {
                            kind: EvidenceKind::DecompiledFunction,
                            location,
                            snippet: &excerpt_around(&code, &host),
                            tool: "rea",
                            version: &self.version,
                            rule_id: Some("procedure_pseudo_code"),
                            notes: Some(
                                "Ghidra pseudocode via REA; an interpretation, not original source"
                                    .into(),
                            ),
                        }),
                    );
                }
                let (title, severity) = if apis.is_empty() {
                    (
                        format!("Destination {host} is used in function {fname}"),
                        Severity::Info,
                    )
                } else {
                    (
                        format!(
                            "Function {fname} uses destination {host} and calls {}",
                            apis.join(", ").replace('(', "")
                        ),
                        Severity::Low,
                    )
                };
                b.finding(FindingSpec {
                    category: "privacy.recipients",
                    title,
                    severity,
                    strength: EvidenceStrength::StaticReference,
                    evidence_ids: ids,
                    recipient: Some(Recipient { domain: host.clone(), ownership: "unknown".into() }),
                    conditions: vec![],
                    purpose: None,
                    limitations: vec!["Static code reading; whether and when this code runs, and what it sends, is not established".into()],
                });
            }
        }
    }

    /// Model tool specs: the allow-listed tools the server actually offers,
    /// with the server's own schemas, renamed `rea_<name>`.
    pub fn tool_specs(&self) -> Vec<(String, String, Value)> {
        let Ok(server) = self.server.lock() else {
            return vec![];
        };
        server
            .tools
            .iter()
            .filter_map(|t| {
                let name = t["name"].as_str()?;
                MODEL_TOOLS.contains(&name).then(|| {
                    let desc = t["description"].as_str().unwrap_or_default();
                    let desc: String = desc.chars().take(400).collect();
                    (
                        format!("rea_{name}"),
                        format!("REA (Ghidra): {desc}"),
                        t["inputSchema"].clone(),
                    )
                })
            })
            .collect()
    }

    /// Run an allow-listed tool for the model and record the result as evidence.
    pub fn model_call(&self, prefixed: &str, args: &Value) -> Result<Value, String> {
        let name = prefixed.strip_prefix("rea_").ok_or("not a REA tool")?;
        if !MODEL_TOOLS.contains(&name) {
            return Err(format!("{prefixed} is not available"));
        }
        // No tool may receive host paths from the model.
        if args.to_string().contains("\"path\"") {
            return Err("path arguments are not accepted".into());
        }
        let result = self.call(name, args.clone())?;
        let kind = match name {
            "procedure_pseudo_code"
            | "batch_decompile"
            | "analyze_function"
            | "procedure_assembly"
            | "read_function_instructions" => EvidenceKind::DecompiledFunction,
            "trace_call_path" | "get_call_graph" | "procedure_callers" | "procedure_callees" => {
                EvidenceKind::CallPath
            }
            "search_strings" | "list_strings" | "trace_feature" | "xrefs"
            | "find_xrefs_to_name" => EvidenceKind::StringReference,
            _ => EvidenceKind::Symbol,
        };
        let id = {
            let mut c = self.counter.lock().map_err(|_| "poisoned")?;
            *c += 1;
            format!("evidence-rea-{}-{:03}", &self.sha256[..8], *c)
        };
        let summary = result["normalized_result"].to_string();
        let (snippet, truncated) = bytebouncer_core::evidence::bound_snippet(&summary);
        let evidence = Evidence {
            id: id.clone(),
            kind,
            artifact_sha256: self.sha256.clone(),
            artifact_path: self.artifact_path.clone(),
            location: Location {
                function: args["procedure"].as_str().map(str::to_owned),
                ..Default::default()
            },
            snippet: Some(snippet),
            snippet_truncated: truncated,
            producer: Producer {
                tool: "rea".into(),
                version: self.version.clone(),
                rule_id: Some(name.into()),
            },
            notes: Some(format!(
                "model-requested {name} {}",
                bytebouncer_core::evidence::bound_snippet(&args.to_string()).0
            )),
        };
        if let Ok(mut v) = self.new_evidence.lock() {
            v.push(evidence);
        }
        Ok(
            json!({"bytebouncer_evidence_id": id, "artifact": self.artifact_path, "untrusted_sample_data": bounded_json(&result)}),
        )
    }

    pub fn drain_new_evidence(&self) -> Vec<Evidence> {
        self.new_evidence
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }

    pub fn artifact(&self) -> &str {
        &self.artifact_path
    }
}

/// The part of decompiled code around the first mention of `needle`.
fn excerpt_around(code: &str, needle: &str) -> String {
    let at = code.find(needle).unwrap_or(0);
    let start = code[..at]
        .rfind('\n')
        .map(|i| at.saturating_sub(at - i).saturating_sub(120))
        .unwrap_or(0);
    let mut s = start;
    while !code.is_char_boundary(s) {
        s -= 1;
    }
    code[s..]
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_excerpts() {
        assert_eq!(
            host_of("https://a.example.com/x").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(host_of("https://localhost/x"), None);
        let code = "int f() {\n  x = 1;\n  send(fd, \"https://t.example/c\", 5);\n}\n";
        assert!(excerpt_around(code, "t.example").contains("send(fd"));
    }

    #[test]
    fn strip_removes_headers() {
        let v = strip(json!({"subject": 1, "provider": 2, "normalized_result": 3}));
        assert_eq!(v, json!({"normalized_result": 3}));
    }
}

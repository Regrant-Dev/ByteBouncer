//! Ghidra headless export (`ExportEvidence.java`) parsing and mapping.

use std::collections::{BTreeMap, BTreeSet};

use bytebouncer_core::{EvidenceKind, EvidenceStrength, Location, Recipient, Severity};
use serde::{Deserialize, Serialize};

use crate::out::{Builder, EvidenceSpec, FindingSpec, parse_hex_address, split_label};

/// The GhidraScript, written into the scratch directory at runtime.
pub const EXPORT_SCRIPT: &str = include_str!("../ghidra/ExportEvidence.java");
pub const EXPORT_SCRIPT_NAME: &str = "ExportEvidence.java";
pub const EXPORT_SCHEMA: &str = "bytebouncer-ghidra-export/1";

// Rust-side bounds, enforced regardless of what the export claims: the
// export is produced by a tool that processed untrusted input.
const MAX_FUNCTIONS: usize = 5000;
const MAX_EDGES: usize = 15;
const MAX_IMPORTS: usize = 3000;
const MAX_API_USES: usize = 300;
const MAX_CALLERS: usize = 25;
const MAX_CHAINS: usize = 5;
const MAX_CHAIN_LEN: usize = 12;
const MAX_STRINGS: usize = 600;
const MAX_STRING_CHARS: usize = 300;
const MAX_NAME_CHARS: usize = 200;
pub const MAX_DECOMPILED_CHARS: usize = 16_000;
const MAX_DECOMPILED: usize = 200;
/// APIs shown as evidence per category finding.
const MAX_APIS_PER_FINDING: usize = 8;
/// Destination (recipient) findings per artifact.
const MAX_RECIPIENT_FINDINGS: usize = 20;
/// Few functions in a sizeable binary suggests packing.
const FEW_FUNCTIONS: u64 = 10;
const SIZEABLE_BYTES: u64 = 64 << 10;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub compiler: String,
    #[serde(default)]
    pub image_base: String,
    #[serde(default)]
    pub function_count: u64,
    #[serde(default)]
    pub external_function_count: u64,
    #[serde(default)]
    pub entry_points: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub thunk: bool,
    #[serde(default)]
    pub entry: bool,
    #[serde(default)]
    pub callees: Vec<String>,
    #[serde(default)]
    pub callers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportInfo {
    pub name: String,
    #[serde(default)]
    pub library: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiUse {
    pub api: String,
    pub category: String,
    #[serde(default)]
    pub caller_count: u64,
    /// Direct (non-thunk) callers as `name@address`.
    #[serde(default)]
    pub callers: Vec<String>,
    /// Chains `entry@addr → … → caller@addr → api`, entry first.
    #[serde(default)]
    pub chains: Vec<Vec<String>>,
}

impl ApiUse {
    pub fn reachable(&self) -> bool {
        !self.chains.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRef {
    pub value: String,
    #[serde(default)]
    pub truncated: bool,
    /// `url`, `domain`, `path`, or `registry`.
    pub kind: String,
    #[serde(default)]
    pub address: String,
    /// Referencing functions as `name@address`.
    #[serde(default)]
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub function: String,
    #[serde(default)]
    pub relevance: i64,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhidraExport {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub analysis_timed_out: bool,
    #[serde(default)]
    pub program: ProgramInfo,
    #[serde(default)]
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub functions_truncated: bool,
    #[serde(default)]
    pub imports: Vec<ImportInfo>,
    #[serde(default)]
    pub imports_truncated: bool,
    #[serde(default)]
    pub api_uses: Vec<ApiUse>,
    #[serde(default)]
    pub api_uses_truncated: bool,
    #[serde(default)]
    pub strings: Vec<StringRef>,
    #[serde(default)]
    pub strings_truncated: bool,
    #[serde(default)]
    pub relevant_function_count: u64,
    #[serde(default)]
    pub decompiled: Vec<DecompiledFunction>,
    #[serde(default)]
    pub decompiler_error: Option<String>,
    #[serde(default)]
    pub cancelled: bool,
}

fn cap_str(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

fn cap_vec<T>(v: &mut Vec<T>, max: usize) -> bool {
    let cut = v.len() > max;
    v.truncate(max);
    cut
}

fn cap_names(v: &mut Vec<String>, max: usize) {
    v.truncate(max);
    for s in v {
        cap_str(s, MAX_NAME_CHARS);
    }
}

pub fn parse(json: &str) -> Result<GhidraExport, String> {
    let mut e: GhidraExport = serde_json::from_str(json)
        .map_err(|err| format!("Ghidra export JSON not understood: {err}"))?;
    if e.schema != EXPORT_SCHEMA {
        return Err(format!("unexpected Ghidra export schema '{}'", e.schema));
    }
    e.functions_truncated |= cap_vec(&mut e.functions, MAX_FUNCTIONS);
    for f in &mut e.functions {
        cap_str(&mut f.name, MAX_NAME_CHARS);
        cap_names(&mut f.callees, MAX_EDGES);
        cap_names(&mut f.callers, MAX_EDGES);
    }
    e.imports_truncated |= cap_vec(&mut e.imports, MAX_IMPORTS);
    for i in &mut e.imports {
        cap_str(&mut i.name, MAX_NAME_CHARS);
    }
    e.api_uses_truncated |= cap_vec(&mut e.api_uses, MAX_API_USES);
    for a in &mut e.api_uses {
        cap_str(&mut a.api, MAX_NAME_CHARS);
        cap_names(&mut a.callers, MAX_CALLERS);
        a.chains.truncate(MAX_CHAINS);
        for c in &mut a.chains {
            cap_names(c, MAX_CHAIN_LEN);
        }
    }
    e.strings_truncated |= cap_vec(&mut e.strings, MAX_STRINGS);
    for s in &mut e.strings {
        s.truncated |= cap_str(&mut s.value, MAX_STRING_CHARS);
        cap_names(&mut s.functions, 10);
    }
    e.decompiled.truncate(MAX_DECOMPILED);
    for d in &mut e.decompiled {
        if let Some(code) = &mut d.code {
            d.truncated |= cap_str(code, MAX_DECOMPILED_CHARS);
        }
    }
    cap_names(&mut e.program.entry_points, 50);
    Ok(e)
}

struct CategoryInfo {
    category: &'static str,
    severity: Severity,
    title: &'static str,
    purpose: Option<&'static str>,
}

fn category_info(cat: &str) -> CategoryInfo {
    let (category, severity, title, purpose) = match cat {
        "network" => (
            "security.capability",
            Severity::Info,
            "Calls network APIs",
            Some("Networking is common in legitimate software (updates, sync, licensing)"),
        ),
        "download" => (
            "security.downloader",
            Severity::Low,
            "Calls download APIs",
            Some("Updaters and installers download files"),
        ),
        "process" => (
            "security.capability",
            Severity::Low,
            "Starts other programs",
            Some("Launching helpers, shells, or browsers is common"),
        ),
        "injection" => (
            "security.capability",
            Severity::Medium,
            "Calls process memory/injection APIs",
            Some("Debuggers, profilers, and game overlays use these APIs"),
        ),
        "input_capture" => (
            "privacy.sensitive_collection",
            Severity::Medium,
            "Calls keyboard/input capture APIs",
            Some("Hotkey handlers and accessibility tools read input state"),
        ),
        "clipboard" => (
            "privacy.sensitive_collection",
            Severity::Low,
            "Calls clipboard APIs",
            Some("Copy/paste support uses the clipboard"),
        ),
        "screen_capture" => (
            "privacy.sensitive_collection",
            Severity::Low,
            "Calls screen capture APIs",
            Some("Drawing and screenshot features use these APIs"),
        ),
        "service" => (
            "security.persistence",
            Severity::Low,
            "Calls service creation/configuration APIs",
            Some("Installers register services"),
        ),
        "registry_write" => (
            "security.capability",
            Severity::Info,
            "Writes to the registry",
            None,
        ),
        "file_write" => (
            "security.capability",
            Severity::Info,
            "Creates, renames, or deletes files",
            None,
        ),
        "crypto" => (
            "security.capability",
            Severity::Info,
            "Calls cryptography APIs",
            Some("Encryption and hashing are routine (TLS, integrity checks)"),
        ),
        "dynamic_load" => (
            "security.capability",
            Severity::Info,
            "Loads libraries or resolves functions at runtime",
            Some("Plugin systems and optional dependencies load code dynamically"),
        ),
        _ => (
            "security.capability",
            Severity::Info,
            "Calls notable APIs",
            None,
        ),
    };
    CategoryInfo {
        category,
        severity,
        title,
        purpose,
    }
}

const CALLGRAPH_LIMIT: &str = "Static call graph only: calls through function pointers, vtables, callbacks, or dynamically resolved APIs are not followed";
const NOT_REACHED: &str = "No call chain from an entry point or exported function was found; the code may be unused or reached indirectly";

fn chain_text(chain: &[String]) -> String {
    chain.join(" → ")
}

/// A short excerpt of decompiled code around the first line mentioning `needle`.
fn excerpt(code: &str, needle: &str) -> String {
    let lines: Vec<&str> = code.lines().filter(|l| !l.trim().is_empty()).collect();
    let pos = lines.iter().position(|l| l.contains(needle)).unwrap_or(0);
    let start = pos.saturating_sub(1);
    lines[start..lines.len().min(start + 5)]
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("\n")
}

struct Ctx<'e> {
    e: &'e GhidraExport,
    version: String,
}

impl Ctx<'_> {
    fn decompiled(&self, label: &str) -> Option<&DecompiledFunction> {
        self.e
            .decompiled
            .iter()
            .find(|d| d.function == label && d.code.is_some())
    }

    fn call_path(&self, b: &mut Builder<'_>, chain: &[String], api: &str) -> String {
        let caller = chain
            .len()
            .checked_sub(2)
            .and_then(|i| chain.get(i))
            .map(|c| split_label(c));
        b.evidence(EvidenceSpec {
            kind: EvidenceKind::CallPath,
            location: Location {
                function: caller.map(|(n, _)| n.to_owned()),
                address: caller.and_then(|(_, a)| a),
                ..Default::default()
            },
            snippet: &chain_text(chain),
            tool: "ghidra",
            version: &self.version,
            rule_id: Some(api),
            notes: Some("Direct calls only, entry point first".into()),
        })
    }

    fn decompiled_evidence(
        &self,
        b: &mut Builder<'_>,
        label: &str,
        needle: &str,
    ) -> Option<String> {
        let d = self.decompiled(label)?;
        let (name, addr) = split_label(label);
        Some(b.evidence(EvidenceSpec {
            kind: EvidenceKind::DecompiledFunction,
            location: Location {
                function: Some(name.to_owned()),
                address: addr,
                ..Default::default()
            },
            snippet: &excerpt(d.code.as_deref().unwrap_or(""), needle),
            tool: "ghidra",
            version: &self.version,
            rule_id: None,
            notes: Some(format!(
                "Excerpt; the bounded decompilation of {name} is retained for get_function{}",
                if d.truncated {
                    " (itself truncated)"
                } else {
                    ""
                }
            )),
        }))
    }
}

/// Add Ghidra findings, evidence, and coverage. `input_size` is the
/// artifact size in bytes (used for the packing heuristic).
pub fn map(
    e: &GhidraExport,
    version: &str,
    max_decompiled: usize,
    input_size: u64,
    b: &mut Builder<'_>,
) {
    let ctx = Ctx {
        e,
        version: version.to_owned(),
    };
    let imports: BTreeSet<&str> = e.imports.iter().map(|i| i.name.as_str()).collect();

    // One finding per API category.
    let mut by_cat: BTreeMap<&str, Vec<&ApiUse>> = BTreeMap::new();
    for a in &e.api_uses {
        by_cat.entry(a.category.as_str()).or_default().push(a);
    }
    for (cat, uses) in &by_cat {
        let info = category_info(cat);
        let mut ids = Vec::new();
        let reachable = uses.iter().any(|u| u.reachable());
        let mut sorted = uses.clone();
        sorted.sort_by_key(|u| (!u.reachable(), u.api.clone()));
        let mut decompiled_done = BTreeSet::new();
        for u in sorted.iter().take(MAX_APIS_PER_FINDING) {
            if let Some(chain) = u.chains.first() {
                ids.push(ctx.call_path(b, chain, &u.api));
            } else {
                let callers: Vec<&str> = u.callers.iter().take(3).map(String::as_str).collect();
                let kind = if imports.contains(u.api.as_str()) {
                    EvidenceKind::Import
                } else {
                    EvidenceKind::Symbol
                };
                let first = u.callers.first().map(|c| split_label(c));
                ids.push(b.evidence(EvidenceSpec {
                    kind,
                    location: Location {
                        function: first.map(|(n, _)| n.to_owned()),
                        address: first.and_then(|(_, a)| a),
                        ..Default::default()
                    },
                    snippet: &format!(
                        "{} called from {} ({} call site function(s))",
                        u.api,
                        callers.join(", "),
                        u.caller_count
                    ),
                    tool: "ghidra",
                    version: &ctx.version,
                    rule_id: Some(&u.api),
                    notes: None,
                }));
            }
            // One decompiled excerpt per finding, from the most relevant caller.
            if decompiled_done.is_empty() {
                for c in &u.callers {
                    if let Some(id) = ctx.decompiled_evidence(b, c, &format!("{}(", u.api)) {
                        ids.push(id);
                        decompiled_done.insert(c.clone());
                        break;
                    }
                }
            }
        }
        let apis: Vec<&str> = sorted.iter().take(4).map(|u| u.api.as_str()).collect();
        let more = if sorted.len() > 4 {
            format!(", +{} more", sorted.len() - 4)
        } else {
            String::new()
        };
        let mut limitations = vec![CALLGRAPH_LIMIT.to_owned()];
        if !reachable {
            limitations.push(NOT_REACHED.to_owned());
        }
        if uses.len() > MAX_APIS_PER_FINDING {
            limitations.push(format!(
                "{} more API(s) in this category are listed in the retained deep-analysis data",
                uses.len() - MAX_APIS_PER_FINDING
            ));
        }
        b.finding(FindingSpec {
            category: info.category,
            title: format!(
                "{} ({}{more}){}",
                info.title,
                apis.join(", "),
                if reachable {
                    ", reachable from an entry point"
                } else {
                    ""
                }
            ),
            severity: info.severity,
            strength: if reachable {
                EvidenceStrength::StaticReachability
            } else {
                EvidenceStrength::StaticReference
            },
            evidence_ids: ids,
            recipient: None,
            conditions: Vec::new(),
            purpose: info.purpose.map(str::to_owned),
            limitations,
        });
    }

    map_recipients(&ctx, b);
    coverage(e, max_decompiled, input_size, b);
}

/// Host part of a URL, or the domain itself.
pub fn host_of(value: &str, kind: &str) -> Option<String> {
    let host = if kind == "url" {
        let rest = value.split_once("://")?.1;
        let authority = rest.split(['/', '?', '#']).next()?;
        let authority = authority.rsplit('@').next()?;
        if authority.starts_with('[') {
            authority.split(']').next()?.trim_start_matches('[')
        } else {
            authority.split(':').next()?
        }
    } else {
        value
    };
    let host = host.trim().trim_end_matches('.').to_lowercase();
    (!host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')))
    .then_some(host)
}

/// A destination string, the function referencing it, a network call chain
/// through that function (if any), and how the function reaches the network.
type HostRef<'e> = (&'e StringRef, &'e str, Option<&'e Vec<String>>, String);

/// "URL referenced by function F which calls a network API" → recipients.
fn map_recipients(ctx: &Ctx<'_>, b: &mut Builder<'_>) {
    let e = ctx.e;
    let network: Vec<&ApiUse> = e
        .api_uses
        .iter()
        .filter(|a| a.category == "network")
        .collect();
    if network.is_empty() {
        return;
    }
    let net_callers: BTreeSet<&str> = network
        .iter()
        .flat_map(|a| a.callers.iter().map(String::as_str))
        .collect();
    let callees_of = |label: &str| -> Vec<String> {
        let (name, addr) = split_label(label);
        e.functions
            .iter()
            .find(|f| f.name == name && parse_hex_address(&f.address) == addr)
            .map(|f| f.callees.clone())
            .unwrap_or_default()
    };
    // Network-calling function names, for matching callee names.
    let net_caller_names: BTreeSet<&str> = net_callers.iter().map(|c| split_label(c).0).collect();
    let net_api_names: BTreeSet<&str> = network.iter().map(|a| a.api.as_str()).collect();

    let mut by_host: BTreeMap<String, Vec<HostRef<'_>>> = BTreeMap::new();
    for s in e
        .strings
        .iter()
        .filter(|s| s.kind == "url" || s.kind == "domain")
    {
        let Some(host) = host_of(&s.value, &s.kind) else {
            continue;
        };
        for f in &s.functions {
            let direct = net_callers.contains(f.as_str());
            let callees = callees_of(f);
            let via = callees.iter().find(|c| {
                net_caller_names.contains(c.as_str()) || net_api_names.contains(c.as_str())
            });
            if !direct && via.is_none() {
                continue;
            }
            let how = if direct {
                "itself calls network APIs".to_owned()
            } else {
                format!(
                    "calls {} which calls network APIs",
                    via.map(String::as_str).unwrap_or("?")
                )
            };
            // A network chain passing through F makes the reference reachable.
            let chain = network
                .iter()
                .flat_map(|a| a.chains.iter())
                .find(|c| c.iter().any(|x| x == f));
            by_host
                .entry(host.clone())
                .or_default()
                .push((s, f.as_str(), chain, how));
            break;
        }
    }
    for (host, refs) in by_host.into_iter().take(MAX_RECIPIENT_FINDINGS) {
        let mut ids = Vec::new();
        let mut reachable = false;
        for (s, f, chain, how) in refs.iter().take(4) {
            let (fname, faddr) = split_label(f);
            ids.push(b.evidence(EvidenceSpec {
                kind: EvidenceKind::StringReference,
                location: Location {
                    function: Some(fname.to_owned()),
                    address: parse_hex_address(&s.address).or(faddr),
                    ..Default::default()
                },
                snippet: &s.value,
                tool: "ghidra",
                version: &ctx.version,
                rule_id: None,
                notes: Some(format!("Referenced by {f}, which {how}")),
            }));
            if let Some(chain) = chain {
                reachable = true;
                let api = chain.last().cloned().unwrap_or_default();
                ids.push(ctx.call_path(b, chain, &api));
            }
            if let Some(id) = ctx.decompiled_evidence(b, f, &s.value) {
                ids.push(id);
            }
        }
        let mut limitations = vec![
            "An embedded destination referenced by networking code does not prove that data is sent there; data flow was not traced".to_owned(),
            CALLGRAPH_LIMIT.to_owned(),
        ];
        if !reachable {
            limitations.push(NOT_REACHED.to_owned());
        }
        b.finding(FindingSpec {
            category: "privacy.recipients",
            title: format!("Destination {host} referenced by code that calls network APIs"),
            severity: Severity::Info,
            strength: if reachable {
                EvidenceStrength::StaticReachability
            } else {
                EvidenceStrength::StaticReference
            },
            evidence_ids: ids,
            recipient: Some(Recipient {
                domain: host,
                ownership: "unknown".into(),
            }),
            conditions: Vec::new(),
            purpose: None,
            limitations,
        });
    }
}

fn coverage(e: &GhidraExport, max_decompiled: usize, input_size: u64, b: &mut Builder<'_>) {
    let decompiled_ok = e.decompiled.iter().filter(|d| d.code.is_some()).count();
    let failed = e.decompiled.len() - decompiled_ok;
    let path = b.path.to_owned();
    let cov = &mut b.out.coverage;
    cov.analyzed.push(format!(
        "{path}: Ghidra ({}, {}): {} functions, {} imports, {} notable API(s) with call sites, {} string(s) of interest, {} function(s) decompiled",
        e.program.format,
        e.program.language,
        e.program.function_count,
        e.program.external_function_count,
        e.api_uses.len(),
        e.strings.len(),
        decompiled_ok
    ));
    cov.limitations.push(format!("Ghidra: {CALLGRAPH_LIMIT}"));
    if e.analysis_timed_out {
        cov.limitations.push(
            "Ghidra auto-analysis hit its time limit; functions and references may be missing"
                .into(),
        );
    }
    if e.cancelled {
        cov.limitations
            .push("Ghidra export was cancelled before completion".into());
    }
    for (flag, what) in [
        (e.functions_truncated, "function list"),
        (e.imports_truncated, "import list"),
        (e.api_uses_truncated, "API call-site list"),
        (e.strings_truncated, "string list"),
    ] {
        if flag {
            cov.limitations
                .push(format!("Ghidra {what} truncated at its size bound"));
        }
    }
    let relevant = e.relevant_function_count as usize;
    if relevant > decompiled_ok {
        cov.limitations.push(format!(
            "Decompiled {decompiled_ok} of {relevant} relevant function(s) (limit {max_decompiled}); others were not reviewed in decompiled form"
        ));
    }
    if failed > 0 {
        cov.limitations.push(format!(
            "Decompilation failed or timed out for {failed} function(s)"
        ));
    }
    let truncated = e.decompiled.iter().filter(|d| d.truncated).count();
    if truncated > 0 {
        cov.limitations.push(format!(
            "{truncated} decompiled function(s) truncated at the per-function size bound"
        ));
    }
    if let Some(err) = &e.decompiler_error {
        cov.limitations.push(format!(
            "Ghidra decompiler unavailable: {}",
            crate::runner::bounded(err, 200)
        ));
    }
    let own = e
        .program
        .function_count
        .saturating_sub(e.program.external_function_count);
    if own < FEW_FUNCTIONS && input_size >= SIZEABLE_BYTES {
        cov.limitations.push(format!(
            "Ghidra recovered only {own} function(s) from a {} KiB file; it may be packed, obfuscated, or mostly data",
            input_size >> 10
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> GhidraExport {
        parse(
            &std::fs::read_to_string(format!(
                "{}/tests/fixtures/ghidra_net_elf.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn parses_real_export() {
        let e = fixture();
        assert_eq!(e.program.language, "x86:LE:64:default");
        let connect = e.api_uses.iter().find(|a| a.api == "connect").unwrap();
        assert_eq!(connect.category, "network");
        assert!(connect.reachable());
        assert_eq!(
            connect.chains[0].first().map(String::as_str),
            Some("main@00101410")
        );
        assert!(
            e.strings
                .iter()
                .any(|s| s.kind == "url" && s.value.contains("telemetry.example.invalid"))
        );
        assert!(
            e.decompiled
                .iter()
                .any(|d| d.code.as_deref().unwrap_or("").contains("connect("))
        );
    }

    #[test]
    fn maps_reachable_network_and_recipient() {
        let e = fixture();
        let mut b = Builder::new("abc", "net", "elf-64");
        map(&e, "12.1.4", 20, 16_712, &mut b);
        let out = b.out;
        let net = out
            .findings
            .iter()
            .find(|f| f.title.starts_with("Calls network APIs"))
            .unwrap();
        assert_eq!(net.evidence_strength, EvidenceStrength::StaticReachability);
        assert_eq!(net.severity, Severity::Info);
        let path = out
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::CallPath)
            .unwrap();
        assert!(
            path.snippet
                .as_deref()
                .unwrap()
                .starts_with("main@00101410 → collect_and_send")
        );
        assert_eq!(path.location.function.as_deref(), Some("send_report"));
        assert!(
            out.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::DecompiledFunction)
        );

        let rec = out
            .findings
            .iter()
            .find(|f| f.category == "privacy.recipients")
            .unwrap();
        assert_eq!(
            rec.recipient.as_ref().unwrap().domain,
            "telemetry.example.invalid"
        );
        assert_eq!(rec.recipient.as_ref().unwrap().ownership, "unknown");
        assert_eq!(rec.evidence_strength, EvidenceStrength::StaticReachability);
        assert!(rec.limitations.iter().any(|l| l.contains("does not prove")));
        let sref = out
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::StringReference)
            .unwrap();
        assert_eq!(sref.location.function.as_deref(), Some("collect_and_send"));
        assert!(sref.notes.as_deref().unwrap().contains("send_report"));
        // Only one recipient finding for URL + bare domain of the same host.
        assert_eq!(
            out.findings
                .iter()
                .filter(|f| f.category == "privacy.recipients")
                .count(),
            1
        );
        for f in &out.findings {
            for id in &f.evidence_ids {
                assert!(out.evidence.iter().any(|e| &e.id == id));
            }
        }
        assert!(out.coverage.analyzed[0].contains("2 function(s) decompiled"));
    }

    #[test]
    fn unreachable_is_static_reference() {
        let mut e = fixture();
        for a in &mut e.api_uses {
            a.chains.clear();
        }
        let mut b = Builder::new("abc", "net", "elf-64");
        map(&e, "12.1.4", 20, 16_712, &mut b);
        assert!(
            b.out
                .findings
                .iter()
                .all(|f| f.evidence_strength == EvidenceStrength::StaticReference)
        );
        assert!(
            b.out
                .findings
                .iter()
                .all(|f| f.limitations.iter().any(|l| l.contains("No call chain")))
        );
    }

    #[test]
    fn limits_reported() {
        let mut e = fixture();
        e.analysis_timed_out = true;
        e.strings_truncated = true;
        e.relevant_function_count = 50;
        e.program.function_count = 3;
        e.program.external_function_count = 0;
        let mut b = Builder::new("abc", "net", "elf-64");
        map(&e, "12.1.4", 2, 1 << 20, &mut b);
        let l = b.out.coverage.limitations.join("\n");
        assert!(l.contains("time limit"));
        assert!(l.contains("string list truncated"));
        assert!(l.contains("Decompiled 2 of 50"));
        assert!(l.contains("packed"));
    }

    #[test]
    fn rejects_wrong_schema_and_bounds_input() {
        assert!(parse(r#"{"schema":"other"}"#).is_err());
        let long = "x".repeat(100_000);
        let json = format!(
            r#"{{"schema":"{EXPORT_SCHEMA}","decompiled":[{{"function":"f@1","code":"{long}"}}],"strings":[{{"value":"{long}","kind":"url"}}]}}"#
        );
        let e = parse(&json).unwrap();
        assert!(e.decompiled[0].truncated);
        assert_eq!(
            e.decompiled[0].code.as_ref().unwrap().len(),
            MAX_DECOMPILED_CHARS
        );
        assert!(e.strings[0].truncated);
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://user@Api.Example.com:8443/x?y", "url").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(host_of("http://[::1]:80/", "url").as_deref(), Some("::1"));
        assert_eq!(
            host_of("example.org.", "domain").as_deref(),
            Some("example.org")
        );
        assert_eq!(host_of("https://%s/x", "url"), None);
    }
}

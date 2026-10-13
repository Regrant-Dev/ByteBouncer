//! capa (`capa -j`) result parsing and mapping to findings.
//!
//! Evidence strength: capa rules match *structural code features* (API calls,
//! constants, strings, instruction patterns) scoped to functions or basic
//! blocks. That is more than "a string is present", but it is still a rule
//! match over static features that says nothing about whether the code is
//! reachable or executed, and rules can misfire (e.g. curl matches "run
//! PowerShell expression"). `pattern_match` ("a rule or signature matched")
//! is therefore the honest strength; `static_reference` would overstate it
//! as a direct observation of a specific import or string.

use std::collections::BTreeMap;

use bytebouncer_core::{EvidenceKind, EvidenceStrength, Location, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::out::{Builder, EvidenceSpec, FindingSpec};

/// Rules reported as evidence per finding group; the rest are counted.
const MAX_RULES_PER_GROUP: usize = 8;
/// Match addresses kept per rule.
const MAX_ADDRESSES: usize = 20;
/// Addresses shown in an evidence snippet.
const SNIPPET_ADDRESSES: usize = 3;
/// Rules retained for model tools.
pub const MAX_RETAINED_RULES: usize = 1000;

#[derive(Debug, Deserialize)]
struct Doc {
    meta: Meta,
    rules: BTreeMap<String, RuleResult>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    version: String,
    #[serde(default)]
    analysis: Analysis,
}

#[derive(Debug, Default, Deserialize)]
struct Analysis {
    #[serde(default)]
    format: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RuleResult {
    meta: RuleMeta,
    #[serde(default)]
    matches: Value,
}

#[derive(Debug, Deserialize)]
struct RuleMeta {
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    attack: Vec<Value>,
    #[serde(default)]
    mbc: Vec<Value>,
    #[serde(default)]
    lib: bool,
    #[serde(default)]
    is_subscope_rule: bool,
}

/// One matched capa rule, as retained for model tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapaRule {
    pub name: String,
    pub namespace: Option<String>,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub match_count: usize,
    pub addresses: Vec<u64>,
    /// capa library rule (building block, not reported as a finding).
    pub lib: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapaReport {
    pub version: String,
    /// `embedded` when the rules bundled with the standalone binary were used.
    pub rules_source: String,
    pub format: String,
    pub arch: String,
    pub os: String,
    pub rules: Vec<CapaRule>,
}

fn id_list(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|v| {
            let id = v.get("id")?.as_str()?;
            let label = v
                .get("technique")
                .or_else(|| v.get("behavior"))
                .and_then(Value::as_str)
                .unwrap_or("");
            Some(if label.is_empty() {
                id.to_owned()
            } else {
                format!("{id} {label}")
            })
        })
        .collect()
}

fn address_of(v: &Value) -> Option<u64> {
    match v.get("type").and_then(Value::as_str) {
        Some("absolute" | "relative" | "file") => v.get("value")?.as_u64(),
        _ => None,
    }
}

/// capa ≥ 7 emits `matches` as `[[address, match], …]`; older versions as
/// `{ "<address>": match }`.
fn match_addresses(matches: &Value) -> (usize, Vec<u64>) {
    match matches {
        Value::Array(items) => {
            let addrs = items
                .iter()
                .filter_map(|m| address_of(m.get(0)?))
                .take(MAX_ADDRESSES)
                .collect();
            (items.len(), addrs)
        }
        Value::Object(map) => {
            let addrs = map
                .keys()
                .filter_map(|k| k.parse::<u64>().ok())
                .take(MAX_ADDRESSES)
                .collect();
            (map.len(), addrs)
        }
        _ => (0, Vec::new()),
    }
}

pub fn parse(json: &str) -> Result<CapaReport, String> {
    let doc: Doc =
        serde_json::from_str(json).map_err(|e| format!("capa JSON not understood: {e}"))?;
    let rules_source = if doc.meta.analysis.rules.is_empty()
        || doc
            .meta
            .analysis
            .rules
            .iter()
            .any(|r| r.contains("_MEI") || r.contains("(embedded"))
    {
        "embedded".to_owned()
    } else {
        "custom".to_owned()
    };
    let rules = doc
        .rules
        .into_values()
        .take(MAX_RETAINED_RULES)
        .map(|r| {
            let (match_count, addresses) = match_addresses(&r.matches);
            CapaRule {
                name: r.meta.name,
                namespace: r.meta.namespace.filter(|n| !n.is_empty()),
                attack: id_list(&r.meta.attack),
                mbc: id_list(&r.meta.mbc),
                match_count,
                addresses,
                lib: r.meta.lib || r.meta.is_subscope_rule,
            }
        })
        .collect();
    Ok(CapaReport {
        version: doc.meta.version,
        rules_source,
        format: doc.meta.analysis.format,
        arch: doc.meta.analysis.arch,
        os: doc.meta.analysis.os,
        rules,
    })
}

/// How a rule is reported. `None` group = metadata only (linking, compiler).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Class {
    pub category: &'static str,
    pub severity: Severity,
    /// Group key and human label, e.g. `collection/keylog`.
    pub group: String,
    pub title: &'static str,
    pub purpose: Option<&'static str>,
}

fn prefix(ns: &str, depth: usize) -> String {
    ns.split('/').take(depth).collect::<Vec<_>>().join("/")
}

/// Map a capa rule to a finding class. Severity is conservative: capa alone
/// never yields more than `medium`.
pub fn classify(name: &str, namespace: Option<&str>) -> Option<Class> {
    let ns = namespace.unwrap_or("");
    let lname = name.to_lowercase();
    let c = |category, severity, group: String, title, purpose| {
        Some(Class {
            category,
            severity,
            group,
            title,
            purpose,
        })
    };

    if ns.starts_with("internal/") {
        return None;
    }
    if ns.starts_with("linking/")
        || ns.starts_with("compiler/")
        || ns.starts_with("runtime/")
        || ns.starts_with("executable/")
    {
        return None;
    }
    let sensitive = [
        "collection/keylog",
        "collection/screenshot",
        "collection/browser",
        "collection/credential",
    ];
    if sensitive.iter().any(|p| ns.starts_with(p))
        || ((ns.starts_with("collection/") || ns.starts_with("host-interaction/"))
            && ns.contains("credential"))
        || lname.contains("credential")
        || lname.contains("keystroke")
    {
        return c(
            "privacy.sensitive_collection",
            Severity::Medium,
            prefix(ns, 2),
            "Code patterns for collecting sensitive user data",
            Some(
                "Password managers, accessibility, and remote-support tools may legitimately use these",
            ),
        );
    }
    if ns.starts_with("collection/") || ns.starts_with("host-interaction/clipboard") {
        return c(
            "privacy.sensitive_collection",
            Severity::Low,
            prefix(ns, 2),
            "Code patterns for collecting user or system data",
            Some("Clipboard and data access is common in editors and productivity tools"),
        );
    }
    if ns.starts_with("persistence/") {
        return c(
            "security.persistence",
            Severity::Medium,
            prefix(ns, 2),
            "Code patterns for persistence",
            Some("Services, agents, and auto-start helpers legitimately register themselves"),
        );
    }
    if ns.starts_with("anti-analysis/") {
        return c(
            "security.evasion",
            Severity::Low,
            prefix(ns, 2),
            "Anti-analysis or obfuscation code patterns",
            Some("Packers and anti-debugging are also used for licensing and tamper protection"),
        );
    }
    if ns.starts_with("host-interaction/process/inject") {
        return c(
            "security.capability",
            Severity::Medium,
            prefix(ns, 3),
            "Process injection code patterns",
            Some("Debuggers, profilers, and accessibility tools can use these techniques"),
        );
    }
    if lname.contains("download") || ns.starts_with("load-code/") {
        return c(
            "security.downloader",
            Severity::Low,
            if ns.starts_with("load-code/") {
                prefix(ns, 1)
            } else {
                "download".to_owned()
            },
            "Code patterns for downloading or loading code at runtime",
            Some("Updaters, plugin systems, and interpreters download or load code"),
        );
    }
    if ns.starts_with("communication/") {
        return c(
            "security.capability",
            Severity::Info,
            prefix(ns, 1),
            "Network communication code patterns",
            Some("Networking is common in legitimate software (updates, sync, licensing)"),
        );
    }
    if ns.starts_with("data-manipulation/encryption")
        || ns.starts_with("data-manipulation/hashing")
        || ns.contains("crypt")
    {
        return c(
            "security.capability",
            Severity::Info,
            "cryptography".to_owned(),
            "Cryptography code patterns",
            Some("Encryption and hashing are routine (TLS, integrity checks, storage)"),
        );
    }
    if ns.starts_with("host-interaction/") {
        return c(
            "security.capability",
            Severity::Info,
            prefix(ns, 2),
            "Host interaction code patterns",
            None,
        );
    }
    c(
        "security.capability",
        Severity::Info,
        if ns.is_empty() {
            "other".to_owned()
        } else {
            prefix(ns, 1)
        },
        "Capability code patterns",
        None,
    )
}

fn is_packer_rule(rule: &CapaRule) -> bool {
    let ns = rule.namespace.as_deref().unwrap_or("");
    ns.starts_with("anti-analysis/packer")
        || ns.starts_with("internal/limitation")
        || rule.name.to_lowercase().contains("packed with")
}

/// Add capa findings, evidence, and coverage to `b`.
pub fn map(report: &CapaReport, b: &mut Builder<'_>) {
    let tool_version = format!("{} (rules: {})", report.version, report.rules_source);
    let mut groups: BTreeMap<(&'static str, String), (Class, Vec<&CapaRule>)> = BTreeMap::new();
    let mut packers = Vec::new();
    let mut metadata_only = 0usize;
    for rule in &report.rules {
        if is_packer_rule(rule) {
            packers.push(rule.name.clone());
        }
        if rule.lib {
            metadata_only += 1;
            continue;
        }
        match classify(&rule.name, rule.namespace.as_deref()) {
            Some(class) => {
                groups
                    .entry((class.category, class.group.clone()))
                    .or_insert_with(|| (class.clone(), Vec::new()))
                    .1
                    .push(rule);
            }
            None => metadata_only += 1,
        }
    }

    for ((category, group), (class, rules)) in &groups {
        let mut evidence_ids = Vec::new();
        let mut severity = class.severity;
        for rule in rules.iter().take(MAX_RULES_PER_GROUP) {
            severity = severity.max(
                classify(&rule.name, rule.namespace.as_deref()).map_or(severity, |c| c.severity),
            );
            let addrs: Vec<String> = rule
                .addresses
                .iter()
                .take(SNIPPET_ADDRESSES)
                .map(|a| format!("{a:#x}"))
                .collect();
            let mut snippet = format!("capa rule '{}'", rule.name);
            if let Some(ns) = &rule.namespace {
                snippet.push_str(&format!(" ({ns})"));
            }
            if !addrs.is_empty() {
                snippet.push_str(&format!(" matched at {}", addrs.join(", ")));
            }
            if rule.match_count > addrs.len() && !addrs.is_empty() {
                snippet.push_str(&format!(" (+{} more)", rule.match_count - addrs.len()));
            }
            let tags: Vec<&str> = rule
                .attack
                .iter()
                .chain(&rule.mbc)
                .map(String::as_str)
                .collect();
            let notes = (!tags.is_empty()).then(|| format!("ATT&CK/MBC: {}", tags.join("; ")));
            evidence_ids.push(b.evidence(EvidenceSpec {
                kind: EvidenceKind::RuleMatch,
                location: Location {
                    address: rule.addresses.first().copied(),
                    ..Default::default()
                },
                snippet: &snippet,
                tool: "capa",
                version: &tool_version,
                rule_id: Some(&rule.name),
                notes,
            }));
        }
        let mut limitations = vec![
            "capa matches static code patterns; it does not show that this code is reachable or ever runs".to_owned(),
        ];
        if rules.len() > MAX_RULES_PER_GROUP {
            limitations.push(format!(
                "{} more matching rule(s) in this group are omitted here and available in the retained deep-analysis data",
                rules.len() - MAX_RULES_PER_GROUP
            ));
        }
        let names: Vec<&str> = rules.iter().take(3).map(|r| r.name.as_str()).collect();
        let more = if rules.len() > 3 {
            format!(", +{} more", rules.len() - 3)
        } else {
            String::new()
        };
        b.finding(FindingSpec {
            category,
            title: format!("{} [{group}]: {}{more}", class.title, names.join(", ")),
            severity,
            strength: EvidenceStrength::PatternMatch,
            evidence_ids,
            recipient: None,
            conditions: Vec::new(),
            purpose: class.purpose.map(str::to_owned),
            limitations,
        });
    }

    let cov = &mut b.out.coverage;
    cov.analyzed.push(format!(
        "{}: capa {} ({} rules matched, {} finding group(s), {} library/metadata rule(s) not reported)",
        b.path,
        tool_version,
        report.rules.len(),
        groups.len(),
        metadata_only
    ));
    if !packers.is_empty() {
        packers.sort();
        packers.dedup();
        cov.limitations.push(format!(
            "capa indicates the sample is packed or obfuscated ({}); static analysis results are likely incomplete",
            packers.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn parses_real_curl_output() {
        let r = parse(&fixture("capa_curl_elf.json")).unwrap();
        assert_eq!(r.version, "9.4.0");
        assert_eq!(r.rules_source, "embedded");
        assert_eq!(r.format, "elf");
        let sock = r
            .rules
            .iter()
            .find(|x| x.name == "set socket configuration")
            .unwrap();
        assert_eq!(sock.namespace.as_deref(), Some("communication/socket"));
        assert!(sock.mbc.iter().any(|m| m.starts_with("C0001.001")));
        assert!(!sock.addresses.is_empty());
    }

    #[test]
    fn maps_curl_without_flooding() {
        let r = parse(&fixture("capa_curl_elf.json")).unwrap();
        let mut b = Builder::new("abc", "usr/bin/curl", "elf-64");
        map(&r, &mut b);
        let out = b.out;
        assert!(out.findings.len() < r.rules.len(), "rules must be grouped");
        assert!(out.findings.iter().all(|f| f.severity <= Severity::Medium));
        assert!(
            out.findings
                .iter()
                .all(|f| f.evidence_strength == EvidenceStrength::PatternMatch)
        );
        let net = out
            .findings
            .iter()
            .find(|f| f.title.contains("[communication]"))
            .unwrap();
        assert_eq!(net.category, "security.capability");
        assert_eq!(net.severity, Severity::Info);
        // Every finding references existing rule_match evidence.
        for f in &out.findings {
            for id in &f.evidence_ids {
                let ev = out.evidence.iter().find(|e| &e.id == id).unwrap();
                assert_eq!(ev.kind, EvidenceKind::RuleMatch);
                assert!(ev.producer.rule_id.is_some());
            }
        }
        // "run PowerShell expression" (load-code/powershell) in curl: downloader, low.
        let dl = out
            .findings
            .iter()
            .find(|f| f.category == "security.downloader")
            .unwrap();
        assert_eq!(dl.severity, Severity::Low);
        assert!(out.coverage.analyzed[0].contains("capa 9.4.0"));
    }

    #[test]
    fn maps_synthetic_categories() {
        let r = parse(&fixture("capa_synthetic_pe.json")).unwrap();
        let mut b = Builder::new("abc", "app.exe", "pe-32");
        map(&r, &mut b);
        let out = b.out;
        let find = |cat: &str| {
            out.findings
                .iter()
                .filter(|f| f.category == cat)
                .collect::<Vec<_>>()
        };
        let sens = find("privacy.sensitive_collection");
        assert!(
            sens.iter()
                .any(|f| f.title.contains("collection/keylog") && f.severity == Severity::Medium)
        );
        assert!(sens.iter().any(|f| f.title.contains("collection/browser")));
        assert_eq!(find("security.persistence")[0].severity, Severity::Medium);
        assert!(!find("security.evasion").is_empty());
        let inject = out
            .findings
            .iter()
            .find(|f| f.title.contains("injection"))
            .unwrap();
        assert_eq!(inject.severity, Severity::Medium);
        assert!(!find("security.downloader").is_empty());
        // 30 file-create rules collapse into one finding with bounded evidence.
        let fs = out
            .findings
            .iter()
            .find(|f| f.title.contains("host-interaction/file-system"))
            .unwrap();
        assert_eq!(fs.evidence_ids.len(), MAX_RULES_PER_GROUP);
        assert!(fs.limitations.iter().any(|l| l.contains("22 more")));
        // Library and linking rules are not findings.
        assert!(
            !out.findings
                .iter()
                .any(|f| f.title.contains("ZLIB") || f.title.contains("parse PE header"))
        );
        assert!(out.findings.iter().all(|f| f.severity < Severity::High));
        assert!(
            out.coverage
                .limitations
                .iter()
                .any(|l| l.contains("packed") && l.contains("UPX"))
        );
        let ev = out
            .evidence
            .iter()
            .find(|e| e.producer.rule_id.as_deref() == Some("log keystrokes via polling"))
            .unwrap();
        assert!(ev.snippet.as_deref().unwrap().contains("0x401000"));
        assert!(ev.notes.as_deref().unwrap().contains("T1056.001"));
    }

    #[test]
    fn empty_result_has_no_findings() {
        let r = parse(&fixture("capa_no_matches.json")).unwrap();
        let mut b = Builder::new("abc", "net", "elf-64");
        map(&r, &mut b);
        assert!(b.out.findings.is_empty());
        assert!(b.out.coverage.analyzed[0].contains("0 rules matched"));
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse("ERROR capa: Input file does not appear to be a supported file.").is_err());
    }

    #[test]
    fn legacy_dict_matches() {
        let v: Value = serde_json::json!({"4198400": {}, "4198500": {}});
        assert_eq!(match_addresses(&v).0, 2);
    }
}

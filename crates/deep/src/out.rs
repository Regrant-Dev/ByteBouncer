//! Helpers for building evidence-linked findings from tool output.

use bytebouncer_core::evidence::bound_snippet;
use bytebouncer_core::{
    AnalysisOutput, Evidence, EvidenceKind, EvidenceStrength, Finding, Location, OptOut,
    OptOutStatus, Producer, Recipient, Severity, TriState,
};

/// Accumulates findings and evidence with IDs unique within one output.
pub struct Builder<'a> {
    pub sha256: &'a str,
    pub path: &'a str,
    pub out: AnalysisOutput,
}

pub struct EvidenceSpec<'a> {
    pub kind: EvidenceKind,
    pub location: Location,
    pub snippet: &'a str,
    pub tool: &'a str,
    pub version: &'a str,
    pub rule_id: Option<&'a str>,
    pub notes: Option<String>,
}

pub struct FindingSpec {
    pub category: &'static str,
    pub title: String,
    pub severity: Severity,
    pub strength: EvidenceStrength,
    pub evidence_ids: Vec<String>,
    pub recipient: Option<Recipient>,
    pub conditions: Vec<String>,
    pub purpose: Option<String>,
    pub limitations: Vec<String>,
}

impl<'a> Builder<'a> {
    pub fn new(sha256: &'a str, path: &'a str, format: &str) -> Self {
        Self {
            sha256,
            path,
            out: AnalysisOutput {
                format: format.to_owned(),
                ..Default::default()
            },
        }
    }

    pub fn evidence(&mut self, spec: EvidenceSpec<'_>) -> String {
        let id = format!("evidence-{:03}", self.out.evidence.len() + 1);
        let (snippet, snippet_truncated) = bound_snippet(spec.snippet);
        self.out.evidence.push(Evidence {
            id: id.clone(),
            kind: spec.kind,
            artifact_sha256: self.sha256.to_owned(),
            artifact_path: self.path.to_owned(),
            location: spec.location,
            snippet: Some(snippet),
            snippet_truncated,
            producer: Producer {
                tool: spec.tool.to_owned(),
                version: spec.version.to_owned(),
                rule_id: spec.rule_id.map(str::to_owned),
            },
            notes: spec.notes,
        });
        id
    }

    pub fn finding(&mut self, spec: FindingSpec) {
        let id = format!("finding-{:03}", self.out.findings.len() + 1);
        self.out.findings.push(Finding {
            id,
            category: spec.category.to_owned(),
            title: spec.title,
            severity: spec.severity,
            evidence_strength: spec.strength,
            artifact_sha256: self.sha256.to_owned(),
            evidence_ids: spec.evidence_ids,
            data_types: Vec::new(),
            recipient: spec.recipient,
            enabled_by_default: TriState::Unknown,
            runtime_observed: false,
            conditions: spec.conditions,
            possible_legitimate_purpose: spec.purpose,
            opt_out: OptOut {
                status: OptOutStatus::NotEstablished,
            },
            limitations: spec.limitations,
        });
    }
}

/// Parse a Ghidra address string ("00101410", "ram:00401000") as hex.
pub fn parse_hex_address(text: &str) -> Option<u64> {
    let hex = text.rsplit(':').next()?.trim_start_matches("0x");
    u64::from_str_radix(hex, 16).ok()
}

/// Split Ghidra's `name@address` labels.
pub fn split_label(label: &str) -> (&str, Option<u64>) {
    match label.rsplit_once('@') {
        Some((name, addr)) => match parse_hex_address(addr) {
            Some(a) => (name, Some(a)),
            None => (label, None),
        },
        None => (label, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_split() {
        assert_eq!(split_label("main@00101410"), ("main", Some(0x101410)));
        assert_eq!(split_label("connect"), ("connect", None));
        assert_eq!(split_label("a@b@zz"), ("a@b@zz", None));
        assert_eq!(parse_hex_address("ram:00401000"), Some(0x401000));
    }
}

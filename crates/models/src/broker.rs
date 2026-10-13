//! Trust broker: validates model-proposed findings against retained evidence.
//!
//! The broker is the security boundary for model output.
//! It never trusts claimed strength, categories, IDs, or recipients; it only
//! *adds* findings, so a model cannot remove or downgrade existing ones.

use std::collections::{BTreeSet, HashMap};

use bytebouncer_core::{
    Evidence, EvidenceKind, EvidenceStrength, Finding, OptOut, OptOutStatus, Recipient, Severity,
    TriState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Closed set of categories a model may propose (plus `provenance.*`).
pub const ALLOWED_CATEGORIES: &[&str] = &[
    "security.capability",
    "security.persistence",
    "security.evasion",
    "security.downloader",
    "security.signature_match",
    "security.packing",
    "privacy.telemetry",
    "privacy.identifiers",
    "privacy.crash_reporting",
    "privacy.sensitive_collection",
    "privacy.recipients",
    "privacy.controls",
    "privacy.persistence_updates",
];

const MAX_FINDINGS_PER_SUBMISSION: usize = 50;
const MAX_LIST_ITEMS: usize = 16;
const MAX_TITLE_CHARS: usize = 200;
const MAX_TEXT_CHARS: usize = 600;
const MAX_EXPLANATION_CHARS: usize = 2_000;
const MAX_SUMMARY_CHARS: usize = 4_000;

/// Limitation attached to every accepted model finding.
pub const MODEL_FINDING_NOTE: &str = "Proposed by a model and accepted by the broker: evidence IDs, \
     artifact, and strength were verified mechanically; the model's reasoning was not.";

/// Whether `category` may be used by a model-proposed finding.
pub fn category_allowed(category: &str) -> bool {
    ALLOWED_CATEGORIES.contains(&category)
        || category.strip_prefix("provenance.").is_some_and(|rest| {
            !rest.is_empty()
                && rest.len() <= 48
                && rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Strongest evidence strength a single evidence kind can support.
pub fn strength_for_kind(kind: EvidenceKind) -> EvidenceStrength {
    use EvidenceKind as K;
    match kind {
        K::RuleMatch | K::Signature => EvidenceStrength::PatternMatch,
        K::StringReference
        | K::Import
        | K::Symbol
        | K::ManifestEntry
        | K::ScriptCommand
        | K::DecompiledFunction => EvidenceStrength::StaticReference,
        K::CallPath => EvidenceStrength::StaticReachability,
        K::DataflowTrace => EvidenceStrength::StaticDataflow,
        K::NetworkObservation | K::FileObservation | K::ProcessObservation => {
            EvidenceStrength::RuntimeObserved
        }
    }
}

fn is_observation(kind: EvidenceKind) -> bool {
    matches!(
        kind,
        EvidenceKind::NetworkObservation
            | EvidenceKind::FileObservation
            | EvidenceKind::ProcessObservation
    )
}

/// A model claim that failed validation. Kept, explicitly unverified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub claim: String,
    pub category: Option<String>,
    pub evidence_ids: Vec<String>,
    pub reason_rejected: String,
}

/// The model's free-text explanation for an accepted finding. Unverified
/// narrative; core [`Finding`] has no field for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingExplanation {
    pub finding_id: String,
    pub text: String,
}

#[derive(Debug, Default)]
pub(crate) struct Validated {
    pub summary: String,
    pub findings: Vec<Finding>,
    pub hypotheses: Vec<Hypothesis>,
    pub explanations: Vec<FindingExplanation>,
}

const DUPLICATE_PREFIX: &str = "duplicates existing finding ";

pub(crate) struct Broker<'a> {
    evidence: HashMap<String, Evidence>,
    existing: &'a [Finding],
    accepted: Vec<Finding>,
    next_id: usize,
}

/// Remove control characters, collapse whitespace, bound length.
pub(crate) fn clean(text: &str, max_chars: usize) -> String {
    let collapsed: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    if collapsed.chars().count() <= max_chars {
        collapsed
    } else {
        let mut s: String = collapsed.chars().take(max_chars).collect();
        s.push('…');
        s
    }
}

fn str_list(v: Option<&Value>, max_chars: usize) -> Result<Vec<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items
            .iter()
            .filter_map(Value::as_str)
            .map(|s| clean(s, max_chars))
            .filter(|s| !s.is_empty())
            .take(MAX_LIST_ITEMS)
            .collect()),
        Some(Value::String(s)) => Ok(vec![clean(s, max_chars)]),
        Some(_) => Err("expected a list of strings".into()),
    }
}

fn opt_text(v: Option<&Value>, max_chars: usize) -> Option<String> {
    v.and_then(Value::as_str)
        .map(|s| clean(s, max_chars))
        .filter(|s| !s.is_empty())
}

fn parse_enum<T: serde::de::DeserializeOwned>(v: Option<&Value>) -> Option<T> {
    let s = v?.as_str()?.trim().to_ascii_lowercase();
    serde_json::from_value(Value::String(s)).ok()
}

fn strength_name(s: EvidenceStrength) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn looks_like_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && !d.starts_with('.')
        && !d.ends_with('.')
        && d.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

impl<'a> Broker<'a> {
    pub(crate) fn new(evidence: &'a [Evidence], existing: &'a [Finding]) -> Self {
        Self {
            evidence: evidence.iter().map(|e| (e.id.clone(), e.clone())).collect(),
            existing,
            accepted: Vec::new(),
            next_id: 1,
        }
    }

    /// Make evidence produced during the session citable. Existing IDs are
    /// never replaced, so a source cannot overwrite report evidence.
    pub(crate) fn add_evidence(&mut self, new: &[Evidence]) {
        for e in new {
            self.evidence
                .entry(e.id.clone())
                .or_insert_with(|| e.clone());
        }
    }

    /// Validate a whole `submit_findings` payload. Errors only when the
    /// payload's top-level shape is wrong (so the model can be told to retry);
    /// individual bad findings become hypotheses.
    pub(crate) fn validate_submission(&mut self, payload: &Value) -> Result<Validated, String> {
        let obj = payload
            .as_object()
            .ok_or("submission must be a JSON object with 'summary' and 'findings'")?;
        let findings = match obj.get("findings") {
            Some(Value::Array(a)) => a.as_slice(),
            None | Some(Value::Null) => &[],
            Some(_) => return Err("'findings' must be an array".into()),
        };
        let mut out = Validated {
            summary: opt_text(obj.get("summary"), MAX_SUMMARY_CHARS).unwrap_or_default(),
            ..Validated::default()
        };
        for (i, proposed) in findings.iter().enumerate() {
            if i >= MAX_FINDINGS_PER_SUBMISSION {
                out.hypotheses.push(Hypothesis {
                    claim: claim_text(proposed),
                    category: None,
                    evidence_ids: vec![],
                    reason_rejected: format!(
                        "more than {MAX_FINDINGS_PER_SUBMISSION} findings proposed"
                    ),
                });
                continue;
            }
            match self.validate_one(proposed) {
                Ok((finding, explanation)) => {
                    if let Some(text) = explanation {
                        out.explanations.push(FindingExplanation {
                            finding_id: finding.id.clone(),
                            text,
                        });
                    }
                    self.accepted.push(finding.clone());
                    out.findings.push(finding);
                }
                // A claim that restates an existing finding is agreement, not a
                // rejected hypothesis: keep its explanation on that finding.
                Err(reason)
                    if reason.starts_with(DUPLICATE_PREFIX)
                        && proposed
                            .get("explanation")
                            .and_then(Value::as_str)
                            .is_some_and(|e| !e.trim().is_empty()) =>
                {
                    let finding_id = reason[DUPLICATE_PREFIX.len()..].to_owned();
                    let text =
                        opt_text(proposed.get("explanation"), MAX_TEXT_CHARS).unwrap_or_default();
                    if !out.explanations.iter().any(|e| e.finding_id == finding_id) {
                        out.explanations
                            .push(FindingExplanation { finding_id, text });
                    }
                }
                Err(reason) => out.hypotheses.push(Hypothesis {
                    claim: claim_text(proposed),
                    category: proposed
                        .get("category")
                        .and_then(Value::as_str)
                        .map(|c| clean(c, 64)),
                    evidence_ids: proposed
                        .get("evidence_ids")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .take(MAX_LIST_ITEMS)
                                .map(|s| clean(s, 64))
                                .collect()
                        })
                        .unwrap_or_default(),
                    reason_rejected: reason,
                }),
            }
        }
        Ok(out)
    }

    fn validate_one(&mut self, p: &Value) -> Result<(Finding, Option<String>), String> {
        if !p.is_object() {
            return Err("proposed finding is not an object".into());
        }
        let category = p
            .get("category")
            .and_then(Value::as_str)
            .map(|c| c.trim().to_ascii_lowercase())
            .ok_or("missing category")?;
        if !category_allowed(&category) {
            return Err(format!(
                "category '{}' is not allowed",
                clean(&category, 64)
            ));
        }
        let title = opt_text(p.get("title"), MAX_TITLE_CHARS).ok_or("missing title")?;
        let severity: Severity =
            parse_enum(p.get("severity")).ok_or("severity is missing or not in the closed set")?;
        let claimed: EvidenceStrength = parse_enum(p.get("claimed_strength"))
            .ok_or("claimed_strength is missing or not in the closed set")?;

        let ids: Vec<String> = match p.get("evidence_ids") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| v.as_str().map(|s| s.trim().to_owned()))
                .collect::<Option<Vec<_>>>()
                .ok_or("evidence_ids must be strings")?,
            _ => return Err("evidence_ids must be a non-empty list".into()),
        };
        let mut seen = BTreeSet::new();
        let ids: Vec<String> = ids.into_iter().filter(|i| seen.insert(i.clone())).collect();
        if ids.is_empty() {
            return Err("no evidence cited".into());
        }
        if ids.len() > MAX_LIST_ITEMS * 2 {
            return Err("too many evidence IDs cited".into());
        }
        let mut cited = Vec::with_capacity(ids.len());
        for id in &ids {
            match self.evidence.get(id.as_str()) {
                Some(e) => cited.push(e),
                None => return Err(format!("evidence '{}' does not exist", clean(id, 64))),
            }
        }
        let artifact = cited[0].artifact_sha256.clone();
        if cited.iter().any(|e| e.artifact_sha256 != artifact) {
            return Err("cited evidence spans more than one artifact".into());
        }

        let mut limitations = str_list(p.get("limitations"), MAX_TEXT_CHARS)
            .map_err(|e| format!("limitations: {e}"))?;
        let supported = cited
            .iter()
            .map(|e| strength_for_kind(e.kind))
            .max()
            .unwrap_or(EvidenceStrength::PatternMatch);
        let strength = claimed.min(supported);
        if strength < claimed {
            limitations.push(format!(
                "Claimed evidence strength {} capped to {} by the kinds of evidence cited",
                strength_name(claimed),
                strength_name(strength)
            ));
        }

        let recipient = match opt_text(p.get("recipient_domain"), 253) {
            None => None,
            Some(raw) => {
                let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
                let found = looks_like_domain(&domain)
                    && cited.iter().any(|e| {
                        e.snippet
                            .as_deref()
                            .is_some_and(|s| s.to_ascii_lowercase().contains(&domain))
                    });
                if found {
                    Some(Recipient {
                        domain,
                        ownership: "unknown".into(),
                    })
                } else {
                    limitations.push(format!(
                        "Proposed recipient domain '{}' was not found in cited evidence and was dropped",
                        clean(&raw, 80)
                    ));
                    None
                }
            }
        };

        let cited_ids: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        if let Some(dup) = self.existing.iter().chain(self.accepted.iter()).find(|f| {
            f.category == category
                && f.artifact_sha256 == artifact
                && cited_ids
                    .iter()
                    .all(|i| f.evidence_ids.iter().any(|x| x == i))
        }) {
            return Err(format!("{DUPLICATE_PREFIX}{}", dup.id));
        }

        limitations.push(MODEL_FINDING_NOTE.into());
        let id = format!("finding-m{:03}", self.next_id);
        self.next_id += 1;
        let finding = Finding {
            id,
            category,
            title,
            severity,
            evidence_strength: strength,
            artifact_sha256: artifact,
            evidence_ids: ids,
            data_types: str_list(p.get("data_types"), 64)
                .map_err(|e| format!("data_types: {e}"))?,
            recipient,
            enabled_by_default: TriState::Unknown,
            runtime_observed: cited.iter().any(|e| is_observation(e.kind)),
            conditions: str_list(p.get("conditions"), MAX_TEXT_CHARS)
                .map_err(|e| format!("conditions: {e}"))?,
            possible_legitimate_purpose: opt_text(
                p.get("possible_legitimate_purpose"),
                MAX_TEXT_CHARS,
            ),
            opt_out: OptOut {
                status: OptOutStatus::NotEstablished,
            },
            limitations,
        };
        Ok((
            finding,
            opt_text(p.get("explanation"), MAX_EXPLANATION_CHARS),
        ))
    }
}

fn claim_text(p: &Value) -> String {
    let title = p.get("title").and_then(Value::as_str).unwrap_or("");
    let expl = p.get("explanation").and_then(Value::as_str).unwrap_or("");
    let text = match (title.is_empty(), expl.is_empty()) {
        (false, false) => format!("{title}: {expl}"),
        (false, true) => title.to_owned(),
        (true, false) => expl.to_owned(),
        (true, true) => p.to_string(),
    };
    clean(&text, MAX_TITLE_CHARS + MAX_TEXT_CHARS)
}

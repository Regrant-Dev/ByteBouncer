use serde::{Deserialize, Serialize};

/// Closed severity set, ordered (SPEC §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Kind of evidence backing a finding, weakest to strongest. Not a probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    PatternMatch,
    StaticReference,
    StaticReachability,
    StaticDataflow,
    RuntimeObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriState {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptOutStatus {
    Available,
    Unavailable,
    NotEstablished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptOut {
    pub status: OptOutStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub domain: String,
    /// Owner name only when evidence supports it; otherwise "unknown".
    pub ownership: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// Dotted category, e.g. `privacy.telemetry`, `security.capability`, `provenance.mismatch`.
    pub category: String,
    pub title: String,
    pub severity: Severity,
    pub evidence_strength: EvidenceStrength,
    pub artifact_sha256: String,
    pub evidence_ids: Vec<String>,
    pub data_types: Vec<String>,
    pub recipient: Option<Recipient>,
    pub enabled_by_default: TriState,
    pub runtime_observed: bool,
    pub conditions: Vec<String>,
    pub possible_legitimate_purpose: Option<String>,
    pub opt_out: OptOut,
    pub limitations: Vec<String>,
}

impl Finding {
    pub fn is_security(&self) -> bool {
        self.category.starts_with("security.")
    }

    pub fn is_privacy(&self) -> bool {
        self.category.starts_with("privacy.")
    }

    pub fn is_provenance(&self) -> bool {
        self.category.starts_with("provenance.")
    }
}

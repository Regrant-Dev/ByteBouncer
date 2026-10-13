use serde::{Deserialize, Serialize};

use crate::acquisition::AcquisitionManifest;
use crate::evidence::Evidence;
use crate::finding::Finding;
use crate::policy::PolicyOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Quick,
    Deep,
    Dynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultState {
    FindingsDetected,
    NoFindingsDetected,
    Incomplete,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTier {
    /// Memory-safe analyzers in a confined worker process.
    Tier1Sandbox,
    /// Locally installed external tools confined between fork and exec.
    Tier2Sandbox,
}

/// What isolation was actually in force, as opposed to what was requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Isolation {
    pub tier: IsolationTier,
    /// Restrictions confirmed active in the worker, e.g. `landlock_fs`, `netns`.
    pub active: Vec<String>,
    /// Restrictions the spec requires that were not available.
    pub missing: Vec<String>,
    pub reduced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub format: String,
    pub expected_sha256: Option<String>,
    /// Container this artifact was extracted from, if any (`outer.zip!inner.exe`).
    #[serde(default)]
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolVersion {
    pub name: String,
    pub version: String,
    /// Digest of a rule bundle or image, where applicable.
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInfo {
    pub provider: String,
    pub base_url_host: String,
    pub model_id: String,
    /// Immutable revision when the provider exposes one.
    pub revision: Option<String>,
    pub hosted: bool,
    pub prompt_version: String,
    pub tool_calling: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub wall_clock_seconds_limit: u64,
    pub wall_clock_millis_used: u64,
    pub model_tokens_limit: Option<u64>,
    pub model_tokens_used: u64,
    pub exhausted: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub analyzed: Vec<String>,
    pub skipped: Vec<String>,
    pub unsupported: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub scan_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub mode: ScanMode,
    pub result_state: ResultState,
    pub tool_version: String,
    pub artifacts: Vec<ArtifactRecord>,
    pub isolation: Isolation,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub coverage: Coverage,
    pub policy: PolicyOutcome,
    pub sample_executed: bool,
    pub network_observation: bool,
    pub external_lookups: Vec<String>,
    pub cleanup_ok: bool,
    #[serde(default)]
    pub acquisition: AcquisitionManifest,
    #[serde(default)]
    pub tools: Vec<ToolVersion>,
    #[serde(default)]
    pub model: Option<ModelInfo>,
    #[serde(default)]
    pub budget: Budget,
    /// Stages served from cache, e.g. `tier1:<key>`.
    #[serde(default)]
    pub cache_hits: Vec<String>,
    /// Model synthesis output that is NOT verified evidence (SPEC §6.3).
    #[serde(default)]
    pub model_notes: ModelNotes,
}

/// Unverified model narrative kept apart from validated findings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelNotes {
    pub summary: Option<String>,
    /// (finding id, explanation) for model-proposed findings.
    pub explanations: Vec<(String, String)>,
    /// Claims the broker rejected, kept as explicitly unverified hypotheses.
    pub hypotheses: Vec<UnverifiedClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnverifiedClaim {
    pub claim: String,
    pub category: Option<String>,
    pub evidence_ids: Vec<String>,
    pub reason_rejected: String,
}

/// CLI exit codes from SPEC §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Ok = 0,
    PolicyExceeded = 1,
    InvalidRequest = 2,
    Incomplete = 3,
    InternalFailure = 4,
    Cancelled = 130,
}

impl Report {
    /// Incomplete/unsupported takes precedence over a policy result.
    pub fn exit_code(&self) -> ExitCode {
        match self.result_state {
            ResultState::Incomplete | ResultState::Unsupported => ExitCode::Incomplete,
            _ if self.policy.exceeded => ExitCode::PolicyExceeded,
            _ => ExitCode::Ok,
        }
    }

    /// Check that every evidence ID referenced by a finding exists and belongs
    /// to the same artifact (SPEC §6.3).
    pub fn validate_evidence_links(&self) -> Result<(), String> {
        for f in &self.findings {
            for id in &f.evidence_ids {
                let ev =
                    self.evidence.iter().find(|e| &e.id == id).ok_or_else(|| {
                        format!("finding {} references missing evidence {id}", f.id)
                    })?;
                if ev.artifact_sha256 != f.artifact_sha256 {
                    return Err(format!(
                        "finding {} evidence {id} is from a different artifact",
                        f.id
                    ));
                }
            }
        }
        Ok(())
    }
}

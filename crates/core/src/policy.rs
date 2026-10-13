use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};

/// An explicit user policy. [`Policy::default`] is the conservative built-in
/// policy from SPEC §3.3 so that exit code 0 means something without config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    /// Fail on security findings at or above this severity.
    pub fail_on_security: Option<Severity>,
    /// Fail on privacy findings at or above this severity.
    pub fail_on_privacy: Option<Severity>,
    /// Fail on any `provenance.mismatch` finding.
    pub fail_on_provenance_mismatch: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: "builtin-default".into(),
            fail_on_security: Some(Severity::High),
            fail_on_privacy: None,
            fail_on_provenance_mismatch: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcome {
    pub policy: String,
    pub exceeded: bool,
    /// IDs of findings that caused the policy to be exceeded.
    pub triggering_findings: Vec<String>,
}

impl Policy {
    pub fn evaluate(&self, findings: &[Finding]) -> PolicyOutcome {
        let triggering_findings: Vec<String> = findings
            .iter()
            .filter(|f| self.triggers(f))
            .map(|f| f.id.clone())
            .collect();
        PolicyOutcome {
            policy: self.name.clone(),
            exceeded: !triggering_findings.is_empty(),
            triggering_findings,
        }
    }

    fn triggers(&self, f: &Finding) -> bool {
        if f.is_provenance() && f.category == "provenance.mismatch" {
            return self.fail_on_provenance_mismatch;
        }
        let threshold = if f.is_security() {
            self.fail_on_security
        } else if f.is_privacy() {
            self.fail_on_privacy
        } else {
            None
        };
        threshold.is_some_and(|t| f.severity >= t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{EvidenceStrength, OptOut, OptOutStatus, TriState};

    fn finding(category: &str, severity: Severity) -> Finding {
        Finding {
            id: format!("f-{category}-{severity:?}"),
            category: category.into(),
            title: String::new(),
            severity,
            evidence_strength: EvidenceStrength::StaticReference,
            artifact_sha256: String::new(),
            evidence_ids: vec![],
            data_types: vec![],
            recipient: None,
            enabled_by_default: TriState::Unknown,
            runtime_observed: false,
            conditions: vec![],
            possible_legitimate_purpose: None,
            opt_out: OptOut {
                status: OptOutStatus::NotEstablished,
            },
            limitations: vec![],
        }
    }

    #[test]
    fn default_policy_fails_on_high_security_only() {
        let p = Policy::default();
        assert!(
            !p.evaluate(&[finding("security.capability", Severity::Medium)])
                .exceeded
        );
        assert!(
            p.evaluate(&[finding("security.capability", Severity::High)])
                .exceeded
        );
        assert!(
            !p.evaluate(&[finding("privacy.telemetry", Severity::Critical)])
                .exceeded
        );
    }

    #[test]
    fn default_policy_fails_on_provenance_mismatch() {
        let out = Policy::default().evaluate(&[finding("provenance.mismatch", Severity::Info)]);
        assert!(out.exceeded);
        assert_eq!(out.triggering_findings.len(), 1);
    }
}

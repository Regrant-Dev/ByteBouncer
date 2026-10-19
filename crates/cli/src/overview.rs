//! A short, deterministic overview shared by HTML and terminal reports.
//! Severity describes the recorded findings, never a safety score.

use bytebouncer_core::{Finding, Report, ResultState, Severity};

pub const LEVELS: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

pub fn label(level: Severity) -> &'static str {
    match level {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

pub struct Overview<'a> {
    pub report: &'a Report,
    pub highest: Option<Severity>,
    pub complete: bool,
    pub highlights: Vec<&'a Finding>,
}

impl<'a> Overview<'a> {
    pub fn new(report: &'a Report) -> Self {
        let mut findings: Vec<_> = report.findings.iter().collect();
        findings.sort_by_key(|f| {
            std::cmp::Reverse((
                f.severity,
                report.policy.triggering_findings.contains(&f.id),
                if f.is_security() {
                    2
                } else if f.is_privacy() {
                    1
                } else {
                    0
                },
            ))
        });
        Self {
            report,
            highest: findings.first().map(|f| f.severity),
            complete: matches!(
                report.result_state,
                ResultState::FindingsDetected | ResultState::NoFindingsDetected
            ) && !report.budget.exhausted,
            highlights: findings.into_iter().take(3).collect(),
        }
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    pub fn headline(&self) -> String {
        if self.report.result_state == ResultState::Unsupported {
            return "Input not supported".into();
        }
        if !self.complete {
            return "Analysis incomplete".into();
        }
        if self.report.policy.exceeded {
            return "Review required: installation policy exceeded".into();
        }
        match self.highest {
            Some(Severity::Info) => "Only informational findings".into(),
            Some(level) => format!("{} severity findings detected", label(level)),
            None => "No findings detected".into(),
        }
    }

    pub fn action(&self) -> &'static str {
        if !self.complete {
            "Review the missing coverage before deciding whether to continue."
        } else if self.report.policy.exceeded {
            "Review the findings that exceeded your installation policy."
        } else {
            "Review the findings, then choose whether to continue."
        }
    }

    pub fn category(&self, predicate: fn(&Finding) -> bool) -> &'static str {
        self.report
            .findings
            .iter()
            .filter(|f| predicate(f))
            .map(|f| f.severity)
            .max()
            .map(label)
            .unwrap_or("None detected")
    }
}

pub fn compact(text: &str, limit: usize) -> String {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();
    let text = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = text.chars();
    let mut out: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// Only an explicit short takeaway is promoted from the unverified narrative.
/// Existing reports without one still get the deterministic findings overview.
pub fn ai_takeaway(report: &Report) -> Option<String> {
    report.model.as_ref()?;
    let line = report
        .model_notes
        .summary
        .as_deref()?
        .trim()
        .lines()
        .next()?;
    for prefix in ["TL;DR:", "TLDR:", "**TL;DR:**", "**TL;DR**:"] {
        if line
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
        {
            let text = compact(line[prefix.len()..].trim(), 240);
            return (!text.is_empty()).then_some(text);
        }
    }
    None
}

#[cfg(test)]
pub fn test_model() -> bytebouncer_core::ModelInfo {
    serde_json::from_value(serde_json::json!({
        "provider":"test","base_url_host":"localhost","model_id":"local","revision":null,
        "hosted":false,"prompt_version":"test","tool_calling":true
    }))
    .unwrap()
}

#[cfg(test)]
pub fn test_report() -> Report {
    serde_json::from_value(serde_json::json!({
        "schema_version":"0.2.0", "scan_id":"01M58V37239RD61SPBH3VNE3E2",
        "started_at":"2026-10-18T00:00:00Z", "finished_at":"2026-10-18T00:00:01Z",
        "mode":"quick", "result_state":"no_findings_detected", "tool_version":"test",
        "artifacts":[{"path":"sample", "sha256":"a".repeat(64), "size":10,"format":"elf", "parent":null,"expected_sha256":null}],
        "isolation":{"tier":"tier1_sandbox","active":[],"missing":[],"reduced":false},
        "findings":[],"evidence":[],"coverage":{"analyzed":[],"skipped":[],"unsupported":[],"limitations":[]},
        "policy":{"policy":"test","exceeded":false,"triggering_findings":[]},
        "sample_executed":false,"network_observation":false,"external_lookups":[],"cleanup_ok":true
    })).unwrap()
}

#[cfg(test)]
pub fn test_finding(severity: Severity, title: &str) -> Finding {
    serde_json::from_value(serde_json::json!({
        "id":format!("finding-{}",label(severity)), "category":"security.capability", "title":title,
        "severity":severity,"evidence_strength":"static_reference","artifact_sha256":"a".repeat(64),
        "evidence_ids":[],"data_types":[],"recipient":null,"enabled_by_default":"unknown",
        "runtime_observed":false,"conditions":[],"possible_legitimate_purpose":null,
        "opt_out":{"status":"not_established"},"limitations":[]
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_uses_actual_severity_and_keeps_coverage_separate() {
        let mut r = test_report();
        r.findings = vec![
            test_finding(Severity::Info, "URL reference"),
            test_finding(Severity::High, "Credential access"),
        ];
        let overview = Overview::new(&r);
        assert_eq!(overview.highest, Some(Severity::High));
        assert_eq!(overview.highlights[0].title, "Credential access");
        assert_eq!(overview.count(Severity::Medium), 0);
        r.result_state = ResultState::Incomplete;
        assert_eq!(Overview::new(&r).headline(), "Analysis incomplete");
        assert_eq!(Overview::new(&r).highest, Some(Severity::High));
        r.findings.clear();
        assert_eq!(Overview::new(&r).headline(), "Analysis incomplete");
    }

    #[test]
    fn informational_policy_failure_is_not_presented_as_a_pass() {
        let mut r = test_report();
        r.findings
            .push(test_finding(Severity::Info, "Checksum mismatch"));
        r.policy.exceeded = true;
        assert_eq!(Overview::new(&r).highest, Some(Severity::Info));
        assert!(Overview::new(&r).headline().contains("policy exceeded"));
    }

    #[test]
    fn long_narratives_are_not_promoted_to_the_takeaway() {
        let mut r = test_report();
        r.model = Some(test_model());
        r.model_notes.summary = Some("Artifact: a lengthy investigation".into());
        assert!(ai_takeaway(&r).is_none());
        r.model_notes.summary = Some(format!(
            "TL;DR: {}\n\n1. Full investigation",
            "ü".repeat(1000)
        ));
        assert_eq!(ai_takeaway(&r).unwrap().chars().count(), 241);
        assert!(!ai_takeaway(&r).unwrap().contains("Full investigation"));
    }
}

//! Markdown rendering, used for both the terminal summary and report.md.

use std::fmt::Write;

use crate::overview::{self, LEVELS, Overview};
use bytebouncer_core::{Finding, Report, ResultState};

/// Default terminal output: the decision-relevant overview, not all evidence.
pub fn brief(r: &Report, saved: bool) -> String {
    let mut s = format!(
        "# ByteBouncer — {}\n\n",
        overview::compact(
            r.artifacts
                .first()
                .map(|a| a.path.as_str())
                .unwrap_or("report"),
            160
        )
    );
    summary(&mut s, r);
    if saved {
        let _ = writeln!(s, "Full report: `bytebouncer report {}`\n", r.scan_id);
    }
    s
}

fn summary(s: &mut String, r: &Report) {
    let overview = Overview::new(r);
    let _ = writeln!(s, "## TL;DR\n\n**{}**\n", overview.headline());
    let _ = writeln!(
        s,
        "Highest finding: **{}**{} · Analysis: **{}** · Policy: **{}**\n",
        overview
            .highest
            .map(overview::label)
            .unwrap_or("None detected"),
        if overview.complete { "" } else { " (so far)" },
        if overview.complete {
            "complete"
        } else {
            "incomplete"
        },
        if r.policy.exceeded {
            "EXCEEDED"
        } else {
            "not exceeded"
        }
    );
    let counts: Vec<_> = LEVELS
        .iter()
        .map(|level| format!("{} {}", overview::label(*level), overview.count(*level)))
        .collect();
    let _ = writeln!(s, "{}\n", counts.join(" · "));
    let _ = writeln!(
        s,
        "Security: {} · Privacy: {} · Provenance: {}\n",
        overview.category(Finding::is_security),
        overview.category(Finding::is_privacy),
        overview.category(Finding::is_provenance)
    );
    for finding in &overview.highlights {
        let _ = writeln!(
            s,
            "- **[{}]** {}",
            overview::label(finding.severity),
            overview::compact(&finding.title, 180)
        );
    }
    if r.findings.len() > overview.highlights.len() {
        let _ = writeln!(
            s,
            "- {} more finding(s) in the full report.",
            r.findings.len() - overview.highlights.len()
        );
    }
    if let Some(takeaway) = overview::ai_takeaway(r) {
        let _ = writeln!(s, "\n**AI takeaway (unverified):** {takeaway}");
    }
    if !r.coverage.skipped.is_empty() || !r.coverage.unsupported.is_empty() {
        let _ = writeln!(
            s,
            "\nCoverage gaps: {} skipped, {} unsupported.",
            r.coverage.skipped.len(),
            r.coverage.unsupported.len()
        );
    }
    if r.isolation.reduced {
        let _ = writeln!(
            s,
            "\nReduced isolation: {}.",
            r.isolation.missing.join(", ")
        );
    }
    let _ = writeln!(
        s,
        "\n{} Static analysis is not a safety guarantee.\n",
        overview.action()
    );
}

pub fn markdown(r: &Report) -> String {
    let mut s = String::new();
    let a = r.artifacts.first();
    let _ = writeln!(s, "# ByteBouncer report {}\n", r.scan_id);
    summary(&mut s, r);
    let _ = writeln!(s, "## Scan details\n");
    if let Some(a) = a {
        let _ = writeln!(
            s,
            "- **Artifact:** {} ({}, {} bytes)",
            a.path, a.format, a.size
        );
        let _ = writeln!(s, "- **SHA-256:** `{}`", a.sha256);
    }
    if r.artifacts.len() > 1 {
        let nested = r.artifacts.iter().filter(|a| a.parent.is_some()).count();
        let _ = writeln!(
            s,
            "- **Artifacts:** {} ({} nested)",
            r.artifacts.len(),
            nested
        );
    }
    for sig in &r.acquisition.signatures {
        let _ = writeln!(
            s,
            "- **Signature:** {} {:?}{}",
            sig.kind,
            sig.status,
            sig.signer
                .as_deref()
                .map(|x| format!(" ({x})"))
                .unwrap_or_default()
        );
    }
    let _ = writeln!(s, "- **Mode:** {:?}", r.mode);
    let _ = writeln!(s, "- **Result:** {}", state_text(r.result_state));
    let _ = writeln!(
        s,
        "- **Policy:** {} — {}",
        r.policy.policy,
        if r.policy.exceeded {
            "EXCEEDED"
        } else {
            "not exceeded"
        }
    );
    let iso = &r.isolation;
    let _ = writeln!(
        s,
        "- **Isolation:** {:?}{}",
        iso.tier,
        if iso.reduced {
            format!(" (REDUCED — missing: {})", iso.missing.join(", "))
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        s,
        "- **Sample executed:** {}",
        if r.sample_executed { "yes" } else { "no" }
    );
    let _ = writeln!(s);

    section(
        &mut s,
        "Security",
        r.findings.iter().filter(|f| f.is_security()),
        r,
    );
    section(
        &mut s,
        "Privacy",
        r.findings.iter().filter(|f| f.is_privacy()),
        r,
    );
    section(
        &mut s,
        "Provenance",
        r.findings.iter().filter(|f| f.is_provenance()),
        r,
    );

    if let Some(m) = &r.model {
        let _ = writeln!(s, "## AI investigation ({})\n", m.model_id);
        let _ = writeln!(
            s,
            "_Narrative written by the model after investigating the evidence; it is unverified. The findings below are checked against evidence._\n"
        );
        if let Some(summary) = &r.model_notes.summary {
            let _ = writeln!(s, "{}\n", summary.trim());
        }
        if !r.model_notes.hypotheses.is_empty() {
            let _ = writeln!(
                s,
                "**Unverified hypotheses** (rejected by the evidence check):\n"
            );
            for h in &r.model_notes.hypotheses {
                let _ = writeln!(s, "- {} — _{}_", h.claim, h.reason_rejected);
            }
            let _ = writeln!(s);
        }
    }

    let _ = writeln!(s, "## Coverage\n");
    list(&mut s, "Analyzed", &r.coverage.analyzed);
    list(&mut s, "Skipped", &r.coverage.skipped);
    list(&mut s, "Unsupported", &r.coverage.unsupported);

    let _ = writeln!(s, "## Unknowns and limitations\n");
    list(&mut s, "", &r.coverage.limitations);
    let _ = writeln!(
        s,
        "Static analysis only. A lack of findings is not proof that this software is safe.\n"
    );
    s
}

fn state_text(state: ResultState) -> &'static str {
    match state {
        ResultState::FindingsDetected => "findings detected",
        ResultState::NoFindingsDetected => "no findings detected (not proof of safety)",
        ResultState::Incomplete => "INCOMPLETE",
        ResultState::Unsupported => "UNSUPPORTED",
    }
}

fn section<'a>(
    s: &mut String,
    title: &str,
    findings: impl Iterator<Item = &'a Finding>,
    r: &Report,
) {
    let _ = writeln!(s, "## {title}\n");
    let mut findings: Vec<_> = findings.collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let any = !findings.is_empty();
    for f in findings {
        let _ = writeln!(
            s,
            "- **[{:?}] {}** (`{}`, {:?})",
            f.severity, f.title, f.category, f.evidence_strength
        );
        if r.artifacts.len() > 1
            && let Some(ev) = f
                .evidence_ids
                .first()
                .and_then(|id| r.evidence.iter().find(|e| &e.id == id))
        {
            let _ = writeln!(s, "  - In: `{}`", ev.artifact_path);
        }
        if let Some(rec) = &f.recipient {
            let _ = writeln!(
                s,
                "  - Recipient: {} (ownership: {})",
                rec.domain, rec.ownership
            );
        }
        if let Some(p) = &f.possible_legitimate_purpose {
            let _ = writeln!(s, "  - Possible legitimate purpose: {p}");
        }
        for l in &f.limitations {
            let _ = writeln!(s, "  - Limitation: {l}");
        }
        if let Some((_, text)) = r
            .model_notes
            .explanations
            .iter()
            .find(|(id, _)| id == &f.id)
        {
            let _ = writeln!(s, "  - Model explanation (unverified): {text}");
        }
        for id in f.evidence_ids.iter().take(5) {
            if let Some(ev) = r.evidence.iter().find(|e| &e.id == id) {
                let snippet = ev.snippet.as_deref().unwrap_or("");
                let _ = writeln!(s, "  - Evidence {id}: `{}`", snippet.replace('`', "'"));
            }
        }
        if f.evidence_ids.len() > 5 {
            let _ = writeln!(
                s,
                "  - …and {} more evidence items in report.json",
                f.evidence_ids.len() - 5
            );
        }
    }
    if !any {
        let _ = writeln!(s, "_None detected by the analyzers that ran._");
    }
    let _ = writeln!(s);
}

fn list(s: &mut String, label: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    if !label.is_empty() {
        let _ = writeln!(s, "**{label}:**\n");
    }
    for i in items {
        let _ = writeln!(s, "- {i}");
    }
    let _ = writeln!(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytebouncer_core::Severity;

    #[test]
    fn default_summary_does_not_dump_the_investigation() {
        let mut r = overview::test_report();
        r.findings.push(overview::test_finding(
            Severity::Medium,
            "Reads the clipboard",
        ));
        r.model = Some(overview::test_model());
        r.model_notes.summary =
            Some("TL;DR: Clipboard access needs review.\n\n1. Very long investigation".into());
        let text = brief(&r, true);
        assert!(text.contains("Medium 1"));
        assert!(text.contains("Clipboard access needs review."));
        assert!(!text.contains("Very long investigation"));
        assert!(text.contains("bytebouncer report"));
        assert!(markdown(&r).contains("Very long investigation"));
        assert!(!brief(&r, false).contains("Full report:"));
    }
}

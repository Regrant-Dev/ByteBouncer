//! Markdown rendering, used for both the terminal summary and report.md.

use std::fmt::Write;

use bytebouncer_core::{Finding, Report, ResultState};

pub fn markdown(r: &Report) -> String {
    let mut s = String::new();
    let a = r.artifacts.first();
    let _ = writeln!(s, "# ByteBouncer report {}\n", r.scan_id);
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
    let mut any = false;
    for f in findings {
        any = true;
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

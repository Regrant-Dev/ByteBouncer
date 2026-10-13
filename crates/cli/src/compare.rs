//! `bytebouncer compare OLD NEW` (SPEC §8): what changed between two scans,
//! e.g. an application update. Removals are only claimed when both scans
//! completed; a missing finding after a failed scan is not a removal.

use std::collections::BTreeSet;
use std::fmt::Write;

use bytebouncer_core::{Report, ResultState};

fn complete(r: &Report) -> bool {
    matches!(
        r.result_state,
        ResultState::FindingsDetected | ResultState::NoFindingsDetected
    )
}

fn finding_keys(r: &Report) -> BTreeSet<String> {
    r.findings
        .iter()
        .map(|f| format!("[{:?}] {} ({})", f.severity, f.title, f.category))
        .collect()
}

fn domains(r: &Report) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = r
        .findings
        .iter()
        .filter_map(|f| f.recipient.as_ref().map(|x| x.domain.clone()))
        .collect();
    for e in r
        .evidence
        .iter()
        .filter(|e| e.producer.rule_id.as_deref() == Some("embedded-url"))
    {
        if let Some(snippet) = &e.snippet {
            let host = snippet
                .split("://")
                .nth(1)
                .unwrap_or(snippet)
                .split(['/', ':', '?'])
                .next()
                .unwrap_or_default();
            out.insert(host.to_owned());
        }
    }
    out
}

fn artifact_names(r: &Report) -> BTreeSet<String> {
    // Strip the top-level name so renamed versions (app-1.0 → app-1.1) line up.
    r.artifacts
        .iter()
        .map(|a| {
            a.path
                .split_once(['/', '!'])
                .map(|(_, rest)| rest.to_owned())
                .unwrap_or_default()
        })
        .collect()
}

pub fn compare(old: &Report, new: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Comparison {} → {}\n", old.scan_id, new.scan_id);
    let both_complete = complete(old) && complete(new);
    if !both_complete {
        let _ = writeln!(
            s,
            "> One or both scans are incomplete or unsupported. Additions are shown, but items missing from the newer scan are NOT reported as removed.\n"
        );
    }
    let section = |s: &mut String, title: &str, old: BTreeSet<String>, new: BTreeSet<String>| {
        let added: Vec<_> = new.difference(&old).collect();
        let removed: Vec<_> = old.difference(&new).collect();
        let _ = writeln!(s, "## {title}\n");
        if added.is_empty() && (removed.is_empty() || !both_complete) {
            let _ = writeln!(s, "_No changes detected._\n");
            return;
        }
        for a in added {
            let _ = writeln!(s, "- added: {a}");
        }
        if both_complete {
            for r in removed {
                let _ = writeln!(s, "- removed: {r}");
            }
        }
        let _ = writeln!(s);
    };
    section(&mut s, "Findings", finding_keys(old), finding_keys(new));
    section(&mut s, "Network destinations", domains(old), domains(new));
    section(
        &mut s,
        "Bundled files",
        artifact_names(old),
        artifact_names(new),
    );
    let _ = writeln!(
        s,
        "Changes reflect static analysis of each version; they do not establish runtime behavior."
    );
    s
}

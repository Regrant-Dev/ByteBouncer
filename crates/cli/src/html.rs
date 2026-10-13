//! Standalone HTML report. Everything from the report is attacker-influenced
//! (file names, strings, snippets), so every value is escaped and the page
//! carries a strict CSP with no scripts at all.

use std::fmt::Write;

use bytebouncer_core::{Finding, Report, ResultState, Severity};

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#6b6b70;--card:#fff;--line:#e4e4e7;--crit:#b42318;--high:#c4320a;--med:#b54708;--low:#475467;--info:#3e6ea8;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececf0;--muted:#9a9aa3;--card:#1c1c20;--line:#2c2c33;--crit:#f97066;--high:#fd853a;--med:#fdb022;--low:#98a2b3;--info:#84adff;--ok:#47cd89}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:12px 0}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;white-space:pre-wrap}
.sev{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;border:1px solid currentColor;margin-right:6px}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}.okc{color:var(--ok)}
ul{padding-left:20px}li{margin:3px 0}.banner{border-left:4px solid var(--med);padding:8px 12px;background:var(--card);border-radius:6px}
"#;

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Escape model narrative, render `**bold**`, and start a new paragraph at
/// each bold heading so the six investigation sections read separately.
fn narrative(text: &str) -> String {
    let escaped = esc(text);
    let mut out = String::from("<p>");
    for (i, part) in escaped.split("**").enumerate() {
        if i % 2 == 1 {
            if i > 1 && part.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                out.push_str("</p><p>");
            }
            out.push_str("<strong>");
            out.push_str(part);
            out.push_str("</strong>");
        } else {
            out.push_str(&part.replace('\n', "<br>"));
        }
    }
    out.push_str("</p>");
    out
}

pub fn render(r: &Report) -> String {
    let mut s = String::new();
    let title = r
        .artifacts
        .first()
        .map(|a| a.path.as_str())
        .unwrap_or("report");
    let _ = write!(
        s,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<title>ByteBouncer — {}</title><style>{STYLE}</style></head><body><main>",
        esc(title)
    );
    let state = match r.result_state {
        ResultState::FindingsDetected => "Findings detected",
        ResultState::NoFindingsDetected => "No findings detected",
        ResultState::Incomplete => "Incomplete analysis",
        ResultState::Unsupported => "Unsupported input",
    };
    let _ = write!(
        s,
        "<h1>{}</h1><div class=\"muted\">ByteBouncer report {} · {}</div>",
        esc(title),
        esc(&r.scan_id),
        esc(&r.finished_at)
    );
    let _ = write!(
        s,
        "<p class=\"banner\"><strong>{state}.</strong> Static analysis only; the software was not run. A lack of findings is not proof of safety.</p>"
    );
    let _ = write!(
        s,
        "<dl><dt>Mode</dt><dd>{:?}</dd><dt>Policy</dt><dd>{} — {}</dd><dt>Isolation</dt><dd>{:?}{}</dd>",
        r.mode,
        esc(&r.policy.policy),
        if r.policy.exceeded {
            "<strong class=\"critical\">exceeded</strong>"
        } else {
            "<span class=\"okc\">not exceeded</span>"
        },
        r.isolation.tier,
        if r.isolation.reduced {
            format!(
                " (reduced: missing {})",
                esc(&r.isolation.missing.join(", "))
            )
        } else {
            String::new()
        }
    );
    if let Some(a) = r.artifacts.first() {
        let _ = write!(
            s,
            "<dt>SHA-256</dt><dd><code>{}</code></dd><dt>Format</dt><dd>{}</dd><dt>Artifacts</dt><dd>{}</dd>",
            esc(&a.sha256),
            esc(&a.format),
            r.artifacts.len()
        );
    }
    if let Some(m) = &r.model {
        let _ = write!(
            s,
            "<dt>Model</dt><dd>{} ({})</dd>",
            esc(&m.model_id),
            esc(&m.base_url_host)
        );
    }
    s.push_str("</dl>");

    // With a model, its investigation is the headline; the verified findings
    // below are the evidence it worked from and was checked against.
    if let (Some(m), Some(summary)) = (&r.model, &r.model_notes.summary) {
        let _ = write!(
            s,
            "<h2>AI investigation</h2><div class=\"card\"><p class=\"muted\">Written by {} after investigating the evidence. This narrative is unverified; the findings below are checked against evidence.</p>{}</div>",
            esc(&m.model_id),
            narrative(summary)
        );
    }

    for (title, pred) in [
        ("Security", Finding::is_security as fn(&Finding) -> bool),
        ("Privacy", Finding::is_privacy),
        ("Provenance", Finding::is_provenance),
    ] {
        let _ = write!(s, "<h2>{title}</h2>");
        let mut findings: Vec<&Finding> = r.findings.iter().filter(|f| pred(f)).collect();
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        if findings.is_empty() {
            s.push_str("<p class=\"muted\">None detected by the analyzers that ran.</p>");
        }
        for f in findings {
            let _ = write!(
                s,
                "<div class=\"card\"><span class=\"sev {c}\">{sev:?}</span><strong>{t}</strong> <span class=\"muted\">{cat} · {st:?}</span><ul>",
                c = sev_class(f.severity),
                sev = f.severity,
                t = esc(&f.title),
                cat = esc(&f.category),
                st = f.evidence_strength
            );
            if let Some(rec) = &f.recipient {
                let _ = write!(
                    s,
                    "<li>Recipient: <code>{}</code> (ownership {})</li>",
                    esc(&rec.domain),
                    esc(&rec.ownership)
                );
            }
            if let Some(p) = &f.possible_legitimate_purpose {
                let _ = write!(s, "<li>Possible legitimate purpose: {}</li>", esc(p));
            }
            for l in &f.limitations {
                let _ = write!(s, "<li class=\"muted\">{}</li>", esc(l));
            }
            if let Some((_, text)) = r
                .model_notes
                .explanations
                .iter()
                .find(|(id, _)| id == &f.id)
            {
                let _ = write!(s, "<li>Model explanation (unverified): {}</li>", esc(text));
            }
            for id in f.evidence_ids.iter().take(8) {
                if let Some(ev) = r.evidence.iter().find(|e| &e.id == id) {
                    let _ = write!(
                        s,
                        "<li><span class=\"muted\">{} · {}</span><pre>{}</pre></li>",
                        esc(&ev.artifact_path),
                        esc(&format!("{:?}", ev.kind)),
                        esc(ev.snippet.as_deref().unwrap_or(""))
                    );
                }
            }
            s.push_str("</ul></div>");
        }
    }

    if !r.model_notes.hypotheses.is_empty() {
        s.push_str("<h2>Unverified hypotheses</h2><ul>");
        for h in &r.model_notes.hypotheses {
            let _ = write!(
                s,
                "<li>{} <span class=\"muted\">— rejected: {}</span></li>",
                esc(&h.claim),
                esc(&h.reason_rejected)
            );
        }
        s.push_str("</ul>");
    }

    for (title, items) in [
        ("Analyzed", &r.coverage.analyzed),
        ("Skipped", &r.coverage.skipped),
        ("Unsupported", &r.coverage.unsupported),
        ("Unknowns and limitations", &r.coverage.limitations),
    ] {
        if items.is_empty() {
            continue;
        }
        let _ = write!(s, "<h2>{title}</h2><ul>");
        for i in items.iter().take(500) {
            let _ = write!(s, "<li>{}</li>", esc(i));
        }
        if items.len() > 500 {
            let _ = write!(
                s,
                "<li class=\"muted\">…{} more in report.json</li>",
                items.len() - 500
            );
        }
        s.push_str("</ul>");
    }
    s.push_str("</main></body></html>\n");
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes_markup() {
        assert_eq!(
            super::esc("<script>alert('x')</script>&"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;"
        );
    }
}

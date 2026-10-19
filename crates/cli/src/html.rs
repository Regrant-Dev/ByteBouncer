//! Standalone HTML report. Everything from the report is attacker-influenced
//! (file names, strings, snippets), so every value is escaped and the page
//! carries a strict CSP with no scripts at all.

use std::fmt::Write;

use crate::overview::{self, LEVELS, Overview};
use bytebouncer_core::{Finding, Report, Severity};

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
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px;overflow-wrap:anywhere}h2{font-size:17px;margin:32px 0 10px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:12px 0}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;white-space:pre-wrap}
.sev{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;border:1px solid currentColor;margin-right:6px}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}.okc{color:var(--ok)}
ul{padding-left:20px}li{margin:3px 0}.banner{border-left:4px solid var(--med);padding:8px 12px;background:var(--card);border-radius:6px}
.tldr{margin:20px 0;padding:20px}.tldr h2{margin:0;font-size:13px;letter-spacing:.06em}.verdict{font-size:24px;font-weight:700;margin:8px 0 12px;line-height:1.25}.statusline{display:flex;gap:8px 20px;flex-wrap:wrap;font-size:13px}
.levels{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin:18px 0}.level{border:1px solid var(--line);border-radius:8px;padding:10px 12px}.level strong{display:block;font-size:24px;line-height:1.2}.level span{font-size:12px}.zero{color:var(--muted)}
.categories{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;font-size:13px}.category{padding:8px 0}.category strong{display:block}.highlights{list-style:none;padding:0}.highlights li{padding:8px 0;border-top:1px solid var(--line)}
details summary{cursor:pointer;font-weight:600;overflow-wrap:anywhere}details[open]>summary{margin-bottom:12px}details summary::marker{color:var(--muted)}.finding summary{line-height:1.7}.finding pre{max-height:280px;overflow:auto}.fine{font-size:12px}.description{overflow-wrap:anywhere}
@media(max-width:580px){.levels{grid-template-columns:repeat(3,minmax(0,1fr))}.categories{grid-template-columns:1fr}.category{display:flex;justify-content:space-between;border-top:1px solid var(--line)}.verdict{font-size:21px}dl{grid-template-columns:1fr;gap:2px}dd{margin-bottom:8px}}
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
            let mut paragraph = part.replace('\n', "<br>");
            for number in 1..=6 {
                paragraph =
                    paragraph.replace(&format!(" {number}. "), &format!("</p><p>{number}. "));
            }
            out.push_str(&paragraph);
        }
    }
    out.push_str("</p>");
    out
}

fn overview_html(r: &Report) -> String {
    let overview = Overview::new(r);
    let mut s =
        String::from("<section class=\"card tldr\" aria-label=\"Report summary\"><h2>TL;DR</h2>");
    let color = if !overview.complete {
        "medium"
    } else if r.policy.exceeded {
        "critical"
    } else {
        overview.highest.map(sev_class).unwrap_or("muted")
    };
    let _ = write!(
        s,
        "<p class=\"verdict {color}\">{}</p><div class=\"statusline\"><span>Highest finding{}: <strong>{}</strong></span><span>Analysis: <strong>{}</strong></span><span>Policy: <strong>{}</strong></span></div>",
        esc(&overview.headline()),
        if overview.complete { "" } else { " so far" },
        overview
            .highest
            .map(overview::label)
            .unwrap_or("None detected"),
        if overview.complete {
            "complete"
        } else {
            "incomplete"
        },
        if r.policy.exceeded {
            "exceeded"
        } else {
            "not exceeded"
        }
    );
    s.push_str("<div class=\"levels\" aria-label=\"Finding counts by severity\">");
    for level in LEVELS {
        let count = overview.count(level);
        let _ = write!(
            s,
            "<div class=\"level {}\"><strong>{count}</strong><span>{}</span></div>",
            if count == 0 { "zero" } else { sev_class(level) },
            overview::label(level)
        );
    }
    s.push_str("</div><div class=\"categories\">");
    for (title, predicate) in [
        ("Security", Finding::is_security as fn(&Finding) -> bool),
        ("Privacy", Finding::is_privacy),
        ("Provenance", Finding::is_provenance),
    ] {
        let _ = write!(
            s,
            "<div class=\"category\"><strong>{title}</strong><span>{}</span></div>",
            overview.category(predicate)
        );
    }
    s.push_str("</div>");
    if !overview.highlights.is_empty() {
        s.push_str("<ul class=\"highlights\" aria-label=\"Key findings\">");
        for finding in &overview.highlights {
            let _ = write!(
                s,
                "<li><span class=\"sev {}\">{}</span>{}</li>",
                sev_class(finding.severity),
                overview::label(finding.severity),
                esc(&overview::compact(&finding.title, 180))
            );
        }
        s.push_str("</ul>");
        if r.findings.len() > overview.highlights.len() {
            let _ = write!(
                s,
                "<p class=\"muted fine\">{} more {} in the sections below.</p>",
                r.findings.len() - overview.highlights.len(),
                if r.findings.len() - overview.highlights.len() == 1 {
                    "finding"
                } else {
                    "findings"
                }
            );
        }
    }
    if let Some(takeaway) = overview::ai_takeaway(r) {
        let _ = write!(
            s,
            "<p><strong>AI takeaway <span class=\"muted fine\">(unverified)</span>:</strong> {}</p>",
            esc(&takeaway)
        );
    }
    if !r.coverage.skipped.is_empty() || !r.coverage.unsupported.is_empty() {
        let _ = write!(
            s,
            "<p class=\"medium\">Coverage gaps: {} skipped, {} unsupported. See coverage below.</p>",
            r.coverage.skipped.len(),
            r.coverage.unsupported.len()
        );
    }
    if r.isolation.reduced {
        s.push_str("<p class=\"medium\">Reduced isolation; see scan details.</p>");
    }
    let _ = write!(
        s,
        "<p class=\"fine muted\">{} Severity describes findings, not a safety score.</p></section>",
        overview.action()
    );
    s
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
    let _ = write!(
        s,
        "<h1>{}</h1><div class=\"muted\">ByteBouncer · {:?} analysis · {} {}</div>",
        esc(title),
        r.mode,
        r.findings.len(),
        if r.findings.len() == 1 {
            "finding"
        } else {
            "findings"
        }
    );
    s.push_str(&overview_html(r));
    s.push_str("<p class=\"muted fine\">Static analysis only; the software was not run. A lack of findings is not proof of safety.</p>");
    let mut metadata = String::new();
    let _ = write!(
        metadata,
        "<dl><dt>Report ID</dt><dd>{}</dd><dt>Finished</dt><dd>{}</dd><dt>Mode</dt><dd>{:?}</dd><dt>Policy</dt><dd>{} — {}</dd><dt>Isolation</dt><dd>{:?}{}</dd>",
        esc(&r.scan_id),
        esc(&r.finished_at),
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
            metadata,
            "<dt>SHA-256</dt><dd><code>{}</code></dd><dt>Format</dt><dd>{}</dd><dt>Artifacts</dt><dd>{}</dd>",
            esc(&a.sha256),
            esc(&a.format),
            r.artifacts.len()
        );
    }
    if let Some(m) = &r.model {
        let _ = write!(
            metadata,
            "<dt>Model</dt><dd>{} ({})</dd>",
            esc(&m.model_id),
            esc(&m.base_url_host)
        );
    }
    metadata.push_str("</dl>");

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
                "<details class=\"card finding\"><summary><span class=\"sev {c}\">{sev:?}</span>{short}</summary><p class=\"description\"><strong>{t}</strong></p><p class=\"muted fine\">{cat} · {st:?}</p><ul>",
                c = sev_class(f.severity),
                sev = f.severity,
                t = esc(&f.title),
                short = esc(&overview::compact(&f.title, 140)),
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
            s.push_str("</ul></details>");
        }
    }

    if let (Some(m), Some(summary)) = (&r.model, &r.model_notes.summary) {
        let _ = write!(
            s,
            "<h2>Full investigation</h2><details class=\"card investigation\"><summary>Full AI investigation · {}</summary><p class=\"muted fine\">AI-generated narrative (unverified). Finding citations are checked against the recorded evidence.</p>{}</details>",
            esc(&m.model_id),
            narrative(summary)
        );
    }

    if !r.model_notes.hypotheses.is_empty() {
        let _ = write!(
            s,
            "<details class=\"card\"><summary>Unverified hypotheses ({})</summary><ul>",
            r.model_notes.hypotheses.len()
        );
        for h in &r.model_notes.hypotheses {
            let _ = write!(
                s,
                "<li>{} <span class=\"muted\">— rejected: {}</span></li>",
                esc(&h.claim),
                esc(&h.reason_rejected)
            );
        }
        s.push_str("</ul></details>");
    }

    let _ = write!(
        s,
        "<details class=\"card\"><summary>Scan details</summary>{metadata}</details>"
    );
    s.push_str("<h2>Coverage and limitations</h2>");

    for (title, items) in [
        ("Analyzed", &r.coverage.analyzed),
        ("Skipped", &r.coverage.skipped),
        ("Unsupported", &r.coverage.unsupported),
        ("Unknowns and limitations", &r.coverage.limitations),
    ] {
        if items.is_empty() {
            continue;
        }
        let _ = write!(
            s,
            "<details class=\"card\"><summary>{title} ({})</summary><ul>",
            items.len()
        );
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
        s.push_str("</ul></details>");
    }
    s.push_str("</main></body></html>\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_summary_leads_and_full_investigation_stays_collapsed() {
        let mut r = overview::test_report();
        r.model = Some(overview::test_model());
        r.findings
            .push(overview::test_finding(Severity::High, "Clipboard access"));
        r.model_notes.summary = Some(
            "TL;DR: Clipboard access needs review.\n\n1. Detailed-only investigation text".into(),
        );
        let html = render(&r);
        let summary = html.find("<h2>TL;DR</h2>").unwrap();
        let investigation = html.find("<details class=\"card investigation\">").unwrap();
        assert!(summary < html.find("<h2>Security</h2>").unwrap());
        assert!(html.contains("High severity findings detected"));
        assert!(html.contains("Clipboard access needs review."));
        assert!(investigation < html.find("Detailed-only investigation text").unwrap());
        assert!(!html.contains(" open>"));
        assert!(html.contains("<details class=\"card finding\">"));
    }

    #[test]
    fn summary_and_full_narrative_both_escape_hostile_content() {
        let mut r = overview::test_report();
        r.model = Some(overview::test_model());
        r.findings.push(overview::test_finding(
            Severity::Low,
            "<img src=x onerror=alert(1)>",
        ));
        r.model_notes.summary = Some("TL;DR: <script>alert('x')</script>\n\n1. <iframe>".into());
        let html = render(&r);
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<iframe>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Content-Security-Policy"));
    }

    #[test]
    fn escapes_markup() {
        assert_eq!(
            super::esc("<script>alert('x')</script>&"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;"
        );
    }
}

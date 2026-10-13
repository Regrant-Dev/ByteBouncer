//! ClamAV (`clamscan --no-summary --stdout`) result parsing and mapping.

use bytebouncer_core::{EvidenceKind, EvidenceStrength, Location, Severity};

use crate::out::{Builder, EvidenceSpec, FindingSpec};

/// Detections reported per artifact (with `--allmatch` there can be many).
const MAX_DETECTIONS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub detections: Vec<String>,
    /// Lines clamscan reported as errors for the file.
    pub errors: Vec<String>,
    pub clean: bool,
}

/// Parse clamscan stdout for one scanned file. Lines look like
/// `<path>: <Signature> FOUND`, `<path>: OK`, or `<path>: <message> ERROR`.
pub fn parse(stdout: &str) -> ScanResult {
    let mut r = ScanResult {
        detections: Vec::new(),
        errors: Vec::new(),
        clean: false,
    };
    for line in stdout.lines().map(str::trim_end) {
        if let Some(rest) = line.strip_suffix(" FOUND") {
            if let Some((_, sig)) = rest.rsplit_once(": ") {
                let sig = sig.trim();
                if !sig.is_empty() && !r.detections.iter().any(|d| d == sig) {
                    r.detections.push(sig.to_owned());
                }
            }
        } else if line.ends_with(": OK") {
            r.clean = true;
        } else if line.ends_with(" ERROR") {
            r.errors.push(crate::runner::bounded(
                line.rsplit_once(": ").map_or(line, |(_, m)| m),
                200,
            ));
        }
    }
    r.detections.truncate(MAX_DETECTIONS);
    r
}

/// Add ClamAV findings and coverage. `exit_code` 0 = clean, 1 = detection.
pub fn map(
    result: &ScanResult,
    exit_code: i32,
    engine: &str,
    db_version: &str,
    b: &mut Builder<'_>,
) {
    let version = format!("{engine} (db: {db_version})");
    for sig in &result.detections {
        let ev = b.evidence(EvidenceSpec {
            kind: EvidenceKind::Signature,
            location: Location::default(),
            snippet: &format!("ClamAV signature '{sig}' matched"),
            tool: "clamav",
            version: &version,
            rule_id: Some(sig),
            notes: None,
        });
        let mut limitations = vec![
            "Signature databases can produce false positives; check the detection name before acting".to_owned(),
            format!("Signature database: {db_version}"),
        ];
        if sig.ends_with(".UNOFFICIAL") {
            limitations.push("Signature comes from an unofficial or locally added database".into());
        }
        b.finding(FindingSpec {
            category: "security.signature_match",
            title: format!("ClamAV signature match: {sig}"),
            severity: Severity::High,
            strength: EvidenceStrength::PatternMatch,
            evidence_ids: vec![ev],
            recipient: None,
            conditions: Vec::new(),
            purpose: None,
            limitations,
        });
    }
    let cov = &mut b.out.coverage;
    match (exit_code, result.detections.is_empty()) {
        (0, true) if result.clean => {
            cov.analyzed.push(format!(
                "{}: ClamAV {engine}: no signature matched (DB {db_version})",
                b.path
            ));
        }
        (1, false) => {
            cov.analyzed.push(format!(
                "{}: ClamAV {engine}: {} signature(s) matched (DB {db_version})",
                b.path,
                result.detections.len()
            ));
        }
        _ => {
            if !result.detections.is_empty() {
                cov.analyzed.push(format!(
                    "{}: ClamAV {engine}: signature(s) matched (DB {db_version})",
                    b.path
                ));
            }
            let detail = result
                .errors
                .first()
                .cloned()
                .unwrap_or_else(|| "no per-file result".into());
            cov.limitations.push(format!(
                "ClamAV scan did not complete cleanly (exit {exit_code}): {detail}; absence of a detection is not established"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn parses_detection() {
        let r = parse(&fixture("clamscan_found.txt"));
        assert_eq!(r.detections, vec!["ByteBouncer.Test.EICAR.UNOFFICIAL"]);
        let mut b = Builder::new("abc", "eicar.com", "unknown");
        map(&r, 1, "1.5.4", "custom database (1 file(s))", &mut b);
        let f = &b.out.findings[0];
        assert_eq!(f.category, "security.signature_match");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence_strength, EvidenceStrength::PatternMatch);
        assert_eq!(b.out.evidence[0].kind, EvidenceKind::Signature);
        assert_eq!(
            b.out.evidence[0].producer.rule_id.as_deref(),
            Some("ByteBouncer.Test.EICAR.UNOFFICIAL")
        );
        assert!(f.limitations.iter().any(|l| l.contains("unofficial")));
    }

    #[test]
    fn clean_scan_is_coverage_not_finding() {
        let r = parse(&fixture("clamscan_clean.txt"));
        assert!(r.clean && r.detections.is_empty());
        let mut b = Builder::new("abc", "true", "elf-64");
        map(&r, 0, "1.5.4", "daily 27400 (07 Oct 2024)", &mut b);
        assert!(b.out.findings.is_empty());
        assert!(b.out.coverage.analyzed[0].contains("no signature matched (DB daily 27400"));
    }

    #[test]
    fn error_is_limitation() {
        let r = parse("/x/y: Can't open file or directory ERROR\n");
        let mut b = Builder::new("abc", "y", "unknown");
        map(&r, 2, "1.5.4", "db", &mut b);
        assert!(b.out.findings.is_empty());
        assert!(b.out.coverage.limitations[0].contains("exit 2"));
        assert!(b.out.coverage.analyzed.is_empty());
    }

    #[test]
    fn path_with_colon_and_multiple_matches() {
        let r = parse(
            "/a: b/file: Sig.One FOUND\n/a: b/file: Sig.Two FOUND\n/a: b/file: Sig.One FOUND\n",
        );
        assert_eq!(r.detections, vec!["Sig.One", "Sig.Two"]);
    }
}

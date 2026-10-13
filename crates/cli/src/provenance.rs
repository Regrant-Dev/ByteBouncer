//! Provenance checks (SPEC §5.2.1): publisher checksums and detached
//! signatures. A valid signature or matching checksum is a provenance fact,
//! never a safety verdict; a mismatch fails the default policy.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bytebouncer_core::{
    AnalysisOutput, Evidence, EvidenceKind, EvidenceStrength, Finding, Location, OptOut,
    OptOutStatus, Producer, Severity, SignatureCheck, SignatureStatus, TriState,
};
use bytebouncer_sandbox::Profile;

/// Parse `SHA256SUMS`-style (`<hex>  [*]name`) and BSD-style
/// (`SHA256 (name) = <hex>`) lines. Returns (name, lowercase hex) pairs.
pub fn parse_checksums(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("SHA256 (")
            && let Some((name, hex)) = rest.split_once(") = ")
        {
            out.push((name.to_owned(), hex.trim().to_ascii_lowercase()));
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if let (Some(hex), Some(name)) = (parts.next(), parts.next())
            && hex.len() == 64
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            let name = name.trim().trim_start_matches('*');
            out.push((name.to_owned(), hex.to_ascii_lowercase()));
        }
    }
    out
}

/// Look up `file_name` (by basename) in a parsed checksum list.
pub fn expected_for(sums: &[(String, String)], file_name: &str) -> Option<String> {
    let base = |s: &str| s.rsplit(['/', '\\']).next().unwrap_or(s).to_owned();
    sums.iter()
        .find(|(n, _)| base(n) == base(file_name))
        .map(|(_, h)| h.clone())
}

/// Build the provenance output for one artifact.
pub struct Checker<'a> {
    pub sha256: &'a str,
    pub display: &'a str,
    pub out: AnalysisOutput,
    pub checks: Vec<SignatureCheck>,
}

impl<'a> Checker<'a> {
    pub fn new(sha256: &'a str, display: &'a str) -> Self {
        Self {
            sha256,
            display,
            out: AnalysisOutput::default(),
            checks: vec![],
        }
    }

    fn evidence(&mut self, kind: EvidenceKind, snippet: String, tool: &str) -> String {
        let id = format!("evidence-{:03}", self.out.evidence.len() + 1);
        self.out.evidence.push(Evidence {
            id: id.clone(),
            kind,
            artifact_sha256: self.sha256.to_owned(),
            artifact_path: self.display.to_owned(),
            location: Location::default(),
            snippet: Some(snippet),
            snippet_truncated: false,
            producer: Producer {
                tool: tool.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                rule_id: None,
            },
            notes: None,
        });
        id
    }

    fn mismatch(&mut self, title: &str, evidence_id: String, purpose: &str) {
        self.out.findings.push(Finding {
            id: format!("finding-{:03}", self.out.findings.len() + 1),
            category: "provenance.mismatch".into(),
            title: title.into(),
            severity: Severity::Critical,
            evidence_strength: EvidenceStrength::PatternMatch,
            artifact_sha256: self.sha256.to_owned(),
            evidence_ids: vec![evidence_id],
            data_types: vec![],
            recipient: None,
            enabled_by_default: TriState::Unknown,
            runtime_observed: false,
            conditions: vec![],
            possible_legitimate_purpose: Some(purpose.into()),
            opt_out: OptOut {
                status: OptOutStatus::NotEstablished,
            },
            limitations: vec![],
        });
    }

    /// Compare against a publisher-supplied digest from `source`.
    pub fn expect_sha256(&mut self, expected: &str, source: &str) {
        if expected == self.sha256 {
            self.out
                .coverage
                .analyzed
                .push(format!("{}: SHA-256 matches {source}", self.display));
            self.checks.push(SignatureCheck {
                artifact: self.display.into(),
                kind: format!("sha256 ({source})"),
                status: SignatureStatus::Valid,
                signer: None,
                detail: Some("integrity only: a checksum from the same server proves nothing about authenticity".into()),
            });
        } else {
            let ev = self.evidence(
                EvidenceKind::ManifestEntry,
                format!(
                    "expected sha256 {expected} ({source}), actual {}",
                    self.sha256
                ),
                "bytebouncer-provenance",
            );
            self.mismatch(
                "File does not match the publisher-supplied SHA-256",
                ev,
                "A corrupted download or a checksum for a different version",
            );
            self.checks.push(SignatureCheck {
                artifact: self.display.into(),
                kind: format!("sha256 ({source})"),
                status: SignatureStatus::Invalid,
                signer: None,
                detail: None,
            });
        }
    }

    /// Verify a minisign signature against trusted public keys.
    pub fn minisign(&mut self, data: &[u8], sig_text: &str, trusted_keys: &[String]) {
        let mut check = SignatureCheck {
            artifact: self.display.into(),
            kind: "minisign".into(),
            status: SignatureStatus::UnknownKey,
            signer: None,
            detail: None,
        };
        let Ok(sig) = minisign_verify::Signature::decode(sig_text) else {
            check.status = SignatureStatus::Invalid;
            check.detail = Some("signature file could not be parsed".into());
            self.checks.push(check);
            return;
        };
        if trusted_keys.is_empty() {
            check.detail = Some(
                "no trusted minisign keys configured (--minisign-key or [keys] minisign)".into(),
            );
        }
        for key in trusted_keys {
            let pk = minisign_verify::PublicKey::from_base64(key.trim())
                .or_else(|_| minisign_verify::PublicKey::decode(key));
            let Ok(pk) = pk else { continue };
            match pk.verify(data, &sig, false) {
                Ok(()) => {
                    check.status = SignatureStatus::Valid;
                    check.signer = Some(key.trim().chars().take(56).collect());
                    break;
                }
                // A key ID mismatch means "not this key"; a bad signature from
                // the matching key is an invalid signature.
                Err(minisign_verify::Error::UnexpectedKeyId) => {}
                Err(e) => {
                    check.status = SignatureStatus::Invalid;
                    check.detail = Some(e.to_string());
                }
            }
        }
        self.record(check);
    }

    /// Verify an OpenPGP detached signature with `gpgv`, run in the Tier 2
    /// sandbox because it parses untrusted signature packets.
    pub fn openpgp(
        &mut self,
        data_path: &Path,
        sig_path: &Path,
        keyrings: &[PathBuf],
        scratch: &Path,
        allow_reduced: bool,
    ) {
        let mut check = SignatureCheck {
            artifact: self.display.into(),
            kind: "openpgp".into(),
            status: SignatureStatus::NotChecked,
            signer: None,
            detail: None,
        };
        let gpgv = ["/usr/bin/gpgv", "/bin/gpgv", "/usr/local/bin/gpgv"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists());
        let (Some(gpgv), false) = (gpgv, keyrings.is_empty()) else {
            check.detail = Some(if keyrings.is_empty() {
                "no trusted OpenPGP keyring configured (--pgp-keyring or [keys] pgp_keyrings)"
                    .into()
            } else {
                "gpgv not found".into()
            });
            self.checks.push(check);
            return;
        };
        let _ = std::fs::create_dir_all(scratch);
        let inputs = [
            vec![data_path.to_path_buf(), sig_path.to_path_buf()],
            keyrings.to_vec(),
        ]
        .concat();
        let mut profile = Profile::external_tool(vec![], inputs, scratch.to_path_buf());
        profile
            .env
            .push(("GNUPGHOME".into(), scratch.as_os_str().to_owned()));
        let spawned = bytebouncer_sandbox::spawn(
            &profile,
            gpgv,
            |c| {
                c.arg("--status-fd").arg("1");
                for k in keyrings {
                    c.arg("--keyring").arg(k);
                }
                c.arg(sig_path)
                    .arg(data_path)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            },
            allow_reduced,
        );
        let output = match spawned {
            Ok((child, _)) => wait_with_timeout(child, Duration::from_secs(60)),
            Err(e) => Err(e.to_string()),
        };
        match output {
            Ok(status_text) => {
                let line = |tag: &str| {
                    status_text
                        .lines()
                        .find(|l| l.starts_with(&format!("[GNUPG:] {tag} ")))
                };
                if let Some(l) = line("VALIDSIG") {
                    check.status = SignatureStatus::Valid;
                    check.signer = l.split_whitespace().nth(2).map(str::to_owned);
                    if let Some(g) = line("GOODSIG") {
                        check.detail = Some(g.splitn(4, ' ').nth(3).unwrap_or_default().to_owned());
                    }
                } else if line("BADSIG").is_some() {
                    check.status = SignatureStatus::Invalid;
                } else if line("NO_PUBKEY").is_some() || line("ERRSIG").is_some() {
                    check.status = SignatureStatus::UnknownKey;
                    check.detail =
                        Some("signed by a key that is not in the trusted keyring".into());
                } else {
                    check.detail = Some("gpgv gave no verdict".into());
                }
            }
            Err(e) => check.detail = Some(format!("gpgv failed: {e}")),
        }
        self.record(check);
    }

    fn record(&mut self, check: SignatureCheck) {
        match check.status {
            SignatureStatus::Valid => self.out.coverage.analyzed.push(format!(
                "{}: {} signature valid ({})",
                self.display,
                check.kind,
                check.signer.as_deref().unwrap_or("signer unknown")
            )),
            SignatureStatus::Invalid => {
                let ev = self.evidence(
                    EvidenceKind::Signature,
                    format!(
                        "{} signature verification failed: {}",
                        check.kind,
                        check.detail.as_deref().unwrap_or("bad signature")
                    ),
                    "bytebouncer-provenance",
                );
                self.mismatch(
                    &format!("Detached {} signature does not verify", check.kind),
                    ev,
                    "A signature for a different file or version",
                );
            }
            _ => self.out.coverage.limitations.push(format!(
                "{}: {} signature not verified: {}",
                self.display,
                check.kind,
                check.detail.as_deref().unwrap_or("unknown key")
            )),
        }
        self.checks.push(check);
    }
}

fn wait_with_timeout(
    mut child: bytebouncer_sandbox::Child,
    timeout: Duration,
) -> Result<String, String> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                return Err("timed out".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e.to_string()),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_checksum_styles() {
        let h = "a".repeat(64);
        let text = format!(
            "{h}  app-1.0.tar.gz\n{h} *bin/app.exe\nSHA256 (other.zip) = {}\n# comment\n",
            "B".repeat(64)
        );
        let sums = parse_checksums(&text);
        assert_eq!(sums.len(), 3);
        assert_eq!(expected_for(&sums, "app.exe").as_deref(), Some(h.as_str()));
        assert_eq!(expected_for(&sums, "other.zip"), Some("b".repeat(64)));
        assert!(expected_for(&sums, "missing").is_none());
    }

    #[test]
    fn checksum_mismatch_is_a_finding() {
        let mut c = Checker::new("ab", "f");
        c.expect_sha256("cd", "--expect-sha256");
        assert_eq!(c.out.findings[0].category, "provenance.mismatch");
        let mut c = Checker::new("ab", "f");
        c.expect_sha256("ab", "--expect-sha256");
        assert!(c.out.findings.is_empty());
        assert_eq!(c.checks[0].status, SignatureStatus::Valid);
    }

    #[test]
    fn minisign_roundtrip() {
        // Test vector from the minisign-verify crate documentation.
        let pk = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        let sig = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";
        let mut c = Checker::new("x", "test");
        c.minisign(b"test", sig, &[pk.into()]);
        assert_eq!(
            c.checks[0].status,
            SignatureStatus::Valid,
            "{:?}",
            c.checks[0]
        );
        let mut c = Checker::new("x", "test");
        c.minisign(b"tampered", sig, &[pk.into()]);
        assert_eq!(c.checks[0].status, SignatureStatus::Invalid);
        assert_eq!(c.out.findings.len(), 1);
    }
}

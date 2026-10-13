//! Opt-in, hash-only reputation lookups (SPEC §10). Only the SHA-256 leaves
//! the machine; files are never uploaded. A hit is strong evidence; absence
//! from a database says nothing about safety.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytebouncer_core::{
    AnalysisOutput, Evidence, EvidenceKind, EvidenceStrength, Finding, Location, OptOut,
    OptOutStatus, Producer, Severity, TriState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Service {
    Malwarebazaar,
    Virustotal,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Self::Malwarebazaar => "malwarebazaar",
            Self::Virustotal => "virustotal",
        }
    }

    fn default_key_env(self) -> &'static str {
        match self {
            Self::Malwarebazaar => "MALWAREBAZAAR_KEY",
            Self::Virustotal => "VT_API_KEY",
        }
    }
}

pub enum Verdict {
    /// Known to the service with this description and severity.
    Hit {
        summary: String,
        severity: Severity,
    },
    NotFound,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .user_agent(concat!("bytebouncer/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

pub fn query(service: Service, sha256: &str, key_env: Option<&str>) -> Result<Verdict> {
    let env_name = key_env.unwrap_or(service.default_key_env());
    let key = std::env::var(env_name)
        .with_context(|| format!("{} needs an API key in ${env_name}", service.name()))?;
    match service {
        Service::Malwarebazaar => {
            let mut resp = agent()
                .post("https://mb-api.abuse.ch/api/v1/")
                .header("Auth-Key", &key)
                .send_form([("query", "get_info"), ("hash", sha256)])?;
            let body: serde_json::Value = serde_json::from_slice(
                &resp.body_mut().with_config().limit(1 << 20).read_to_vec()?,
            )?;
            match body["query_status"].as_str() {
                Some("ok") => {
                    let d = &body["data"][0];
                    let sig = d["signature"].as_str().unwrap_or("unnamed");
                    let tags = d["tags"].as_array().map(|t| {
                        t.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    });
                    Ok(Verdict::Hit {
                        summary: format!(
                            "MalwareBazaar lists this exact file as malware (signature: {sig}; tags: {})",
                            tags.unwrap_or_default()
                        ),
                        severity: Severity::Critical,
                    })
                }
                Some("hash_not_found") | Some("no_results") => Ok(Verdict::NotFound),
                other => bail!(
                    "MalwareBazaar returned {}",
                    other.unwrap_or("an unexpected response")
                ),
            }
        }
        Service::Virustotal => {
            let mut resp = agent()
                .get(&format!("https://www.virustotal.com/api/v3/files/{sha256}"))
                .header("x-apikey", &key)
                .call()?;
            if resp.status() == 404 {
                return Ok(Verdict::NotFound);
            }
            if !resp.status().is_success() {
                bail!("VirusTotal returned HTTP {}", resp.status());
            }
            let body: serde_json::Value = serde_json::from_slice(
                &resp.body_mut().with_config().limit(8 << 20).read_to_vec()?,
            )?;
            let stats = &body["data"]["attributes"]["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let total: u64 = ["malicious", "suspicious", "undetected", "harmless"]
                .iter()
                .filter_map(|k| stats[k].as_u64())
                .sum();
            if malicious + suspicious == 0 {
                return Ok(Verdict::NotFound);
            }
            // A handful of engines often flag legitimate tools; scale severity.
            let severity = match malicious {
                0..=1 => Severity::Low,
                2..=4 => Severity::Medium,
                5..=14 => Severity::High,
                _ => Severity::Critical,
            };
            Ok(Verdict::Hit {
                summary: format!(
                    "VirusTotal: {malicious} malicious and {suspicious} suspicious detections out of {total} engines"
                ),
                severity,
            })
        }
    }
}

/// Turn a hit into a finding for the artifact.
pub fn hit_output(
    service: Service,
    sha256: &str,
    display: &str,
    summary: String,
    severity: Severity,
) -> AnalysisOutput {
    let mut out = AnalysisOutput::default();
    out.evidence.push(Evidence {
        id: "evidence-001".into(),
        kind: EvidenceKind::Signature,
        artifact_sha256: sha256.into(),
        artifact_path: display.into(),
        location: Location::default(),
        snippet: Some(summary.clone()),
        snippet_truncated: false,
        producer: Producer {
            tool: service.name().into(),
            version: "api".into(),
            rule_id: None,
        },
        notes: None,
    });
    out.findings.push(Finding {
        id: "finding-001".into(),
        category: "security.signature_match".into(),
        title: summary,
        severity,
        evidence_strength: EvidenceStrength::PatternMatch,
        artifact_sha256: sha256.into(),
        evidence_ids: vec!["evidence-001".into()],
        data_types: vec![],
        recipient: None,
        enabled_by_default: TriState::Unknown,
        runtime_observed: false,
        conditions: vec![],
        possible_legitimate_purpose: None,
        opt_out: OptOut {
            status: OptOutStatus::NotEstablished,
        },
        limitations: vec![
            "Reputation data from a third-party service, matched by exact SHA-256".into(),
        ],
    });
    out
}

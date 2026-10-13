//! Approval records. An approval says "the user reviewed
//! report R and accepts these exact bytes". Records are keyed by SHA-256, so
//! any change to a payload needs a new inspection and a new decision.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bytebouncer_core::{Report, ResultState};
use serde::{Deserialize, Serialize};

use crate::store;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub sha256: String,
    pub artifact: String,
    pub report_id: String,
    pub approved_at: String,
    /// Set when the user approved despite an incomplete scan or exceeded policy.
    pub override_reason: Option<String>,
}

pub fn approvals_dir() -> Result<PathBuf> {
    Ok(directories::ProjectDirs::from("", "", "ByteBouncer")
        .context("cannot determine home directory")?
        .data_dir()
        .join("approvals"))
}

fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The artifacts an approval covers: downloaded/acquired top-level files.
fn approvable(report: &Report) -> Vec<(&str, &str)> {
    report
        .artifacts
        .iter()
        .filter(|a| a.parent.is_none() && !a.path.contains("/recipe/"))
        .map(|a| (a.sha256.as_str(), a.path.as_str()))
        .collect()
}

pub fn approve(report_id: &str, override_reason: Option<String>) -> Result<Vec<Approval>> {
    let report = store::load(report_id)?;
    let complete = matches!(
        report.result_state,
        ResultState::FindingsDetected | ResultState::NoFindingsDetected
    );
    if (!complete || report.policy.exceeded) && override_reason.is_none() {
        bail!(
            "report {} is {}{}; re-run with --override \"<reason>\" to approve anyway",
            report.scan_id,
            if complete { "complete" } else { "INCOMPLETE" },
            if report.policy.exceeded {
                " and EXCEEDED the policy"
            } else {
                ""
            }
        );
    }
    let dir = approvals_dir()?;
    std::fs::create_dir_all(&dir)?;
    let mut out = Vec::new();
    for (sha256, artifact) in approvable(&report) {
        let a = Approval {
            sha256: sha256.into(),
            artifact: artifact.into(),
            report_id: report.scan_id.clone(),
            approved_at: jiff::Timestamp::now().to_string(),
            override_reason: override_reason.clone(),
        };
        store::write_private_file(
            &dir.join(format!("{sha256}.json")),
            &serde_json::to_vec_pretty(&a)?,
        )?;
        out.push(a);
    }
    Ok(out)
}

/// Look up an approval in `dir` (the hook passes the user's directory explicitly).
pub fn lookup(dir: &Path, sha256: &str) -> Option<Approval> {
    if !valid_sha(sha256) {
        return None;
    }
    let a: Approval =
        serde_json::from_slice(&std::fs::read(dir.join(format!("{sha256}.json"))).ok()?).ok()?;
    (a.sha256 == sha256).then_some(a)
}

pub fn revoke(sha256: &str) -> Result<bool> {
    if !valid_sha(sha256) {
        bail!("expected a lowercase 64-character SHA-256");
    }
    let path = approvals_dir()?.join(format!("{sha256}.json"));
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

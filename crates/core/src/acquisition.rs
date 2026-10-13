//! Acquisition manifest: what was requested, what it resolved to,
//! where bytes came from, and what could not be resolved safely.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Manager {
    Pacman,
    Aur,
    Apt,
    Dnf,
    Homebrew,
    Winget,
    Scoop,
    Chocolatey,
}

/// A package request parsed from familiar package-manager syntax. Never executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRequest {
    pub manager: Manager,
    /// Normalized operation, e.g. `install`.
    pub operation: String,
    pub packages: Vec<String>,
    /// Recognized options that change resolution (e.g. `--exact`, `--cask`).
    pub options: Vec<String>,
    /// The original text, for display.
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    pub repository: Option<String>,
    /// Files to acquire for this package.
    pub sources: Vec<SourceRef>,
    /// Recipe/manifest files retrieved as data (PKGBUILD, formula, winget YAML…).
    pub recipe_files: Vec<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub url: String,
    pub file_name: String,
    pub expected_sha256: Option<String>,
    pub expected_sha512: Option<String>,
    /// URL of a detached signature, if the repository publishes one.
    pub signature_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub requested_url: String,
    pub final_url: String,
    pub redirects: u32,
    pub sha256: String,
    pub size: u64,
    pub retrieved_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Invalid,
    UnknownKey,
    NotChecked,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureCheck {
    pub artifact: String,
    pub kind: String,
    pub status: SignatureStatus,
    pub signer: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionManifest {
    pub request: Option<PackageRequest>,
    pub packages: Vec<ResolvedPackage>,
    pub origins: Vec<Origin>,
    pub signatures: Vec<SignatureCheck>,
    pub dependencies_included: Vec<String>,
    pub dependencies_excluded: Vec<String>,
    /// Steps that could not be resolved safely; each makes the scan incomplete.
    pub unresolved: Vec<String>,
    /// Directory inputs: files that changed while being snapshotted.
    pub changed_during_snapshot: Vec<String>,
}

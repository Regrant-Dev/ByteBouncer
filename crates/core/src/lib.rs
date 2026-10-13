//! Core contracts shared by every ByteBouncer stage: evidence, findings,
//! reports, and policy. See SPEC.md §7 and §8.

pub mod acquisition;
pub mod analysis;
pub mod evidence;
pub mod finding;
pub mod policy;
pub mod report;

pub use acquisition::{
    AcquisitionManifest, Manager, Origin, PackageRequest, ResolvedPackage, SignatureCheck,
    SignatureStatus, SourceRef,
};
pub use analysis::{AnalysisOutput, Merger};
pub use evidence::{Evidence, EvidenceKind, Location, Producer};
pub use finding::{EvidenceStrength, Finding, OptOut, OptOutStatus, Recipient, Severity, TriState};
pub use policy::{Policy, PolicyOutcome};
pub use report::{
    ArtifactRecord, Budget, Coverage, ExitCode, Isolation, IsolationTier, ModelInfo, ModelNotes,
    Report, ResultState, ScanMode, ToolVersion, UnverifiedClaim,
};

/// Version of the JSON report schema. Bump on any breaking change.
pub const SCHEMA_VERSION: &str = "0.2.0";

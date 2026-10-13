//! Recursive in-memory expansion of archives, packages, and installers.
//! Every nested file becomes an artifact (`outer!inner` path) analyzed like a
//! top-level input. Install-time scripts and package metadata that change the
//! system (services, hooks, custom actions, restricted capabilities) become
//! findings. Nothing touches the filesystem.

use std::collections::HashMap;

use bytebouncer_core::{ArtifactRecord, EvidenceKind, Location, Severity};
use bytebouncer_formats::{ContainerKind, EntryKind, Expanded, FormatError, Limits};
use sha2::{Digest, Sha256};

use crate::{
    AnalysisOutput, ArtifactAnalysis, Builder, analyze_leaf_with_code, code, scan_script, yara,
};

/// Bounds for one input's whole tree.
pub struct TreeLimits {
    pub max_depth: u32,
    pub max_artifacts: usize,
    pub max_total_bytes: u64,
    pub container: Limits,
}

impl Default for TreeLimits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_artifacts: 20_000,
            max_total_bytes: 8 << 30,
            container: Limits::default(),
        }
    }
}

/// A nested executable handed back to the caller for deep analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Exported {
    pub path: String,
    pub sha256: String,
    pub format: String,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

/// Export budget for nested executables: (max per file, max total, max count).
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ExportLimits {
    pub per_file: u64,
    pub total: u64,
    pub count: usize,
}

/// A nested file to extract to disk and analyze separately.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpillRequest {
    /// Child paths leading from the input to the container holding the file
    /// (empty when the input itself is that container).
    pub chain: Vec<String>,
    /// The file's path inside that container.
    pub entry: String,
    pub size: u64,
    /// Display path for reports (`outer!…!entry`).
    pub display: String,
    /// Display path of the container that holds it.
    pub container: String,
}

/// Re-open the container named by `req.chain` inside `input` and stream
/// `req.entry` into `out` (at most `max` bytes). Intermediate containers are
/// expanded in memory within the default limits; the large file itself is
/// never held in memory.
pub fn extract_spilled(
    input: &[u8],
    req: &SpillRequest,
    out: &mut dyn std::io::Write,
    max: u64,
) -> Result<u64, String> {
    let limits = Limits::default();
    let mut owned: Option<Vec<u8>> = None;
    let mut name = req.container.clone();
    for step in &req.chain {
        let cur: &[u8] = owned.as_deref().unwrap_or(input);
        let kind = bytebouncer_formats::detect(cur, &name)
            .ok_or_else(|| format!("{name}: not a container"))?;
        let exp = bytebouncer_formats::expand(cur, kind, &limits).map_err(|e| e.to_string())?;
        let child = exp
            .children
            .into_iter()
            .find(|c| &c.path == step)
            .ok_or_else(|| format!("{step} not found in {name}"))?;
        name = step.clone();
        owned = Some(child.data);
    }
    let cur: &[u8] = owned.as_deref().unwrap_or(input);
    let hint = name.rsplit(['/', '!']).next().unwrap_or(&name);
    let kind =
        bytebouncer_formats::detect(cur, hint).ok_or_else(|| format!("{name}: not a container"))?;
    bytebouncer_formats::extract_entry(cur, kind, &req.entry, out, max).map_err(|e| e.to_string())
}

struct Walk<'r> {
    /// Child paths from the input to the container currently being expanded.
    chain: Vec<String>,
    rules: Option<&'r yara::Rules>,
    export: Option<ExportLimits>,
    exported: Vec<Exported>,
    exported_bytes: u64,
    limits: TreeLimits,
    out: ArtifactAnalysis,
    total_bytes: u64,
    /// sha256 → format, so duplicate files inside one input are analyzed once.
    seen: HashMap<String, String>,
    stopped: bool,
    /// Serialized bytes of code maps retained so far for this input.
    code_bytes: usize,
}

pub fn analyze_tree(
    bytes: &[u8],
    display: &str,
    sha256: &str,
    rules: Option<&yara::Rules>,
) -> ArtifactAnalysis {
    analyze_tree_exporting(bytes, display, sha256, rules, None).0
}

/// Like [`analyze_tree`], also returning nested executables (not the input
/// itself) within `export` limits, for deep-mode tools that need files.
pub fn analyze_tree_exporting(
    bytes: &[u8],
    display: &str,
    sha256: &str,
    rules: Option<&yara::Rules>,
    export: Option<ExportLimits>,
) -> (ArtifactAnalysis, Vec<Exported>) {
    let mut w = Walk {
        chain: Vec::new(),
        rules,
        export,
        exported: vec![],
        exported_bytes: 0,
        limits: TreeLimits::default(),
        out: ArtifactAnalysis::default(),
        total_bytes: 0,
        seen: HashMap::new(),
        stopped: false,
        code_bytes: 0,
    };
    w.visit(bytes, display, sha256, None, 0);
    (w.out, w.exported)
}

fn kind_name(k: ContainerKind) -> String {
    format!("{k:?}").to_ascii_lowercase()
}

impl Walk<'_> {
    fn record(
        &mut self,
        path: &str,
        sha256: &str,
        size: u64,
        format: String,
        parent: Option<&str>,
    ) {
        self.out.artifacts.push(ArtifactRecord {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            size,
            format,
            expected_sha256: None,
            parent: parent.map(str::to_owned),
        });
    }

    fn visit(&mut self, bytes: &[u8], path: &str, sha256: &str, parent: Option<&str>, depth: u32) {
        if self.stopped {
            return;
        }
        if self.out.artifacts.len() >= self.limits.max_artifacts
            || self.total_bytes + bytes.len() as u64 > self.limits.max_total_bytes
        {
            self.stopped = true;
            self.out.incomplete.push(format!(
                "{path}: expansion stopped at {} artifacts / {} bytes; remaining contents not inspected",
                self.out.artifacts.len(),
                self.total_bytes
            ));
            return;
        }
        self.total_bytes += bytes.len() as u64;
        if let Some(format) = self.seen.get(sha256).cloned() {
            self.record(path, sha256, bytes.len() as u64, format, parent);
            return;
        }

        let name = path.rsplit(['/', '!']).next().unwrap_or(path);
        let kind = bytebouncer_formats::detect(bytes, name);
        let Some(kind) = kind else {
            return self.leaf(bytes, path, sha256, parent, None);
        };
        if depth >= self.limits.max_depth {
            self.out.incomplete.push(format!(
                "{path}: nesting deeper than {} levels not inspected",
                self.limits.max_depth
            ));
            return self.leaf(bytes, path, sha256, parent, Some(kind_name(kind)));
        }
        match bytebouncer_formats::expand(bytes, kind, &self.limits.container) {
            Ok(exp) => self.container(bytes, exp, path, sha256, parent, depth),
            Err(FormatError::Unsupported(msg)) => {
                // e.g. NSIS/Inno Setup: still analyze the outer executable.
                self.leaf(bytes, path, sha256, parent, None);
                if let Some(last) = self.out.outputs.last_mut() {
                    last.coverage.unsupported.push(format!(
                        "{path}: {} contents not extracted: {msg}",
                        kind_name(kind)
                    ));
                }
            }
            Err(e) => {
                self.leaf(bytes, path, sha256, parent, None);
                if let Some(last) = self.out.outputs.last_mut() {
                    last.coverage.limitations.push(format!(
                        "{path}: could not expand as {}: {e}",
                        kind_name(kind)
                    ));
                }
            }
        }
    }

    fn leaf(
        &mut self,
        bytes: &[u8],
        path: &str,
        sha256: &str,
        parent: Option<&str>,
        format_override: Option<String>,
    ) {
        let (mut out, map) = analyze_leaf_with_code(bytes, path, sha256, self.rules);
        if let Some(mut map) = map {
            let budget = code::MAX_CODE_MAP_BYTES.saturating_sub(self.code_bytes);
            if budget > 4096 && map.shrink_to(budget) {
                self.code_bytes += map.json_len();
                self.out.code.push(map);
            } else {
                out.coverage.limitations.push(format!(
                    "{path}: code map not retained for model tools (per-input {} byte cap reached)",
                    code::MAX_CODE_MAP_BYTES
                ));
            }
        }
        if let Some(f) = format_override {
            out.format = f;
        }
        self.seen.insert(sha256.to_owned(), out.format.clone());
        self.record(path, sha256, bytes.len() as u64, out.format.clone(), parent);
        let executable = ["elf", "pe", "mach"]
            .iter()
            .any(|p| out.format.starts_with(p));
        if let (Some(lim), true, Some(_)) = (self.export, executable, parent)
            && self.exported.len() < lim.count
            && bytes.len() as u64 <= lim.per_file
            && self.exported_bytes + bytes.len() as u64 <= lim.total
        {
            self.exported_bytes += bytes.len() as u64;
            self.exported.push(Exported {
                path: path.into(),
                sha256: sha256.into(),
                format: out.format.clone(),
                data: bytes.to_vec(),
            });
        }
        self.out.outputs.push(out);
    }

    fn container(
        &mut self,
        bytes: &[u8],
        exp: Expanded,
        path: &str,
        sha256: &str,
        parent: Option<&str>,
        depth: u32,
    ) {
        let format = kind_name(exp.kind);
        self.seen.insert(sha256.to_owned(), format.clone());
        self.record(path, sha256, bytes.len() as u64, format.clone(), parent);
        let mut b = Builder {
            sha256,
            path,
            findings: vec![],
            evidence: vec![],
        };
        let mut out = AnalysisOutput {
            format: format.clone(),
            ..Default::default()
        };
        out.coverage.analyzed.push(format!(
            "{path}: expanded {format} ({} entries)",
            exp.children.len()
        ));

        for script in &exp.scripts {
            scan_script(&mut b, &script.text, Some(&script.kind));
        }
        if !exp.scripts.is_empty() {
            let kinds: Vec<&str> = exp.scripts.iter().map(|s| s.kind.as_str()).collect();
            out.coverage.analyzed.push(format!(
                "{path}: install-time scripts reviewed ({})",
                kinds.join(", ")
            ));
        }
        package_metadata(&mut b, &exp);

        let traversal: Vec<&String> = exp
            .problems
            .iter()
            .filter(|p| p.contains("..") || p.contains("absolute") || p.contains("traversal"))
            .collect();
        if !traversal.is_empty() {
            let ids = traversal
                .iter()
                .take(5)
                .map(|p| {
                    b.add_evidence(
                        EvidenceKind::ManifestEntry,
                        Location::default(),
                        p,
                        "bytebouncer-formats",
                        Some("path-traversal"),
                    )
                })
                .collect();
            b.add_finding_with(
                "security.evasion",
                "Archive entry names try to escape the extraction directory".into(),
                Severity::Medium,
                ids,
                Some("Some legacy archivers store absolute paths"),
            );
        }
        for p in &exp.problems {
            out.coverage.limitations.push(format!("{path}: {p}"));
        }
        if exp.truncated {
            self.out.incomplete.push(format!(
                "{path}: container limits reached; some entries not inspected"
            ));
        }
        let links = exp
            .children
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    EntryKind::Symlink { .. } | EntryKind::Hardlink { .. }
                )
            })
            .count();
        let specials = exp
            .children
            .iter()
            .filter(|c| matches!(c.kind, EntryKind::Special(_)))
            .count();
        if links + specials > 0 {
            out.coverage.skipped.push(format!(
                "{path}: {links} link(s) and {specials} special file(s) recorded, not followed"
            ));
        }
        out.findings = b.findings;
        out.evidence = b.evidence;
        self.out.outputs.push(out);

        for o in exp.oversized {
            self.out.spill.push(SpillRequest {
                chain: self.chain.clone(),
                display: format!("{path}!{}", o.path),
                entry: o.path,
                size: o.size,
                container: path.to_owned(),
            });
        }
        for child in exp.children {
            if child.kind != EntryKind::File || child.data.is_empty() {
                continue;
            }
            let child_sha = hex(&Sha256::digest(&child.data));
            let child_path = format!("{path}!{}", child.path);
            self.chain.push(child.path);
            self.visit(&child.data, &child_path, &child_sha, Some(path), depth + 1);
            self.chain.pop();
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Package metadata that installs persistent or privileged behavior.
fn package_metadata(b: &mut Builder, exp: &Expanded) {
    let group = |key_prefix: &str| -> Vec<&str> {
        exp.metadata
            .iter()
            .filter(|(k, _)| k.starts_with(key_prefix))
            .map(|(_, v)| v.as_str())
            .collect()
    };
    let rules: [(&str, &str, Severity, &str, &str); 6] = [
        (
            "arch.systemd_unit",
            "security.persistence",
            Severity::Info,
            "Package installs systemd units",
            "Daemons and timers shipped by the package",
        ),
        (
            "arch.hook",
            "security.persistence",
            Severity::Low,
            "Package installs pacman hooks that run on future transactions",
            "Cache/index updates after package changes",
        ),
        (
            "msi.ServiceInstall",
            "security.persistence",
            Severity::Low,
            "MSI installs a Windows service",
            "Background services shipped on purpose",
        ),
        (
            "msix.restricted_capability",
            "security.capability",
            Severity::Medium,
            "MSIX package requests restricted capabilities",
            "Full-trust desktop apps commonly request runFullTrust",
        ),
        (
            "rpm.trigger",
            "security.persistence",
            Severity::Low,
            "RPM declares triggers that run when other packages change",
            "Cache and index maintenance",
        ),
        (
            "deb.triggers",
            "security.persistence",
            Severity::Low,
            "Debian package declares triggers",
            "Cache and index maintenance",
        ),
    ];
    for (prefix, category, severity, title, purpose) in rules {
        let values = group(prefix);
        if values.is_empty() {
            continue;
        }
        let ids = values
            .iter()
            .take(10)
            .map(|v| {
                b.add_evidence(
                    EvidenceKind::ManifestEntry,
                    Location::default(),
                    v,
                    "bytebouncer-formats",
                    Some(prefix),
                )
            })
            .collect();
        b.add_finding_with(
            category,
            format!("{title} ({})", values.len()),
            severity,
            ids,
            Some(purpose),
        );
    }
}

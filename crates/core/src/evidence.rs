use serde::{Deserialize, Serialize};

/// Maximum stored snippet length in bytes (SPEC §7: snippets are bounded).
pub const MAX_SNIPPET_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    StringReference,
    Import,
    Symbol,
    RuleMatch,
    Signature,
    ScriptCommand,
    ManifestEntry,
    DecompiledFunction,
    CallPath,
    DataflowTrace,
    NetworkObservation,
    FileObservation,
    ProcessObservation,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub offset: Option<u64>,
    pub section: Option<String>,
    pub function: Option<String>,
    pub address: Option<u64>,
    pub line: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Producer {
    pub tool: String,
    pub version: String,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub kind: EvidenceKind,
    pub artifact_sha256: String,
    pub artifact_path: String,
    pub location: Location,
    pub snippet: Option<String>,
    pub snippet_truncated: bool,
    pub producer: Producer,
    pub notes: Option<String>,
}

/// Bound a snippet to [`MAX_SNIPPET_BYTES`] on a char boundary.
/// Returns the bounded text and whether it was truncated.
pub fn bound_snippet(text: &str) -> (String, bool) {
    if text.len() <= MAX_SNIPPET_BYTES {
        return (text.to_owned(), false);
    }
    let mut end = MAX_SNIPPET_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_truncates_on_char_boundary() {
        let s = "é".repeat(200);
        let (out, truncated) = bound_snippet(&s);
        assert!(truncated);
        assert!(out.len() <= MAX_SNIPPET_BYTES);
    }
}

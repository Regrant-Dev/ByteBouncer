//! Shared plumbing: path normalization, limit accounting, bounded reads, and
//! bounds-checked integer readers. Every format module funnels children
//! through [`Sink`] so limits and path rules are enforced in one place.

use std::io::Read;

use crate::{Child, ContainerKind, EntryKind, Expanded, Limits, Script};

/// Expansion below this size never trips the ratio guard, so tiny but highly
/// compressible inputs (empty files, small text) still expand.
pub(crate) const RATIO_FLOOR: u64 = 1 << 20;

/// Normalize an archive path. Returns the safe relative path (possibly empty,
/// meaning "the root") and, if the raw path tried to escape, a description.
/// Both `/` and `\` separate components so Windows-style traversal is caught.
/// `..` components are kept as `__` so the entry stays inspectable but can
/// never resolve outside the root.
pub(crate) fn normalize_path(raw: &str) -> (String, Option<String>) {
    let mut issue = None;
    let mut out: Vec<String> = Vec::new();
    let trimmed = raw.trim_start_matches(['/', '\\']);
    if trimmed.len() != raw.len() {
        issue = Some(format!("absolute path {raw:?} made relative"));
    }
    for (i, comp) in trimmed.split(['/', '\\']).enumerate() {
        match comp {
            "" | "." => {}
            ".." => {
                issue = Some(format!("path traversal in {raw:?}; `..` renamed to `__`"));
                out.push("__".into());
            }
            c if i == 0 && c.len() == 2 && c.ends_with(':') => {
                issue = Some(format!("drive-qualified path {raw:?} made relative"));
            }
            c => out.push(c.replace('\0', "\u{fffd}")),
        }
    }
    (out.join("/"), issue)
}

/// True if a link at `link_path` pointing to `target` resolves outside the
/// container root (absolute targets always do).
pub(crate) fn link_escapes(link_path: &str, target: &str) -> bool {
    if target.starts_with('/') || target.starts_with('\\') {
        return true;
    }
    let mut depth: i64 = link_path.split('/').filter(|c| !c.is_empty()).count() as i64 - 1;
    for comp in target.split(['/', '\\']) {
        match comp {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// Collects children for one [`Expanded`] while enforcing [`Limits`].
pub(crate) struct Sink<'a> {
    pub(crate) out: Expanded,
    pub(crate) limits: &'a Limits,
    total: u64,
    total_cap: u64,
}

impl<'a> Sink<'a> {
    /// `input_len` is the size of the container being expanded; it sets the
    /// aggregate ratio cap.
    pub(crate) fn new(kind: ContainerKind, limits: &'a Limits, input_len: usize) -> Self {
        let ratio_cap = (input_len as u64)
            .saturating_mul(limits.max_ratio)
            .max(RATIO_FLOOR);
        Self {
            out: Expanded::new(kind),
            limits,
            total: 0,
            total_cap: limits.max_total_bytes.min(ratio_cap),
        }
    }

    pub(crate) fn problem(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.out.problems.len() < 1000 && !self.out.problems.contains(&msg) {
            self.out.problems.push(msg);
        }
    }

    pub(crate) fn meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.out.metadata.push((key.into(), value.into()));
    }

    pub(crate) fn script(
        &mut self,
        kind: &str,
        interpreter: Option<String>,
        path: &str,
        text: String,
    ) {
        self.out.scripts.push(Script {
            kind: kind.into(),
            interpreter,
            path: path.into(),
            text,
        });
    }

    /// Record a regular file too large for memory; the caller extracts it
    /// separately with `extract_entry`. It does not count against budgets.
    pub(crate) fn oversized(&mut self, raw_path: &str, size: u64) {
        let (path, issue) = normalize_path(raw_path);
        if let Some(issue) = issue {
            self.problem(issue);
        }
        self.problem(format!(
            "{path:?} ({size} bytes) is larger than the in-memory limit; listed for separate extraction"
        ));
        self.out.oversized.push(crate::Oversized { path, size });
    }

    /// Record that a limit stopped expansion.
    pub(crate) fn truncate(&mut self, msg: impl Into<String>) {
        self.out.truncated = true;
        self.problem(msg);
    }

    /// True (and marks truncation) once the entry-count or byte budget is
    /// exhausted; callers check it before each entry and stop.
    pub(crate) fn full(&mut self) -> bool {
        if self.out.children.len() >= self.limits.max_entries {
            self.truncate(format!(
                "entry limit of {} reached",
                self.limits.max_entries
            ));
            true
        } else if self.total >= self.total_cap {
            self.truncate(format!(
                "total expansion limit ({} bytes) reached",
                self.total_cap
            ));
            true
        } else {
            false
        }
    }

    /// Bytes the next entry may expand to.
    pub(crate) fn entry_budget(&self) -> u64 {
        self.limits
            .max_entry_bytes
            .min(self.total_cap.saturating_sub(self.total))
    }

    /// Per-entry cap combining the entry budget with a ratio cap derived from
    /// the entry's compressed size.
    pub(crate) fn entry_cap(&self, compressed_len: u64) -> u64 {
        let ratio = compressed_len
            .saturating_mul(self.limits.max_ratio)
            .max(RATIO_FLOOR);
        self.entry_budget().min(ratio)
    }

    /// Add a child after normalizing its path and checking links. Returns
    /// false (and marks truncation) when a limit refuses the entry.
    pub(crate) fn push(
        &mut self,
        raw_path: &str,
        kind: EntryKind,
        mode: Option<u32>,
        data: Vec<u8>,
    ) -> bool {
        if self.out.children.len() >= self.limits.max_entries {
            self.truncate(format!(
                "entry limit of {} reached",
                self.limits.max_entries
            ));
            return false;
        }
        let (path, issue) = normalize_path(raw_path);
        if let Some(issue) = issue {
            self.problem(issue);
        }
        if path.is_empty() {
            if !matches!(kind, EntryKind::Directory) {
                self.problem(format!("entry with empty path {raw_path:?} skipped"));
            }
            return true;
        }
        let kind = match kind {
            EntryKind::Symlink { target } => {
                if link_escapes(&path, &target) {
                    self.problem(format!(
                        "symlink {path:?} -> {target:?} escapes the archive root"
                    ));
                }
                EntryKind::Symlink { target }
            }
            EntryKind::Hardlink { target } => {
                let (norm, issue) = normalize_path(&target);
                if issue.is_some() {
                    self.problem(format!(
                        "hardlink {path:?} -> {target:?} escapes the archive root"
                    ));
                }
                EntryKind::Hardlink { target: norm }
            }
            EntryKind::Special(what) => {
                self.problem(format!(
                    "special file {path:?} ({what}) recorded, not extracted"
                ));
                EntryKind::Special(what)
            }
            k => k,
        };
        let data = if matches!(kind, EntryKind::File) {
            data
        } else {
            Vec::new()
        };
        let len = data.len() as u64;
        if self.total.saturating_add(len) > self.total_cap {
            self.truncate(format!(
                "total expansion limit ({} bytes) reached at {path:?}",
                self.total_cap
            ));
            return false;
        }
        self.total += len;
        self.out.children.push(Child {
            path,
            kind,
            mode,
            data,
        });
        true
    }

    pub(crate) fn finish(self) -> Expanded {
        self.out
    }
}

/// Outcome of a bounded read.
pub(crate) struct Bounded {
    pub(crate) data: Vec<u8>,
    /// The cap was hit; `data` holds exactly `cap` bytes.
    pub(crate) capped: bool,
    /// The reader failed (corrupt or truncated stream); `data` is partial.
    pub(crate) error: Option<String>,
}

/// Read at most `cap` bytes from `r`, never panicking or over-allocating.
pub(crate) fn read_bounded<R: Read>(r: R, cap: u64) -> Bounded {
    let mut data = Vec::new();
    let mut take = r.take(cap.saturating_add(1));
    let mut buf = vec![0u8; 64 * 1024];
    let mut error = None;
    loop {
        match take.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    let capped = data.len() as u64 > cap;
    if capped {
        data.truncate(cap as usize);
    }
    Bounded {
        data,
        capped,
        error,
    }
}

/// Bounds-checked slice access.
pub(crate) fn slice(b: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(len)?)
}

pub(crate) fn u16le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(slice(b, off, 2)?.try_into().ok()?))
}
pub(crate) fn u32le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(slice(b, off, 4)?.try_into().ok()?))
}
pub(crate) fn u64le(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(slice(b, off, 8)?.try_into().ok()?))
}
pub(crate) fn u16be(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(slice(b, off, 2)?.try_into().ok()?))
}
pub(crate) fn u32be(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(slice(b, off, 4)?.try_into().ok()?))
}
pub(crate) fn u64be(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_be_bytes(slice(b, off, 8)?.try_into().ok()?))
}

/// Lossy UTF-8 text of `b`, trimmed of trailing NULs.
pub(crate) fn text(b: &[u8]) -> String {
    let end = b.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The interpreter named by a `#!` line, if any.
pub(crate) fn shebang(text: &str) -> Option<String> {
    let line = text.strip_prefix("#!")?.lines().next()?.trim();
    (!line.is_empty()).then(|| line.to_owned())
}

const XML_NODES_LIMIT: u32 = 2_000_000;
/// roxmltree parses recursively and overflows a 2 MiB stack somewhere past
/// ~120 levels, so deeper documents are rejected before parsing.
const MAX_XML_DEPTH: usize = 96;

/// Parse untrusted XML: a node budget, a nesting-depth check done first so
/// hostile nesting cannot overflow the stack, and DTDs only when they are a
/// bare external reference (plists carry one) with no internal subset that
/// could declare entities. Every module that parses XML should use this.
pub(crate) fn xml(text: &str) -> Result<roxmltree::Document<'_>, String> {
    if xml_depth(text.as_bytes()) > MAX_XML_DEPTH {
        return Err(format!("XML nesting deeper than {MAX_XML_DEPTH} levels"));
    }
    let allow_dtd = text.find("<!DOCTYPE").is_some_and(|i| {
        let decl = &text[i..];
        decl.find('>').is_some_and(|end| !decl[..end].contains('['))
    });
    let opt = roxmltree::ParsingOptions {
        allow_dtd,
        nodes_limit: XML_NODES_LIMIT,
        ..Default::default()
    };
    roxmltree::Document::parse_with_options(text, opt).map_err(|e| e.to_string())
}

/// Conservative element-nesting depth of `b` (skips comments, CDATA,
/// processing instructions, declarations and quoted attribute values).
pub(crate) fn xml_depth(b: &[u8]) -> usize {
    let find = |from: usize, pat: &[u8]| {
        b.get(from..)
            .and_then(|rest| rest.windows(pat.len()).position(|w| w == pat))
            .map_or(b.len(), |p| from + p + pat.len())
    };
    let (mut i, mut depth, mut max) = (0usize, 0usize, 0usize);
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &b[i..];
        if rest.starts_with(b"<!--") {
            i = find(i + 4, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = find(i + 9, b"]]>");
        } else if rest.starts_with(b"<?") {
            i = find(i + 2, b"?>");
        } else if rest.starts_with(b"<!") {
            i = find(i + 2, b">");
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = find(i + 2, b">");
        } else {
            let mut j = i + 1;
            let mut quote = None;
            while j < b.len() {
                match (quote, b[j]) {
                    (None, q @ (b'"' | b'\'')) => quote = Some(q),
                    (Some(q), c) if c == q => quote = None,
                    (None, b'>') => break,
                    _ => {}
                }
                j += 1;
            }
            if b.get(j.wrapping_sub(1)) != Some(&b'/') {
                depth += 1;
                max = max.max(depth);
            }
            i = j + 1;
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize_path("./a//b/./c"), ("a/b/c".into(), None));
        let (p, issue) = normalize_path("../../etc/passwd");
        assert_eq!(p, "__/__/etc/passwd");
        assert!(issue.is_some());
        let (p, issue) = normalize_path("/etc/shadow");
        assert_eq!(p, "etc/shadow");
        assert!(issue.is_some());
        let (p, issue) = normalize_path("C:\\Windows\\..\\x");
        assert_eq!(p, "Windows/__/x");
        assert!(issue.is_some());
    }

    #[test]
    fn detects_link_escape() {
        assert!(link_escapes("a/link", "/etc/passwd"));
        assert!(link_escapes("a/link", "../../x"));
        assert!(!link_escapes("a/link", "../b"));
        assert!(!link_escapes("a/b/link", "../../c"));
        assert!(link_escapes("link", ".."));
    }

    #[test]
    fn bounded_read_caps() {
        let b = read_bounded(&[1u8; 100][..], 10);
        assert!(b.capped);
        assert_eq!(b.data.len(), 10);
        let b = read_bounded(&[1u8; 10][..], 10);
        assert!(!b.capped);
    }
}

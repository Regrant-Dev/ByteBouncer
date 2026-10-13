//! The model's tool surface. It is fixed by construction:
//!
//! * three built-in **read-only** tools over the immutable synthesis input
//!   (`list_evidence`, `get_evidence`, `list_findings`);
//! * the read-only tools an [`EvidenceSource`] exposes (`&self` only);
//! * `submit_findings`, which the broker intercepts and validates.
//!
//! Nothing else can be dispatched. There is no tool that writes, executes,
//! fetches URLs, or changes configuration; an unknown tool name or bad
//! arguments produce an error *result* for the model, never a crash.
//! Every result is size-bounded and wrapped in a labelled data block.

use std::collections::{BTreeMap, HashSet};

use bytebouncer_core::{Evidence, EvidenceKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::synth::SynthesisInput;

/// A tool offered to the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the arguments object.
    pub parameters: Value,
}

/// Additional read-only investigation tools, implemented by the CLI over the
/// report and retained analysis data. Implementations must be side-effect
/// free: `call` takes `&self`, and results are treated as untrusted data.
pub trait EvidenceSource {
    fn tools(&self) -> Vec<ToolSpec>;
    fn call(&self, name: &str, args: &Value) -> Result<Value, String>;
    /// Evidence created by tool calls since the last drain (e.g. a decompiled
    /// function the model fetched). Its IDs become citable in findings.
    /// Sources must assign IDs that cannot collide with the report's.
    fn drain_new_evidence(&self) -> Vec<bytebouncer_core::Evidence> {
        Vec::new()
    }
}

/// An [`EvidenceSource`] with no extra tools.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoExtraTools;

impl EvidenceSource for NoExtraTools {
    fn tools(&self) -> Vec<ToolSpec> {
        Vec::new()
    }
    fn call(&self, name: &str, _args: &Value) -> Result<Value, String> {
        Err(format!("no such tool: {name}"))
    }
}

pub const LIST_EVIDENCE: &str = "list_evidence";
pub const GET_EVIDENCE: &str = "get_evidence";
pub const LIST_FINDINGS: &str = "list_findings";
pub const SUBMIT_FINDINGS: &str = "submit_findings";
pub const BUILTIN_TOOLS: [&str; 3] = [LIST_EVIDENCE, GET_EVIDENCE, LIST_FINDINGS];

const DEFAULT_PAGE: u64 = 20;
const MAX_PAGE: u64 = 50;
const LIST_SNIPPET_CHARS: usize = 160;
const DATA_OPEN: &str = "<<<BYTEBOUNCER_DATA";
const DATA_CLOSE: &str = "<<<END_BYTEBOUNCER_DATA>>>";

/// Wrap untrusted text in a labelled data block. Any run of three or more
/// `<` or `>` inside `body` is broken up with a backslash, so sample text can
/// never forge the opening or closing delimiter.
pub(crate) fn data_block(label: &str, body: &str) -> String {
    format!(
        "{DATA_OPEN} {label}>>>\n{}\n{DATA_CLOSE}",
        escape_delimiters(body)
    )
}

pub(crate) fn escape_delimiters(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = '\0';
    let mut run = 0usize;
    for c in text.chars() {
        if (c == '<' || c == '>') && c == last {
            run += 1;
        } else {
            run = usize::from(c == '<' || c == '>');
        }
        if run == 3 {
            out.push('\\');
            run = 1;
        }
        out.push(c);
        last = c;
    }
    out
}

/// Truncate on a char boundary; returns the text and how many bytes were cut.
pub(crate) fn truncate_bytes(text: &str, max: usize) -> (&str, usize) {
    if text.len() <= max {
        return (text, 0);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], text.len() - end)
}

fn short(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_owned()
    } else {
        let mut s: String = text.chars().take(max_chars).collect();
        s.push('…');
        s
    }
}

pub(crate) fn kind_name(kind: EvidenceKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn obj_schema(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required, "additionalProperties": false})
}

pub(crate) fn builtin_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: LIST_EVIDENCE.into(),
            description: "List evidence items (paged). Snippets are shortened; use get_evidence for one item in full. Optional filters: kind (evidence kind) and artifact (sha256 or path).".into(),
            parameters: obj_schema(
                json!({
                    "kind": {"type": "string", "description": "e.g. string_reference, import, call_path"},
                    "artifact": {"type": "string", "description": "artifact sha256 or path"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE}
                }),
                &[],
            ),
        },
        ToolSpec {
            name: GET_EVIDENCE.into(),
            description: "Get one evidence item by ID, including its full bounded snippet.".into(),
            parameters: obj_schema(json!({"id": {"type": "string"}}), &["id"]),
        },
        ToolSpec {
            name: LIST_FINDINGS.into(),
            description: "List existing findings (read-only; they cannot be changed). Paged.".into(),
            parameters: obj_schema(
                json!({
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE}
                }),
                &[],
            ),
        },
    ]
}

pub(crate) fn submit_spec() -> ToolSpec {
    let finding = json!({
        "type": "object",
        "properties": {
            "category": {"type": "string"},
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            "evidence_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "claimed_strength": {"type": "string", "enum": ["pattern_match", "static_reference", "static_reachability", "static_dataflow", "runtime_observed"]},
            "data_types": {"type": "array", "items": {"type": "string"}},
            "recipient_domain": {"type": ["string", "null"]},
            "conditions": {"type": "array", "items": {"type": "string"}},
            "possible_legitimate_purpose": {"type": ["string", "null"]},
            "limitations": {"type": "array", "items": {"type": "string"}},
            "explanation": {"type": "string"}
        },
        "required": ["category", "title", "severity", "evidence_ids", "claimed_strength", "data_types", "conditions", "limitations", "explanation"]
    });
    ToolSpec {
        name: SUBMIT_FINDINGS.into(),
        description: "Submit your final answer: a plain-language summary and any NEW findings, each citing existing evidence IDs. Call exactly once, at the end.".into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "findings": {"type": "array", "items": finding}
            },
            "required": ["summary", "findings"]
        }),
    }
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The dispatch table for one synthesis session.
pub(crate) struct Toolbox<'a> {
    input: &'a SynthesisInput<'a>,
    source: &'a dyn EvidenceSource,
    source_names: HashSet<String>,
    /// Investigation tools (built-in + source), excluding `submit_findings`.
    pub specs: Vec<ToolSpec>,
    pub limitations: Vec<String>,
    max_result_bytes: usize,
}

impl<'a> Toolbox<'a> {
    pub(crate) fn new(
        input: &'a SynthesisInput<'a>,
        source: &'a dyn EvidenceSource,
        max_result_bytes: usize,
    ) -> Self {
        let mut specs = builtin_specs();
        let mut source_names = HashSet::new();
        let mut limitations = Vec::new();
        for spec in source.tools() {
            let reserved =
                BUILTIN_TOOLS.contains(&spec.name.as_str()) || spec.name == SUBMIT_FINDINGS;
            if !valid_tool_name(&spec.name) || reserved || !source_names.insert(spec.name.clone()) {
                limitations.push(format!(
                    "evidence-source tool '{}' was not offered (invalid or reserved name)",
                    short(&spec.name, 64)
                ));
                continue;
            }
            specs.push(spec);
        }
        Self {
            input,
            source,
            source_names,
            specs,
            limitations,
            max_result_bytes,
        }
    }

    /// Run one tool call and return the bounded, wrapped tool-message text.
    pub(crate) fn drain_new_evidence(&self) -> Vec<bytebouncer_core::Evidence> {
        self.source.drain_new_evidence()
    }

    pub(crate) fn dispatch(&self, name: &str, raw_args: &str) -> String {
        let args = if raw_args.trim().is_empty() {
            Ok(json!({}))
        } else {
            serde_json::from_str::<Value>(raw_args)
                .map_err(|e| format!("arguments are not valid JSON: {e}"))
                .and_then(|v| {
                    if v.is_object() {
                        Ok(v)
                    } else {
                        Err("arguments must be a JSON object".into())
                    }
                })
        };
        let result = args.and_then(|args| self.call(name, &args));
        match result {
            Ok(value) => {
                let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                self.bounded_block("tool_result", &text)
            }
            Err(e) => self.bounded_block("tool_error", &format!("ERROR: {e}")),
        }
    }

    fn bounded_block(&self, label: &str, text: &str) -> String {
        let (kept, cut) = truncate_bytes(text, self.max_result_bytes);
        let mut out = data_block(label, kept);
        if cut > 0 {
            out.push_str(&format!(
                "\n[ByteBouncer: result truncated, {cut} bytes omitted; use offset/limit or get_evidence to narrow]"
            ));
        }
        out
    }

    fn call(&self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            LIST_EVIDENCE => self.list_evidence(args),
            GET_EVIDENCE => self.get_evidence(args),
            LIST_FINDINGS => self.list_findings(args),
            n if self.source_names.contains(n) => self.source.call(n, args),
            other => Err(format!(
                "unknown tool '{}'. Available tools: {}, {SUBMIT_FINDINGS}",
                short(other, 64),
                self.specs
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    fn list_evidence(&self, args: &Value) -> Result<Value, String> {
        let (offset, limit) = paging(args)?;
        let kind = match args.get("kind") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                serde_json::from_value::<EvidenceKind>(v.clone())
                    .map_err(|_| format!("unknown evidence kind {v}"))?,
            ),
        };
        let artifact = opt_str(args, "artifact")?;
        let matching: Vec<&Evidence> = self
            .input
            .evidence
            .iter()
            .filter(|e| kind.is_none_or(|k| e.kind == k))
            .filter(|e| artifact.is_none_or(|a| e.artifact_sha256 == a || e.artifact_path == a))
            .collect();
        let items: Vec<Value> = matching
            .iter()
            .skip(offset)
            .take(limit)
            .map(|e| {
                json!({
                    "id": e.id,
                    "kind": e.kind,
                    "artifact_path": e.artifact_path,
                    "artifact_sha256": e.artifact_sha256,
                    "location": e.location,
                    "snippet": e.snippet.as_deref().map(|s| short(s, LIST_SNIPPET_CHARS)),
                    "producer": e.producer.tool,
                })
            })
            .collect();
        Ok(
            json!({"total": matching.len(), "offset": offset, "returned": items.len(), "items": items}),
        )
    }

    fn get_evidence(&self, args: &Value) -> Result<Value, String> {
        let id = opt_str(args, "id")?.ok_or("missing required argument 'id'")?;
        let ev = self
            .input
            .evidence
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| format!("no evidence with id '{}'", short(id, 64)))?;
        serde_json::to_value(ev).map_err(|e| e.to_string())
    }

    fn list_findings(&self, args: &Value) -> Result<Value, String> {
        let (offset, limit) = paging(args)?;
        let items: Vec<Value> = self
            .input
            .findings
            .iter()
            .skip(offset)
            .take(limit)
            .map(|f| {
                json!({
                    "id": f.id,
                    "category": f.category,
                    "title": f.title,
                    "severity": f.severity,
                    "evidence_strength": f.evidence_strength,
                    "artifact_sha256": f.artifact_sha256,
                    "evidence_ids": f.evidence_ids,
                })
            })
            .collect();
        Ok(
            json!({"total": self.input.findings.len(), "offset": offset, "returned": items.len(), "items": items}),
        )
    }
}

fn opt_str<'v>(args: &'v Value, key: &str) -> Result<Option<&'v str>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("argument '{key}' must be a string")),
    }
}

fn opt_u64(args: &Value, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("argument '{key}' must be a non-negative integer")),
    }
}

fn paging(args: &Value) -> Result<(usize, usize), String> {
    let offset = opt_u64(args, "offset")?.unwrap_or(0);
    let limit = opt_u64(args, "limit")?
        .unwrap_or(DEFAULT_PAGE)
        .clamp(1, MAX_PAGE);
    Ok((
        usize::try_from(offset).unwrap_or(usize::MAX),
        usize::try_from(limit).unwrap_or(1),
    ))
}

/// Compact digest of the input: artifact list, finding titles, evidence
/// counts by kind. Sample-derived text is wrapped in a data block.
pub(crate) fn digest(input: &SynthesisInput<'_>, max_bytes: usize) -> String {
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_artifact: BTreeMap<&str, usize> = BTreeMap::new();
    for e in input.evidence {
        *by_kind.entry(kind_name(e.kind)).or_default() += 1;
        *by_artifact.entry(e.artifact_sha256.as_str()).or_default() += 1;
    }
    let artifacts: Vec<Value> = input
        .artifacts
        .iter()
        .take(50)
        .map(|a| {
            json!({
                "path": a.path,
                "sha256": a.sha256,
                "format": a.format,
                "size": a.size,
                "evidence_items": by_artifact.get(a.sha256.as_str()).copied().unwrap_or(0),
            })
        })
        .collect();
    let findings: Vec<Value> = input
        .findings
        .iter()
        .take(100)
        .map(|f| json!({"id": f.id, "category": f.category, "severity": f.severity, "title": short(&f.title, 120)}))
        .collect();
    let cov = input.coverage;
    let digest = json!({
        "artifacts_total": input.artifacts.len(),
        "artifacts": artifacts,
        "existing_findings_total": input.findings.len(),
        "existing_findings": findings,
        "evidence_total": input.evidence.len(),
        "evidence_by_kind": by_kind,
        "coverage": {
            "analyzed": cov.analyzed.len(),
            "skipped": cov.skipped.len(),
            "unsupported": cov.unsupported.len(),
            "limitations": cov.limitations.iter().take(20).map(|l| short(l, 200)).collect::<Vec<_>>(),
        },
    });
    let text = serde_json::to_string_pretty(&digest).unwrap_or_default();
    let (kept, cut) = truncate_bytes(&text, max_bytes);
    let mut out = data_block("scan_digest", kept);
    if cut > 0 {
        out.push_str(&format!(
            "\n[ByteBouncer: digest truncated, {cut} bytes omitted; use list_findings/list_evidence]"
        ));
    }
    out
}

/// Bounded evidence listing for structured (no-tools) mode. Returns the
/// block and how many items were included.
pub(crate) fn evidence_digest(input: &SynthesisInput<'_>, max_bytes: usize) -> (String, usize) {
    let mut lines = String::new();
    let mut included = 0;
    for e in input.evidence {
        let line = json!({
            "id": e.id,
            "kind": e.kind,
            "artifact_path": short(&e.artifact_path, 120),
            "artifact_sha256": e.artifact_sha256,
            "snippet": e.snippet.as_deref().map(|s| short(s, LIST_SNIPPET_CHARS)),
        })
        .to_string();
        if lines.len() + line.len() + 1 > max_bytes {
            break;
        }
        lines.push_str(&line);
        lines.push('\n');
        included += 1;
    }
    (data_block("evidence_items", lines.trim_end()), included)
}

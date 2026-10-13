//! Built-in, zero-setup code map (Tier 1): linear-sweep disassembly of x86 /
//! x86-64 PE, ELF and Mach-O executables, import resolution at call sites,
//! string references, a direct call graph with reachability from entry
//! points, API classification, and a bounded, serializable [`CodeMap`] that a
//! model can query through [`tools`].
//!
//! Everything here is pure computation over borrowed bytes: no threads, no
//! filesystem, no clock. All work is bounded; truncation is reported.
#![forbid(unsafe_code)]

mod apis;
mod asm;
mod findings;
mod graph;
mod image;
mod sweep;
mod text;
pub mod tools;

use std::collections::HashSet;

use bytebouncer_core::Coverage;
use serde::{Deserialize, Serialize};

use crate::Builder;
use graph::Analysis;
use image::{Load, RootKind};
pub(crate) use sweep::SweepLimits;

/// Functions retained in a [`CodeMap`].
const MAX_RETAINED: usize = 1500;
/// Retained functions including ancestors on paths from entry points.
const MAX_RETAINED_WITH_PATHS: usize = 2000;
/// Functions whose disassembly text is stored.
const MAX_ASM_FUNCTIONS: usize = 40;
/// Characters of disassembly text stored per function.
const MAX_ASM_CHARS: usize = 4096;
const MAX_FUNCTION_APIS: usize = 32;
const MAX_FUNCTION_STRINGS: usize = 16;
const MAX_FUNCTION_EDGES: usize = 32;
const MAX_PATH: usize = 16;
const MAX_API_CALLERS: usize = 32;
const MAX_APIS: usize = 2000;
/// Serialized size cap for all code maps of one input.
pub const MAX_CODE_MAP_BYTES: usize = 4 << 20;
/// Serialized size cap for one code map.
const MAX_SINGLE_MAP_BYTES: usize = 3 << 20;

/// Static code map of one executable artifact, retained for model tools.
/// Derived from an untrusted sample: data, never instructions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeMap {
    pub artifact_path: String,
    pub sha256: String,
    pub format: String,
    pub arch: String,
    #[serde(default)]
    pub entry_points: Vec<CodeRoot>,
    #[serde(default)]
    pub stats: CodeStats,
    /// Most relevant functions (by API category and referenced strings), plus
    /// the functions on their paths from entry points.
    #[serde(default)]
    pub functions: Vec<CodeFunction>,
    /// Resolved APIs (imports, named library functions, string-named APIs).
    #[serde(default)]
    pub apis: Vec<CodeApi>,
    /// What the map cannot show and which bounds were hit.
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRoot {
    pub address: u64,
    pub kind: String,
    pub function: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeStats {
    pub instructions_decoded: u64,
    pub executable_bytes: u64,
    pub functions_discovered: u64,
    pub functions_reachable: u64,
    pub functions_retained: u64,
    pub call_edges: u64,
    pub import_call_sites: u64,
    pub strings_referenced: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFunction {
    pub address: u64,
    /// Symbol / export / Go name when known, else `sub_<hex>`.
    pub label: String,
    #[serde(default)]
    pub named: bool,
    pub size: u64,
    /// Reachable from an entry point, export, or initializer through direct
    /// calls, tail jumps, or taken function addresses.
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Ranking score (API categories, interesting strings, reachability).
    pub relevance: u32,
    /// Part of a language runtime / standard library (Go std, Rust std, libc internals).
    #[serde(default)]
    pub runtime: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apis: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<CodeString>,
    /// Direct callees as `name@0xaddr` / `sub_<hex>` (bounded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees: Vec<String>,
    pub callee_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<String>,
    pub caller_count: u32,
    /// Shortest discovered chain from an entry point (root first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_from_entry: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asm: Option<String>,
    #[serde(default)]
    pub asm_truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeString {
    pub address: u64,
    pub text: String,
    pub kind: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeApi {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub call_sites: u32,
    pub caller_count: u32,
    pub reachable_callers: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<String>,
    /// Named only by a string literal (resolved at runtime, e.g. GetProcAddress).
    #[serde(default)]
    pub dynamic: bool,
}

impl CodeMap {
    /// Serialized size in bytes.
    pub fn json_len(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |v| v.len())
    }

    /// Drop the least relevant data until the serialized map fits `max`.
    /// Returns false if even an empty function list does not fit.
    pub fn shrink_to(&mut self, max: usize) -> bool {
        let mut note = false;
        for _ in 0..64 {
            self.stats.functions_retained = self.functions.len() as u64;
            if self.json_len() <= max {
                if note {
                    self.limitations.push(format!(
                        "retained map reduced to {} functions to fit the {max}-byte size cap",
                        self.functions.len()
                    ));
                }
                return true;
            }
            note = true;
            self.stats.truncated = true;
            if self.functions.iter().any(|f| f.asm.is_some()) && self.functions.len() <= 64 {
                for f in &mut self.functions {
                    f.asm = None;
                }
                continue;
            }
            if self.functions.is_empty() {
                self.apis.truncate(self.apis.len() / 2);
                if self.apis.is_empty() {
                    return self.json_len() <= max;
                }
                continue;
            }
            // Functions are kept sorted by relevance (descending): drop the tail.
            let keep = self.functions.len() * 3 / 4;
            self.functions.truncate(keep);
            self.apis.truncate(self.apis.len().max(4) * 3 / 4);
        }
        self.json_len() <= max
    }
}

/// Result of [`analyze`] for one artifact.
pub(crate) struct CodeResult {
    pub map: Option<CodeMap>,
}

/// Build the code map for an executable and add reachability-backed findings
/// to `b`. Non-executables return `None` without touching `coverage`.
pub(crate) fn analyze(
    b: &mut Builder,
    coverage: &mut Coverage,
    bytes: &[u8],
    limits: SweepLimits,
) -> CodeResult {
    let path = b.path.to_owned();
    let img = match image::load(bytes) {
        Load::Ok(img) => img,
        Load::Unsupported(why) => {
            coverage.unsupported.push(format!("{path}: {why}"));
            return CodeResult { map: None };
        }
        Load::NotExecutable => return CodeResult { map: None },
    };
    let arch = if img.bits == 64 { "x86-64" } else { "x86" };
    let ev = sweep::sweep(&img, limits);
    let a = Analysis::build(&img, ev);
    if a.instructions == 0 {
        coverage
            .limitations
            .push(format!("{path}: no executable code found for the code map"));
        return CodeResult { map: None };
    }
    findings::add(b, &a);

    let reachable = (0..a.len() as u32).filter(|f| a.reachable(*f)).count();
    coverage.analyzed.push(format!(
        "{path}: built-in code map ({arch} {}): {} instructions, {} functions ({} reachable from {} entry point(s)), {} import call sites, {} referenced strings",
        img.format,
        a.instructions,
        a.len(),
        reachable,
        a.roots.len(),
        a.api_call_sites,
        a.strings.len()
    ));
    let mut limitations = vec![
        "Linear-sweep disassembly: data in code sections can be misread and some functions may be missed".to_owned(),
        "Call graph uses direct calls, tail jumps and taken function addresses only; indirect/virtual calls and callbacks registered at runtime are not followed".to_owned(),
        "APIs resolved at runtime (GetProcAddress/dlsym, syscalls, COM, JNI) are invisible unless named by a string literal".to_owned(),
        "No data-flow tracking: co-occurrence in a call chain does not show which data is sent".to_owned(),
    ];
    if img.is_go {
        limitations.push("Go binary: interface and closure calls are indirect and not followed; Go strings are recovered from length immediates where possible".into());
    }
    limitations.extend(img.notes.iter().cloned());
    limitations.extend(a.truncated.iter().cloned());
    for l in &a.truncated {
        coverage.limitations.push(format!("{path}: code map: {l}"));
    }
    if a.roots.is_empty() {
        coverage.limitations.push(format!(
            "{path}: code map: no entry point or export found; reachability not established"
        ));
    }
    coverage.limitations.push(format!("{path}: code map is static: direct calls only, no data flow; indirect calls and runtime-resolved APIs are not visible"));

    let mut map = build_map(&a, &path, b.sha256, arch, limitations);
    map.shrink_to(MAX_SINGLE_MAP_BYTES);
    CodeResult { map: Some(map) }
}

fn relevance(a: &Analysis, f: u32) -> u32 {
    let mut score: u32 = a.categories_of(f).iter().map(|c| apis::weight(c)).sum();
    let mut kinds: Vec<&str> = a
        .strings_of(f)
        .iter()
        .map(|(_, s)| a.strings[*s as usize].kind)
        .collect();
    kinds.sort_unstable();
    let mut per_kind = 0;
    for (i, k) in kinds.iter().enumerate() {
        per_kind = if i > 0 && kinds[i - 1] == *k {
            per_kind + 1
        } else {
            0
        };
        if per_kind < 3 {
            score += text::weight(k);
        }
    }
    if a.is_runtime(f) {
        score /= 4;
    }
    if score > 0 && a.reachable(f) {
        score += 3;
    }
    score
}

fn build_map(
    a: &Analysis,
    path: &str,
    sha256: &str,
    arch: &str,
    limitations: Vec<String>,
) -> CodeMap {
    let n = a.len() as u32;
    let scores: Vec<u32> = (0..n)
        .map(|f| if a.is_thunk(f) { 0 } else { relevance(a, f) })
        .collect();
    let mut ranked: Vec<u32> = (0..n).filter(|f| scores[*f as usize] > 0).collect();
    ranked.sort_by(|x, y| scores[*y as usize].cmp(&scores[*x as usize]).then(x.cmp(y)));
    ranked.truncate(MAX_RETAINED);

    let mut keep: Vec<u32> = ranked.clone();
    let mut kept: HashSet<u32> = keep.iter().copied().collect();
    for (r, _) in a
        .roots
        .iter()
        .filter(|(_, k)| matches!(k, RootKind::Entry | RootKind::Main))
        .chain(a.roots.iter().take(32))
    {
        if kept.insert(*r) {
            keep.push(*r);
        }
    }
    'paths: for f in ranked.iter().take(300) {
        for g in a.path_from_root(*f) {
            if keep.len() >= MAX_RETAINED_WITH_PATHS {
                break 'paths;
            }
            if kept.insert(g) {
                keep.push(g);
            }
        }
    }
    // Sorted by relevance so `shrink_to` drops the least relevant first.
    keep.sort_by(|x, y| scores[*y as usize].cmp(&scores[*x as usize]).then(x.cmp(y)));

    let cx = asm::AsmContext::new(a);
    let root_kind = |f: u32| {
        a.roots
            .iter()
            .find(|r| r.0 == f)
            .map(|r| r.1.as_str().to_owned())
    };
    let mut asm_budget = MAX_ASM_FUNCTIONS;
    let functions: Vec<CodeFunction> = keep
        .iter()
        .map(|&f| {
            let mut apis: Vec<String> = a
                .apis_of(f)
                .iter()
                .map(|(_, x)| a.apis[*x as usize].name.clone())
                .collect();
            apis.sort();
            apis.dedup();
            apis.truncate(MAX_FUNCTION_APIS);
            let mut strs: Vec<&sweep::RefString> = a
                .strings_of(f)
                .iter()
                .map(|(_, s)| &a.strings[*s as usize])
                .collect();
            strs.sort_by_key(|s| std::cmp::Reverse(text::weight(s.kind)));
            let strings = strs
                .iter()
                .take(MAX_FUNCTION_STRINGS)
                .map(|s| CodeString {
                    address: s.address,
                    text: s.text.clone(),
                    kind: s.kind.to_owned(),
                    truncated: s.truncated,
                })
                .collect();
            let out = a.fwd.of(f);
            let mut callees: Vec<u32> = out.iter().map(|e| e.0).collect();
            callees.sort_by_key(|c| (!kept.contains(c), a.names[*c as usize].is_none(), *c));
            callees.dedup();
            let incoming = a.rev.of(f);
            let mut callers: Vec<u32> = incoming.iter().map(|e| e.0).collect();
            callers.sort_by_key(|c| (!a.reachable(*c), !kept.contains(c), *c));
            callers.dedup();
            let path_from_entry = if a.reachable(f) {
                let p = a.path_from_root(f);
                let mut labels: Vec<String> = p.iter().map(|g| a.reference(*g)).collect();
                if labels.len() > MAX_PATH {
                    let tail = labels.split_off(labels.len() - (MAX_PATH - 3));
                    labels.truncate(2);
                    labels.push("…".into());
                    labels.extend(tail);
                }
                labels
            } else {
                vec![]
            };
            let (asm, asm_truncated) =
                if asm_budget > 0 && scores[f as usize] > 0 && a.sizes[f as usize] > 0 {
                    asm_budget -= 1;
                    let (t, cut) = asm::function_text(a, &cx, f, MAX_ASM_CHARS);
                    (Some(t), cut)
                } else {
                    (None, false)
                };
            CodeFunction {
                address: a.starts[f as usize],
                label: a.label(f),
                named: a.names[f as usize].is_some(),
                size: a.sizes[f as usize],
                reachable: a.reachable(f),
                root: root_kind(f),
                relevance: scores[f as usize],
                runtime: a.is_runtime(f),
                categories: a.categories_of(f).iter().map(|c| (*c).to_owned()).collect(),
                apis,
                strings,
                callee_count: callees.len() as u32,
                callees: callees
                    .iter()
                    .take(MAX_FUNCTION_EDGES)
                    .map(|c| a.reference(*c))
                    .collect(),
                caller_count: callers.len() as u32,
                callers: callers
                    .iter()
                    .take(MAX_FUNCTION_EDGES / 2)
                    .map(|c| a.reference(*c))
                    .collect(),
                path_from_entry,
                asm,
                asm_truncated,
            }
        })
        .collect();

    // API index.
    let mut callers_by_api: Vec<Vec<u32>> = vec![Vec::new(); a.apis.len()];
    for (f, api) in &a.func_apis {
        callers_by_api[*api as usize].push(*f);
    }
    let mut apis: Vec<CodeApi> = a
        .apis
        .iter()
        .enumerate()
        .filter(|(i, _)| !callers_by_api[*i].is_empty())
        .map(|(i, api)| {
            let mut callers = callers_by_api[i].clone();
            callers.sort_by_key(|c| (!a.reachable(*c), *c));
            CodeApi {
                name: api.name.clone(),
                category: api.category.map(str::to_owned),
                call_sites: api.call_sites,
                caller_count: callers.len() as u32,
                reachable_callers: callers.iter().filter(|c| a.reachable(**c)).count() as u32,
                callers: callers
                    .iter()
                    .take(MAX_API_CALLERS)
                    .map(|c| a.reference(*c))
                    .collect(),
                dynamic: api.dynamic,
            }
        })
        .collect();
    apis.sort_by(|x, y| {
        y.category
            .is_some()
            .cmp(&x.category.is_some())
            .then(y.reachable_callers.cmp(&x.reachable_callers))
            .then(x.name.cmp(&y.name))
    });
    let truncated_apis = apis.len() > MAX_APIS;
    apis.truncate(MAX_APIS);

    let mut roots = a.roots.clone();
    roots.sort_by_key(|(f, k)| (*k as u8, *f));
    let entry_points = roots
        .iter()
        .take(64)
        .map(|(f, k)| CodeRoot {
            address: a.starts[*f as usize],
            kind: k.as_str().to_owned(),
            function: a.reference(*f),
        })
        .collect();
    let reachable = (0..n).filter(|f| a.reachable(*f)).count() as u64;
    let mut limitations = limitations;
    if truncated_apis {
        limitations.push(format!("only {MAX_APIS} APIs retained"));
    }
    CodeMap {
        artifact_path: path.to_owned(),
        sha256: sha256.to_owned(),
        format: format!("{}-{}", a.img.format, a.img.bits),
        arch: arch.to_owned(),
        entry_points,
        stats: CodeStats {
            instructions_decoded: a.instructions,
            executable_bytes: a.exec_bytes,
            functions_discovered: n as u64,
            functions_reachable: reachable,
            functions_retained: functions.len() as u64,
            call_edges: a.edges as u64,
            import_call_sites: a.api_call_sites,
            strings_referenced: a.strings.len() as u64,
            truncated: !a.truncated.is_empty() || truncated_apis,
        },
        functions,
        apis,
        limitations,
    }
}

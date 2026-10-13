//! Inspection-only MCP server over stdio (SPEC §13, §15 Phase 5). Agents can
//! inspect and read reports. There is deliberately no install, approve,
//! shell, configuration, or sandbox-policy tool, and scans always use full
//! isolation, quick or deep mode, and no model or reputation lookups.

use std::io::{BufRead, Write};

use anyhow::Result;
use bytebouncer_core::ExitCode;
use serde_json::{Value, json};

use crate::config::Config;
use crate::inspect::{Progress, ScanContext};
use crate::{InspectArgs, Mode, compare, render, store};

const PROTOCOL_VERSION: &str = "2025-06-18";

fn tools() -> Value {
    json!([
        {
            "name": "inspect",
            "description": "Inspect a local file, directory, http(s) URL, or package request (e.g. \"pacman -S firefox\") without installing or running it. Returns a summary and the report ID. A lack of findings is not proof of safety.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Path, URL, or package request"},
                    "mode": {"type": "string", "enum": ["quick", "deep"], "default": "quick"},
                    "expect_sha256": {"type": "string", "description": "Publisher-supplied SHA-256 to verify"}
                },
                "required": ["target"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": true}
        },
        {
            "name": "get_report",
            "description": "Return a saved report as Markdown or JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Report ID or unique prefix (8+ characters)"},
                    "format": {"type": "string", "enum": ["markdown", "json"], "default": "markdown"}
                },
                "required": ["id"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "list_reports",
            "description": "List saved reports, newest first.",
            "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20}}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "compare_reports",
            "description": "Compare two saved reports (e.g. before and after an update).",
            "inputSchema": {
                "type": "object",
                "properties": {"old": {"type": "string"}, "new": {"type": "string"}},
                "required": ["old", "new"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true}
        }
    ])
}

fn text(s: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": s}], "isError": is_error})
}

fn call_tool(name: &str, args: &Value, config: &Config) -> Value {
    let str_arg = |k: &str| args.get(k).and_then(Value::as_str);
    match name {
        "inspect" => {
            let Some(target) = str_arg("target") else {
                return text("missing `target`".into(), true);
            };
            let mut a = InspectArgs::defaults_for(target);
            a.mode = if str_arg("mode") == Some("deep") {
                Mode::Deep
            } else {
                Mode::Quick
            };
            a.expect_sha256 = str_arg("expect_sha256").map(str::to_owned);
            let ctx = ScanContext {
                args: &a,
                config,
                cancel: Default::default(),
                progress: Progress::new(true),
            };
            match crate::inspect::scan_target(&ctx, target) {
                Ok(Some(report)) => {
                    let saved = store::save(&report).is_ok();
                    let mut md = render::markdown(&report);
                    if md.len() > 60_000 {
                        md.truncate(60_000);
                        md.push_str("\n…truncated; use get_report for the full report\n");
                    }
                    text(
                        format!(
                            "report_id: {}{}\n\n{md}",
                            report.scan_id,
                            if saved { "" } else { " (not saved)" }
                        ),
                        false,
                    )
                }
                Ok(None) => text("cancelled".into(), true),
                Err(e) => text(format!("inspection failed: {e:#}"), true),
            }
        }
        "get_report" => match str_arg("id").map(store::load) {
            Some(Ok(r)) if str_arg("format") == Some("json") => {
                text(serde_json::to_string_pretty(&r).unwrap_or_default(), false)
            }
            Some(Ok(r)) => text(render::markdown(&r), false),
            Some(Err(e)) => text(format!("{e:#}"), true),
            None => text("missing `id`".into(), true),
        },
        "list_reports" => {
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .clamp(1, 200) as usize;
            match store::list() {
                Ok(list) => text(
                    list.into_iter()
                        .take(limit)
                        .map(|(id, s)| format!("{id}  {s}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    false,
                ),
                Err(e) => text(format!("{e:#}"), true),
            }
        }
        "compare_reports" => match (
            str_arg("old").map(store::load),
            str_arg("new").map(store::load),
        ) {
            (Some(Ok(o)), Some(Ok(n))) => text(compare::compare(&o, &n), false),
            (Some(Err(e)), _) | (_, Some(Err(e))) => text(format!("{e:#}"), true),
            _ => text("missing `old` or `new`".into(), true),
        },
        other => text(format!("unknown tool `{other}`"), true),
    }
}

fn handle(msg: &Value, config: &Config) -> Option<Value> {
    let id = msg.get("id")?.clone(); // notifications get no response
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "bytebouncer", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "ByteBouncer inspects software without installing or running it. Results are evidence, not verdicts: a lack of findings is not proof of safety."
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            call_tool(name, &args, config)
        }
        _ => {
            return Some(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("method not found: {method}")}}),
            );
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

pub fn serve(config: &Config) -> Result<ExitCode> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg, config),
            Err(e) => Some(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}}),
            ),
        };
        if let Some(r) = response {
            writeln!(stdout, "{r}")?;
            stdout.flush()?;
        }
    }
    Ok(ExitCode::Ok)
}

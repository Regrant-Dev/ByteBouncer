//! Minimal MCP client over stdio for analysis servers (REA, or a connector
//! that runs one inside a VM). Line-delimited JSON-RPC 2.0; every request
//! has a deadline; the server process is killed when the client drops.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use bytebouncer_sandbox::{Applied, Child, Profile};
use serde_json::{Value, json};

/// Largest single message accepted from the server.
const MAX_LINE: usize = 32 << 20;
const PROTOCOL_VERSION: &str = "2025-06-18";

pub struct McpServer {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
    pub tools: Vec<Value>,
    pub server_name: String,
}

/// How to start the server.
pub struct Launch<'a> {
    pub program: &'a Path,
    pub args: &'a [String],
    pub env: Vec<(OsString, OsString)>,
    /// Confine with the Tier 2 sandbox; `None` runs the command as configured
    /// (for connectors that provide their own isolation, e.g. a VM).
    pub sandbox: Option<Profile>,
    pub allow_reduced: bool,
}

impl McpServer {
    pub fn start(
        launch: Launch,
        init_timeout: Duration,
    ) -> Result<(Self, Option<Applied>), String> {
        let configure = |c: &mut Command| {
            c.args(launch.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
        };
        let (mut child, applied) = match launch.sandbox {
            Some(mut profile) => {
                profile.env.extend(launch.env);
                let (child, applied) =
                    bytebouncer_sandbox::spawn(&profile, launch.program, configure, launch.allow_reduced)
                        .map_err(|e| e.to_string())?;
                (child, Some(applied))
            }
            #[cfg(unix)]
            None => {
                let mut cmd = Command::new(launch.program);
                configure(&mut cmd);
                cmd.envs(launch.env);
                let child = cmd.spawn().map_err(|e| format!("starting {}: {e}", launch.program.display()))?;
                (child, None)
            }
            #[cfg(not(unix))]
            None => return Err("running an analysis server without ByteBouncer's sandbox is only supported on Unix".into()),
        };
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match (&mut reader).take(MAX_LINE as u64).read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if tx.send(line.trim_end().to_owned()).is_err() => break,
                    Ok(_) => {}
                }
            }
        });
        let mut server = Self {
            child,
            stdin: Some(stdin),
            lines: rx,
            next_id: 0,
            tools: vec![],
            server_name: String::new(),
        };
        let init = server.request(
            "initialize",
            json!({"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "bytebouncer", "version": env!("CARGO_PKG_VERSION")}}),
            init_timeout,
        )?;
        server.server_name = init["serverInfo"]["name"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        server.notify("notifications/initialized")?;
        let list = server.request("tools/list", json!({}), init_timeout)?;
        server.tools = list["tools"].as_array().cloned().unwrap_or_default();
        Ok((server, applied))
    }

    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t["name"] == name)
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let stdin = self.stdin.as_mut().ok_or("server closed")?;
        stdin
            .write_all(&line)
            .and_then(|_| stdin.flush())
            .map_err(|e| format!("server closed: {e}"))
    }

    fn notify(&mut self, method: &str) -> Result<(), String> {
        self.send(&json!({"jsonrpc": "2.0", "method": method}))
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(left) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("{method} timed out after {}s", timeout.as_secs()));
                }
                Err(RecvTimeoutError::Disconnected) => return Err("analysis server exited".into()),
            };
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            // Server-to-client requests: answer pings, refuse everything else
            // (no sampling, roots, or elicitation is offered).
            if msg.get("method").is_some() {
                if let Some(rid) = msg.get("id").cloned() {
                    let reply = if msg["method"] == "ping" {
                        json!({"jsonrpc": "2.0", "id": rid, "result": {}})
                    } else {
                        json!({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not supported by bytebouncer"}})
                    };
                    self.send(&reply)?;
                }
                continue;
            }
            if msg.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = msg.get("error") {
                return Err(format!(
                    "{method}: {}",
                    err["message"].as_str().unwrap_or("error")
                ));
            }
            return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Call a tool. Returns the structured result (or parsed text content);
    /// tool-level errors (`isError`) become `Err` with the server's message.
    pub fn call_tool(
        &mut self,
        name: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let r = self.request(
            "tools/call",
            json!({"name": name, "arguments": args}),
            timeout,
        )?;
        let text = r["content"]
            .as_array()
            .and_then(|c| c.iter().find_map(|i| i["text"].as_str()))
            .unwrap_or_default()
            .to_owned();
        if r["isError"].as_bool() == Some(true) {
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| {
                    v["error"]["details"]["issues"][0]["message"]
                        .as_str()
                        .or(v["error"]["message"].as_str())
                        .map(str::to_owned)
                })
                .unwrap_or(text);
            return Err(msg.chars().take(500).collect());
        }
        Ok(match r.get("structuredContent") {
            Some(v) if !v.is_null() => v.clone(),
            _ => serde_json::from_str(&text).unwrap_or(Value::String(text)),
        })
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        // Closing stdin lets well-behaved servers (and VM connectors) tear
        // down cleanly; kill as a backstop.
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

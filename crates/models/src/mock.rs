//! Tiny scripted OpenAI-compatible server for offline tests.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn status(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.into(),
            headers: vec![],
        }
    }

    pub fn message(message: Value, usage: Option<u64>) -> Self {
        let mut v = json!({
            "id": "cmpl-test", "object": "chat.completion",
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        });
        if let Some(t) = usage {
            v["usage"] =
                json!({"prompt_tokens": t / 2, "completion_tokens": t - t / 2, "total_tokens": t});
        }
        Self::status(200, &v.to_string())
    }

    /// Assistant message with tool calls `(name, arguments-string)`.
    pub fn tools(calls: &[(&str, &str)]) -> Self {
        let calls: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(i, (n, a))| json!({"id": format!("call_{i}"), "type": "function", "function": {"name": n, "arguments": a}}))
            .collect();
        Self::message(
            json!({"role": "assistant", "content": null, "reasoning_content": "thinking…", "tool_calls": calls}),
            Some(100),
        )
    }

    pub fn submit(payload: Value) -> Self {
        Self::tools(&[("submit_findings", &payload.to_string())])
    }

    pub fn content(text: &str) -> Self {
        Self::message(json!({"role": "assistant", "content": text}), Some(100))
    }
}

pub struct MockServer {
    pub base_url: String,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    /// `chat[i]` answers the i-th POST /chat/completions; GET /models gets `models`.
    pub fn start(chat: Vec<Reply>, models: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&requests);
        thread::spawn(move || {
            let mut chat_count = 0usize;
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let Some(req) = read_request(&stream) else {
                    continue;
                };
                let reply = if req.path.ends_with("/models") {
                    models.clone()
                } else {
                    let r = chat.get(chat_count).cloned().unwrap_or_else(|| {
                        Reply::status(500, r#"{"error":{"message":"mock script exhausted"}}"#)
                    });
                    chat_count += 1;
                    r
                };
                rec.lock().unwrap().push(req);
                write_reply(stream, &reply);
            }
        });
        Self {
            base_url: format!("http://{addr}/v1"),
            requests,
        }
    }

    pub fn chat_requests(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.ends_with("/chat/completions"))
            .cloned()
            .collect()
    }
}

pub fn models_reply(ids: &[&str]) -> Reply {
    let data: Vec<Value> = ids
        .iter()
        .map(|id| json!({"id": id, "object": "model"}))
        .collect();
    Reply::status(200, &json!({"object": "list", "data": data}).to_string())
}

fn read_request(stream: &TcpStream) -> Option<Recorded> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    Some(Recorded {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_reply(mut stream: TcpStream, reply: &Reply) {
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (k, v) in &reply.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(reply.body.as_bytes());
    let _ = stream.flush();
}

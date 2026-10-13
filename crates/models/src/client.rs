//! Blocking OpenAI-compatible HTTP client with bounded retries and key
//! redaction. Only `GET /models` and `POST /chat/completions` are issued.

use std::fmt;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ModelError;
use crate::config::{ModelConfig, is_hosted};

/// Retries after the first attempt on 429/5xx/timeouts.
const MAX_RETRIES: u32 = 2;
const BACKOFF_BASE_MS: u64 = if cfg!(test) { 10 } else { 500 };
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ERROR_EXCERPT: usize = 300;
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// An API key. `Debug` never shows the value.
pub(crate) struct Secret(String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[derive(Debug)]
pub(crate) struct HttpResponse {
    pub status: u16,
    pub body: String,
    retry_after: Option<Duration>,
}

#[derive(Debug)]
pub(crate) struct Client {
    agent: ureq::Agent,
    base: String,
    key: Option<Secret>,
    timeout: Duration,
}

impl Client {
    pub(crate) fn new(
        cfg: &ModelConfig,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, ModelError> {
        cfg.validate()?;
        let key = match &cfg.api_key_env {
            Some(var) => match lookup(var) {
                Some(k) if !k.trim().is_empty() => Some(Secret(k.trim().to_owned())),
                _ => {
                    return Err(ModelError::MissingApiKey {
                        env_var: var.clone(),
                    });
                }
            },
            None => match &cfg.api_key_file {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(k) if !k.trim().is_empty() => Some(Secret(k.trim().to_owned())),
                    _ => {
                        return Err(ModelError::Config(format!(
                            "cannot read an API key from {}",
                            path.display()
                        )));
                    }
                },
                None => None,
            },
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // Never follow redirects: the Authorization header must only go to
            // the configured host.
            .max_redirects(0)
            .user_agent(concat!("bytebouncer-models/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            agent,
            base: cfg.base_url.trim_end_matches('/').to_owned(),
            key,
            timeout: Duration::from_secs(cfg.timeout_secs),
        })
    }

    /// Replace the API key (if any) in text that may echo it back.
    pub(crate) fn redact(&self, text: &str) -> String {
        match &self.key {
            Some(Secret(k)) if !k.is_empty() => text.replace(k.as_str(), "[redacted]"),
            _ => text.to_owned(),
        }
    }

    fn once(
        &self,
        path: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<HttpResponse, ModelError> {
        let url = format!("{}{path}", self.base);
        let auth = self.key.as_ref().map(|Secret(k)| format!("Bearer {k}"));
        let result = match body {
            Some(b) => {
                let mut req = self
                    .agent
                    .post(&url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build()
                    .header("Content-Type", "application/json");
                if let Some(a) = &auth {
                    req = req.header("Authorization", a);
                }
                req.send(b)
            }
            None => {
                let mut req = self
                    .agent
                    .get(&url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build();
                if let Some(a) = &auth {
                    req = req.header("Authorization", a);
                }
                req.call()
            }
        };
        let mut resp = result.map_err(|e| self.map_transport(e))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|s| Duration::from_secs(s).min(MAX_BACKOFF));
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| self.map_transport(e))?;
        Ok(HttpResponse {
            status,
            body,
            retry_after,
        })
    }

    fn map_transport(&self, e: ureq::Error) -> ModelError {
        match e {
            ureq::Error::Timeout(_) => ModelError::Timeout,
            ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => ModelError::Timeout,
            other => ModelError::Connect(self.redact(&other.to_string())),
        }
    }

    /// Issue a request, retrying 429/5xx/timeouts up to [`MAX_RETRIES`]
    /// times with backoff, never past `deadline`. Non-retryable statuses are
    /// returned as `Ok` for the caller to interpret.
    pub(crate) fn request(
        &self,
        path: &str,
        body: Option<&str>,
        deadline: Option<Instant>,
    ) -> Result<HttpResponse, ModelError> {
        let mut attempt = 0;
        loop {
            let timeout = match deadline {
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(ModelError::Timeout);
                    }
                    left.min(self.timeout)
                }
                None => self.timeout,
            };
            let result = self.once(path, body, timeout);
            let retry_wait = match &result {
                Ok(r) if r.status == 429 || r.status >= 500 => Some(r.retry_after),
                Err(ModelError::Timeout) => Some(None),
                _ => None,
            };
            let Some(hint) = retry_wait else {
                return result;
            };
            if attempt >= MAX_RETRIES {
                return result;
            }
            let wait = hint
                .unwrap_or_else(|| Duration::from_millis(BACKOFF_BASE_MS << attempt))
                .min(MAX_BACKOFF);
            if deadline.is_some_and(|d| Instant::now() + wait >= d) {
                return result;
            }
            thread::sleep(wait);
            attempt += 1;
        }
    }

    /// Convert a non-2xx response into a clear, redacted error.
    pub(crate) fn status_error(&self, resp: &HttpResponse) -> ModelError {
        match resp.status {
            401 | 403 => ModelError::Auth {
                status: resp.status,
            },
            status => ModelError::Http {
                status,
                message: self.error_excerpt(&resp.body),
            },
        }
    }

    pub(crate) fn error_excerpt(&self, body: &str) -> String {
        let msg = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| {
                v.pointer("/error/message")
                    .or_else(|| v.get("error"))
                    .or_else(|| v.get("message"))
                    .or_else(|| v.get("detail"))
                    .map(|m| match m {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
            })
            .unwrap_or_else(|| body.to_owned());
        let msg = self.redact(&msg);
        let mut end = msg.len().min(MAX_ERROR_EXCERPT);
        while !msg.is_char_boundary(end) {
            end -= 1;
        }
        msg[..end].chars().filter(|c| !c.is_control()).collect()
    }
}

/// Result of [`probe`]: `GET {base_url}/models`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// False when the endpoint could not be reached or timed out.
    pub reachable: bool,
    /// Whether the configured model ID is in the listing.
    pub model_listed: bool,
    /// Model IDs the endpoint lists (bounded).
    pub models: Vec<String>,
    /// An immutable revision/digest for the configured model, if exposed.
    pub revision: Option<String>,
    pub hosted: bool,
    /// Why the endpoint was unreachable, when it was.
    pub detail: Option<String>,
}

const MAX_LISTED_MODELS: usize = 100;
/// Fields that, when present on a `/models` entry, identify immutable weights.
const REVISION_FIELDS: &[&str] = &["revision", "digest", "sha256", "sha", "commit"];

/// Check that the endpoint is reachable and lists the configured model.
/// Connection failures and timeouts yield `Ok` with `reachable: false`;
/// configuration, credential, and protocol problems are errors.
pub fn probe(cfg: &ModelConfig) -> Result<ProbeResult, ModelError> {
    let client = Client::new(cfg, &|v| std::env::var(v).ok())?;
    probe_with(&client, cfg, None)
}

pub(crate) fn probe_with(
    client: &Client,
    cfg: &ModelConfig,
    deadline: Option<Instant>,
) -> Result<ProbeResult, ModelError> {
    let hosted = is_hosted(cfg);
    let deadline = Some(match deadline {
        Some(d) => d.min(Instant::now() + PROBE_TIMEOUT),
        None => Instant::now() + PROBE_TIMEOUT.max(client.timeout),
    });
    let resp = match client.request("/models", None, deadline) {
        Ok(r) => r,
        Err(e @ (ModelError::Connect(_) | ModelError::Timeout)) => {
            return Ok(ProbeResult {
                reachable: false,
                model_listed: false,
                models: vec![],
                revision: None,
                hosted,
                detail: Some(e.to_string()),
            });
        }
        Err(e) => return Err(e),
    };
    if !(200..300).contains(&resp.status) {
        return Err(client.status_error(&resp));
    }
    let v: Value = serde_json::from_str(&resp.body)
        .map_err(|_| ModelError::InvalidResponse("/models did not return JSON".into()))?;
    let entries = v
        .get("data")
        .or_else(|| v.get("models"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut models = Vec::new();
    let mut revision = None;
    let mut model_listed = false;
    for entry in &entries {
        let Some(id) = entry
            .get("id")
            .or_else(|| entry.get("name"))
            .or_else(|| entry.get("model"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if id == cfg.model {
            model_listed = true;
            revision = REVISION_FIELDS
                .iter()
                .filter_map(|f| entry.get(*f).and_then(Value::as_str))
                .map(str::trim)
                .find(|s| !s.is_empty())
                .map(|s| s.chars().take(128).collect());
        }
        if models.len() < MAX_LISTED_MODELS {
            models.push(id.chars().take(200).collect());
        }
    }
    Ok(ProbeResult {
        reachable: true,
        model_listed,
        models,
        revision,
        hosted,
        detail: None,
    })
}

//! Model profile configuration and local/hosted classification.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::ModelError;

/// Whether to use OpenAI-style tool calling.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCalling {
    /// Try tool calling; fall back to structured synthesis if unsupported.
    #[default]
    Auto,
    /// Require tool calling; an endpoint without it is an error.
    On,
    /// Structured synthesis only (one request, bounded digest).
    Off,
}

/// One model profile. Contains the *name* of the environment variable that
/// holds the API key, never the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Profile name, e.g. `local`.
    pub name: String,
    /// OpenAI-compatible base URL, e.g. `http://host:8000/v1`.
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// File holding the API key (used when `api_key_env` is not set). It
    /// should be readable only by the user.
    #[serde(default)]
    pub api_key_file: Option<std::path::PathBuf>,
    /// `None` infers from the host: loopback, private-LAN, link-local,
    /// `.local`, `.lan`, `.home.arpa` are local; everything else is hosted.
    #[serde(default)]
    pub hosted: Option<bool>,
    #[serde(default = "default_context_tokens")]
    pub context_tokens: u32,
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
    /// Passed through as `reasoning_effort` when set.
    #[serde(default)]
    pub reasoning_effort: Option<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub tool_calling: ToolCalling,
}

fn default_context_tokens() -> u32 {
    32_768
}
fn default_max_output_tokens() -> u32 {
    4_096
}
fn default_timeout_secs() -> u64 {
    120
}

impl ModelConfig {
    /// A profile with conservative defaults for the remaining fields.
    pub fn new(name: &str, base_url: &str, model: &str) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            model: model.into(),
            api_key_env: None,
            api_key_file: None,
            hosted: None,
            context_tokens: default_context_tokens(),
            max_output_tokens: default_max_output_tokens(),
            reasoning_effort: None,
            timeout_secs: default_timeout_secs(),
            tool_calling: ToolCalling::Auto,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        let lower = self.base_url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return Err(ModelError::Config(
                "base_url must start with http:// or https://".into(),
            ));
        }
        if host_of(&self.base_url).is_none() {
            return Err(ModelError::Config("base_url has no host".into()));
        }
        if self.model.trim().is_empty() {
            return Err(ModelError::Config("model is empty".into()));
        }
        if self.context_tokens < 1024 || self.max_output_tokens == 0 {
            return Err(ModelError::Config(
                "context_tokens must be >= 1024 and max_output_tokens > 0".into(),
            ));
        }
        if self.timeout_secs == 0 {
            return Err(ModelError::Config("timeout_secs must be > 0".into()));
        }
        Ok(())
    }
}

/// True when requests to this profile leave the user's machine/LAN. The CLI
/// must show [`hosted_disclosure`] and require explicit confirmation first.
pub fn is_hosted(cfg: &ModelConfig) -> bool {
    cfg.hosted.unwrap_or_else(|| match host_of(&cfg.base_url) {
        Some(h) => !is_local_host(&h),
        None => true,
    })
}

/// Disclosure text for hosted endpoints.
pub fn hosted_disclosure(cfg: &ModelConfig) -> String {
    let host = host_of(&cfg.base_url).unwrap_or_else(|| "<unknown host>".into());
    format!(
        "Model profile '{}' uses a hosted endpoint ({host}). Selected evidence from this scan \
         (snippets, file paths, finding titles) will be transmitted to that provider. \
         No sample files are uploaded.",
        cfg.name
    )
}

/// Host part of a URL: no scheme, userinfo, port, path, or brackets; lowercase.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

pub(crate) fn is_local_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if [".localhost", ".local", ".lan", ".home.arpa"]
        .iter()
        .any(|s| host.ends_with(s))
    {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(IpAddr::V6(v6)) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private() || v4.is_link_local())
        }
        Err(_) => false,
    }
}

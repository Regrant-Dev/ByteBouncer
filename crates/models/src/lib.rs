//! bytebouncer-models: bring-your-own-model synthesis behind a trust broker.
//!
//! The model is treated as an **untrusted analyst**. It talks to an
//! OpenAI-compatible endpoint chosen by the user, may only read evidence
//! through read-only tools, and may only *propose* findings. Every proposal
//! goes through the broker in [`broker`], which:
//!
//! * accepts only categories from a closed list and severities from the
//!   closed enum;
//! * requires every cited evidence ID to exist and all cited evidence to come
//!   from one artifact;
//! * caps the claimed evidence strength at what the cited evidence kinds can
//!   actually support;
//! * keeps a recipient domain only if it literally appears in a cited snippet;
//! * records anything that fails validation as an explicitly unverified
//!   [`Hypothesis`].
//!
//! The model can only **add** findings (with `finding-mNNN` IDs). It has no
//! way to delete, edit, or downgrade existing findings, and there is no tool
//! that writes, executes, fetches URLs, or changes configuration: the tool set
//! is fixed by construction in [`tools`].
//!
//! # Prompt injection
//!
//! All sample-derived text placed in prompts or tool results is wrapped in
//! labelled data blocks with delimiter-collision escaping, and the system
//! prompt states that such text is data. That is hygiene only. **The security
//! guarantee does not depend on the prompt or on model behaviour**: it comes
//! from the fixed read-only tool set, the add-only result shape, and broker
//! validation, all enforced in code regardless of what the model outputs.
//!
//! # Hosted endpoints
//!
//! [`is_hosted`] decides whether a profile transmits evidence off the user's
//! machine/LAN. Callers must show [`hosted_disclosure`] and obtain explicit
//! confirmation before calling [`synthesize`] against a hosted endpoint.
//! API keys are read from the environment variable named in the profile, are
//! sent only as a `Bearer` header, and are redacted from errors and `Debug`.

#![forbid(unsafe_code)]

pub mod broker;
mod client;
pub mod config;
pub mod synth;
pub mod tools;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use broker::{FindingExplanation, Hypothesis, category_allowed, strength_for_kind};
pub use client::{ProbeResult, probe};
pub use config::{ModelConfig, ToolCalling, hosted_disclosure, is_hosted};
pub use synth::{PROMPT_VERSION, SynthesisBudget, SynthesisInput, SynthesisResult, synthesize};
pub use tools::{EvidenceSource, NoExtraTools, ToolSpec};

/// Errors from talking to a model endpoint. Messages never contain the API key.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("invalid model configuration: {0}")]
    Config(String),
    #[error("API key environment variable {env_var} is not set or empty")]
    MissingApiKey { env_var: String },
    #[error("could not connect to model endpoint: {0}")]
    Connect(String),
    #[error("model endpoint timed out")]
    Timeout,
    #[error("model endpoint rejected credentials (HTTP {status})")]
    Auth { status: u16 },
    #[error("model endpoint returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("model endpoint does not support tool calling: {0}")]
    ToolsUnsupported(String),
    #[error("invalid response from model endpoint: {0}")]
    InvalidResponse(String),
}

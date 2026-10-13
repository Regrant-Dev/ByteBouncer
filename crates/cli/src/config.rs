//! User configuration (`~/.config/bytebouncer/config.toml` on Linux). Every
//! section is optional; with no file at all ByteBouncer runs quick mode with
//! the built-in default policy.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bytebouncer_core::{Policy, Severity};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub deep: DeepConfig,
    #[serde(default)]
    pub lookup: LookupConfig,
    /// Model profiles by name, e.g. `[models.local]`.
    #[serde(default)]
    pub models: BTreeMap<String, ModelProfile>,
    pub default_model: Option<String>,
    #[serde(default)]
    pub watch: WatchConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub keys: KeysConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// `none`, `info`, `low`, `medium`, `high`, `critical`.
    pub fail_on_security: Option<String>,
    pub fail_on_privacy: Option<String>,
    pub fail_on_provenance_mismatch: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeepConfig {
    pub capa: Option<PathBuf>,
    pub clamscan: Option<PathBuf>,
    pub clamav_db: Option<PathBuf>,
    pub ghidra_dir: Option<PathBuf>,
    /// JDK for Ghidra (it compiles its export script; a JRE is not enough).
    pub java_home: Option<PathBuf>,
    pub timeout_per_tool_secs: Option<u64>,
    pub ghidra_max_functions: Option<usize>,
    /// REA (Ghidra over MCP). Without this section, a REA installed by
    /// `bytebouncer setup rea` is used automatically.
    pub rea: Option<ReaConfig>,
    /// capa/ClamAV through an MCP scan server (e.g. inside an isolated VM)
    /// exposing `capa_scan` and `clamav_scan`. Replaces local capa/ClamAV.
    pub scan: Option<ScanServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanServerConfig {
    pub command: Vec<String>,
    /// Copy inputs into this folder first; copies are removed afterwards.
    pub staging_dir: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaConfig {
    /// Command that starts a REA MCP server on stdio, e.g. `["rea", "mcp"]`
    /// or a connector that runs REA inside an isolated VM.
    pub command: Vec<String>,
    /// Run the command inside ByteBouncer's Tier 2 sandbox (default true).
    /// Set false only for a connector that provides its own isolation.
    pub sandbox: Option<bool>,
    /// Copy inputs into this folder before analysis (for connectors that only
    /// accept files from specific folders). Copies are removed afterwards.
    pub staging_dir: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub open_timeout_secs: Option<u64>,
    /// Most executables per scan to open in REA (each opens a session).
    pub max_artifacts: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupConfig {
    /// Env var holding the abuse.ch Auth-Key.
    pub malwarebazaar_key_env: Option<String>,
    /// Env var holding the VirusTotal API key.
    pub virustotal_key_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    pub base_url: String,
    pub model: String,
    pub api_key_env: Option<String>,
    /// File containing the API key (keep it owner-readable only).
    pub api_key_file: Option<PathBuf>,
    pub hosted: Option<bool>,
    pub context_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub reasoning_effort: Option<String>,
    pub timeout_secs: Option<u64>,
    /// `auto`, `on`, `off`.
    pub tool_calling: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
    pub notify: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    /// Extra YARA rule directories (`*.yar`, `*.yara`), compiled alongside the bundled rules.
    #[serde(default)]
    pub directories: Vec<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysConfig {
    /// Trusted minisign public keys (base64 key lines or files).
    #[serde(default)]
    pub minisign: Vec<String>,
    /// OpenPGP keyring files trusted for detached `.sig`/`.asc` verification.
    #[serde(default)]
    pub pgp_keyrings: Vec<PathBuf>,
}

pub fn config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "ByteBouncer")
        .map(|d| d.config_dir().join("config.toml"))
}

pub fn load(explicit: Option<&Path>) -> Result<Config> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => match config_path() {
            Some(p) if p.exists() => p,
            _ => return Ok(Config::default()),
        },
    };
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    cfg.watch.directories = cfg
        .watch
        .directories
        .iter()
        .map(|p| expand_home(p))
        .collect();
    cfg.rules.directories = cfg
        .rules
        .directories
        .iter()
        .map(|p| expand_home(p))
        .collect();
    cfg.keys.pgp_keyrings = cfg
        .keys
        .pgp_keyrings
        .iter()
        .map(|p| expand_home(p))
        .collect();
    Ok(cfg)
}

pub fn expand_home(p: &Path) -> PathBuf {
    match (p.strip_prefix("~"), directories::BaseDirs::new()) {
        (Ok(rest), Some(b)) => b.home_dir().join(rest),
        _ => p.to_path_buf(),
    }
}

fn parse_threshold(v: &str) -> Result<Option<Severity>> {
    Ok(Some(match v {
        "none" => return Ok(None),
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => anyhow::bail!("unknown severity threshold '{other}'"),
    }))
}

impl PolicyConfig {
    pub fn to_policy(&self) -> Result<Policy> {
        let mut p = Policy::default();
        let customized = self.fail_on_security.is_some()
            || self.fail_on_privacy.is_some()
            || self.fail_on_provenance_mismatch.is_some();
        if let Some(v) = &self.fail_on_security {
            p.fail_on_security = parse_threshold(v)?;
        }
        if let Some(v) = &self.fail_on_privacy {
            p.fail_on_privacy = parse_threshold(v)?;
        }
        if let Some(v) = self.fail_on_provenance_mismatch {
            p.fail_on_provenance_mismatch = v;
        }
        if customized {
            p.name = "user-config".into();
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_example() {
        let cfg: Config = toml::from_str(
            r#"
            default_model = "local"
            [policy]
            fail_on_security = "medium"
            fail_on_privacy = "high"
            [models.local]
            base_url = "http://127.0.0.1:8000/v1"
            model = "some-model"
            [watch]
            directories = ["~/Downloads"]
            "#,
        )
        .unwrap();
        let p = cfg.policy.to_policy().unwrap();
        assert_eq!(p.fail_on_security, Some(Severity::Medium));
        assert_eq!(p.fail_on_privacy, Some(Severity::High));
        assert!(cfg.models.contains_key("local"));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(toml::from_str::<Config>("[policy]\nfail_on_everything = true").is_err());
    }
}

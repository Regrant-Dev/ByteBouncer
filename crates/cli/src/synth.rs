//! Optional bring-your-own-model synthesis. The model reads
//! evidence through read-only tools and may only add broker-validated
//! findings; its narrative is stored separately as unverified notes.

use std::time::Duration;

use anyhow::{Context, Result};
use bytebouncer_core::{Report, UnverifiedClaim};
use bytebouncer_models::{ModelConfig, SynthesisBudget, SynthesisInput, ToolCalling};

use crate::config::{Config, ModelProfile};
use crate::inspect::{InvalidRequest, ScanContext};

pub fn profile(config: &Config, name: &str) -> Result<ModelConfig> {
    let name = if name == "default" {
        config
            .default_model
            .as_deref()
            .ok_or_else(|| InvalidRequest("no default_model set in the config file".into()))?
    } else {
        name
    };
    let p: &ModelProfile = config.models.get(name).ok_or_else(|| {
        InvalidRequest(format!(
            "no model profile named '{name}' (add [models.{name}] to the config file)"
        ))
    })?;
    let mut cfg = ModelConfig::new(name, &p.base_url, &p.model);
    cfg.api_key_env = p.api_key_env.clone();
    cfg.api_key_file = p.api_key_file.as_deref().map(crate::config::expand_home);
    cfg.hosted = p.hosted;
    if let Some(v) = p.context_tokens {
        cfg.context_tokens = v;
    }
    if let Some(v) = p.max_output_tokens {
        cfg.max_output_tokens = v;
    }
    cfg.reasoning_effort = p.reasoning_effort.clone();
    if let Some(v) = p.timeout_secs {
        cfg.timeout_secs = v;
    }
    cfg.tool_calling = match p.tool_calling.as_deref() {
        None | Some("auto") => ToolCalling::Auto,
        Some("on") => ToolCalling::On,
        Some("off") => ToolCalling::Off,
        Some(other) => {
            return Err(InvalidRequest(format!(
                "tool_calling must be auto, on, or off (got '{other}')"
            ))
            .into());
        }
    };
    Ok(cfg)
}

pub fn run(
    ctx: &ScanContext,
    model: &str,
    report: &mut Report,
    retained: &[crate::deep::Retained],
    code: &[bytebouncer_analysis::code::CodeMap],
) -> Result<()> {
    let mut cfg = profile(ctx.config, model)?;
    if let Some(effort) = &ctx.args.effort {
        cfg.reasoning_effort = Some(effort.clone());
    }
    if bytebouncer_models::is_hosted(&cfg) && !ctx.args.allow_hosted_model {
        return Err(InvalidRequest(format!(
            "{}\nRe-run with --allow-hosted-model to send this evidence.",
            bytebouncer_models::hosted_disclosure(&cfg)
        ))
        .into());
    }
    ctx.progress.phase(&format!(
        "model synthesis with '{}' ({})",
        cfg.name, cfg.model
    ));
    let source = crate::deep::evidence_source(retained, code);
    let input = SynthesisInput {
        artifacts: &report.artifacts,
        findings: &report.findings,
        evidence: &report.evidence,
        coverage: &report.coverage,
        question: ctx.args.ask.clone(),
    };
    let budget = SynthesisBudget {
        max_tool_calls: ctx.args.model_max_tool_calls,
        max_total_tokens: ctx.args.model_max_tokens,
        wall_clock: Duration::from_secs(ctx.args.model_timeout),
    };
    let result = match bytebouncer_models::synthesize(&cfg, &input, source.as_ref(), &budget) {
        Ok(r) => r,
        Err(e) => {
            // A failed model run never changes the static result; it is a limitation.
            report
                .coverage
                .limitations
                .push(format!("Model synthesis failed: {e}"));
            return Ok(());
        }
    };
    report.budget.model_tokens_limit = Some(budget.max_total_tokens);
    report.budget.model_tokens_used = result.tokens_used;
    report.budget.exhausted |= result.budget_exhausted;
    report.model = Some(result.model_info);
    // Evidence the model fetched through tools must precede findings citing it.
    report.evidence.extend(result.new_evidence);
    report.findings.extend(result.findings);
    report.coverage.limitations.extend(result.limitations);
    report.model_notes.summary = Some(result.summary).filter(|s| !s.trim().is_empty());
    report.model_notes.explanations = result
        .explanations
        .into_iter()
        .map(|e| (e.finding_id, e.text))
        .collect();
    report.model_notes.hypotheses = result
        .hypotheses
        .into_iter()
        .map(|h| UnverifiedClaim {
            claim: h.claim,
            category: h.category,
            evidence_ids: h.evidence_ids,
            reason_rejected: h.reason_rejected,
        })
        .collect();
    ctx.progress.phase(&format!(
        "model synthesis done: {} tool call(s), {} token(s)",
        result.tool_calls, result.tokens_used
    ));
    Ok(())
}

/// `bytebouncer models probe NAME`.
pub fn probe(config: &Config, name: &str) -> Result<()> {
    let cfg = profile(config, name)?;
    let r = bytebouncer_models::probe(&cfg).context("probing model endpoint")?;
    println!("profile:      {}", cfg.name);
    println!("endpoint:     {}", cfg.base_url);
    println!("hosted:       {}", bytebouncer_models::is_hosted(&cfg));
    println!("reachable:    {}", r.reachable);
    println!("model listed: {}", r.model_listed);
    println!(
        "revision:     {}",
        r.revision
            .as_deref()
            .unwrap_or("not exposed (results are not reused across sessions)")
    );
    if let Some(d) = r.detail {
        println!("detail:       {d}");
    }
    Ok(())
}

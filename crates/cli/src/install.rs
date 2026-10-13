//! Install handoff: after the user has inspected and
//! approved a package request, re-acquire the exact artifacts, verify their
//! bytes match the approved report, and hand them to the native package
//! manager, which applies its own signature and trust checks. Any changed
//! payload stops the handoff.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use bytebouncer_core::{ExitCode, Manager};

use crate::fetch::{self, FetchRequest};
use crate::{approve, store};

pub fn run(report_id: &str, yes: bool, allow_reduced: bool) -> Result<ExitCode> {
    let report = store::load(report_id)?;
    let Some(req) = &report.acquisition.request else {
        bail!(
            "report {} is not a package request; install handoff only applies to package requests",
            report.scan_id
        );
    };
    let (program, base_args): (&str, &[&str]) = match &req.manager {
        Manager::Pacman => ("pacman", &["-U"]),
        Manager::Apt => ("apt", &["install"]),
        Manager::Dnf => ("dnf", &["install"]),
        other => bail!(
            "install handoff for {other:?} is not supported yet; install it with your package manager after reviewing the report"
        ),
    };
    let dir = approve::approvals_dir()?;
    let ws = store::new_workspace(&format!("install-{}", report.scan_id))?;
    let result = (|| -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for (i, origin) in report.acquisition.origins.iter().enumerate() {
            let approval = approve::lookup(&dir, &origin.sha256).with_context(|| {
                format!(
                    "{} is not approved; run `bytebouncer approve {}` first",
                    origin.final_url, report.scan_id
                )
            })?;
            let name = crate::acquire::url_file_name(&origin.final_url)
                .unwrap_or_else(|| format!("pkg-{i}"));
            let dest = ws.join(&name);
            eprintln!("re-downloading {name}");
            let reply = fetch::fetch(&FetchRequest {
                url: origin.requested_url.clone(),
                headers: vec![],
                max_bytes: origin.size + 1,
                dest: dest.clone(),
                timeout_secs: 1800,
                allow_reduced,
            })?;
            if reply.sha256 != origin.sha256 {
                bail!(
                    "{name} changed since report {} (was {}, now {}); inspect it again",
                    approval.report_id,
                    origin.sha256,
                    reply.sha256
                );
            }
            files.push(dest);
        }
        Ok(files)
    })();
    let files = match result {
        Ok(f) if !f.is_empty() => f,
        Ok(_) => {
            let _ = std::fs::remove_dir_all(&ws);
            bail!(
                "report {} has no downloaded artifacts to install",
                report.scan_id
            );
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&ws);
            return Err(e);
        }
    };

    let mut cmd = Command::new("sudo");
    cmd.arg(program).args(base_args).args(&files);
    eprintln!(
        "verified {} file(s) against report {}",
        files.len(),
        report.scan_id
    );
    eprintln!(
        "about to run: sudo {program} {} {}",
        base_args.join(" "),
        files
            .iter()
            .map(|f| f.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    if !yes {
        eprint!("proceed? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            let _ = std::fs::remove_dir_all(&ws);
            eprintln!("cancelled");
            return Ok(ExitCode::Cancelled);
        }
    }
    let status = cmd.status().context("running the package manager")?;
    let _ = std::fs::remove_dir_all(&ws);
    Ok(if status.success() {
        ExitCode::Ok
    } else {
        ExitCode::InternalFailure
    })
}

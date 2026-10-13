//! Install-script and shell/PowerShell heuristics. Scripts are read as text,
//! never executed. Each pattern describes a behavior worth reviewing;
//! severities stay conservative because installers legitimately enable
//! services, create users, and download components.

use std::sync::LazyLock;

use bytebouncer_core::Severity;
use regex::Regex;

pub struct ScriptRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub legitimate: &'static str,
    pattern: &'static str,
}

pub const RULES: &[ScriptRule] = &[
    ScriptRule {
        id: "pipe-download-to-shell",
        category: "security.downloader",
        severity: Severity::Medium,
        title: "Downloads code and pipes it straight into an interpreter",
        legitimate: "Installer bootstrap scripts (curl | sh installers)",
        pattern: r"(?i)\b(curl|wget|fetch)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|(?i)(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*iex\b|(?i)iex\s*\(?\s*\(?new-object\s+net\.webclient\)?\.downloadstring",
    },
    ScriptRule {
        id: "download-and-execute",
        category: "security.downloader",
        severity: Severity::Low,
        title: "Downloads a file and makes it executable or runs it",
        legitimate: "Installers fetching their own components",
        pattern: r"(?i)\b(curl|wget)\b[^\n]*(-o|-O|--output)\s*\S+[^\n]*(&&|;)\s*(chmod\s+\+?[0-7]*x|\./)|(?i)certutil(\.exe)?\s+-urlcache|(?i)bitsadmin(\.exe)?\s+/transfer|(?i)start-bitstransfer",
    },
    ScriptRule {
        id: "encoded-execution",
        category: "security.evasion",
        severity: Severity::Medium,
        title: "Executes base64-encoded or dynamically built code",
        legitimate: "Some installers embed small encoded payloads",
        pattern: r"(?i)base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh\b|(?i)\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}|(?i)\[convert\]::frombase64string\([^\n]*\)[^\n]*(iex|invoke-expression)|\beval\s+\x22?\$\((curl|wget|base64)",
    },
    ScriptRule {
        id: "persistence-service",
        category: "security.persistence",
        severity: Severity::Low,
        title: "Enables a service or scheduled task",
        legitimate: "Daemons and updaters installed on purpose",
        pattern: r"(?i)\bsystemctl\s+(--user\s+)?enable\b|\bcrontab\s+-|/etc/cron\.|(?i)schtasks(\.exe)?\s+/create|(?i)register-scheduledtask|(?i)new-service\b|(?i)\bsc(\.exe)?\s+create\b|launchctl\s+(load|bootstrap)|/Library/LaunchDaemons/|\.config/autostart/",
    },
    ScriptRule {
        id: "persistence-run-key",
        category: "security.persistence",
        severity: Severity::Medium,
        title: "Writes a Windows Run/RunOnce autostart key",
        legitimate: "Applications that start at login",
        pattern: r"(?i)\\currentversion\\run(once)?\b",
    },
    ScriptRule {
        id: "security-weakening",
        category: "security.evasion",
        severity: Severity::High,
        title: "Disables or weakens system security controls",
        legitimate: "Administrative hardening/unhardening scripts",
        pattern: r"(?i)set-executionpolicy\s+(bypass|unrestricted)\s+-scope\s+(localmachine|currentuser)|(?i)add-mppreference\s+-exclusion|(?i)set-mppreference\s+-disable|\bsetenforce\s+0\b|\bufw\s+disable\b|\biptables\s+-F\b|(?i)netsh\s+advfirewall\s+set\s+\S+\s+state\s+off",
    },
    ScriptRule {
        id: "setuid",
        category: "security.capability",
        severity: Severity::Medium,
        title: "Sets the setuid/setgid bit on a file",
        legitimate: "Packages shipping privileged helpers",
        pattern: r"\bchmod\s+([ug]\+s|[2467][0-7]{3})\b",
    },
    ScriptRule {
        id: "account-creation",
        category: "security.capability",
        severity: Severity::Low,
        title: "Creates a user account",
        legitimate: "Daemons running under a dedicated system user",
        pattern: r"\buseradd\b|\badduser\b|(?i)\bnet\s+user\s+\S+\s+\S+\s+/add|(?i)new-localuser",
    },
    ScriptRule {
        id: "shell-profile-modification",
        category: "security.persistence",
        severity: Severity::Low,
        title: "Modifies shell startup files",
        legitimate: "Tools adding themselves to PATH",
        pattern: r">>\s*~?/?\S*/?\.(bashrc|zshrc|profile|bash_profile)\b",
    },
];

static COMPILED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|r| Regex::new(r.pattern).expect("valid script rule"))
        .collect()
});

pub struct ScriptHit {
    pub rule: &'static ScriptRule,
    pub line: u64,
    pub text: String,
}

/// Scan script text; at most a few hits per rule.
pub fn scan(text: &str) -> Vec<ScriptHit> {
    let mut hits = Vec::new();
    for (rule, re) in RULES.iter().zip(COMPILED.iter()) {
        let mut n = 0;
        for (i, line) in text.lines().enumerate() {
            if re.is_match(line) {
                hits.push(ScriptHit {
                    rule,
                    line: i as u64 + 1,
                    text: line.trim().to_owned(),
                });
                n += 1;
                if n == 3 {
                    break;
                }
            }
        }
    }
    hits
}

/// Guess whether bytes are a script and which kind. `name` is the file name.
pub fn script_kind(bytes: &[u8], name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if bytes.starts_with(b"#!") {
        let first = bytes.split(|&b| b == b'\n').next().unwrap_or_default();
        let first = String::from_utf8_lossy(first);
        return Some(if first.contains("python") {
            "script-python"
        } else if first.contains("node") {
            "script-javascript"
        } else if first.contains("pwsh") || first.contains("powershell") {
            "script-powershell"
        } else {
            "script-shell"
        });
    }
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    let by_ext = [
        (".sh", "script-shell"),
        (".bash", "script-shell"),
        (".zsh", "script-shell"),
        (".install", "script-shell"),
        (".ps1", "script-powershell"),
        (".psm1", "script-powershell"),
        (".bat", "script-batch"),
        (".cmd", "script-batch"),
        (".vbs", "script-vbscript"),
        (".py", "script-python"),
        (".js", "script-javascript"),
        (".rb", "script-ruby"),
    ];
    if let Some((_, kind)) = by_ext.iter().find(|(ext, _)| base.ends_with(ext)) {
        return Some(kind);
    }
    match base {
        "pkgbuild" | "preinst" | "postinst" | "prerm" | "postrm" | "config" => Some("script-shell"),
        _ => None,
    }
}

/// Mostly printable UTF-8 text.
pub fn is_text(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(8192)];
    !sample.is_empty()
        && !sample.contains(&0)
        && std::str::from_utf8(sample).is_ok_and(|s| {
            s.chars()
                .filter(|c| c.is_control() && !c.is_whitespace())
                .count()
                * 100
                / s.len().max(1)
                < 2
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str) -> Vec<&'static str> {
        scan(text).iter().map(|h| h.rule.id).collect()
    }

    #[test]
    fn detects_common_patterns() {
        assert_eq!(
            ids("curl -fsSL https://x.sh | sh"),
            ["pipe-download-to-shell"]
        );
        assert_eq!(ids("iwr https://x/a.ps1 | iex"), ["pipe-download-to-shell"]);
        assert_eq!(ids("echo aGk= | base64 -d | bash"), ["encoded-execution"]);
        assert_eq!(ids("systemctl enable foo.service"), ["persistence-service"]);
        assert_eq!(
            ids("Add-MpPreference -ExclusionPath C:\\x"),
            ["security-weakening"]
        );
        assert_eq!(ids("chmod u+s /usr/bin/helper"), ["setuid"]);
    }

    #[test]
    fn ordinary_lines_are_quiet() {
        assert!(ids("echo installing\nmkdir -p /opt/app\ncp app /opt/app/").is_empty());
        assert!(ids("curl -o file.tar.gz https://example.org/file.tar.gz").is_empty());
    }

    #[test]
    fn kinds() {
        assert_eq!(script_kind(b"#!/bin/bash\necho", "x"), Some("script-shell"));
        assert_eq!(
            script_kind(b"Write-Host hi", "setup.PS1"),
            Some("script-powershell")
        );
        assert_eq!(script_kind(b"pkgname=x", "PKGBUILD"), Some("script-shell"));
        assert!(is_text(b"hello\nworld"));
        assert!(!is_text(b"\x7fELF\x00\x01"));
    }
}

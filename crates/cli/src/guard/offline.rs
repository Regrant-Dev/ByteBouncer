//! Preserve native transaction goals and dependency reasons while preventing
//! any new package download after review.

use anyhow::{Result, bail};
use std::path::Path;

pub fn pacman_config(source: &str) -> Result<String> {
    let mut out = String::new();
    let mut options = false;
    let mut inserted = false;
    for line in source.lines() {
        let trimmed = line.split('#').next().unwrap_or_default().trim();
        if trimmed.starts_with('[') {
            if options {
                out.push_str("XferCommand = /usr/bin/false\n");
                inserted = true;
            }
            options = trimmed == "[options]";
        }
        if options
            && trimmed
                .split('=')
                .next()
                .is_some_and(|key| key.trim() == "XferCommand")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if options {
        out.push_str("XferCommand = /usr/bin/false\n");
        inserted = true;
    }
    if !inserted {
        bail!("pacman.conf has no [options] section; cannot disable downloads safely");
    }
    Ok(out)
}

pub fn pacman_args(original: &[String], cache: &Path, config: &Path) -> Vec<String> {
    let mut args = vec![
        "--config".into(),
        config.display().to_string(),
        "--cachedir".into(),
        cache.display().to_string(),
    ];
    let mut words = original.iter();
    while let Some(a) = words.next() {
        if a == "--config" {
            words.next();
            continue;
        }
        if a.starts_with("--config=") {
            continue;
        }
        if a == "--refresh" {
            continue;
        }
        // The download phase already refreshed the database. The installation
        // phase uses that database and cannot synchronize another version.
        if a.starts_with('-') && !a.starts_with("--") {
            let filtered = a.replace('y', "");
            if filtered != "-" {
                args.push(filtered);
            }
        } else {
            args.push(a.clone());
        }
    }
    args
}

pub fn pacman_source(args: &[String]) -> &Path {
    let mut source = Path::new("/etc/pacman.conf");
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if word == "--config"
            && let Some(value) = words.next()
        {
            source = Path::new(value);
        } else if let Some(value) = word.strip_prefix("--config=") {
            source = Path::new(value);
        }
    }
    source
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacman_keeps_trust_and_goals_but_disables_new_downloads() {
        let text = "[options]\nSigLevel = Required DatabaseOptional\nXferCommand = curl %u\nInclude = /etc/pacman.d/options\n[core]\nInclude = /etc/pacman.d/mirrorlist\n";
        let offline = pacman_config(text).unwrap();
        assert!(offline.contains("SigLevel = Required DatabaseOptional"));
        assert!(
            offline
                .contains("Include = /etc/pacman.d/options\nXferCommand = /usr/bin/false\n[core]")
        );
        assert!(!offline.contains("curl"));
        let args = pacman_args(
            &["-Syyu".into(), "--needed".into(), "foo".into()],
            Path::new("/cache"),
            Path::new("/config"),
        );
        assert!(args.contains(&"-Su".into()));
        assert!(args.contains(&"foo".into()));
        assert!(!args.contains(&"-U".into()));
    }
}

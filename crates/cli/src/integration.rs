//! Opt-in shell entry points and the AUR helpers' two small callbacks.
//! Nothing modifies shell startup files, PATH or system configuration.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{Mode, guard};
use bytebouncer_core::ExitCode;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
}

#[derive(clap::Args)]
pub struct Args {
    #[arg(long, value_enum, default_value_t = Shell::Bash)]
    pub shell: Shell,
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    #[arg(long)]
    pub model: Option<String>,
    #[arg(long)]
    pub allow_hosted_model: bool,
    #[arg(long)]
    pub allow_reduced_isolation: bool,
    /// Print commands to remove the functions from the current shell
    #[arg(long)]
    pub disable: bool,
}

const MANAGERS: &[&str] = &[
    "pacman", "yay", "paru", "makepkg", "apt", "apt-get", "dnf", "dnf5",
];

pub fn run(args: &Args, config: Option<&Path>) -> Result<ExitCode> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("automatic shell integration currently supports Linux (bash and zsh)");
    }
    if args.disable {
        println!("unset -f {} sudo", MANAGERS.join(" "));
        return Ok(ExitCode::Ok);
    }
    let options = guard::Args {
        mode: args.mode,
        model: args.model.clone(),
        allow_hosted_model: args.allow_hosted_model,
        allow_reduced_isolation: args.allow_reduced_isolation,
        yes: false,
        command: Vec::new(),
    };
    let prefix = prefix(&options, config)?;
    print!("{}", shell_source(&prefix));
    Ok(ExitCode::Ok)
}

fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn prefix(args: &guard::Args, config: Option<&Path>) -> Result<String> {
    let mut words = vec![std::env::current_exe()?.display().to_string()];
    if let Some(config) = config {
        words.extend([
            "--config".into(),
            std::fs::canonicalize(config)?.display().to_string(),
        ]);
    }
    words.push("guard".into());
    words.extend(guard::forward_options(args));
    words.push("--".into());
    Ok(words
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" "))
}

fn shell_source(prefix: &str) -> String {
    let mut source =
        String::from("# ByteBouncer: eval this output in bash or zsh. No service is needed.\n");
    for manager in MANAGERS {
        source.push_str(&format!("{manager}() {{ {prefix} {manager} \"$@\"; }}\n"));
    }
    // A shell function for pacman alone does not catch `sudo pacman`.
    // Preserve every other sudo invocation verbatim. Sudo options are not
    // interpreted or silently removed by this entry point.
    source.push_str(&format!("sudo() {{\n  case \"${{1-}}\" in\n    {}) local bb_manager=\"$1\"; shift; {prefix} \"$bb_manager\" \"$@\" ;;\n    *) command sudo \"$@\" ;;\n  esac\n}}\n", MANAGERS.join("|")));
    source
}

pub fn write_proxy(
    directory: &Path,
    manager: &str,
    args: &guard::Args,
    config: Option<&Path>,
) -> Result<PathBuf> {
    let path = directory.join(format!("bytebouncer-{manager}"));
    crate::store::write_private_file(
        &path,
        format!(
            "#!/bin/sh\nexec {} {} \"$@\"\n",
            prefix(args, config)?,
            quote(manager)
        )
        .as_bytes(),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn shell_functions_preserve_arguments_and_simple_sudo_is_guarded() {
        let source = shell_source("bb-test guard --");
        let script = format!(
            r#"
bb-test() {{ printf '%s\n' "$@"; }}
{source}
sudo apt install 'name with spaces' 'literal$(text)'
"#
        );
        let output = std::process::Command::new("bash")
            .args(["--noprofile", "--norc", "-c", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "guard\n--\napt\ninstall\nname with spaces\nliteral$(text)\n"
        );
    }

    #[test]
    fn shell_quoting_does_not_evaluate_profile_names() {
        let value = "profile ' $HOME `id` $(id)\nnext";
        let output = std::process::Command::new("bash")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                &format!("printf '%s' {}", quote(value)),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), value);
    }
}

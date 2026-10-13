//! Finite parser for package requests (SPEC §3.1). Input is NEVER passed to a
//! shell: we accept a tiny word grammar (plain words, '…', "…" with `\"`),
//! reject anything with shell meaning, and recognize a fixed set of
//! operations and flags per manager. Unknown flags are errors, never dropped.

use bytebouncer_core::{Manager, PackageRequest};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("empty request")]
    Empty,
    /// Shell syntax (operators, expansions, globbing, redirections…).
    #[error("{0}")]
    ShellSyntax(String),
    #[error("ByteBouncer never installs; drop `{0}` and pass the package request on its own")]
    Privilege(String),
    #[error(
        "environment assignment `{0}` is not supported: requests are never run, so variables have no effect"
    )]
    EnvAssignment(String),
    #[error(
        "unsupported package manager `{0}` (supported: pacman, yay, paru, apt, apt-get, dnf, brew, winget, scoop, choco)"
    )]
    UnknownProgram(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("invalid package name `{name}` for {manager}: {reason}")]
    InvalidPackage {
        manager: String,
        name: String,
        reason: String,
    },
    #[error("{0}")]
    MissingPackages(String),
}

fn shell(msg: impl Into<String>) -> ParseError {
    ParseError::ShellSyntax(msg.into())
}

fn unsupported(msg: impl Into<String>) -> ParseError {
    ParseError::Unsupported(msg.into())
}

/// Parse a request written as one string, e.g. `"pacman -S firefox"`.
pub fn parse_command_str(input: &str) -> Result<PackageRequest, ParseError> {
    let tokens = tokenize(input)?;
    parse_tokens(tokens, input.trim().to_string())
}

/// Parse a request already split into words (e.g. everything after `--`).
/// Each element is treated like a quoted word: it is still checked for shell
/// syntax because the user may have expected a shell to interpret it.
pub fn parse_argv(argv: &[String]) -> Result<PackageRequest, ParseError> {
    let mut tokens = Vec::with_capacity(argv.len());
    for (i, arg) in argv.iter().enumerate() {
        if arg.contains('\n') || arg.contains('\r') {
            return Err(shell("newlines are not allowed in a package request"));
        }
        // A word that starts with `~` or `#` would have been expanded/ignored
        // by a shell; reject it like the string form does.
        if arg.starts_with('~') {
            return Err(shell(
                "`~` (home directory expansion) is not supported in package requests",
            ));
        }
        if i == 0 || !arg.contains(' ') {
            // Unquoted-looking words get the full metacharacter check.
            check_unquoted_word(arg)?;
        }
        tokens.push(Token {
            text: arg.clone(),
            quoted: arg.contains(' '),
        });
    }
    let raw = argv
        .iter()
        .map(|a| {
            if a.is_empty() || a.contains(' ') {
                format!("'{a}'")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    parse_tokens(tokens, raw)
}

#[derive(Debug, Clone)]
struct Token {
    text: String,
    quoted: bool,
}

fn meta_message(c: char, next: Option<char>) -> Option<String> {
    let m = match c {
        '|' if next == Some('|') => "`||` (command chaining) is not supported",
        '|' => "`|` (pipe) is not supported",
        '&' if next == Some('&') => "`&&` (command chaining) is not supported",
        '&' => "`&` (background/chaining) is not supported",
        ';' => "`;` (command separator) is not supported",
        '$' => "`$` (variable or command substitution) is not supported",
        '`' => "backtick command substitution is not supported",
        '(' | ')' => "parentheses (subshells/grouping) are not supported",
        '>' if next == Some('>') => "`>>` (redirection) is not supported",
        '<' | '>' => "redirections are not supported",
        '*' | '?' | '[' | ']' => "glob patterns (`*`, `?`, `[...]`) are not supported",
        '{' | '}' => "brace expansion (`{...}`) is not supported",
        '\\' => "backslash escapes are not supported outside double quotes",
        '!' => "`!` (history expansion) is not supported",
        '\n' | '\r' => "newlines are not allowed in a package request",
        _ => return None,
    };
    Some(m.to_string())
}

fn check_unquoted_word(word: &str) -> Result<(), ParseError> {
    let chars: Vec<char> = word.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if let Some(m) = meta_message(c, chars.get(i + 1).copied()) {
            return Err(shell(m));
        }
        if c == '#' && i == 0 {
            return Err(shell("`#` starts a shell comment; it is not supported"));
        }
    }
    Ok(())
}

fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    #[derive(PartialEq)]
    enum Mode {
        Plain,
        Single,
        Double,
    }
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut mode = Mode::Plain;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match mode {
            Mode::Plain => match c {
                ' ' | '\t' => {
                    if in_word {
                        tokens.push(Token {
                            text: std::mem::take(&mut cur),
                            quoted,
                        });
                        in_word = false;
                        quoted = false;
                    }
                }
                '\'' => {
                    mode = Mode::Single;
                    in_word = true;
                    quoted = true;
                }
                '"' => {
                    mode = Mode::Double;
                    in_word = true;
                    quoted = true;
                }
                '#' if !in_word => {
                    return Err(shell("`#` starts a shell comment; it is not supported"));
                }
                '~' if !in_word || cur.ends_with('=') || cur.ends_with(':') => {
                    return Err(shell(
                        "`~` (home directory expansion) is not supported in package requests",
                    ));
                }
                _ => {
                    if let Some(m) = meta_message(c, next) {
                        return Err(shell(m));
                    }
                    cur.push(c);
                    in_word = true;
                }
            },
            Mode::Single => match c {
                '\'' => mode = Mode::Plain,
                '\n' | '\r' => {
                    return Err(shell("newlines are not allowed in a package request"));
                }
                _ => cur.push(c),
            },
            Mode::Double => match c {
                '"' => mode = Mode::Plain,
                '\\' if next == Some('"') => {
                    cur.push('"');
                    i += 1;
                }
                '\\' => {
                    return Err(shell(
                        "only `\\\"` is supported as an escape inside double quotes",
                    ));
                }
                '$' => {
                    return Err(shell(
                        "`$` inside double quotes expands variables/commands; it is not supported",
                    ));
                }
                '`' => {
                    return Err(shell(
                        "backtick command substitution is not supported (even inside double quotes)",
                    ));
                }
                '\n' | '\r' => {
                    return Err(shell("newlines are not allowed in a package request"));
                }
                _ => cur.push(c),
            },
        }
        i += 1;
    }
    if mode != Mode::Plain {
        return Err(shell("unterminated quote"));
    }
    if in_word {
        tokens.push(Token { text: cur, quoted });
    }
    Ok(tokens)
}

/// Characters a word may contain once quoting is removed. Spaces only appear
/// inside quotes (e.g. a winget display name), and are then rejected by the
/// per-manager package validators anyway.
fn check_token_chars(t: &Token) -> Result<(), ParseError> {
    if t.text.is_empty() {
        return Err(unsupported("empty word (`''` or `\"\"`) in request"));
    }
    for c in t.text.chars() {
        let ok = c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.' | '_' | '+' | '@' | '/' | ':' | '=' | ',' | '%' | '~'
            )
            || (c == ' ' && t.quoted);
        if !ok {
            return Err(match meta_message(c, None) {
                Some(m) => shell(format!("{m} (even when quoted)")),
                None => shell(format!(
                    "character {c:?} is not allowed in a package request"
                )),
            });
        }
    }
    Ok(())
}

fn is_env_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn parse_tokens(tokens: Vec<Token>, raw: String) -> Result<PackageRequest, ParseError> {
    let Some(first) = tokens.first() else {
        return Err(ParseError::Empty);
    };
    for t in &tokens {
        check_token_chars(t)?;
    }
    let program = first.text.as_str();
    if matches!(program, "sudo" | "doas" | "pkexec" | "run0" | "su") {
        return Err(ParseError::Privilege(program.to_string()));
    }
    if is_env_assignment(program) {
        return Err(ParseError::EnvAssignment(program.to_string()));
    }
    if program.contains('/') {
        return Err(unsupported(format!(
            "give the package manager by name, not by path (`{program}`)"
        )));
    }
    let args: Vec<String> = tokens[1..].iter().map(|t| t.text.clone()).collect();
    let (manager, packages, options) = match program {
        "pacman" => parse_pacman(&args, None)?,
        "yay" | "paru" => parse_pacman(&args, Some(program))?,
        "apt" | "apt-get" => parse_apt(program, &args)?,
        "dnf" => parse_dnf(&args)?,
        "yum" => {
            return Err(unsupported(
                "`yum` is not supported; use the equivalent `dnf install` request",
            ));
        }
        "brew" => parse_brew(&args)?,
        "winget" | "winget.exe" => parse_winget(&args)?,
        "scoop" => parse_scoop(&args)?,
        "choco" | "choco.exe" => parse_choco(&args)?,
        other => return Err(ParseError::UnknownProgram(other.to_string())),
    };
    if packages.is_empty() {
        return Err(ParseError::MissingPackages(format!(
            "`{program}` request names no package"
        )));
    }
    Ok(PackageRequest {
        manager,
        operation: "install".to_string(),
        packages,
        options,
        raw,
    })
}

type Parsed = (Manager, Vec<String>, Vec<String>);

fn push_opt(options: &mut Vec<String>, o: &str) {
    if !options.iter().any(|x| x == o) {
        options.push(o.to_string());
    }
}

fn invalid(manager: &str, name: &str, reason: &str) -> ParseError {
    ParseError::InvalidPackage {
        manager: manager.to_string(),
        name: name.to_string(),
        reason: reason.to_string(),
    }
}

fn reject_path_or_url(manager: &str, name: &str) -> Result<(), ParseError> {
    if name.contains("://") {
        return Err(unsupported(format!(
            "{manager}: installing from a URL (`{name}`) is not a package request; run `bytebouncer inspect <url>` instead"
        )));
    }
    if name.starts_with('.')
        || name.starts_with('/')
        || name.ends_with(".deb")
        || name.ends_with(".rpm")
        || name.contains(".pkg.tar")
    {
        return Err(unsupported(format!(
            "{manager}: `{name}` looks like a local file; run `bytebouncer inspect <file>` instead"
        )));
    }
    Ok(())
}

/// Lowercase-ish package name: alnum plus `extra`, starting with alnum.
fn simple_name(name: &str, extra: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

// ---------------------------------------------------------------- pacman ---

fn parse_pacman(args: &[String], helper: Option<&str>) -> Result<Parsed, ParseError> {
    let prog = helper.unwrap_or("pacman");
    if args.is_empty() {
        return Err(match helper {
            Some(h) => unsupported(format!(
                "`{h}` with no arguments performs a full system upgrade; name packages with `{h} -S <pkg>`"
            )),
            None => unsupported("`pacman` needs an operation; use `pacman -S <pkg>`"),
        });
    }
    let mut sync = false;
    let mut packages = Vec::new();
    let mut options = Vec::new();
    for a in args {
        if let Some(long) = a.strip_prefix("--") {
            match long {
                "sync" => sync = true,
                "needed" => push_opt(&mut options, "--needed"),
                "noconfirm" => push_opt(&mut options, "--noconfirm"),
                "refresh" | "sysupgrade" => {
                    return Err(unsupported(format!(
                        "`--{long}` refreshes/upgrades the whole system, which changes what would be installed; drop it"
                    )));
                }
                "" => {
                    return Err(unsupported(format!(
                        "`--` is not supported in {prog} requests"
                    )));
                }
                _ => {
                    return Err(unsupported(format!(
                        "unsupported {prog} option `--{long}` (supported: -S/--sync, --needed, --noconfirm)"
                    )));
                }
            }
        } else if let Some(short) = a.strip_prefix('-') {
            if short.is_empty() {
                return Err(unsupported(format!(
                    "bare `-` is not supported in {prog} requests"
                )));
            }
            for c in short.chars() {
                match c {
                    'S' => sync = true,
                    'y' | 'u' => {
                        return Err(unsupported(format!(
                            "`-{short}`: `-y`/`-u` refresh or upgrade the whole system, which changes what would be installed; use plain `-S`"
                        )));
                    }
                    'U' => {
                        return Err(unsupported(
                            "`-U` installs a local file or URL; run `bytebouncer inspect <file|url>` instead",
                        ));
                    }
                    'R' | 'Q' | 'D' | 'F' | 'T' => {
                        return Err(unsupported(format!(
                            "`-{c}` is not an install operation; only `-S` is supported"
                        )));
                    }
                    's' | 'i' | 'l' | 'g' | 'p' | 'w' | 'c' | 'q' => {
                        return Err(unsupported(format!(
                            "`-S{c}` is a query/download variant, not a plain install; only `-S <pkg>` is supported"
                        )));
                    }
                    _ => {
                        return Err(unsupported(format!(
                            "unsupported {prog} flag `-{c}` in `{a}`"
                        )));
                    }
                }
            }
        } else {
            validate_pacman_name(prog, a)?;
            packages.push(a.clone());
        }
    }
    if !sync {
        return Err(match helper {
            Some(h) => unsupported(format!(
                "`{h} <name>` is an interactive search-and-install; use `{h} -S <pkg>` with exact package names"
            )),
            None => unsupported("missing operation; only `pacman -S <pkg>` (install) is supported"),
        });
    }
    let manager = if helper.is_some() {
        Manager::Aur
    } else {
        Manager::Pacman
    };
    Ok((manager, packages, options))
}

fn validate_pacman_name(prog: &str, a: &str) -> Result<(), ParseError> {
    reject_path_or_url(prog, a)?;
    let (repo, name) = match a.split_once('/') {
        Some((r, n)) => (Some(r), n),
        None => (None, a),
    };
    if let Some(r) = repo
        && !simple_name(r, "._-")
    {
        return Err(invalid(
            prog,
            a,
            "repository part must be a plain repository name",
        ));
    }
    if name.contains('/') {
        return Err(invalid(prog, a, "use `repo/package` with a single `/`"));
    }
    if !simple_name(name, "@._+-") {
        return Err(invalid(
            prog,
            a,
            "package names use letters, digits and `@._+-` (version constraints are not supported)",
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------- apt ---

fn parse_apt(prog: &str, args: &[String]) -> Result<Parsed, ParseError> {
    let mut install = false;
    let mut packages = Vec::new();
    let mut options = Vec::new();
    for a in args {
        if a.starts_with('-') {
            match a.as_str() {
                "-y" | "--yes" | "--assume-yes" => push_opt(&mut options, "--yes"),
                "--no-install-recommends" => push_opt(&mut options, "--no-install-recommends"),
                _ => {
                    return Err(unsupported(format!(
                        "unsupported {prog} option `{a}` (supported: -y/--yes, --no-install-recommends)"
                    )));
                }
            }
        } else if !install {
            match a.as_str() {
                "install" => install = true,
                "upgrade" | "full-upgrade" | "dist-upgrade" => {
                    return Err(unsupported(format!(
                        "`{prog} {a}` upgrades the whole system; name packages with `{prog} install <pkg>`"
                    )));
                }
                _ => {
                    return Err(unsupported(format!(
                        "`{prog} {a}` is not supported; only `{prog} install <pkg>` is"
                    )));
                }
            }
        } else {
            validate_apt_name(prog, a)?;
            packages.push(a.clone());
        }
    }
    if !install {
        return Err(unsupported(format!(
            "missing operation; use `{prog} install <pkg>`"
        )));
    }
    Ok((Manager::Apt, packages, options))
}

fn validate_apt_name(prog: &str, a: &str) -> Result<(), ParseError> {
    reject_path_or_url(prog, a)?;
    // name[:arch][=version | /release]
    let (head, suffix_ok) = if let Some((h, v)) = a.split_once('=') {
        (h, simple_name(v, ".+~:-"))
    } else if let Some((h, r)) = a.split_once('/') {
        (h, simple_name(r, ".-"))
    } else {
        (a, true)
    };
    let name = match head.split_once(':') {
        Some((n, arch)) => {
            if !simple_name(arch, "-") {
                return Err(invalid(prog, a, "invalid architecture qualifier"));
            }
            n
        }
        None => head,
    };
    if !suffix_ok {
        return Err(invalid(prog, a, "invalid `=version` or `/release` suffix"));
    }
    if !simple_name(name, "+.-") || name.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(invalid(
            prog,
            a,
            "Debian package names use lowercase letters, digits and `+.-`",
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------- dnf ---

fn parse_dnf(args: &[String]) -> Result<Parsed, ParseError> {
    let mut install = false;
    let mut packages = Vec::new();
    let mut options = Vec::new();
    for a in args {
        if a.starts_with('-') {
            match a.as_str() {
                "-y" | "--assumeyes" => push_opt(&mut options, "--assumeyes"),
                _ => {
                    return Err(unsupported(format!(
                        "unsupported dnf option `{a}` (supported: -y/--assumeyes)"
                    )));
                }
            }
        } else if !install {
            if a == "install" {
                install = true;
            } else {
                return Err(unsupported(format!(
                    "`dnf {a}` is not supported; only `dnf install <pkg>` is"
                )));
            }
        } else {
            reject_path_or_url("dnf", a)?;
            if a.starts_with('@') {
                return Err(unsupported(format!(
                    "dnf groups/environments (`{a}`) are not supported; name packages explicitly"
                )));
            }
            if !simple_name(a, "._+:-") {
                return Err(invalid(
                    "dnf",
                    a,
                    "package specs use letters, digits and `._+:-`",
                ));
            }
            packages.push(a.clone());
        }
    }
    if !install {
        return Err(unsupported("missing operation; use `dnf install <pkg>`"));
    }
    Ok((Manager::Dnf, packages, options))
}

// ------------------------------------------------------------------ brew ---

fn parse_brew(args: &[String]) -> Result<Parsed, ParseError> {
    let mut install = false;
    let mut packages = Vec::new();
    let mut options = Vec::new();
    for a in args {
        if a.starts_with('-') {
            match a.as_str() {
                "--cask" | "--casks" => push_opt(&mut options, "--cask"),
                "--formula" | "--formulae" => push_opt(&mut options, "--formula"),
                "--HEAD"
                | "--build-from-source"
                | "-s"
                | "--force-bottle"
                | "--build-bottle"
                | "--interactive"
                | "-i" => {
                    return Err(unsupported(format!(
                        "brew `{a}` changes how the package is built; only plain `brew install [--cask|--formula] <name>` is supported"
                    )));
                }
                _ => {
                    return Err(unsupported(format!(
                        "unsupported brew option `{a}` (supported: --cask, --formula)"
                    )));
                }
            }
        } else if !install {
            if a == "install" {
                install = true;
            } else {
                return Err(unsupported(format!(
                    "`brew {a}` is not supported; only `brew install <name>` is"
                )));
            }
        } else {
            reject_path_or_url("brew", a)?;
            let parts: Vec<&str> = a.split('/').collect();
            let ok = match parts.len() {
                1 => simple_name(parts[0], "@._+-"),
                3 => {
                    simple_name(parts[0], "_-")
                        && simple_name(parts[1], "_-")
                        && simple_name(parts[2], "@._+-")
                }
                _ => false,
            };
            if !ok {
                return Err(invalid(
                    "brew",
                    a,
                    "use `name` or `user/tap/name` (letters, digits, `@._+-`)",
                ));
            }
            packages.push(a.clone());
        }
    }
    if !install {
        return Err(unsupported("missing operation; use `brew install <name>`"));
    }
    if options.iter().any(|o| o == "--cask") && options.iter().any(|o| o == "--formula") {
        return Err(unsupported(
            "`--cask` and `--formula` are mutually exclusive",
        ));
    }
    Ok((Manager::Homebrew, packages, options))
}

// ---------------------------------------------------------------- winget ---

/// winget decision: we only resolve exact package identifiers. `--id X` is
/// accepted (ids are matched exactly and case-sensitively against the
/// winget-pkgs repository layout; without `--exact` winget itself would match
/// case-insensitively, which we note). A positional query is accepted only
/// with `-e/--exact` and only when it looks like an identifier
/// (`Publisher.Name`). Fuzzy name/moniker/tag searches are rejected because
/// their result depends on the live index and could pick a different package.
fn parse_winget(args: &[String]) -> Result<Parsed, ParseError> {
    let mut install = false;
    let mut id: Option<String> = None;
    let mut query: Option<String> = None;
    let mut exact = false;
    let mut options = Vec::new();
    let mut i = 0;
    let take_value = |i: &mut usize, flag: &str| -> Result<String, ParseError> {
        *i += 1;
        match args.get(*i) {
            Some(v) if !v.starts_with('-') => Ok(v.clone()),
            _ => Err(unsupported(format!("winget `{flag}` needs a value"))),
        }
    };
    while i < args.len() {
        let a = &args[i];
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        if flag.starts_with('-') {
            let value = |i: &mut usize| -> Result<String, ParseError> {
                match &inline {
                    Some(v) if !v.is_empty() => Ok(v.clone()),
                    Some(_) => Err(unsupported(format!("winget `{flag}` needs a value"))),
                    None => take_value(i, &flag),
                }
            };
            match flag.as_str() {
                "--id" => {
                    let v = value(&mut i)?;
                    if id.replace(v).is_some() {
                        return Err(unsupported("winget `--id` given twice"));
                    }
                }
                "-q" | "--query" => {
                    let v = value(&mut i)?;
                    if query.replace(v).is_some() {
                        return Err(unsupported("winget accepts a single query"));
                    }
                }
                "-e" | "--exact" => exact = true,
                "-v" | "--version" => {
                    let v = value(&mut i)?;
                    if !simple_name(&v, "._+-") {
                        return Err(unsupported(format!("invalid winget version `{v}`")));
                    }
                    push_opt(&mut options, &format!("--version={v}"));
                }
                "-s" | "--source" => {
                    let v = value(&mut i)?;
                    if v != "winget" {
                        return Err(unsupported(format!(
                            "winget source `{v}` is not supported; only the community `winget` source is"
                        )));
                    }
                    push_opt(&mut options, "--source=winget");
                }
                "-a" | "--architecture" => {
                    let v = value(&mut i)?.to_ascii_lowercase();
                    if !matches!(v.as_str(), "x64" | "x86" | "arm64" | "arm") {
                        return Err(unsupported(format!(
                            "winget architecture `{v}` is not one of x64, x86, arm64, arm"
                        )));
                    }
                    push_opt(&mut options, &format!("--architecture={v}"));
                }
                "--scope" => {
                    let v = value(&mut i)?.to_ascii_lowercase();
                    if !matches!(v.as_str(), "user" | "machine") {
                        return Err(unsupported(format!(
                            "winget scope `{v}` is not one of user, machine"
                        )));
                    }
                    push_opt(&mut options, &format!("--scope={v}"));
                }
                "--accept-package-agreements" | "--accept-source-agreements" => {
                    push_opt(&mut options, &flag);
                }
                "-n" | "--name" | "--moniker" | "--tag" | "--cmd" | "--command" => {
                    return Err(unsupported(format!(
                        "winget `{flag}` is a fuzzy search; use `--id <Publisher.Package> --exact`"
                    )));
                }
                "-m" | "--manifest" => {
                    return Err(unsupported(
                        "winget `--manifest` (local manifest) is not supported",
                    ));
                }
                _ => {
                    return Err(unsupported(format!(
                        "unsupported winget option `{flag}` (supported: --id, -e/--exact, --version, --source winget, --architecture, --scope, --accept-*-agreements)"
                    )));
                }
            }
        } else if !install {
            if a == "install" || a == "add" {
                install = true;
            } else {
                return Err(unsupported(format!(
                    "`winget {a}` is not supported; only `winget install --id <Id> --exact` is"
                )));
            }
        } else if query.replace(a.clone()).is_some() {
            return Err(unsupported("winget accepts a single query"));
        }
        i += 1;
    }
    if !install {
        return Err(unsupported(
            "missing operation; use `winget install --id <Id> --exact`",
        ));
    }
    let package = match (id, query) {
        (Some(_), Some(_)) => {
            return Err(unsupported(
                "winget: give either `--id` or a query, not both",
            ));
        }
        (Some(id), None) => id,
        (None, Some(q)) => {
            if !exact || q.contains(' ') || !q.contains('.') {
                return Err(unsupported(format!(
                    "winget query `{q}` is a fuzzy search whose result depends on the live index; use `--id <Publisher.Package> --exact`"
                )));
            }
            push_opt(&mut options, "--query-as-id");
            q
        }
        (None, None) => {
            return Err(ParseError::MissingPackages(
                "winget request names no package".into(),
            ));
        }
    };
    if exact {
        options.insert(0, "--exact".to_string());
    }
    if !simple_name(&package, "._+-") || !package.contains('.') || package.contains("..") {
        return Err(invalid(
            "winget",
            &package,
            "identifiers look like `Publisher.Package` (letters, digits, `._+-`)",
        ));
    }
    Ok((Manager::Winget, vec![package], options))
}

// ----------------------------------------------------------------- scoop ---

pub(crate) const SCOOP_KNOWN_BUCKETS: &[&str] =
    &["main", "extras", "versions", "java", "nerd-fonts", "games"];

fn parse_scoop(args: &[String]) -> Result<Parsed, ParseError> {
    let mut install = false;
    let mut packages = Vec::new();
    let mut options = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            match a.as_str() {
                "-a" | "--arch" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| unsupported("scoop `--arch` needs a value"))?;
                    if !matches!(v.as_str(), "64bit" | "32bit" | "arm64") {
                        return Err(unsupported(format!(
                            "scoop architecture `{v}` is not one of 64bit, 32bit, arm64"
                        )));
                    }
                    push_opt(&mut options, &format!("--arch={v}"));
                }
                "-u" | "--no-update-scoop" => push_opt(&mut options, "--no-update-scoop"),
                "-g" | "--global" => push_opt(&mut options, "--global"),
                "-s" | "--skip-hash-check" | "--skip" => {
                    return Err(unsupported(
                        "scoop `--skip-hash-check` disables hash verification; it is not supported",
                    ));
                }
                _ => {
                    return Err(unsupported(format!(
                        "unsupported scoop option `{a}` (supported: -a/--arch, -u/--no-update-scoop, -g/--global)"
                    )));
                }
            }
        } else if !install {
            if a == "install" {
                install = true;
            } else {
                return Err(unsupported(format!(
                    "`scoop {a}` is not supported; only `scoop install [bucket/]app[@version]` is"
                )));
            }
        } else {
            reject_path_or_url("scoop", a)?;
            if a.ends_with(".json") {
                return Err(unsupported(format!(
                    "scoop: `{a}` looks like a manifest file; run `bytebouncer inspect <file>` instead"
                )));
            }
            let (spec, version) = match a.split_once('@') {
                Some((s, v)) => (s, Some(v)),
                None => (a.as_str(), None),
            };
            if let Some(v) = version
                && !simple_name(v, "._+-")
            {
                return Err(invalid("scoop", a, "invalid `@version`"));
            }
            let ok = match spec.split_once('/') {
                Some((b, app)) => simple_name(b, "._-") && simple_name(app, "._+-"),
                None => simple_name(spec, "._+-"),
            };
            if !ok {
                return Err(invalid(
                    "scoop",
                    a,
                    "use `app`, `bucket/app` or `app@version` (letters, digits, `._+-`)",
                ));
            }
            packages.push(a.clone());
        }
        i += 1;
    }
    if !install {
        return Err(unsupported("missing operation; use `scoop install <app>`"));
    }
    Ok((Manager::Scoop, packages, options))
}

// ---------------------------------------------------------------- choco ---

fn parse_choco(args: &[String]) -> Result<Parsed, ParseError> {
    let mut install = false;
    let mut packages = Vec::new();
    let mut options = Vec::new();
    let mut version: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            let (flag, inline) = match a.split_once('=') {
                Some((f, v)) => (f, Some(v.to_string())),
                None => (a.as_str(), None),
            };
            match flag {
                "-y" | "--yes" | "--confirm" => push_opt(&mut options, "--yes"),
                "--version" => {
                    let v = match inline {
                        Some(v) => v,
                        None => {
                            i += 1;
                            args.get(i)
                                .cloned()
                                .ok_or_else(|| unsupported("choco `--version` needs a value"))?
                        }
                    };
                    if !simple_name(&v, "._+-") {
                        return Err(unsupported(format!("invalid choco version `{v}`")));
                    }
                    version = Some(v);
                }
                "--pre" | "--prerelease" => push_opt(&mut options, "--prerelease"),
                "--x86" | "--forcex86" => push_opt(&mut options, "--forcex86"),
                "-s" | "--source" => {
                    return Err(unsupported(
                        "choco `--source` is not supported; only the community repository is resolved",
                    ));
                }
                _ => {
                    return Err(unsupported(format!(
                        "unsupported choco option `{a}` (supported: -y/--yes, --version, --pre, --x86)"
                    )));
                }
            }
        } else if !install {
            if a == "install" {
                install = true;
            } else {
                return Err(unsupported(format!(
                    "`choco {a}` is not supported; only `choco install <pkg>` is"
                )));
            }
        } else {
            reject_path_or_url("choco", a)?;
            if a.ends_with(".nupkg") || a.ends_with(".config") {
                return Err(unsupported(format!(
                    "choco: `{a}` is a local file; run `bytebouncer inspect <file>` instead"
                )));
            }
            if !simple_name(a, "._-") {
                return Err(invalid(
                    "choco",
                    a,
                    "package ids use letters, digits and `._-`",
                ));
            }
            packages.push(a.clone());
        }
        i += 1;
    }
    if !install {
        return Err(unsupported("missing operation; use `choco install <pkg>`"));
    }
    if let Some(v) = version {
        if packages.len() > 1 {
            return Err(unsupported(
                "choco `--version` with several packages is ambiguous; request one package",
            ));
        }
        options.push(format!("--version={v}"));
    }
    Ok((Manager::Chocolatey, packages, options))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> PackageRequest {
        parse_command_str(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    fn err(s: &str) -> String {
        match parse_command_str(s) {
            Ok(r) => panic!("{s:?} should be rejected, got {r:?}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn accepted_requests() {
        let table: &[(&str, Manager, &[&str], &[&str])] = &[
            ("pacman -S firefox", Manager::Pacman, &["firefox"], &[]),
            (
                "pacman --sync firefox curl",
                Manager::Pacman,
                &["firefox", "curl"],
                &[],
            ),
            (
                "pacman -S --needed --noconfirm extra/firefox",
                Manager::Pacman,
                &["extra/firefox"],
                &["--needed", "--noconfirm"],
            ),
            ("pacman firefox -S", Manager::Pacman, &["firefox"], &[]),
            (
                "  pacman   -S\tgtk2+extra  ",
                Manager::Pacman,
                &["gtk2+extra"],
                &[],
            ),
            ("yay -S yay", Manager::Aur, &["yay"], &[]),
            (
                "paru -S --needed aur/paru-bin",
                Manager::Aur,
                &["aur/paru-bin"],
                &["--needed"],
            ),
            ("apt install curl", Manager::Apt, &["curl"], &[]),
            (
                "apt-get install -y curl=7.88.1-10+deb12u5",
                Manager::Apt,
                &["curl=7.88.1-10+deb12u5"],
                &["--yes"],
            ),
            (
                "apt install --yes curl/bookworm-backports libc6:amd64",
                Manager::Apt,
                &["curl/bookworm-backports", "libc6:amd64"],
                &["--yes"],
            ),
            (
                "apt install pkg=1.0~rc1",
                Manager::Apt,
                &["pkg=1.0~rc1"],
                &[],
            ),
            (
                "dnf install -y curl",
                Manager::Dnf,
                &["curl"],
                &["--assumeyes"],
            ),
            ("dnf install curl-8.6.0", Manager::Dnf, &["curl-8.6.0"], &[]),
            ("brew install wget", Manager::Homebrew, &["wget"], &[]),
            (
                "brew install --cask firefox",
                Manager::Homebrew,
                &["firefox"],
                &["--cask"],
            ),
            (
                "brew install --formula openssl@3",
                Manager::Homebrew,
                &["openssl@3"],
                &["--formula"],
            ),
            (
                "brew install user/tap/tool",
                Manager::Homebrew,
                &["user/tap/tool"],
                &[],
            ),
            (
                "winget install --id Microsoft.PowerToys --exact",
                Manager::Winget,
                &["Microsoft.PowerToys"],
                &["--exact"],
            ),
            (
                "winget install --id=7zip.7zip -e --version 24.09",
                Manager::Winget,
                &["7zip.7zip"],
                &["--exact", "--version=24.09"],
            ),
            (
                "winget install -e 7zip.7zip --source winget",
                Manager::Winget,
                &["7zip.7zip"],
                &["--exact", "--source=winget", "--query-as-id"],
            ),
            (
                "winget install --id Git.Git",
                Manager::Winget,
                &["Git.Git"],
                &[],
            ),
            (
                "winget install --id Git.Git -a arm64 --scope user --accept-package-agreements",
                Manager::Winget,
                &["Git.Git"],
                &[
                    "--architecture=arm64",
                    "--scope=user",
                    "--accept-package-agreements",
                ],
            ),
            ("scoop install 7zip", Manager::Scoop, &["7zip"], &[]),
            (
                "scoop install extras/vscode git@2.40.0",
                Manager::Scoop,
                &["extras/vscode", "git@2.40.0"],
                &[],
            ),
            (
                "scoop install -a 32bit 7zip",
                Manager::Scoop,
                &["7zip"],
                &["--arch=32bit"],
            ),
            (
                "choco install 7zip -y",
                Manager::Chocolatey,
                &["7zip"],
                &["--yes"],
            ),
            (
                "choco install git --version 2.40.0",
                Manager::Chocolatey,
                &["git"],
                &["--version=2.40.0"],
            ),
            (
                "choco install git --version=2.40.0 --yes",
                Manager::Chocolatey,
                &["git"],
                &["--yes", "--version=2.40.0"],
            ),
            ("pacman -S 'firefox'", Manager::Pacman, &["firefox"], &[]),
            ("pacman -S \"fire\"fox", Manager::Pacman, &["firefox"], &[]),
        ];
        for (input, manager, packages, options) in table {
            let r = ok(input);
            assert_eq!(&r.manager, manager, "{input}");
            assert_eq!(r.packages, *packages, "{input}");
            assert_eq!(r.options, *options, "{input}");
            assert_eq!(r.operation, "install");
            assert_eq!(r.raw, input.trim());
        }
    }

    #[test]
    fn rejected_requests() {
        let table: &[(&str, &str)] = &[
            ("", "empty"),
            ("   ", "empty"),
            ("pacman -S firefox | sh", "pipe"),
            ("pacman -S firefox; rm -rf /", "command separator"),
            ("pacman -S firefox && echo", "`&&`"),
            ("pacman -S firefox || echo", "`||`"),
            ("pacman -S firefox &", "background"),
            ("pacman -S $PKG", "`$`"),
            ("pacman -S \"$PKG\"", "`$`"),
            ("pacman -S `id`", "backtick"),
            ("pacman -S \"`id`\"", "backtick"),
            ("pacman -S $(id)", "`$`"),
            ("pacman -S (firefox)", "parentheses"),
            ("pacman -S firefox > log", "redirection"),
            ("pacman -S firefox >> log", "`>>`"),
            ("pacman -S firefox < in", "redirection"),
            ("pacman -S fire*", "glob"),
            ("pacman -S fire?ox", "glob"),
            ("pacman -S fire[f]ox", "glob"),
            ("pacman -S {a,b}", "brace"),
            ("pacman -S ~/pkg", "`~`"),
            ("pacman -S firefox\nrm", "newline"),
            ("pacman -S 'fire\nfox'", "newline"),
            ("pacman -S 'fire*'", "even when quoted"),
            ("pacman -S 'a;b'", "even when quoted"),
            ("pacman -S \"unterminated", "unterminated"),
            ("pacman -S fire\\fox", "backslash"),
            ("pacman -S \"a\\nb\"", "only `\\\"`"),
            ("pacman -S #comment", "comment"),
            ("pacman -S !1", "history"),
            ("pacman -S ''", "empty word"),
            ("sudo pacman -S firefox", "never installs; drop `sudo`"),
            ("doas pacman -S firefox", "drop `doas`"),
            ("FOO=1 apt install curl", "environment assignment"),
            ("/usr/bin/pacman -S curl", "by name, not by path"),
            ("npm install left-pad", "unsupported package manager"),
            ("yum install curl", "dnf"),
            ("pacman", "needs an operation"),
            ("pacman firefox", "missing operation"),
            ("pacman -Sy firefox", "whole system"),
            ("pacman -Syu firefox", "whole system"),
            ("pacman -Su", "whole system"),
            ("pacman -u", "whole system"),
            ("pacman -S --refresh firefox", "--refresh"),
            ("pacman -Ss firefox", "query/download"),
            ("pacman -Sw firefox", "query/download"),
            ("pacman -U ./x.pkg.tar.zst", "local file"),
            ("pacman -R firefox", "not an install"),
            (
                "pacman -S --overwrite x firefox",
                "unsupported pacman option",
            ),
            ("pacman -S -x firefox", "unsupported pacman flag"),
            ("pacman -S", "names no package"),
            ("pacman -S a/b/c", "single `/`"),
            ("pacman -S 'curl>=8'", "even when quoted"),
            ("pacman -S https://x/y.pkg.tar.zst", "URL"),
            ("yay", "full system upgrade"),
            ("yay firefox", "interactive search"),
            ("paru -Syu", "whole system"),
            ("apt install", "names no package"),
            ("apt upgrade", "whole system"),
            ("apt remove curl", "only `apt install"),
            ("apt install -f curl", "unsupported apt option"),
            ("apt install ./x.deb", "local file"),
            ("apt install Curl", "lowercase"),
            ("apt-get curl", "only `apt-get install"),
            ("dnf install @development", "groups"),
            ("dnf install --nogpgcheck curl", "unsupported dnf option"),
            ("dnf upgrade", "only `dnf install"),
            ("dnf install ./x.rpm", "local file"),
            ("brew install --HEAD wget", "changes how"),
            ("brew install -s wget", "changes how"),
            ("brew install --cask --formula wget", "mutually exclusive"),
            ("brew install --verbose wget", "unsupported brew option"),
            ("brew upgrade", "only `brew install"),
            ("brew install a/b", "user/tap/name"),
            ("winget install PowerToys", "fuzzy search"),
            ("winget install Microsoft.PowerToys", "fuzzy search"),
            ("winget install -e \"Visual Studio Code\"", "fuzzy search"),
            ("winget install --name PowerToys", "fuzzy search"),
            ("winget install --id Foo.Bar --source msstore", "msstore"),
            ("winget install --id", "needs a value"),
            (
                "winget install --id Foo.Bar --silent",
                "unsupported winget option",
            ),
            ("winget install --id Foo.Bar Baz.Qux", "not both"),
            ("winget upgrade --all", "only `winget install"),
            ("winget install --id NoDot", "Publisher.Package"),
            ("winget install --id Foo.Bar -a mips", "architecture"),
            ("scoop install", "names no package"),
            ("scoop install -s 7zip", "hash verification"),
            ("scoop install https://x/y.json", "URL"),
            ("scoop install a/b/c", "bucket/app"),
            ("scoop update 7zip", "only `scoop install"),
            ("choco install", "names no package"),
            ("choco install git --source https://evil", "--source"),
            ("choco install git vim --version 1.0", "ambiguous"),
            ("choco install git --force", "unsupported choco option"),
            ("choco upgrade all", "only `choco install"),
        ];
        for (input, needle) in table {
            let e = err(input);
            assert!(
                e.contains(needle),
                "{input:?}: error {e:?} should mention {needle:?}"
            );
        }
    }

    #[test]
    fn argv_form() {
        let argv: Vec<String> = [
            "winget",
            "install",
            "--id",
            "Microsoft.PowerToys",
            "--exact",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let r = parse_argv(&argv).unwrap();
        assert_eq!(r.manager, Manager::Winget);
        assert_eq!(r.packages, vec!["Microsoft.PowerToys"]);
        assert_eq!(r.raw, "winget install --id Microsoft.PowerToys --exact");

        let bad = |v: &[&str]| {
            parse_argv(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap_err()
        };
        assert!(
            bad(&["sudo", "apt", "install", "curl"])
                .to_string()
                .contains("drop `sudo`")
        );
        assert!(
            bad(&["apt", "install", "curl;id"])
                .to_string()
                .contains("separator")
        );
        assert!(
            bad(&["apt", "install", "$(id)"])
                .to_string()
                .contains("`$`")
        );
        assert!(bad(&["apt", "install", "~/x"]).to_string().contains("`~`"));
        assert!(
            bad(&["apt", "install", "a b"])
                .to_string()
                .contains("lowercase")
        );
        assert!(
            bad(&["apt", "install", "a\nb"])
                .to_string()
                .contains("newline")
        );
        assert_eq!(bad(&[]), ParseError::Empty);
    }
}

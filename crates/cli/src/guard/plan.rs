//! Small native-manager connectors. The review/approval code knows nothing
//! about distributions. Unknown install options fail before any command runs.

use std::path::Path;

use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manager {
    Pacman,
    Apt,
    Dnf,
    Dnf5,
}

pub enum Plan {
    Passthrough,
    Packages {
        manager: Manager,
        download: Vec<String>,
        local: Vec<String>,
        install_options: Vec<String>,
    },
    Helper,
    Recipe,
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_owned()).collect()
}

pub fn plan(program: &str, args: &[String], downloads: &Path) -> Result<Plan> {
    match program {
        "pacman" => pacman(args, downloads),
        "apt" | "apt-get" => apt(args, downloads),
        "dnf" | "dnf5" => dnf(program, args, downloads),
        "yay" | "paru" => {
            // These would bypass the callbacks or persist a temporary callback.
            for a in args {
                if [
                    "--pacman",
                    "--makepkg",
                    "--sudo",
                    "--save",
                    "--mflags",
                    "--chroot",
                ]
                .iter()
                .any(|flag| a == flag || a.starts_with(&format!("{flag}=")))
                {
                    bail!("{a} cannot be combined with ByteBouncer's AUR callbacks");
                }
            }
            Ok(Plan::Helper)
        }
        "makepkg" => Ok(Plan::Recipe),
        _ => bail!("guard supports pacman, yay, paru, apt, apt-get, dnf and dnf5 on Linux"),
    }
}

fn pacman(args: &[String], downloads: &Path) -> Result<Plan> {
    let mut operation = None;
    let mut flags = String::new();
    let mut targets = Vec::new();
    let mut options = Vec::new();
    let mut unknown = Vec::new();
    let mut end = false;
    let mut words = args.iter();
    while let Some(a) = words.next() {
        if end {
            targets.push(a.clone());
        } else if a == "--" {
            end = true;
        } else if let Some(long) = a.strip_prefix("--") {
            match long {
                "sync" => set_operation(&mut operation, 'S')?,
                "upgrade" => set_operation(&mut operation, 'U')?,
                "query" => set_operation(&mut operation, 'Q')?,
                "remove" => set_operation(&mut operation, 'R')?,
                "database" => set_operation(&mut operation, 'D')?,
                "files" => set_operation(&mut operation, 'F')?,
                "deptest" => set_operation(&mut operation, 'T')?,
                "help" | "version" => return Ok(Plan::Passthrough),
                "refresh" => flags.push('y'),
                "sysupgrade" => flags.push('u'),
                "search" => flags.push('s'),
                "info" => flags.push('i'),
                "list" => flags.push('l'),
                "groups" => flags.push('g'),
                "print" => flags.push('p'),
                "downloadonly" => flags.push('w'),
                "clean" => flags.push('c'),
                "needed" | "noconfirm" | "confirm" | "asdeps" | "asexplicit" | "quiet" => {
                    options.push(a.clone());
                }
                "config" | "color" | "ask" => {
                    let value = words
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("{a} needs a value"))?;
                    options.extend([a.clone(), value.clone()]);
                }
                _ if long.starts_with("config=")
                    || long.starts_with("color=")
                    || long.starts_with("ask=") =>
                {
                    options.push(a.clone())
                }
                _ => unknown.push(a.clone()),
            }
        } else if let Some(short) = a.strip_prefix('-') {
            for c in short.chars() {
                match c {
                    'S' | 'U' | 'Q' | 'R' | 'D' | 'F' | 'T' => set_operation(&mut operation, c)?,
                    'h' | 'V' => return Ok(Plan::Passthrough),
                    'y' | 'u' | 's' | 'i' | 'l' | 'g' | 'p' | 'w' | 'c' | 'q' | 'n' | 'd' | 't' => {
                        flags.push(c)
                    }
                    _ => unknown.push(format!("-{c}")),
                }
            }
        } else {
            targets.push(a.clone());
        }
    }
    if matches!(operation, Some('Q' | 'R' | 'D' | 'F' | 'T')) {
        return Ok(Plan::Passthrough);
    }
    if !unknown.is_empty() {
        bail!(
            "unsupported guarded pacman options {}; no installation was started",
            unknown.join(", ")
        );
    }
    let Some(op @ ('S' | 'U')) = operation else {
        bail!("guarded pacman needs -S or -U (query and removal commands also pass through)");
    };
    if flags.chars().any(|c| "silgpwc".contains(c)) {
        return Ok(Plan::Passthrough);
    }
    if flags.chars().any(|c| "ndt".contains(c)) {
        bail!("dependency-check bypass flags are not supported by guard");
    }
    if op == 'U' && !flags.is_empty() && flags != "q" {
        bail!("unsupported flags for guarded pacman -U");
    }
    if targets.is_empty() && !flags.contains('u') {
        if op == 'S' && flags.contains('y') {
            return Ok(Plan::Passthrough);
        }
        bail!("no packages were specified");
    }
    let local = if op == 'U' {
        targets.clone()
    } else {
        Vec::new()
    };
    if local.iter().any(|p| !Path::new(p).is_file()) {
        bail!("guarded pacman -U requires local package files; download URLs first");
    }
    let mut download = vec![
        format!("-{op}{flags}"),
        "--downloadonly".into(),
        "--cachedir".into(),
        downloads.display().to_string(),
    ];
    download.extend(options.clone());
    download.push("--".into());
    download.extend(targets);
    // Local -U cannot fetch missing dependencies. Its existing archive is
    // staged directly, preserving native -U dependency validation at handoff.
    if op == 'U' {
        download.clear();
    }
    Ok(Plan::Packages {
        manager: Manager::Pacman,
        download,
        local,
        install_options: options,
    })
}

fn set_operation(op: &mut Option<char>, value: char) -> Result<()> {
    if op.is_some_and(|old| old != value) {
        bail!("multiple pacman operations are not supported");
    }
    *op = Some(value);
    Ok(())
}

fn apt(args: &[String], downloads: &Path) -> Result<Plan> {
    let Some(operation) = args.iter().find(|a| !a.starts_with('-')) else {
        return Ok(Plan::Passthrough);
    };
    if matches!(
        operation.as_str(),
        "update"
            | "remove"
            | "purge"
            | "autoremove"
            | "autopurge"
            | "clean"
            | "autoclean"
            | "show"
            | "search"
            | "list"
            | "policy"
            | "depends"
            | "rdepends"
            | "help"
            | "download"
            | "changelog"
    ) {
        return Ok(Plan::Passthrough);
    }
    if !matches!(operation.as_str(), "install" | "reinstall" | "upgrade") {
        bail!("guarded apt supports install, reinstall and upgrade; {operation} is unsupported");
    }
    let mut options = Vec::new();
    let mut targets = Vec::new();
    let mut seen_operation = false;
    let mut passthrough = false;
    for a in args {
        if a == operation && !seen_operation {
            seen_operation = true;
        } else if a.starts_with('-') {
            match a.as_str() {
                "-s" | "--simulate" | "--dry-run" | "-d" | "--download-only" | "--print-uris" => {
                    passthrough = true
                }
                "-y"
                | "--yes"
                | "--assume-yes"
                | "--no-install-recommends"
                | "--install-recommends"
                | "--no-install-suggests"
                | "--reinstall" => options.push(a.clone()),
                _ => bail!("unsupported guarded apt option {a}"),
            }
        } else {
            targets.push(a.clone());
        }
    }
    if passthrough {
        return Ok(Plan::Passthrough);
    }
    if targets.is_empty() && operation != "upgrade" {
        bail!("name at least one package; apt repair-only installations are unsupported");
    }
    let local: Vec<_> = targets
        .iter()
        .filter(|a| a.ends_with(".deb"))
        .cloned()
        .collect();
    for p in &local {
        if !Path::new(p).is_file() {
            bail!("local package does not exist: {p}");
        }
    }
    let mut download = strings(&[operation, "--download-only", "--no-remove", "-o"]);
    download.push(format!("Dir::Cache::archives={}", downloads.display()));
    download.extend(options.clone());
    download.push("--".into());
    download.extend(targets);
    Ok(Plan::Packages {
        manager: Manager::Apt,
        download,
        local,
        install_options: options,
    })
}

fn dnf(program: &str, args: &[String], downloads: &Path) -> Result<Plan> {
    let Some(operation) = args.iter().find(|a| !a.starts_with('-')) else {
        return Ok(Plan::Passthrough);
    };
    if matches!(
        operation.as_str(),
        "remove"
            | "autoremove"
            | "clean"
            | "check"
            | "check-update"
            | "check-upgrade"
            | "info"
            | "list"
            | "search"
            | "repoquery"
            | "repolist"
            | "makecache"
            | "download"
            | "help"
    ) {
        return Ok(Plan::Passthrough);
    }
    if !matches!(
        operation.as_str(),
        "install" | "upgrade" | "update" | "reinstall" | "downgrade"
    ) {
        bail!("unsupported guarded {program} operation {operation}");
    }
    let mut options = Vec::new();
    let mut targets = Vec::new();
    let mut seen_operation = false;
    let mut passthrough = false;
    for a in args {
        if a == operation && !seen_operation {
            seen_operation = true;
        } else if a.starts_with('-') {
            match a.as_str() {
                "--downloadonly" | "--assumeno" | "--help" => passthrough = true,
                "-y" | "--assumeyes" | "--best" | "--nobest" | "--refresh" => {
                    options.push(a.clone())
                }
                _ => bail!("unsupported guarded {program} option {a}"),
            }
        } else {
            targets.push(a.clone());
        }
    }
    if passthrough {
        return Ok(Plan::Passthrough);
    }
    if targets.is_empty() && !matches!(operation.as_str(), "upgrade" | "update") {
        bail!("name at least one package");
    }
    let local: Vec<_> = targets
        .iter()
        .filter(|a| a.ends_with(".rpm"))
        .cloned()
        .collect();
    for p in &local {
        if !Path::new(p).is_file() {
            bail!("local package does not exist: {p}");
        }
    }
    let mut download = if program == "dnf5" {
        // DNF5 stores the exact transaction, including package reasons, for
        // later offline replay. Storing does not perform an RPM transaction.
        vec![
            operation.clone(),
            format!("--store={}", downloads.display()),
        ]
    } else {
        vec![
            operation.clone(),
            "--downloadonly".into(),
            format!("--destdir={}", downloads.display()),
        ]
    };
    download.extend(options.clone());
    download.push("--".into());
    download.extend(targets);
    let manager = if program == "dnf5" {
        Manager::Dnf5
    } else {
        Manager::Dnf
    };
    // --refresh/best only affect repository resolution, not the local handoff.
    let install_options = options
        .into_iter()
        .filter(|a| matches!(a.as_str(), "-y" | "--assumeyes"))
        .collect();
    Ok(Plan::Packages {
        manager,
        download,
        local,
        install_options,
    })
}

pub fn install_args(
    manager: Manager,
    downloads: &Path,
    files: &[String],
    options: &[String],
    original: &[String],
) -> Vec<String> {
    if manager == Manager::Apt {
        // Replay the requested goals using ONLY the scanned cache. Naming all
        // .debs as install goals would mark dependencies as manually installed.
        let mut args = vec![
            "--no-download".into(),
            "--no-remove".into(),
            "-o".into(),
            format!("Dir::Cache::archives={}", downloads.display()),
        ];
        args.extend(original.iter().map(|a| {
            if a.ends_with(".deb") {
                downloads
                    .join(Path::new(a).file_name().unwrap_or_default())
                    .display()
                    .to_string()
            } else {
                a.clone()
            }
        }));
        return args;
    }
    if manager == Manager::Dnf {
        // DNF4's destdir configuration directs every repository's pkgdir to
        // the reviewed cache. Cache-only mode forbids fetching a missing RPM.
        let mut args = vec![
            "--cacheonly".into(),
            format!("--setopt=destdir={}", downloads.display()),
            "--setopt=keepcache=True".into(),
        ];
        args.extend(
            original
                .iter()
                .filter(|a| a.as_str() != "--refresh")
                .cloned()
                .map(|a| {
                    if a.ends_with(".rpm") {
                        downloads
                            .join(Path::new(&a).file_name().unwrap_or_default())
                            .display()
                            .to_string()
                    } else {
                        a
                    }
                }),
        );
        return args;
    }
    if manager == Manager::Dnf5 {
        let mut args = vec![
            "--cacheonly".into(),
            "replay".into(),
            downloads.display().to_string(),
        ];
        args.extend(options.iter().cloned());
        return args;
    }
    let mut args = match manager {
        Manager::Pacman => strings(&["-U"]),
        Manager::Apt => unreachable!(),
        Manager::Dnf => unreachable!(),
        Manager::Dnf5 => unreachable!(),
    };
    args.extend(options.iter().cloned());
    args.push("--".into());
    args.extend(files.iter().cloned());
    args
}

pub fn is_package(manager: Manager, path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    match manager {
        Manager::Pacman => [
            ".pkg.tar.zst",
            ".pkg.tar.xz",
            ".pkg.tar.gz",
            ".pkg.tar.bz2",
            ".pkg.tar",
        ]
        .iter()
        .any(|s| name.ends_with(s)),
        Manager::Apt => name.ends_with(".deb"),
        Manager::Dnf | Manager::Dnf5 => name.ends_with(".rpm"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        strings(s)
    }

    #[test]
    fn upgrades_download_first_and_handoff_cannot_fetch() {
        for (program, input, expected) in [
            ("pacman", args(&["-Syu"]), "--cachedir"),
            ("apt", args(&["upgrade"]), "--no-remove"),
            ("dnf", args(&["upgrade"]), "--destdir=/tmp/stage"),
            ("dnf5", args(&["upgrade"]), "--store=/tmp/stage"),
        ] {
            let Plan::Packages {
                manager,
                download,
                install_options,
                ..
            } = plan(program, &input, Path::new("/tmp/stage")).unwrap()
            else {
                panic!()
            };
            assert!(download.contains(&expected.into()), "{download:?}");
            let final_args = install_args(
                manager,
                Path::new("/tmp/stage"),
                &args(&["/tmp/stage/a"]),
                &install_options,
                &input,
            );
            if manager == Manager::Pacman {
                assert!(!final_args.contains(&"upgrade".into()));
                assert_eq!(final_args.last().unwrap(), "/tmp/stage/a");
            }
            if manager == Manager::Apt {
                assert!(final_args.contains(&"--no-download".into()));
            }
            if manager == Manager::Dnf {
                assert!(final_args.contains(&"--cacheonly".into()));
                assert!(final_args.contains(&"--setopt=destdir=/tmp/stage".into()));
            }
            if manager == Manager::Dnf5 {
                assert!(final_args.contains(&"replay".into()));
                assert!(final_args.contains(&"--cacheonly".into()));
            }
        }
    }

    #[test]
    fn unsafe_or_unhandled_options_fail_before_download() {
        for (program, input) in [
            ("pacman", args(&["-S", "foo", "--dbpath=/tmp/other"])),
            ("pacman", args(&["-Sd", "foo"])),
            ("pacman", args(&["-S", "foo", "--root", "/tmp/root"])),
            (
                "apt",
                args(&["install", "foo", "-o", "DPkg::Pre-Invoke=evil"]),
            ),
            ("apt", args(&["full-upgrade"])),
            ("dnf", args(&["install", "foo", "--allowerasing"])),
            ("yay", args(&["-S", "foo", "--pacman=other"])),
            ("paru", args(&["--save"])),
        ] {
            assert!(
                plan(program, &input, Path::new("/tmp/stage")).is_err(),
                "{program} {input:?}"
            );
        }
    }

    #[test]
    fn queries_and_removals_pass_through() {
        for (program, input) in [
            ("pacman", args(&["-Ss", "foo"])),
            ("pacman", args(&["-Rns", "foo"])),
            ("apt", args(&["search", "foo"])),
            ("apt", args(&["remove", "foo"])),
            ("dnf", args(&["info", "foo"])),
        ] {
            assert!(matches!(
                plan(program, &input, Path::new("/tmp/stage")).unwrap(),
                Plan::Passthrough
            ));
        }
    }
}

//! Arch Linux packages. `.pkg.tar.{zst,xz,gz}` is a compressed tar, so the
//! caller first expands the compression layer; the inner tar (first member
//! `.PKGINFO`) is then expanded as [`ContainerKind::ArchPackage`], which is a
//! normal tar expansion plus [`arch_package_info`] folded into metadata and
//! scripts.

use crate::util::{Sink, shebang};
use crate::{Child, ContainerKind, EntryKind, Expanded, FormatError, Limits, Script};

/// Install-relevant facts about an Arch package (scripts, hooks,
/// services).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchInfo {
    pub pkgname: Option<String>,
    pub pkgbase: Option<String>,
    pub pkgver: Option<String>,
    pub pkgdesc: Option<String>,
    pub url: Option<String>,
    pub arch: Option<String>,
    pub packager: Option<String>,
    pub license: Vec<String>,
    pub depends: Vec<String>,
    pub optdepends: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
    pub backup: Vec<String>,
    /// Every `.PKGINFO` key/value pair in file order (keys repeat).
    pub fields: Vec<(String, String)>,
    /// The `.INSTALL` scriptlet (kind `arch.install`), sourced by pacman.
    pub install_script: Option<Script>,
    /// libalpm hooks (kind `arch.hook`); their `Exec =` lines run as root.
    pub hooks: Vec<Script>,
    /// systemd unit files shipped under `usr/lib/systemd/` or `etc/systemd/`.
    pub systemd_units: Vec<String>,
    /// sysusers.d / tmpfiles.d snippets, which create users and files.
    pub sysusers_tmpfiles: Vec<String>,
}

/// Extract [`ArchInfo`] from the children of an expanded package tar.
pub fn arch_package_info(tar_children: &[Child]) -> ArchInfo {
    let mut info = ArchInfo::default();
    let files = tar_children.iter().filter(|c| c.kind == EntryKind::File);
    for c in files {
        let p = c.path.as_str();
        let text = || String::from_utf8_lossy(&c.data).into_owned();
        if p == ".PKGINFO" {
            parse_pkginfo(&text(), &mut info);
        } else if p == ".INSTALL" {
            let t = text();
            // pacman sources .INSTALL with bash regardless of any shebang.
            let interp = shebang(&t).or_else(|| Some("/bin/bash".into()));
            info.install_script = Some(Script {
                kind: "arch.install".into(),
                interpreter: interp,
                path: p.into(),
                text: t,
            });
        } else if (p.starts_with("usr/share/libalpm/hooks/")
            || p.starts_with("etc/pacman.d/hooks/"))
            && p.ends_with(".hook")
        {
            let exec = text().lines().find_map(|l| {
                l.trim()
                    .strip_prefix("Exec")
                    .map(|r| r.trim_start_matches([' ', '=']).trim().to_owned())
            });
            info.hooks.push(Script {
                kind: "arch.hook".into(),
                interpreter: exec,
                path: p.into(),
                text: text(),
            });
        } else if p.starts_with("usr/lib/systemd/") || p.starts_with("etc/systemd/") {
            info.systemd_units.push(p.into());
        } else if p.starts_with("usr/lib/sysusers.d/") || p.starts_with("usr/lib/tmpfiles.d/") {
            info.sysusers_tmpfiles.push(p.into());
        }
    }
    // Unit symlinks (e.g. enablement under *.wants/) also matter.
    for c in tar_children
        .iter()
        .filter(|c| matches!(c.kind, EntryKind::Symlink { .. }))
    {
        if c.path.starts_with("usr/lib/systemd/") || c.path.starts_with("etc/systemd/") {
            info.systemd_units.push(c.path.clone());
        }
    }
    info
}

fn parse_pkginfo(body: &str, info: &mut ArchInfo) {
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim().to_owned());
        info.fields.push((k.to_owned(), v.clone()));
        let one = |slot: &mut Option<String>| *slot = Some(v.clone());
        match k {
            "pkgname" => one(&mut info.pkgname),
            "pkgbase" => one(&mut info.pkgbase),
            "pkgver" => one(&mut info.pkgver),
            "pkgdesc" => one(&mut info.pkgdesc),
            "url" => one(&mut info.url),
            "arch" => one(&mut info.arch),
            "packager" => one(&mut info.packager),
            "license" => info.license.push(v),
            "depend" => info.depends.push(v),
            "optdepend" => info.optdepends.push(v),
            "provides" => info.provides.push(v),
            "conflict" => info.conflicts.push(v),
            "replaces" => info.replaces.push(v),
            "backup" => info.backup.push(v),
            _ => {}
        }
    }
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if !crate::tar::is_tar(bytes) {
        return Err(FormatError::malformed(
            ContainerKind::ArchPackage,
            "not a tar archive",
        ));
    }
    let mut sink = Sink::new(ContainerKind::ArchPackage, limits, bytes.len());
    crate::tar::read_into(bytes, &mut sink, "");
    let info = arch_package_info(&sink.out.children);
    if info.pkgname.is_none() {
        sink.problem("arch: .PKGINFO missing or has no pkgname");
    }
    for (k, v) in &info.fields {
        sink.meta(format!("arch.{k}"), v.clone());
    }
    for u in &info.systemd_units {
        sink.meta("arch.systemd_unit", u.clone());
    }
    for u in &info.sysusers_tmpfiles {
        sink.meta("arch.sysusers_tmpfiles", u.clone());
    }
    for h in &info.hooks {
        sink.meta("arch.hook", h.path.clone());
    }
    sink.out.scripts.extend(info.install_script);
    sink.out.scripts.extend(info.hooks);
    Ok(sink.finish())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> Vec<u8> {
        crate::tar::tests::build(
            &[
                (".PKGINFO", b"# Generated by makepkg\npkgname = hello\npkgver = 1.0-1\narch = x86_64\ndepend = glibc\ndepend = bash>=5\nbackup = etc/hello.conf\n"),
                (".INSTALL", b"post_install() {\n  systemctl enable hello\n}\n"),
                ("usr/share/libalpm/hooks/hello.hook", b"[Trigger]\nType = Path\nTarget = usr/lib/*\n[Action]\nWhen = PostTransaction\nExec = /usr/bin/hello --refresh\n"),
                ("usr/lib/systemd/system/hello.service", b"[Service]\nExecStart=/usr/bin/hello\n"),
                ("usr/lib/sysusers.d/hello.conf", b"u hello - -\n"),
                ("usr/bin/hello", b"\x7fELF"),
            ],
            &[],
        )
    }

    #[test]
    fn package_info_scripts_and_units() {
        let out = expand(&sample(), &Limits::default()).unwrap();
        assert_eq!(out.meta("arch.pkgname"), Some("hello"));
        assert_eq!(
            out.meta("arch.systemd_unit"),
            Some("usr/lib/systemd/system/hello.service")
        );
        assert_eq!(out.scripts[0].kind, "arch.install");
        assert_eq!(out.scripts[0].interpreter.as_deref(), Some("/bin/bash"));
        assert_eq!(out.scripts[1].kind, "arch.hook");
        assert_eq!(
            out.scripts[1].interpreter.as_deref(),
            Some("/usr/bin/hello --refresh")
        );
        let info = arch_package_info(&out.children);
        assert_eq!(info.depends, ["glibc", "bash>=5"]);
        assert_eq!(info.backup, ["etc/hello.conf"]);
        assert_eq!(info.sysusers_tmpfiles, ["usr/lib/sysusers.d/hello.conf"]);
        assert!(out.problems.is_empty(), "{:?}", out.problems);
        assert_eq!(
            crate::detect(&sample(), ""),
            Some(ContainerKind::ArchPackage)
        );
    }

    /// Real-world check against the host's pacman cache:
    /// `BYTEBOUNCER_ARCH_PKG=/var/cache/pacman/pkg/foo.pkg.tar.zst cargo test -- --ignored`
    #[test]
    #[ignore]
    fn real_pacman_package() {
        let path = std::env::var("BYTEBOUNCER_ARCH_PKG").expect("set BYTEBOUNCER_ARCH_PKG");
        let bytes = std::fs::read(&path).unwrap();
        let limits = Limits::default();
        let outer = crate::detect(&bytes, &path).unwrap();
        let inner = crate::expand(&bytes, outer, &limits).unwrap();
        let tar = &inner.children[0].data;
        assert_eq!(crate::detect(tar, ""), Some(ContainerKind::ArchPackage));
        let out = crate::expand(tar, ContainerKind::ArchPackage, &limits).unwrap();
        println!(
            "{} children, problems {:?}",
            out.children.len(),
            out.problems
        );
        for (k, v) in out.metadata.iter().take(40) {
            println!("{k} = {v}");
        }
        for s in &out.scripts {
            println!("script {} {:?} {}", s.kind, s.interpreter, s.path);
        }
        assert!(out.meta("arch.pkgname").is_some());
    }
}

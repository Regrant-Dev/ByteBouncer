//! Unix `ar` archives (GNU and BSD name variants) and Debian packages built
//! on them.
//!
//! A `.deb` expands its `control.tar.*` inline (control files become
//! children under `control/`, fields become `deb.control.*` metadata and
//! maintainer scripts become [`Script`](crate::Script)s), while `data.tar.*`
//! is returned as a raw child for the caller to recurse into. That keeps one
//! level per call and avoids holding the payload twice.

use crate::compress::{decompress, note_stream};
use crate::detect::compression;
use crate::util::{Sink, shebang, slice, text};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

pub(crate) const MAGIC: &[u8] = b"!<arch>\n";

/// One raw ar member.
pub(crate) struct Member<'a> {
    pub(crate) name: String,
    pub(crate) mode: Option<u32>,
    pub(crate) data: &'a [u8],
}

/// Parse ar members. Malformed trailing data ends the walk with a problem.
pub(crate) fn members<'a>(bytes: &'a [u8], problems: &mut Vec<String>) -> Vec<Member<'a>> {
    let mut out = Vec::new();
    let mut long_names: &[u8] = &[];
    let mut off = MAGIC.len();
    while off < bytes.len() {
        let Some(h) = slice(bytes, off, 60) else {
            problems.push(format!("ar: truncated header at offset {off}"));
            break;
        };
        if &h[58..60] != b"`\n" {
            problems.push(format!("ar: bad header magic at offset {off}"));
            break;
        }
        let field = |r: std::ops::Range<usize>| text(&h[r]).trim().to_owned();
        let Ok(size) = field(48..58).parse::<usize>() else {
            problems.push(format!("ar: bad size field at offset {off}"));
            break;
        };
        let mode = u32::from_str_radix(&field(40..48), 8).ok();
        let mut data_off = off + 60;
        let Some(mut data) = slice(bytes, data_off, size) else {
            problems.push(format!("ar: truncated member at offset {off}"));
            break;
        };
        let raw = field(0..16);
        let name = if raw == "//" {
            long_names = data;
            None
        } else if raw == "/" || raw == "/SYM64/" || raw.starts_with("__.SYMDEF") {
            None
        } else if let Some(n) = raw.strip_prefix("#1/") {
            // BSD: name stored at the start of the data.
            let n: usize = n.parse().unwrap_or(usize::MAX);
            match (data.get(..n), data.get(n..)) {
                (Some(name), Some(rest)) => {
                    data_off += n;
                    data = rest;
                    Some(text(name))
                }
                _ => {
                    problems.push(format!("ar: bad BSD long name at offset {off}"));
                    break;
                }
            }
        } else if let Some(idx) = raw.strip_prefix('/').and_then(|i| i.parse::<usize>().ok()) {
            let rest = long_names.get(idx..).unwrap_or(&[]);
            let end = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
            Some(text(&rest[..end]).trim_end_matches('/').to_owned())
        } else {
            Some(raw.trim_end_matches('/').to_owned())
        };
        let _ = data_off;
        if let Some(name) = name {
            out.push(Member { name, mode, data });
        }
        off = off + 60 + size + (size & 1);
    }
    out
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if !bytes.starts_with(MAGIC) {
        return Err(FormatError::malformed(ContainerKind::Ar, "no ar magic"));
    }
    let mut sink = Sink::new(ContainerKind::Ar, limits, bytes.len());
    let mut problems = Vec::new();
    for m in members(bytes, &mut problems) {
        if sink.full() || !push_member(&mut sink, &m.name, m.mode, m.data) {
            break;
        }
    }
    problems.into_iter().for_each(|p| sink.problem(p));
    Ok(sink.finish())
}

fn push_member(sink: &mut Sink, name: &str, mode: Option<u32>, data: &[u8]) -> bool {
    let mut data = data.to_vec();
    if data.len() as u64 > sink.entry_budget() {
        sink.truncate(format!("{name:?} exceeds the entry size limit"));
        data.truncate(sink.entry_budget() as usize);
    }
    sink.push(name, EntryKind::File, mode, data)
}

/// Maintainer scripts dpkg runs (or feeds to debconf) at install time.
const DEB_SCRIPTS: &[&str] = &[
    "preinst", "postinst", "prerm", "postrm", "config", "triggers",
];

pub(crate) fn expand_deb(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if !bytes.starts_with(MAGIC) {
        return Err(FormatError::malformed(ContainerKind::Deb, "no ar magic"));
    }
    let mut sink = Sink::new(ContainerKind::Deb, limits, bytes.len());
    let mut problems = Vec::new();
    let members = members(bytes, &mut problems);
    problems.into_iter().for_each(|p| sink.problem(p));
    if !members.iter().any(|m| m.name == "debian-binary") {
        sink.problem("deb: missing debian-binary member");
    }
    for m in &members {
        if sink.full() {
            break;
        }
        if m.name == "debian-binary" {
            sink.meta("deb.format", text(m.data).trim());
        }
        if m.name.starts_with("control.tar") {
            let tar = match compression(m.data) {
                Some(kind) => {
                    let b = decompress(kind, m.data, sink.entry_cap(m.data.len() as u64));
                    note_stream(&mut sink, &b, &m.name);
                    b.data
                }
                None => m.data.to_vec(),
            };
            let before = sink.out.children.len();
            crate::tar::read_into(&tar, &mut sink, "control");
            control_files(&mut sink, before);
        } else if !push_member(&mut sink, &m.name, m.mode, m.data) {
            break;
        }
    }
    Ok(sink.finish())
}

/// Turn freshly added `control/*` children into metadata and scripts.
fn control_files(sink: &mut Sink, from: usize) {
    let files: Vec<(String, String)> = sink.out.children[from..]
        .iter()
        .filter(|c| c.kind == EntryKind::File)
        .map(|c| {
            (
                c.path.clone(),
                String::from_utf8_lossy(&c.data).into_owned(),
            )
        })
        .collect();
    for (path, body) in files {
        let name = path.trim_start_matches("control/");
        if name == "control" {
            for (k, v) in control_fields(&body) {
                sink.meta(format!("deb.control.{k}"), v);
            }
        } else if DEB_SCRIPTS.contains(&name) {
            sink.script(&format!("deb.{name}"), shebang(&body), &path, body);
        } else if name == "conffiles" {
            for line in body.lines().filter(|l| !l.trim().is_empty()) {
                sink.meta("deb.conffile", line.trim());
            }
        }
    }
}

/// Parse an RFC 822-style control paragraph, joining continuation lines.
pub(crate) fn control_fields(body: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in body.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push('\n');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a GNU-style ar archive.
    pub(crate) fn build(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for (name, data) in members {
            out.extend_from_slice(
                format!(
                    "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    format!("{name}/"),
                    0,
                    0,
                    0,
                    100644,
                    data.len()
                )
                .as_bytes(),
            );
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    pub(crate) fn sample_deb() -> Vec<u8> {
        let control = crate::tar::tests::build(
            &[
                (
                    "./control",
                    b"Package: hello\nVersion: 1.0\nDescription: greeter\n more text\n",
                ),
                ("./postinst", b"#!/bin/sh\nset -e\nsystemctl enable hello\n"),
                ("./prerm", b"#!/bin/bash\nexit 0\n"),
                ("./conffiles", b"/etc/hello.conf\n"),
            ],
            &[],
        );
        let data = crate::tar::tests::build(&[("./usr/bin/hello", b"\x7fELF")], &[]);
        build(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", &crate::compress::tests::gz(&control)),
            ("data.tar.gz", &crate::compress::tests::gz(&data)),
        ])
    }

    #[test]
    fn deb_control_and_scripts() {
        let out = expand_deb(&sample_deb(), &Limits::default()).unwrap();
        assert_eq!(out.meta("deb.control.Package"), Some("hello"));
        assert_eq!(
            out.meta("deb.control.Description"),
            Some("greeter\nmore text")
        );
        assert_eq!(out.meta("deb.format"), Some("2.0"));
        assert_eq!(out.meta("deb.conffile"), Some("/etc/hello.conf"));
        let kinds: Vec<_> = out.scripts.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(kinds, ["deb.postinst", "deb.prerm"]);
        assert_eq!(out.scripts[0].interpreter.as_deref(), Some("/bin/sh"));
        assert!(out.child("control/postinst").is_some());
        let data = out.child("data.tar.gz").unwrap();
        assert_eq!(
            crate::detect(&data.data, "data.tar.gz"),
            Some(ContainerKind::Gzip)
        );
        assert!(out.problems.is_empty(), "{:?}", out.problems);
    }

    #[test]
    fn plain_ar_and_long_names() {
        let mut bytes = MAGIC.to_vec();
        let table = b"a_very_long_member_name.o/\n";
        bytes.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "//",
                0,
                0,
                0,
                0,
                table.len()
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(table);
        bytes.push(b'\n');
        bytes.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "/0", 0, 0, 0, 644, 2
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(b"hi");
        bytes.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "#1/8", 0, 0, 0, 644, 9
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(b"bsd_name!\n");
        let out = expand(&bytes, &Limits::default()).unwrap();
        let paths: Vec<_> = out.children.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, ["a_very_long_member_name.o", "bsd_name"]);
        assert_eq!(out.children[1].data, b"!");
    }

    #[test]
    fn truncated_debs_never_panic() {
        let deb = sample_deb();
        for n in 0..deb.len() {
            let _ = expand_deb(&deb[..n], &Limits::default());
            let _ = expand(&deb[..n], &Limits::default());
        }
        let out = expand_deb(&deb[..deb.len() - 10], &Limits::default()).unwrap();
        assert!(!out.problems.is_empty());
    }
}

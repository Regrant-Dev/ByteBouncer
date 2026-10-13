//! tar archives (v7, ustar, GNU long names/sparse, pax) via the `tar` crate,
//! which handles header variants; we only read, never unpack to disk.

use tar::EntryType;

use crate::util::{Sink, read_bounded, text};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

/// True if `b` starts with a ustar/GNU header or a v7 header whose checksum
/// verifies (v7 tar has no magic).
pub(crate) fn is_tar(b: &[u8]) -> bool {
    let Some(h) = b.get(..512) else { return false };
    if &h[257..262] == b"ustar" {
        return true;
    }
    let stored = text(&h[148..156]);
    let Ok(stored) = u32::from_str_radix(stored.trim().trim_end_matches('\0'), 8) else {
        return false;
    };
    let sum: u32 = h
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if (148..156).contains(&i) {
                32
            } else {
                c as u32
            }
        })
        .sum();
    h[0] != 0 && sum == stored
}

/// Paths of the first `n` entries (headers only; used for detection).
pub(crate) fn leading_names(bytes: &[u8], n: usize) -> Vec<String> {
    let mut archive = tar::Archive::new(bytes);
    let Ok(entries) = archive.entries() else {
        return Vec::new();
    };
    entries
        .take(n)
        .map_while(Result::ok)
        .map(|e| String::from_utf8_lossy(&e.path_bytes()).into_owned())
        .collect()
}

pub(crate) fn expand(
    bytes: &[u8],
    kind: ContainerKind,
    limits: &Limits,
) -> Result<Expanded, FormatError> {
    if !is_tar(bytes) {
        return Err(FormatError::malformed(kind, "no valid tar header"));
    }
    let mut sink = Sink::new(kind, limits, bytes.len());
    read_into(bytes, &mut sink, "");
    Ok(sink.finish())
}

/// Append every tar entry to `sink` under `prefix`.
pub(crate) fn read_into(bytes: &[u8], sink: &mut Sink, prefix: &str) {
    let mut archive = tar::Archive::new(bytes);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => return sink.problem(format!("tar: {e}")),
    };
    for entry in entries {
        if sink.full() {
            return;
        }
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => return sink.problem(format!("tar: corrupt or truncated archive: {e}")),
        };
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let link = entry
            .link_name_bytes()
            .map(|l| String::from_utf8_lossy(&l).into_owned())
            .unwrap_or_default();
        let mode = entry.header().mode().ok();
        let kind = match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => EntryKind::File,
            EntryType::Directory => EntryKind::Directory,
            EntryType::Symlink => EntryKind::Symlink { target: link },
            EntryType::Link => EntryKind::Hardlink { target: link },
            EntryType::Char => EntryKind::Special("character device".into()),
            EntryType::Block => EntryKind::Special("block device".into()),
            EntryType::Fifo => EntryKind::Special("fifo".into()),
            other => EntryKind::Special(format!("tar entry type {:?}", other.as_byte() as char)),
        };
        let mut data = Vec::new();
        let declared = entry.header().size().unwrap_or(0);
        if kind == EntryKind::File && declared > sink.limits.max_entry_bytes {
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            sink.oversized(&path, declared);
            continue;
        }
        if kind == EntryKind::File {
            let b = read_bounded(&mut entry, sink.entry_budget());
            if b.capped {
                sink.truncate(format!("tar: {name:?} exceeds the entry size limit"));
            }
            if let Some(e) = b.error {
                sink.problem(format!("tar: truncated data for {name:?}: {e}"));
            }
            data = b.data;
        }
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if !sink.push(&path, kind, mode, data) {
            return;
        }
    }
}

/// Stream the regular file whose normalized path is `want` into `out`.
pub(crate) fn extract(
    bytes: &[u8],
    want: &str,
    out: &mut dyn std::io::Write,
    max: u64,
) -> Result<u64, String> {
    let mut archive = tar::Archive::new(bytes);
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        if crate::util::normalize_path(&name).0 != want {
            continue;
        }
        if !matches!(
            entry.header().entry_type(),
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse
        ) {
            return Err(format!("{want:?} is not a regular file"));
        }
        return copy_capped(entry, out, max);
    }
    Err(format!("{want:?} not found"))
}

/// Copy at most `max` bytes; error if the source has more.
pub(crate) fn copy_capped(
    src: impl std::io::Read,
    out: &mut dyn std::io::Write,
    max: u64,
) -> Result<u64, String> {
    let mut limited = src.take(max.saturating_add(1));
    let n = std::io::copy(&mut limited, out).map_err(|e| e.to_string())?;
    if n > max {
        return Err(format!("entry exceeds the {max}-byte extraction limit"));
    }
    Ok(n)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a tar from `(path, data)` pairs plus optional symlinks.
    pub(crate) fn build(files: &[(&str, &[u8])], links: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_entry_type(EntryType::Regular);
            raw_path(&mut h, path);
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        for (path, target) in links {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(EntryType::Symlink);
            h.set_size(0);
            raw_path(&mut h, path);
            h.set_link_name(target).unwrap();
            h.set_cksum();
            b.append(&h, &[][..]).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// Write a path without the builder's own traversal checks, so tests can
    /// produce hostile archives.
    fn raw_path(h: &mut tar::Header, path: &str) {
        let name = &mut h.as_old_mut().name;
        name.fill(0);
        name[..path.len()].copy_from_slice(path.as_bytes());
    }

    #[test]
    fn reads_files_links_and_long_names() {
        let mut b = tar::Builder::new(Vec::new());
        let long = format!("{}/file.txt", "d".repeat(150));
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        b.append_data(&mut h, &long, &b"abc"[..]).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(EntryType::Link);
        h.set_size(0);
        b.append_link(&mut h, "hard", &long).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(EntryType::Directory);
        h.set_size(0);
        b.append_data(&mut h, "dir/", &[][..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let out = expand(&bytes, ContainerKind::Tar, &Limits::default()).unwrap();
        assert_eq!(out.children[0].path, long);
        assert_eq!(out.children[0].data, b"abc");
        assert_eq!(
            out.children[1].kind,
            EntryKind::Hardlink {
                target: long.clone()
            }
        );
        assert_eq!(out.children[2].kind, EntryKind::Directory);
        assert!(out.problems.is_empty(), "{:?}", out.problems);
    }

    #[test]
    fn pax_long_name() {
        let mut b = tar::Builder::new(Vec::new());
        let long = "p/".repeat(80) + "x";
        let pax = format!("{} path={long}\n", long.len() + 7 + 3);
        let mut ph = tar::Header::new_ustar();
        ph.set_entry_type(EntryType::XHeader);
        ph.set_size(pax.len() as u64);
        ph.set_cksum();
        b.append(&ph, pax.as_bytes()).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(1);
        h.set_path("short").unwrap();
        h.set_cksum();
        b.append(&h, &b"z"[..]).unwrap();
        let out = expand(
            &b.into_inner().unwrap(),
            ContainerKind::Tar,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(out.children[0].path, long.replace("//", "/"));
    }

    #[test]
    fn hostile_paths_and_links() {
        let bytes = build(
            &[("../../etc/passwd", b"root::0:0"), ("/abs/file", b"x")],
            &[
                ("escape", "/etc/shadow"),
                ("a/rel", "../../outside"),
                ("a/ok", "../b"),
            ],
        );
        let out = expand(&bytes, ContainerKind::Tar, &Limits::default()).unwrap();
        let paths: Vec<_> = out.children.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(
            paths,
            ["__/__/etc/passwd", "abs/file", "escape", "a/rel", "a/ok"]
        );
        assert!(out.problems.iter().any(|p| p.contains("traversal")));
        assert!(out.problems.iter().any(|p| p.contains("absolute")));
        assert_eq!(
            out.problems
                .iter()
                .filter(|p| p.contains("escapes"))
                .count(),
            2
        );
    }

    #[test]
    fn limits_and_truncation() {
        let bytes = build(&[("a", &[1u8; 2000]), ("b", b"2"), ("c", b"3")], &[]);
        let out = expand(
            &bytes,
            ContainerKind::Tar,
            &Limits {
                max_entries: 2,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(out.truncated && out.children.len() == 2);
        let out = expand(
            &bytes,
            ContainerKind::Tar,
            &Limits {
                max_entry_bytes: 100,
                ..Limits::default()
            },
        )
        .unwrap();
        // Larger than the per-entry memory limit: listed for separate extraction.
        assert!(
            !out.truncated
                && out.oversized.len() == 1
                && out.children.iter().all(|c| c.path != out.oversized[0].path)
        );
        for n in 0..bytes.len() {
            let _ = expand(&bytes[..n], ContainerKind::Tar, &Limits::default());
        }
        assert!(expand(&[0u8; 1024], ContainerKind::Tar, &Limits::default()).is_err());
    }
}

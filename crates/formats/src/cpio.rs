//! cpio archives: SVR4 `newc`/`crc` (RPM payloads, initramfs), portable
//! `odc` (macOS pkg `Scripts`/`Payload`) and old binary little-endian.

use crate::util::{Sink, slice, text, u16le};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

pub(crate) fn is_cpio(b: &[u8]) -> bool {
    b.starts_with(b"07070") && matches!(b.get(5), Some(b'1' | b'2' | b'7'))
        || b.starts_with(&[0xC7, 0x71])
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if !is_cpio(bytes) {
        return Err(FormatError::malformed(ContainerKind::Cpio, "no cpio magic"));
    }
    let mut sink = Sink::new(ContainerKind::Cpio, limits, bytes.len());
    read_into(bytes, &mut sink, "");
    Ok(sink.finish())
}

/// Entry kind from a POSIX mode; `data` is the symlink target for links.
pub(crate) fn kind_from_mode(mode: u32, data: &[u8]) -> EntryKind {
    match mode & 0o170000 {
        0o040000 => EntryKind::Directory,
        0o120000 => EntryKind::Symlink { target: text(data) },
        0o020000 => EntryKind::Special("character device".into()),
        0o060000 => EntryKind::Special("block device".into()),
        0o010000 => EntryKind::Special("fifo".into()),
        0o140000 => EntryKind::Special("socket".into()),
        _ => EntryKind::File,
    }
}

struct Header {
    mode: u32,
    name_len: usize,
    file_len: usize,
    header_len: usize,
    /// Alignment of name and data (newc: 4, odc: 1, binary: 2).
    align: usize,
}

fn hex(b: &[u8]) -> Option<usize> {
    usize::from_str_radix(std::str::from_utf8(b).ok()?, 16).ok()
}
fn oct(b: &[u8]) -> Option<usize> {
    usize::from_str_radix(std::str::from_utf8(b).ok()?, 8).ok()
}

fn header(b: &[u8], off: usize) -> Option<Header> {
    let h = &b[off..];
    if h.starts_with(b"070701") || h.starts_with(b"070702") {
        let field = |i: usize| hex(slice(h, 6 + i * 8, 8)?);
        Some(Header {
            mode: field(1)? as u32,
            file_len: field(6)?,
            name_len: field(11)?,
            header_len: 110,
            align: 4,
        })
    } else if h.starts_with(b"070707") {
        Some(Header {
            mode: oct(slice(h, 18, 6)?)? as u32,
            name_len: oct(slice(h, 59, 6)?)?,
            file_len: oct(slice(h, 65, 11)?)?,
            header_len: 76,
            align: 1,
        })
    } else if h.starts_with(&[0xC7, 0x71]) {
        let size = (u16le(h, 22)? as usize) << 16 | u16le(h, 24)? as usize;
        Some(Header {
            mode: u16le(h, 6)? as u32,
            name_len: u16le(h, 20)? as usize,
            file_len: size,
            header_len: 26,
            align: 2,
        })
    } else {
        None
    }
}

fn align(n: usize, to: usize) -> usize {
    n.div_ceil(to) * to
}

/// Append every entry of the cpio archive `bytes` to `sink`, prefixing paths
/// with `prefix`. Stops quietly at `TRAILER!!!`; anything else that ends the
/// walk early is reported as a problem.
pub(crate) fn read_into(bytes: &[u8], sink: &mut Sink, prefix: &str) {
    let mut off = 0usize;
    while off < bytes.len() {
        if sink.full() {
            return;
        }
        let Some(h) = header(bytes, off) else {
            if bytes[off..].iter().any(|&b| b != 0) {
                sink.problem(format!("cpio: bad header at offset {off}"));
            }
            return;
        };
        let name_off = off + h.header_len;
        let Some(name) = slice(bytes, name_off, h.name_len) else {
            sink.problem("cpio: truncated entry name");
            return;
        };
        let name = text(name);
        if name == "TRAILER!!!" {
            return;
        }
        let data_off = align(name_off + h.name_len, h.align);
        let Some(data) = slice(bytes, data_off, h.file_len) else {
            sink.problem(format!("cpio: truncated data for {name:?}"));
            return;
        };
        let kind = kind_from_mode(h.mode, data);
        let mut data = data.to_vec();
        if data.len() as u64 > sink.entry_budget() {
            sink.truncate(format!("cpio: {name:?} exceeds the entry size limit"));
            data.truncate(sink.entry_budget() as usize);
        }
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if !sink.push(&path, kind, Some(h.mode & 0o7777), data) {
            return;
        }
        off = align(data_off + h.file_len, h.align);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a newc archive from `(name, mode, data)` triples.
    pub(crate) fn newc(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut all: Vec<(&str, u32, &[u8])> = entries.to_vec();
        all.push(("TRAILER!!!", 0, b""));
        for (i, (name, mode, data)) in all.iter().enumerate() {
            let fields = [
                i as u32,
                *mode,
                0,
                0,
                1,
                0,
                data.len() as u32,
                0,
                0,
                0,
                0,
                name.len() as u32 + 1,
                0,
            ];
            out.extend_from_slice(b"070701");
            for f in fields {
                out.extend_from_slice(format!("{f:08x}").as_bytes());
            }
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(data);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        out
    }

    /// Build an odc archive (what macOS `Scripts` archives use).
    pub(crate) fn odc(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut all: Vec<(&str, u32, &[u8])> = entries.to_vec();
        all.push(("TRAILER!!!", 0, b""));
        for (name, mode, data) in all {
            out.extend_from_slice(
                format!(
                    "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                    0,
                    0,
                    mode,
                    0,
                    0,
                    1,
                    0,
                    0,
                    name.len() + 1,
                    data.len()
                )
                .as_bytes(),
            );
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn reads_newc_and_odc() {
        for build in [newc, odc] {
            let a = build(&[
                ("./usr", 0o040755, b""),
                ("./usr/bin/tool", 0o100755, b"#!/bin/sh\necho hi\n"),
                ("./usr/bin/link", 0o120777, b"tool"),
                ("../../etc/passwd", 0o100644, b"x"),
                ("dev/null", 0o020666, b""),
            ]);
            let out = expand(&a, &Limits::default()).unwrap();
            let paths: Vec<_> = out.children.iter().map(|c| c.path.as_str()).collect();
            assert_eq!(
                paths,
                [
                    "usr",
                    "usr/bin/tool",
                    "usr/bin/link",
                    "__/__/etc/passwd",
                    "dev/null"
                ]
            );
            assert_eq!(out.children[1].data, b"#!/bin/sh\necho hi\n");
            assert_eq!(
                out.children[2].kind,
                EntryKind::Symlink {
                    target: "tool".into()
                }
            );
            assert!(out.problems.iter().any(|p| p.contains("traversal")));
            assert!(out.problems.iter().any(|p| p.contains("special")));
            for n in 0..a.len() {
                let _ = expand(&a[..n], &Limits::default());
            }
        }
    }

    #[test]
    fn entry_limit() {
        let a = newc(&[
            ("a", 0o100644, b"1"),
            ("b", 0o100644, b"2"),
            ("c", 0o100644, b"3"),
        ]);
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let out = expand(&a, &limits).unwrap();
        assert_eq!(out.children.len(), 2);
        assert!(out.truncated);
    }
}

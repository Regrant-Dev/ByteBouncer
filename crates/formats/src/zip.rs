//! ZIP archives (incl. zip64) via the `zip` crate, restricted to its
//! pure-Rust codecs. Encrypted entries and unsupported methods are recorded
//! as problems, and each entry is capped by its compressed size times
//! [`Limits::max_ratio`](crate::Limits) to defuse zip bombs.

use std::io::Cursor;

use zip::ZipArchive;

use crate::util::{Sink, read_bounded};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

pub(crate) fn is_zip(b: &[u8]) -> bool {
    b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") || b.starts_with(b"PK\x07\x08")
}

pub(crate) fn expand(
    bytes: &[u8],
    kind: ContainerKind,
    limits: &Limits,
) -> Result<Expanded, FormatError> {
    let mut sink = Sink::new(kind, limits, bytes.len());
    read_into(bytes, &mut sink, "").map_err(|e| FormatError::malformed(kind, e))?;
    Ok(sink.finish())
}

/// Append all zip entries to `sink`. Fails only if the central directory
/// itself cannot be read.
pub(crate) fn read_into(bytes: &[u8], sink: &mut Sink, prefix: &str) -> Result<(), String> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    for i in 0..zip.len() {
        if sink.full() {
            return Ok(());
        }
        let (name, kind, mode, compressed, declared) = {
            let f = match zip.by_index_raw(i) {
                Ok(f) => f,
                Err(e) => {
                    sink.problem(format!("zip: entry {i}: {e}"));
                    continue;
                }
            };
            let name = f
                .name()
                .map(|n| n.into_owned())
                .unwrap_or_else(|_| String::from_utf8_lossy(f.name_raw()).into_owned());
            if f.encrypted() {
                sink.problem(format!(
                    "zip: {name:?} is encrypted; contents not extracted"
                ));
            }
            let kind = if f.is_dir() {
                EntryKind::Directory
            } else if f.is_symlink() {
                EntryKind::Symlink {
                    target: String::new(),
                }
            } else {
                EntryKind::File
            };
            let kind = if f.encrypted() && kind == EntryKind::File {
                None
            } else {
                Some(kind)
            };
            (name, kind, f.unix_mode(), f.compressed_size(), f.size())
        };
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let Some(kind) = kind else {
            sink.push(
                &path,
                EntryKind::Special("encrypted zip entry".into()),
                mode,
                Vec::new(),
            );
            continue;
        };
        let mut data = Vec::new();
        // Large but plausibly compressed entries are extracted separately;
        // implausible ratios stay a bomb-style truncation below.
        if kind == EntryKind::File
            && declared > sink.limits.max_entry_bytes
            && declared <= compressed.saturating_mul(sink.limits.max_ratio)
        {
            sink.oversized(&path, declared);
            continue;
        }
        if kind != EntryKind::Directory {
            match zip.by_index(i) {
                Ok(f) => {
                    let b = read_bounded(f, sink.entry_cap(compressed));
                    if b.capped {
                        sink.truncate(format!(
                            "zip: {name:?} stopped at the size/ratio limit (possible zip bomb)"
                        ));
                    }
                    if let Some(e) = b.error {
                        sink.problem(format!("zip: {name:?}: corrupt data: {e}"));
                    }
                    data = b.data;
                }
                Err(e) => {
                    sink.problem(format!("zip: {name:?}: {e}"));
                    sink.push(
                        &path,
                        EntryKind::Special(format!("unreadable zip entry: {e}")),
                        mode,
                        Vec::new(),
                    );
                    continue;
                }
            }
        }
        let kind = match kind {
            EntryKind::Symlink { .. } => EntryKind::Symlink {
                target: String::from_utf8_lossy(&data).into_owned(),
            },
            k => k,
        };
        if !sink.push(&path, kind, mode, data) {
            return Ok(());
        }
    }
    Ok(())
}

/// Stream the regular file whose normalized path is `want` into `out`.
pub(crate) fn extract(
    bytes: &[u8],
    want: &str,
    out: &mut dyn std::io::Write,
    max: u64,
) -> Result<u64, String> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    for i in 0..zip.len() {
        let f = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = f
            .name()
            .map(|n| n.into_owned())
            .unwrap_or_else(|_| String::from_utf8_lossy(f.name_raw()).into_owned());
        if crate::util::normalize_path(&name).0 != want {
            continue;
        }
        if f.is_dir() || f.is_symlink() || f.encrypted() {
            return Err(format!("{want:?} is not a readable regular file"));
        }
        return crate::tar::copy_capped(f, out, max);
    }
    Err(format!("{want:?} not found"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Build a zip from `(name, data, deflate?)`.
    pub(crate) fn build(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data, deflate) in files {
            let method = if *deflate {
                zip::CompressionMethod::Deflated
            } else {
                zip::CompressionMethod::Stored
            };
            w.start_file(
                *name,
                SimpleFileOptions::default()
                    .compression_method(method)
                    .unix_permissions(0o644),
            )
            .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn stored_and_deflate() {
        let bytes = build(&[
            ("a.txt", b"stored", false),
            ("dir/b.txt", b"deflated deflated", true),
        ]);
        let out = expand(&bytes, ContainerKind::Zip, &Limits::default()).unwrap();
        assert_eq!(out.children[0].data, b"stored");
        assert_eq!(out.child("dir/b.txt").unwrap().data, b"deflated deflated");
        assert_eq!(out.children[0].mode, Some(0o100644));
    }

    #[test]
    fn zip64_and_symlinks() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().large_file(true);
        w.start_file("big", opts).unwrap();
        w.write_all(b"zip64 entry").unwrap();
        w.add_symlink("link", "../../../etc/passwd", SimpleFileOptions::default())
            .unwrap();
        w.add_directory("d/", SimpleFileOptions::default()).unwrap();
        let bytes = w.finish().unwrap().into_inner();
        let out = expand(&bytes, ContainerKind::Zip, &Limits::default()).unwrap();
        assert_eq!(out.child("big").unwrap().data, b"zip64 entry");
        assert_eq!(
            out.child("link").unwrap().kind,
            EntryKind::Symlink {
                target: "../../../etc/passwd".into()
            }
        );
        assert_eq!(out.child("d").unwrap().kind, EntryKind::Directory);
        assert!(out.problems.iter().any(|p| p.contains("escapes")));
    }

    #[test]
    fn traversal_names() {
        let bytes = build(&[
            ("../../evil.sh", b"x", false),
            ("C:\\Windows\\x.dll", b"y", false),
        ]);
        let out = expand(&bytes, ContainerKind::Zip, &Limits::default()).unwrap();
        assert_eq!(out.children[0].path, "__/__/evil.sh");
        assert_eq!(out.children[1].path, "Windows/x.dll");
        assert!(out.problems.len() >= 2);
    }

    #[test]
    fn bomb_and_entry_limits() {
        let zeros = vec![0u8; 4 << 20];
        let bytes = build(&[
            ("bomb", &zeros, true),
            ("b", b"1", false),
            ("c", b"2", false),
        ]);
        let out = expand(
            &bytes,
            ContainerKind::Zip,
            &Limits {
                max_ratio: 50,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(out.truncated);
        assert!(
            out.oversized.is_empty(),
            "a bomb must never be listed for extraction"
        );
        assert!(out.children[0].data.len() < zeros.len());
        let out = expand(
            &bytes,
            ContainerKind::Zip,
            &Limits {
                max_entries: 1,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(out.truncated && out.children.len() == 1);
    }

    #[test]
    fn encrypted_entries_are_problems() {
        // Flip the "encrypted" general-purpose flag in both headers.
        let mut bytes = build(&[("secret", b"data", false)]);
        bytes[6] |= 1;
        let cd = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        bytes[cd + 8] |= 1;
        let out = expand(&bytes, ContainerKind::Zip, &Limits::default()).unwrap();
        assert!(out.problems.iter().any(|p| p.contains("encrypted")));
        assert!(out.children[0].data.is_empty());
    }

    #[test]
    fn truncations_never_panic() {
        let bytes = build(&[("a", b"hello hello hello", true), ("b", b"x", false)]);
        for n in 0..bytes.len() {
            let _ = expand(&bytes[..n], ContainerKind::Zip, &Limits::default());
        }
        let mut corrupt = bytes.clone();
        for i in (0..corrupt.len()).step_by(7) {
            corrupt[i] ^= 0x5A;
            let _ = expand(&corrupt, ContainerKind::Zip, &Limits::default());
        }
    }
}

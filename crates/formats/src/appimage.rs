//! AppImage: an ELF runtime with a SquashFS image appended (type 2). The
//! runtime is returned as the `runtime` child, the filesystem under
//! `squashfs-root/`. The desktop entry and `AppRun` launcher are surfaced as
//! metadata and scripts since they decide what runs when the user starts it.

use crate::squashfs;
use crate::util::{Sink, shebang, u16be, u16le, u32be, u32le, u64be, u64le};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

const ROOT: &str = "squashfs-root";

/// End of the ELF section header table, which is where the AppImage
/// runtime places the filesystem.
fn elf_end(b: &[u8]) -> Option<u64> {
    let le = match b.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let u16_at = |o| if le { u16le(b, o) } else { u16be(b, o) };
    let (shoff, entsize, num) = match b.get(4)? {
        1 => {
            let off = if le { u32le(b, 0x20) } else { u32be(b, 0x20) };
            (u64::from(off?), u16_at(0x2E)?, u16_at(0x30)?)
        }
        2 => {
            let off = if le { u64le(b, 0x28) } else { u64be(b, 0x28) };
            (off?, u16_at(0x3A)?, u16_at(0x3C)?)
        }
        _ => return None,
    };
    shoff.checked_add(u64::from(entsize) * u64::from(num))
}

/// Locate the SquashFS image: the ELF end first, then a scan for a
/// plausible superblock.
fn squashfs_offset(b: &[u8]) -> Option<usize> {
    if let Some(end) = elf_end(b).and_then(|e| usize::try_from(e).ok()) {
        if b.get(end..).is_some_and(squashfs::looks_valid) {
            return Some(end);
        }
    }
    let mut from = 64;
    while let Some(pos) = b.get(from..)?.windows(4).position(|w| w == b"hsqs") {
        let at = from + pos;
        if squashfs::looks_valid(&b[at..]) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if !bytes.starts_with(b"\x7fELF") {
        return Err(FormatError::malformed(
            ContainerKind::AppImage,
            "not an ELF file",
        ));
    }
    let mut sink = Sink::new(ContainerKind::AppImage, limits, bytes.len());
    if bytes.get(8..11) == Some(b"AI\x01") {
        sink.meta("appimage.type", "1");
        sink.problem("type 1 (ISO 9660) AppImage: filesystem not parsed");
        sink.push("runtime", EntryKind::File, None, bytes.to_vec());
        return Ok(sink.finish());
    }
    let Some(off) = squashfs_offset(bytes) else {
        sink.problem(
            "no SquashFS image found after the ELF runtime; not an AppImage or unsupported type",
        );
        sink.push("runtime", EntryKind::File, None, bytes.to_vec());
        return Ok(sink.finish());
    };
    let fs = &bytes[off..];
    sink.meta("appimage.type", "2");
    sink.meta("appimage.squashfs_offset", off.to_string());
    if let Some(c) = squashfs::compression_name(fs) {
        sink.meta("appimage.compression", c);
    }
    sink.push("runtime", EntryKind::File, None, bytes[..off].to_vec());
    if let Err(e) = squashfs::read_into(fs, &mut sink, ROOT) {
        sink.problem(format!("squashfs payload not expanded: {e}"));
    }
    let mut out = sink.finish();
    describe(&mut out);
    Ok(out)
}

/// Stream one file from the embedded SquashFS (paths under `squashfs-root/`).
pub(crate) fn extract(
    bytes: &[u8],
    path: &str,
    out: &mut dyn std::io::Write,
    max: u64,
) -> Result<u64, String> {
    let off = squashfs_offset(bytes).ok_or("no SquashFS image found")?;
    squashfs::extract(&bytes[off..], ROOT, path, out, max)
}

/// Follow symlinks inside the image (bounded, relative targets only).
fn resolve<'a>(out: &'a Expanded, path: &str) -> Option<&'a crate::Child> {
    let mut path = path.to_owned();
    for _ in 0..8 {
        let child = out.child(&path)?;
        let EntryKind::Symlink { target } = &child.kind else {
            return Some(child);
        };
        let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
        let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
        let base = if target.starts_with('/') {
            vec![ROOT]
        } else {
            std::mem::take(&mut parts)
        };
        let mut parts = base;
        for comp in target.split('/') {
            match comp {
                "" | "." => {}
                ".." if parts.len() > 1 => {
                    parts.pop();
                }
                ".." => return None,
                c => parts.push(c),
            }
        }
        path = parts.join("/");
    }
    None
}

fn describe(out: &mut Expanded) {
    let prefix = format!("{ROOT}/");
    let desktops: Vec<String> = out
        .children
        .iter()
        .filter_map(|c| c.path.strip_prefix(&prefix))
        .filter(|p| !p.contains('/') && p.ends_with(".desktop"))
        .map(|p| format!("{prefix}{p}"))
        .collect();
    let mut meta = Vec::new();
    for path in desktops {
        let Some(child) = resolve(out, &path) else {
            continue;
        };
        meta.push(("appimage.desktop_file".to_owned(), path.clone()));
        let text = String::from_utf8_lossy(&child.data);
        let mut in_entry = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_entry = line == "[Desktop Entry]";
            } else if let Some((k, v)) = line.split_once('=').filter(|_| in_entry) {
                if matches!(k.trim(), "Name" | "Exec" | "Categories") {
                    meta.push((
                        format!("appimage.desktop.{}", k.trim()),
                        v.trim().to_owned(),
                    ));
                }
            }
        }
    }
    let apprun = format!("{prefix}AppRun");
    let mut script = None;
    if let Some(child) = resolve(out, &apprun) {
        if child.data.starts_with(b"\x7fELF") {
            meta.push(("appimage.AppRun".into(), "elf".into()));
        } else if child.data.starts_with(b"#!") {
            let text = String::from_utf8_lossy(&child.data).into_owned();
            meta.push(("appimage.AppRun".into(), "script".into()));
            script = Some(crate::Script {
                kind: "appimage.AppRun".into(),
                interpreter: shebang(&text),
                path: apprun,
                text,
            });
        }
    }
    out.metadata.extend(meta);
    out.scripts.extend(script);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::squashfs::tests::{build, sample_tree};

    /// A minimal 64-bit little-endian ELF header whose section header table
    /// ends at byte 256, followed by padding up to it.
    fn fake_runtime() -> Vec<u8> {
        let mut elf = vec![0u8; 256];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[8..11].copy_from_slice(b"AI\x02");
        elf[0x28..0x30].copy_from_slice(&128u64.to_le_bytes());
        elf[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        elf[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes());
        elf
    }

    #[test]
    fn expands_runtime_and_filesystem() {
        let mut img = fake_runtime();
        img.extend(build(sample_tree(), 1, 12));
        let out = expand(&img, &Limits::default()).unwrap();
        assert_eq!(out.meta("appimage.type"), Some("2"));
        assert_eq!(out.meta("appimage.squashfs_offset"), Some("256"));
        assert_eq!(out.meta("appimage.compression"), Some("gzip"));
        assert_eq!(out.meta("appimage.desktop.Name"), Some("Demo"));
        assert_eq!(out.meta("appimage.desktop.Exec"), Some("app %U"));
        assert_eq!(out.child("runtime").unwrap().data.len(), 256);
        assert!(out.child("squashfs-root/usr/bin/app").is_some());
        assert_eq!(out.scripts.len(), 1);
        assert_eq!(out.scripts[0].interpreter.as_deref(), Some("/bin/sh"));
    }

    #[test]
    fn scans_for_squashfs_when_elf_end_is_wrong() {
        let mut img = fake_runtime();
        img[0x3C..0x3E].copy_from_slice(&0u16.to_le_bytes());
        img.extend(build(sample_tree(), 6, 12));
        let out = expand(&img, &Limits::default()).unwrap();
        assert_eq!(out.meta("appimage.squashfs_offset"), Some("256"));
        assert!(out.child("squashfs-root/AppRun").is_some());
    }

    #[test]
    fn unsupported_compression_keeps_runtime() {
        let mut img = fake_runtime();
        let mut fs = build(sample_tree(), 1, 12);
        fs[20] = 3; // lzo
        img.extend(fs);
        let out = expand(&img, &Limits::default()).unwrap();
        assert!(out.child("runtime").is_some());
        assert!(
            out.problems.iter().any(|p| p.contains("lzo")),
            "{:?}",
            out.problems
        );
    }

    #[test]
    fn truncations_never_panic() {
        let mut img = fake_runtime();
        img.extend(build(sample_tree(), 1, 12));
        for n in 0..img.len() {
            let _ = expand(&img[..n], &Limits::default());
        }
        assert!(expand(b"MZ", &Limits::default()).is_err());
    }
}

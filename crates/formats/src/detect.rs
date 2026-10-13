//! Format identification: magic bytes first, file-name hint second.

use crate::ContainerKind;

/// Identify the stream compression of `b` by magic.
pub(crate) fn compression(b: &[u8]) -> Option<ContainerKind> {
    use ContainerKind as K;
    if b.starts_with(&[0x1F, 0x8B]) {
        Some(K::Gzip)
    } else if b.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        Some(K::Xz)
    } else if b.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Some(K::Zstd)
    } else if b.starts_with(b"BZh")
        && matches!(b.get(3), Some(b'1'..=b'9'))
        && b.get(4..10) == Some(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59])
    {
        Some(K::Bzip2)
    } else {
        None
    }
}

/// Identify the container format of `bytes`. Magic bytes win; `name_hint`
/// (a file name or path) is consulted only when no magic matches, or to tell
/// an MSIX apart from a plain zip. Returns `None` for non-containers
/// (including ordinary PE/ELF executables).
pub fn detect(bytes: &[u8], name_hint: &str) -> Option<ContainerKind> {
    if bytes.is_empty() {
        return None;
    }
    let by_name = by_name(name_hint);
    match magic(bytes) {
        Some(ContainerKind::Zip) if by_name == Some(ContainerKind::Msix) => by_name,
        Some(kind) => Some(kind),
        None => by_name,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(hay, needle).is_some()
}

fn magic(b: &[u8]) -> Option<ContainerKind> {
    use ContainerKind as K;
    if let Some(kind) = compression(b) {
        return Some(kind);
    }
    if b.starts_with(b"BZh") && b.get(4..10) == Some(&[0x17, 0x72, 0x45, 0x38, 0x50, 0x90]) {
        return Some(K::Bzip2);
    }
    if crate::zip::is_zip(b) {
        // The central directory sits at the end; look for the manifest there.
        let tail = &b[b.len().saturating_sub(4 << 20)..];
        let msix = contains(tail, b"AppxManifest.xml")
            || contains(tail, b"AppxMetadata/AppxBundleManifest.xml");
        return Some(if msix { K::Msix } else { K::Zip });
    }
    if b.starts_with(crate::ar::MAGIC) {
        return Some(if b.get(8..21) == Some(b"debian-binary") {
            K::Deb
        } else {
            K::Ar
        });
    }
    let kind = match b.get(..8)? {
        [0xED, 0xAB, 0xEE, 0xDB, ..] => K::Rpm,
        [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] => K::Msi,
        [b'x', b'a', b'r', b'!', ..] => K::Xar,
        [b'M', b'S', b'C', b'F', 0, 0, 0, 0] => K::Cab,
        [b'h', b's', b'q', b's', ..] => K::Squashfs,
        [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, ..] => K::SevenZip,
        [0x7F, b'E', b'L', b'F', ..] => {
            return matches!(b.get(8..11), Some([b'A', b'I', 1 | 2])).then_some(K::AppImage);
        }
        [b'M', b'Z', ..] => return pe_installer(b),
        _ if crate::cpio::is_cpio(b) => K::Cpio,
        _ if crate::tar::is_tar(b) => {
            if crate::tar::leading_names(b, 8)
                .iter()
                .any(|n| n.trim_start_matches("./") == ".PKGINFO")
            {
                K::ArchPackage
            } else {
                K::Tar
            }
        }
        _ if b.len() >= 512 && b[b.len() - 512..].starts_with(b"koly") => K::Dmg,
        _ if is_lzma_alone(b) => K::Lzma,
        _ => return None,
    };
    Some(kind)
}

/// Installer stubs that wrap their payload in a PE executable.
fn pe_installer(b: &[u8]) -> Option<ContainerKind> {
    if contains(b, b"\xEF\xBE\xAD\xDENullsoftInst") {
        Some(ContainerKind::Nsis)
    } else if contains(b, b"Inno Setup Setup Data") || contains(b, b"rDlPtS02\x87eVx") {
        Some(ContainerKind::InnoSetup)
    } else {
        None
    }
}

/// `.lzma` (LZMA-alone) has no magic; accept only the canonical header
/// (lc=3 lp=0 pb=2, power-of-two dictionary, sane or unknown size).
fn is_lzma_alone(b: &[u8]) -> bool {
    let (Some(dict), Some(size)) = (crate::util::u32le(b, 1), crate::util::u64le(b, 5)) else {
        return false;
    };
    b[0] == 0x5D
        && dict.is_power_of_two()
        && (1 << 12..=1 << 30).contains(&dict)
        && (size == u64::MAX || size < 1 << 40)
}

fn by_name(name: &str) -> Option<ContainerKind> {
    use ContainerKind as K;
    let name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|(_, e)| e)?;
    Some(match ext {
        "gz" | "tgz" => K::Gzip,
        "xz" | "txz" => K::Xz,
        "zst" | "tzst" => K::Zstd,
        "bz2" | "tbz2" | "tbz" => K::Bzip2,
        "lzma" => K::Lzma,
        "tar" => K::Tar,
        "zip" | "jar" | "whl" | "nupkg" | "apk" | "ipa" | "vsix" | "xpi" => K::Zip,
        "msix" | "appx" | "msixbundle" | "appxbundle" => K::Msix,
        "deb" | "udeb" => K::Deb,
        "rpm" => K::Rpm,
        "a" | "ar" => K::Ar,
        "cpio" => K::Cpio,
        "appimage" => K::AppImage,
        "squashfs" | "sqfs" | "snap" => K::Squashfs,
        "msi" | "msp" | "msm" => K::Msi,
        "cab" => K::Cab,
        "pkg" | "mpkg" | "xar" => K::Xar,
        "dmg" => K::Dmg,
        "7z" => K::SevenZip,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ContainerKind as K;

    #[test]
    fn magic_beats_name() {
        assert_eq!(detect(&[0x1F, 0x8B, 8, 0], "x.zip"), Some(K::Gzip));
        assert_eq!(detect(b"PK\x03\x04rest", "a.msix"), Some(K::Msix));
        assert_eq!(detect(b"PK\x03\x04rest", "a.jar"), Some(K::Zip));
        assert_eq!(detect(b"\xED\xAB\xEE\xDBxxxxxxxx", ""), Some(K::Rpm));
        assert_eq!(detect(b"!<arch>\ndebian-binary   ", ""), Some(K::Deb));
        assert_eq!(detect(b"!<arch>\nfoo.o/   ", ""), Some(K::Ar));
        assert_eq!(detect(b"070701000000", ""), Some(K::Cpio));
        assert_eq!(detect(b"unknown bytes", "pkg.dmg"), Some(K::Dmg));
        assert_eq!(detect(b"unknown bytes", "README"), None);
        assert_eq!(detect(b"\0", "foo.pkg.tar.zst"), Some(K::Zstd));
        assert_eq!(detect(b"", "empty.gz"), None);
    }

    #[test]
    fn executables_and_installers() {
        let mut elf = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, b'A', b'I', 2, 0];
        assert_eq!(detect(&elf, ""), Some(K::AppImage));
        elf[8] = 0;
        assert_eq!(detect(&elf, ""), None);
        let mut pe = b"MZ\x90\x00".to_vec();
        assert_eq!(detect(&pe, "setup.exe"), None);
        pe.extend_from_slice(b"\x00\x00\x00\x00\xEF\xBE\xAD\xDENullsoftInst");
        assert_eq!(detect(&pe, ""), Some(K::Nsis));
        assert_eq!(
            detect(b"MZ....Inno Setup Setup Data (6.2.0)", ""),
            Some(K::InnoSetup)
        );
        assert_eq!(detect(b"7z\xBC\xAF\x27\x1C\x00\x04", ""), Some(K::SevenZip));
    }

    #[test]
    fn tar_and_arch_packages() {
        let tar = crate::tar::tests::build(&[("file", b"x")], &[]);
        assert_eq!(detect(&tar, ""), Some(K::Tar));
        let arch = crate::tar::tests::build(&[(".PKGINFO", b"pkgname = x\n")], &[]);
        assert_eq!(detect(&arch, ""), Some(K::ArchPackage));
    }
}

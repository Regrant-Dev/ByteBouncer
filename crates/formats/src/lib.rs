//! In-memory identification and expansion of container and installer formats
//! (SPEC §4, §5.2, §6.1). Everything here operates on `&[u8]` and returns owned
//! data: no filesystem, network, process, or environment access. Inputs are
//! hostile, so every expansion is bounded by [`Limits`], paths are normalized
//! before they are reported, links are recorded but never followed, and
//! anything suspicious lands in [`Expanded::problems`] instead of a panic.
//!
//! [`expand`] handles exactly one level. Nested containers (a `data.tar.xz`
//! inside a `.deb`, a `.tar` inside a `.gz`) are returned as children and the
//! caller decides whether to recurse, so it also owns depth limits.

#![forbid(unsafe_code)]

mod appimage;
mod ar;
mod arch;
pub mod authenticode;
mod cab;
mod compress;
mod cpio;
mod detect;
mod dmg;
mod msi;
mod msix;
mod rpm;
mod squashfs;
mod tar;
mod util;
mod xar;
mod zip;

pub use arch::{ArchInfo, arch_package_info};
pub use detect::detect;

/// Resource limits applied to a single [`expand`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest single expanded entry. Larger entries are cut and flagged.
    pub max_entry_bytes: u64,
    /// Total expanded bytes across all children.
    pub max_total_bytes: u64,
    /// Maximum number of children.
    pub max_entries: usize,
    /// Decompression-bomb guard: expanded bytes may not exceed the compressed
    /// input size times this ratio (with a small floor so tiny inputs work).
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entry_bytes: 512 << 20,
            max_total_bytes: 2 << 30,
            max_entries: 100_000,
            max_ratio: 200,
        }
    }
}

/// Container and installer formats this crate can identify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContainerKind {
    Zip,
    Tar,
    Gzip,
    Xz,
    Lzma,
    Zstd,
    Bzip2,
    Ar,
    Deb,
    Rpm,
    Cpio,
    /// An uncompressed tar whose first member is `.PKGINFO`.
    ArchPackage,
    AppImage,
    Squashfs,
    Msi,
    Msix,
    Cab,
    /// Apple flat `.pkg` installers.
    Xar,
    Dmg,
    SevenZip,
    Nsis,
    InnoSetup,
}

/// What a child entry is. Links are recorded, never followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink {
        target: String,
    },
    Hardlink {
        target: String,
    },
    /// Device nodes, FIFOs, sockets and other non-regular entries.
    Special(String),
}

/// One entry from a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// Normalized relative path: `/`-separated, no `..`, no leading `/`.
    pub path: String,
    pub kind: EntryKind,
    pub mode: Option<u32>,
    /// File contents; empty unless `kind` is [`EntryKind::File`].
    pub data: Vec<u8>,
}

/// An install-time script found structurally (maintainer scripts, scriptlets,
/// custom actions). The text is untrusted evidence, never executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// Origin, e.g. `deb.postinst`, `rpm.%post`, `arch.install`,
    /// `pkg.postinstall`, `msi.CustomAction`.
    pub kind: String,
    pub interpreter: Option<String>,
    /// Where the script lives inside the container (or a synthetic locator).
    pub path: String,
    pub text: String,
}

/// The result of expanding one container level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    pub kind: ContainerKind,
    pub children: Vec<Child>,
    /// Format metadata such as `("rpm.name", "foo")` or
    /// `("deb.control.Package", "foo")`. Keys may repeat.
    pub metadata: Vec<(String, String)>,
    pub scripts: Vec<Script>,
    /// Traversal attempts, unsupported features, truncation, limit hits.
    pub problems: Vec<String>,
    /// True if any limit stopped expansion early.
    pub truncated: bool,
    /// Regular files too large to hold in memory. They are not in
    /// `children`; extract them with [`extract_entry`] and analyze separately.
    pub oversized: Vec<Oversized>,
}

/// A file inside a container that exceeded the in-memory entry budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oversized {
    /// Normalized path, as `children` paths are, accepted by [`extract_entry`].
    pub path: String,
    /// Declared uncompressed size.
    pub size: u64,
}

impl Expanded {
    pub fn new(kind: ContainerKind) -> Self {
        Self {
            kind,
            children: Vec::new(),
            metadata: Vec::new(),
            scripts: Vec::new(),
            problems: Vec::new(),
            truncated: false,
            oversized: Vec::new(),
        }
    }

    /// First metadata value for `key`.
    pub fn meta(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The child at `path`, if present.
    pub fn child(&self, path: &str) -> Option<&Child> {
        self.children.iter().find(|c| c.path == path)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// The format is recognized but this crate does not expand it.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The input is not a valid instance of the requested format.
    #[error("malformed {kind:?}: {msg}")]
    Malformed { kind: ContainerKind, msg: String },
}

impl FormatError {
    pub(crate) fn malformed(kind: ContainerKind, msg: impl Into<String>) -> Self {
        Self::Malformed {
            kind,
            msg: msg.into(),
        }
    }
}

/// Expand one level of `bytes` as `kind`, within `limits`.
///
/// Hard failures (wrong magic, unreadable header, unsupported format) are
/// errors; anything that still yields partial results is reported through
/// [`Expanded::problems`] and [`Expanded::truncated`].
pub fn expand(bytes: &[u8], kind: ContainerKind, limits: &Limits) -> Result<Expanded, FormatError> {
    use ContainerKind as K;
    match kind {
        K::Gzip | K::Xz | K::Lzma | K::Zstd | K::Bzip2 => compress::expand(bytes, kind, limits),
        K::Tar => tar::expand(bytes, kind, limits),
        K::ArchPackage => arch::expand(bytes, limits),
        K::Zip => zip::expand(bytes, kind, limits),
        K::Msix => msix::expand(bytes, limits),
        K::Ar => ar::expand(bytes, limits),
        K::Deb => ar::expand_deb(bytes, limits),
        K::Cpio => cpio::expand(bytes, limits),
        K::Rpm => rpm::expand(bytes, limits),
        K::AppImage => appimage::expand(bytes, limits),
        K::Squashfs => squashfs::expand(bytes, limits),
        K::Msi => msi::expand(bytes, limits),
        K::Cab => cab::expand(bytes, limits),
        K::Xar => xar::expand(bytes, limits),
        K::Dmg => dmg::expand(bytes, limits),
        K::SevenZip => Err(FormatError::Unsupported(
            "7z archives are detected but not expanded; inspect in a Tier 2 worker".into(),
        )),
        K::Nsis => Err(FormatError::Unsupported(
            "NSIS installer detected; its compressed script and payload are not expanded".into(),
        )),
        K::InnoSetup => Err(FormatError::Unsupported(
            "Inno Setup installer detected; its setup data and payload are not expanded".into(),
        )),
    }
}

/// Stream one regular file at `path` (a normalized path as reported in
/// [`Expanded::oversized`] or `children`) from the container into `out`,
/// writing at most `max_bytes`. Returns the number of bytes written. Only
/// formats that can be read without holding the whole entry in memory are
/// supported: SquashFS/AppImage, zip-based, and tar-based containers.
pub fn extract_entry(
    bytes: &[u8],
    kind: ContainerKind,
    path: &str,
    out: &mut dyn std::io::Write,
    max_bytes: u64,
) -> Result<u64, FormatError> {
    use ContainerKind as K;
    let res = match kind {
        K::Squashfs => squashfs::extract(bytes, "", path, out, max_bytes),
        K::AppImage => appimage::extract(bytes, path, out, max_bytes),
        K::Zip | K::Msix => zip::extract(bytes, path, out, max_bytes),
        K::Tar | K::ArchPackage => tar::extract(bytes, path, out, max_bytes),
        other => {
            return Err(FormatError::Unsupported(format!(
                "streaming extraction is not implemented for {other:?}"
            )));
        }
    };
    res.map_err(|e| FormatError::malformed(kind, e))
}

#[cfg(test)]
mod oversized_tests {
    use super::*;

    fn small_limits() -> Limits {
        Limits {
            max_entry_bytes: 1000,
            ..Limits::default()
        }
    }

    fn big() -> Vec<u8> {
        (0..5000u32).flat_map(|i| i.to_le_bytes()).collect()
    }

    fn check(bytes: &[u8], kind: ContainerKind, path: &str) {
        let exp = expand(bytes, kind, &small_limits()).unwrap();
        assert!(
            exp.children.iter().all(|c| c.path != path),
            "oversized entry must not be a child"
        );
        let o = exp
            .oversized
            .iter()
            .find(|o| o.path == path)
            .expect("listed as oversized");
        assert_eq!(o.size, 20_000);
        assert!(!exp.truncated);
        let mut out = Vec::new();
        assert_eq!(
            extract_entry(bytes, kind, path, &mut out, 1 << 20).unwrap(),
            20_000
        );
        assert_eq!(out, big());
        assert!(
            extract_entry(bytes, kind, path, &mut Vec::new(), 100).is_err(),
            "cap enforced"
        );
        assert!(extract_entry(bytes, kind, "missing", &mut Vec::new(), 1 << 20).is_err());
    }

    #[test]
    fn tar_oversized_entries_are_listed_and_streamed() {
        let data = big();
        let t = tar::tests::build(&[("small", b"x"), ("dir/large.bin", &data)], &[]);
        check(&t, ContainerKind::Tar, "dir/large.bin");
    }

    #[test]
    fn zip_oversized_entries_are_listed_and_streamed() {
        let data = big();
        let z = zip::tests::build(&[("small", b"x", true), ("dir/large.bin", &data, true)]);
        check(&z, ContainerKind::Zip, "dir/large.bin");
    }

    #[test]
    fn squashfs_oversized_entries_are_listed_and_streamed() {
        use squashfs::tests::{Node, build};
        let img = build(
            Node::Dir(vec![
                ("small", Node::File(b"x".to_vec())),
                ("dir", Node::Dir(vec![("large.bin", Node::File(big()))])),
            ]),
            1,
            12,
        );
        check(&img, ContainerKind::Squashfs, "dir/large.bin");
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;

    /// One small valid sample per format, built in-process.
    fn samples() -> Vec<Vec<u8>> {
        vec![
            compress::tests::gz(b"hello hello hello"),
            tar::tests::build(&[("a/b", b"data"), ("../x", b"y")], &[("l", "../../z")]),
            zip::tests::build(&[("a", b"zip data zip data", true), ("b", b"s", false)]),
            ar::tests::sample_deb(),
            cpio::tests::newc(&[("x", 0o100644, b"cpio")]),
            rpm::tests::sample_rpm(),
            arch::tests::sample(),
            cab::tests::build(
                ::cab::CompressionType::MsZip,
                &[("f.txt", b"cab data cab data")],
            ),
            squashfs::tests::build(squashfs::tests::sample_tree(), 1, 12),
            xar::tests::sample(),
            dmg::tests::build(64),
            msi::tests::sample(),
        ]
    }

    const KINDS: &[ContainerKind] = &[
        ContainerKind::Zip,
        ContainerKind::Tar,
        ContainerKind::Gzip,
        ContainerKind::Xz,
        ContainerKind::Lzma,
        ContainerKind::Zstd,
        ContainerKind::Bzip2,
        ContainerKind::Ar,
        ContainerKind::Deb,
        ContainerKind::Rpm,
        ContainerKind::Cpio,
        ContainerKind::ArchPackage,
        ContainerKind::AppImage,
        ContainerKind::Squashfs,
        ContainerKind::Msi,
        ContainerKind::Msix,
        ContainerKind::Cab,
        ContainerKind::Xar,
        ContainerKind::Dmg,
    ];

    /// Every format sample, mutated deterministically and fed to its own
    /// parser and to every other parser, must never panic; detection must
    /// round-trip on the unmutated sample.
    #[test]
    fn mutated_inputs_never_panic() {
        let limits = Limits {
            max_total_bytes: 64 << 20,
            ..Limits::default()
        };
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // `BYTEBOUNCER_FUZZ_ITERS` raises the per-sample count for longer runs.
        let iters: usize = std::env::var("BYTEBOUNCER_FUZZ_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(400);
        for sample in samples() {
            let kind = detect(&sample, "").expect("sample detected");
            assert!(expand(&sample, kind, &limits).is_ok(), "{kind:?}");
            for _ in 0..iters {
                let mut m = sample.clone();
                for _ in 0..1 + rand() % 4 {
                    let i = (rand() % m.len() as u64) as usize;
                    m[i] = rand() as u8;
                }
                if rand() % 3 == 0 {
                    m.truncate((rand() % m.len() as u64) as usize);
                }
                let _ = detect(&m, "");
                let _ = expand(&m, kind, &limits);
            }
            for &other in KINDS {
                let _ = expand(&sample, other, &limits);
                let _ = expand(&sample[..sample.len() / 2], other, &limits);
            }
        }
    }

    #[test]
    fn detect_only_formats_are_unsupported() {
        for kind in [
            ContainerKind::SevenZip,
            ContainerKind::Nsis,
            ContainerKind::InnoSetup,
        ] {
            assert!(matches!(
                expand(b"anything", kind, &Limits::default()),
                Err(FormatError::Unsupported(_))
            ));
        }
    }
}

//! Single-stream compressions (gzip, xz, lzma, zstd, bzip2). These are also
//! used internally by formats that embed compressed members (deb, rpm, xar).

use crate::util::{Bounded, Sink, read_bounded, u32le};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

/// Dictionary memory an xz/lzma header may demand before we refuse it. A
/// dictionary larger than the output we are willing to produce is pointless,
/// so the limit follows the output cap: at least 64 MiB (`xz -9`), plus
/// decoder overhead, and never more than 1 GiB. Real packages do use 256 MiB
/// dictionaries (Chrome's `.deb`), which the default limits allow.
fn lzma_mem_limit_kb(cap: u64) -> u32 {
    ((cap.clamp(64 << 20, 1 << 30) >> 10) + 16 * 1024) as u32
}

/// Decompress a whole stream of `kind`, returning at most `cap` bytes.
pub(crate) fn decompress(kind: ContainerKind, bytes: &[u8], cap: u64) -> Bounded {
    use ContainerKind as K;
    match kind {
        K::Gzip => read_bounded(flate2::read::MultiGzDecoder::new(bytes), cap),
        K::Xz => read_bounded(
            lzma_rust2::XzReader::new_mem_limit(bytes, true, lzma_mem_limit_kb(cap)),
            cap,
        ),
        K::Lzma => match lzma_rust2::LzmaReader::new_mem_limit(bytes, lzma_mem_limit_kb(cap), None)
        {
            Ok(r) => read_bounded(r, cap),
            Err(e) => failed(e.to_string()),
        },
        K::Bzip2 => read_bounded(bzip2::read::MultiBzDecoder::new(bytes), cap),
        K::Zstd => zstd(bytes, cap),
        _ => failed(format!("{kind:?} is not a stream compression")),
    }
}

/// zlib (RFC 1950) streams, used by xar, DMG and others.
pub(crate) fn zlib(bytes: &[u8], cap: u64) -> Bounded {
    read_bounded(flate2::read::ZlibDecoder::new(bytes), cap)
}

fn failed(error: String) -> Bounded {
    Bounded {
        data: Vec::new(),
        capped: false,
        error: Some(error),
    }
}

/// ruzstd decodes one frame at a time; concatenated and skippable frames
/// are both legal, so walk them explicitly.
fn zstd(bytes: &[u8], cap: u64) -> Bounded {
    let mut src = bytes;
    let mut out = Bounded {
        data: Vec::new(),
        capped: false,
        error: None,
    };
    while src.len() >= 4 {
        let magic = u32le(src, 0).unwrap_or(0);
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let skip = u32le(src, 4)
                .map_or(usize::MAX, |n| n as usize)
                .saturating_add(8);
            src = src.get(skip..).unwrap_or(&[]);
            continue;
        }
        if magic != 0xFD2F_B528 {
            break;
        }
        let left = cap - out.data.len() as u64;
        let decoder = match ruzstd::decoding::StreamingDecoder::new(&mut src) {
            Ok(d) => d,
            Err(e) => {
                out.error = Some(e.to_string());
                break;
            }
        };
        let part = read_bounded(decoder, left);
        out.data.extend_from_slice(&part.data);
        if part.capped || part.error.is_some() {
            out.capped = part.capped;
            out.error = part.error;
            break;
        }
    }
    if out.data.is_empty() && out.error.is_none() && !bytes.is_empty() && !out.capped {
        out.error = Some("no zstd frame found".into());
    }
    out
}

/// Expand a single compressed stream into one child named `decompressed`.
/// The caller recurses into it (typically a tar).
pub(crate) fn expand(
    bytes: &[u8],
    kind: ContainerKind,
    limits: &Limits,
) -> Result<Expanded, FormatError> {
    let mut sink = Sink::new(kind, limits, bytes.len());
    let cap = sink.entry_cap(bytes.len() as u64);
    let b = decompress(kind, bytes, cap);
    if b.data.is_empty() {
        if let Some(e) = b.error {
            return Err(FormatError::malformed(kind, e));
        }
    }
    note_stream(&mut sink, &b, "decompressed");
    sink.push("decompressed", EntryKind::File, None, b.data);
    Ok(sink.finish())
}

/// Record cap hits and stream errors from a bounded decompression.
pub(crate) fn note_stream(sink: &mut Sink, b: &Bounded, what: &str) {
    if b.capped {
        sink.truncate(format!(
            "{what}: decompression stopped at the size/ratio limit (possible decompression bomb)"
        ));
    }
    if let Some(e) = &b.error {
        sink.problem(format!("{what}: corrupt or truncated compressed data: {e}"));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_roundtrip() {
        let out = expand(&gz(b"hello"), ContainerKind::Gzip, &Limits::default()).unwrap();
        assert_eq!(out.children[0].data, b"hello");
        assert!(!out.truncated);
    }

    #[test]
    fn xz_roundtrip() {
        let mut w =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
        w.write_all(b"xz data").unwrap();
        let bytes = w.finish().unwrap();
        let out = expand(&bytes, ContainerKind::Xz, &Limits::default()).unwrap();
        assert_eq!(out.children[0].data, b"xz data");
    }

    #[test]
    fn bzip2_roundtrip() {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        e.write_all(b"bz data").unwrap();
        let out = expand(
            &e.finish().unwrap(),
            ContainerKind::Bzip2,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(out.children[0].data, b"bz data");
    }

    #[test]
    fn zstd_roundtrip_multi_frame() {
        let a = ruzstd::encoding::compress_to_vec(
            &b"one "[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let b = ruzstd::encoding::compress_to_vec(
            &b"two"[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let mut skip = vec![0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 9, 9, 9];
        skip.splice(0..0, a);
        skip.extend(b);
        let out = expand(&skip, ContainerKind::Zstd, &Limits::default()).unwrap();
        assert_eq!(out.children[0].data, b"one two");
    }

    #[test]
    fn bomb_ratio_guard() {
        let bomb = gz(&vec![0u8; 8 << 20]);
        let limits = Limits {
            max_ratio: 10,
            ..Limits::default()
        };
        let out = expand(&bomb, ContainerKind::Gzip, &limits).unwrap();
        assert!(out.truncated);
        assert!(out.children[0].data.len() as u64 <= crate::util::RATIO_FLOOR);
    }

    #[test]
    fn corrupt_streams_never_panic() {
        let good = gz(b"some text that compresses somewhat somewhat somewhat");
        for n in 0..good.len() {
            let _ = expand(&good[..n], ContainerKind::Gzip, &Limits::default());
        }
        for kind in [
            ContainerKind::Xz,
            ContainerKind::Zstd,
            ContainerKind::Bzip2,
            ContainerKind::Lzma,
        ] {
            assert!(expand(b"garbage!", kind, &Limits::default()).is_err());
        }
    }
}

//! Microsoft cabinet (`MSCF`) archives, standalone or embedded in MSI files.
//!
//! The header, folder and file tables are parsed here rather than through the
//! `cab` crate's reader: that reader restarts folder decompression for every
//! file (quadratic on large folders) and indexes block tables with offsets
//! taken from the file. Folders are instead decoded once, sequentially, with
//! `lzxd` (LZX) or flate2 (MSZIP), up to the furthest byte any file needs.

use crate::util::{RATIO_FLOOR, Sink, slice, u16le, u32le};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

const MAX_DICT: usize = 32 * 1024;

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    let cab = parse(bytes).map_err(|e| FormatError::malformed(ContainerKind::Cab, e))?;
    let mut sink = Sink::new(ContainerKind::Cab, limits, bytes.len());
    extract(bytes, &cab, &mut sink, "");
    Ok(sink.finish())
}

/// Expand the cabinet `bytes` into `sink` under `prefix`. Returns false if
/// the header could not be parsed (a problem is recorded).
pub(crate) fn read_into(bytes: &[u8], sink: &mut Sink, prefix: &str) -> bool {
    match parse(bytes) {
        Ok(cab) => {
            extract(bytes, &cab, sink, prefix);
            true
        }
        Err(e) => {
            sink.problem(format!("cabinet {prefix:?}: {e}"));
            false
        }
    }
}

struct Folder {
    first_block: usize,
    blocks: u16,
    ctype: u16,
}

struct File {
    name: String,
    size: u32,
    offset: u32,
    folder: u16,
    attribs: u16,
}

struct Cab {
    folders: Vec<Folder>,
    files: Vec<File>,
    data_reserve: usize,
}

fn cstr(b: &[u8], off: usize) -> Result<(&[u8], usize), String> {
    let rest = b.get(off..).ok_or("truncated string")?;
    let end = rest
        .iter()
        .position(|&c| c == 0)
        .ok_or("unterminated string")?;
    Ok((&rest[..end], off + end + 1))
}

fn parse(b: &[u8]) -> Result<Cab, String> {
    if !b.starts_with(b"MSCF") {
        return Err("not a cabinet (bad signature)".into());
    }
    let short = || "truncated cabinet header".to_string();
    let files_off = u32le(b, 16).ok_or_else(short)? as usize;
    let n_folders = u16le(b, 26).ok_or_else(short)?;
    let n_files = u16le(b, 28).ok_or_else(short)?;
    let flags = u16le(b, 30).ok_or_else(short)?;
    let (mut off, mut folder_reserve, mut data_reserve) = (36usize, 0usize, 0usize);
    if flags & 4 != 0 {
        let header_reserve = u16le(b, 36).ok_or_else(short)? as usize;
        folder_reserve = *b.get(38).ok_or_else(short)? as usize;
        data_reserve = *b.get(39).ok_or_else(short)? as usize;
        off = 40 + header_reserve;
    }
    for flag in [1, 2] {
        if flags & flag != 0 {
            off = cstr(b, off)?.1;
            off = cstr(b, off)?.1;
        }
    }
    let mut folders = Vec::new();
    for _ in 0..n_folders {
        folders.push(Folder {
            first_block: u32le(b, off).ok_or("truncated folder table")? as usize,
            blocks: u16le(b, off + 4).ok_or("truncated folder table")?,
            ctype: u16le(b, off + 6).ok_or("truncated folder table")?,
        });
        off += 8 + folder_reserve;
    }
    let mut files = Vec::new();
    let mut off = files_off;
    for _ in 0..n_files {
        let size = u32le(b, off).ok_or("truncated file table")?;
        let offset = u32le(b, off + 4).ok_or("truncated file table")?;
        let folder = u16le(b, off + 8).ok_or("truncated file table")?;
        let attribs = u16le(b, off + 14).ok_or("truncated file table")?;
        let (name, next) = cstr(b, off + 16)?;
        // 0x80: name is UTF-8; otherwise an unspecified codepage (lossy).
        let name = String::from_utf8_lossy(name).into_owned();
        files.push(File {
            name,
            size,
            offset,
            folder,
            attribs,
        });
        off = next;
    }
    Ok(Cab {
        folders,
        files,
        data_reserve,
    })
}

/// Decompressor for one folder's data blocks.
enum Codec {
    Stored,
    MsZip(flate2::Decompress, Vec<u8>),
    Lzx(Box<lzxd::Lzxd>),
}

impl Codec {
    fn new(ctype: u16) -> Result<Self, String> {
        Ok(match ctype & 0x000f {
            0 => Codec::Stored,
            1 => Codec::MsZip(flate2::Decompress::new(false), Vec::new()),
            3 => {
                use lzxd::WindowSize as W;
                let window = match (ctype >> 8) & 0x1f {
                    15 => W::KB32,
                    16 => W::KB64,
                    17 => W::KB128,
                    18 => W::KB256,
                    19 => W::KB512,
                    20 => W::MB1,
                    21 => W::MB2,
                    22 => W::MB4,
                    23 => W::MB8,
                    24 => W::MB16,
                    25 => W::MB32,
                    w => return Err(format!("invalid LZX window {w}")),
                };
                Codec::Lzx(Box::new(lzxd::Lzxd::new(window)))
            }
            2 => return Err("Quantum compression is not supported".into()),
            t => return Err(format!("unknown compression type {t}")),
        })
    }

    fn block(&mut self, data: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
        match self {
            Codec::Stored => Ok(data.to_vec()),
            Codec::Lzx(d) => d
                .decompress_next(data, out_len)
                .map(<[u8]>::to_vec)
                .map_err(|e| format!("LZX: {e}")),
            Codec::MsZip(d, dict) => {
                let data = data
                    .strip_prefix(b"CK")
                    .ok_or("MSZIP: bad block signature")?;
                // Each MSZIP block is a fresh deflate stream whose history is
                // the previous 32 KiB of output; prime it with a stored block.
                d.reset(false);
                if !dict.is_empty() {
                    let len = dict.len() as u16;
                    let mut prime = vec![0u8];
                    prime.extend_from_slice(&len.to_le_bytes());
                    prime.extend_from_slice(&(!len).to_le_bytes());
                    prime.extend_from_slice(dict);
                    let mut sink = Vec::with_capacity(dict.len());
                    d.decompress_vec(&prime, &mut sink, flate2::FlushDecompress::Sync)
                        .map_err(|e| format!("MSZIP: {e}"))?;
                }
                let mut out = Vec::with_capacity(out_len);
                d.decompress_vec(data, &mut out, flate2::FlushDecompress::Finish)
                    .map_err(|e| format!("MSZIP: {e}"))?;
                if out.len() != out_len {
                    return Err(format!(
                        "MSZIP: block decoded to {} of {out_len} bytes",
                        out.len()
                    ));
                }
                dict.extend_from_slice(&out);
                let excess = dict.len().saturating_sub(MAX_DICT);
                dict.drain(..excess);
                Ok(out)
            }
        }
    }
}

/// Decode folder `f` up to `need` bytes (bounded by `cap`).
fn decode_folder(
    b: &[u8],
    cab: &Cab,
    f: &Folder,
    need: u64,
    cap: u64,
) -> (Vec<u8>, Option<String>) {
    let mut out = Vec::new();
    let mut codec = match Codec::new(f.ctype) {
        Ok(c) => c,
        Err(e) => return (out, Some(e)),
    };
    let mut off = f.first_block;
    for _ in 0..f.blocks {
        if out.len() as u64 >= need.min(cap) {
            break;
        }
        let (Some(packed), Some(unpacked)) = (u16le(b, off + 4), u16le(b, off + 6)) else {
            return (out, Some("truncated data block header".into()));
        };
        let data_off = off + 8 + cab.data_reserve;
        let Some(data) = slice(b, data_off, packed as usize) else {
            return (out, Some("truncated data block".into()));
        };
        match codec.block(data, unpacked as usize) {
            Ok(block) => out.extend_from_slice(&block),
            Err(e) => return (out, Some(e)),
        }
        off = data_off + packed as usize;
    }
    out.truncate(cap.min(out.len() as u64) as usize);
    (out, None)
}

fn extract(b: &[u8], cab: &Cab, sink: &mut Sink, prefix: &str) {
    let join = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        }
    };
    for (index, folder) in cab.folders.iter().enumerate() {
        let files: Vec<&File> = cab
            .files
            .iter()
            .filter(|f| f.folder as usize == index)
            .collect();
        let need = files
            .iter()
            .map(|f| f.offset as u64 + f.size as u64)
            .max()
            .unwrap_or(0);
        if need == 0 && files.is_empty() {
            continue;
        }
        let ratio_cap = (b.len() as u64)
            .saturating_mul(sink.limits.max_ratio)
            .max(RATIO_FLOOR);
        let cap = sink.limits.max_total_bytes.min(ratio_cap);
        let (data, error) = decode_folder(b, cab, folder, need, cap);
        if let Some(e) = error {
            sink.problem(format!("cabinet {prefix:?} folder {index}: {e}"));
        }
        if need > cap {
            sink.truncate(format!(
                "cabinet {prefix:?} folder {index} exceeds the expansion limit"
            ));
        }
        for f in files {
            if sink.full() {
                return;
            }
            let start = f.offset as usize;
            let end = start.saturating_add(f.size as usize);
            let Some(content) = data.get(start..end.min(data.len())) else {
                sink.problem(format!("cabinet file {:?}: data unavailable", f.name));
                continue;
            };
            let mut content = content.to_vec();
            if (content.len() as u64) < f.size as u64 {
                sink.problem(format!(
                    "cabinet file {:?}: only {} of {} bytes recovered",
                    f.name,
                    content.len(),
                    f.size
                ));
            }
            if content.len() as u64 > sink.entry_budget() {
                sink.truncate(format!(
                    "cabinet file {:?} exceeds the entry size limit",
                    f.name
                ));
                content.truncate(sink.entry_budget() as usize);
            }
            let mode = Some(if f.attribs & 0x40 != 0 { 0o755 } else { 0o644 });
            if !sink.push(&join(&f.name), EntryKind::File, mode, content) {
                return;
            }
        }
    }
    let orphans = cab
        .files
        .iter()
        .filter(|f| f.folder as usize >= cab.folders.len())
        .count();
    if orphans > 0 {
        sink.problem(format!(
            "cabinet {prefix:?}: {orphans} file(s) continue in another cabinet of a multi-cabinet set"
        ));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    /// Build a cabinet with one folder of the given compression.
    pub(crate) fn build(ctype: cab::CompressionType, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = cab::CabinetBuilder::new();
        let folder = builder.add_folder(ctype);
        for (name, _) in files {
            folder.add_file(*name);
        }
        let mut writer = builder.build(Cursor::new(Vec::new())).unwrap();
        let mut i = 0;
        while let Some(mut w) = writer.next_file().unwrap() {
            w.write_all(files[i].1).unwrap();
            i += 1;
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn extracts_mszip_and_stored() {
        let big: Vec<u8> = (0..100_000u32)
            .flat_map(|i| (i % 251).to_le_bytes())
            .collect();
        for ctype in [cab::CompressionType::MsZip, cab::CompressionType::None] {
            let bytes = build(
                ctype,
                &[
                    ("a.txt", b"hello"),
                    ("dir\\big.bin", &big),
                    ("..\\evil.dll", b"MZ"),
                ],
            );
            let out = expand(&bytes, &Limits::default()).unwrap();
            assert_eq!(out.child("a.txt").unwrap().data, b"hello");
            assert_eq!(out.child("dir/big.bin").unwrap().data, big);
            assert!(out.child("__/evil.dll").is_some());
            assert!(out.problems.iter().any(|p| p.contains("traversal")));
            for n in (0..bytes.len()).step_by(7) {
                let _ = expand(&bytes[..n], &Limits::default());
            }
        }
    }

    #[test]
    fn rejects_garbage_and_quantum() {
        assert!(expand(b"MSCF", &Limits::default()).is_err());
        assert!(expand(b"nope", &Limits::default()).is_err());
        let mut bytes = build(cab::CompressionType::None, &[("a", b"x")]);
        // Patch the folder's compression type to Quantum.
        bytes[36 + 6] = 2;
        let out = expand(&bytes, &Limits::default()).unwrap();
        assert!(out.problems.iter().any(|p| p.contains("Quantum")));
    }

    #[test]
    fn bomb_guard() {
        let zeros = vec![0u8; 4 << 20];
        let bytes = build(cab::CompressionType::MsZip, &[("z", &zeros)]);
        let limits = Limits {
            max_ratio: 2,
            ..Limits::default()
        };
        let out = expand(&bytes, &limits).unwrap();
        assert!(out.truncated);
        assert!(
            out.children
                .iter()
                .all(|c| c.data.len() as u64 <= RATIO_FLOOR)
        );
    }

    /// `BYTEBOUNCER_CAB_SAMPLE=/path/to.cab cargo test -p bytebouncer-formats -- --ignored cab_sample --nocapture`
    #[test]
    #[ignore]
    fn cab_sample() {
        let path = std::env::var("BYTEBOUNCER_CAB_SAMPLE").expect("set BYTEBOUNCER_CAB_SAMPLE");
        let out = expand(&std::fs::read(path).unwrap(), &Limits::default()).unwrap();
        println!(
            "{} children, problems: {:?}",
            out.children.len(),
            out.problems
        );
        for c in out.children.iter().take(10) {
            println!("  {} ({} bytes)", c.path, c.data.len());
        }
    }
}

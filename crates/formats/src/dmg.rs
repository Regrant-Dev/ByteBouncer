//! Apple UDIF disk images (`.dmg`). The `koly` trailer points at an XML
//! plist whose `blkx` resources describe each partition as `mish` chunk
//! tables; chunks are decompressed and laid out into one raw `disk.img`
//! child. The filesystem inside (HFS+/APFS) is not parsed.

use base64::Engine;

use crate::compress::{decompress, zlib};
use crate::util::xml;
use crate::util::{Sink, slice, u32be, u64be};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

const KIND: ContainerKind = ContainerKind::Dmg;
const SECTOR: u64 = 512;
const MISH_HEADER: usize = 204;
const CHUNK: usize = 40;

fn dict_get<'a, 'i>(dict: roxmltree::Node<'a, 'i>, key: &str) -> Option<roxmltree::Node<'a, 'i>> {
    let mut it = dict.children().filter(|n| n.is_element());
    while let Some(k) = it.next() {
        let v = it.next()?;
        if k.has_tag_name("key") && k.text() == Some(key) {
            return Some(v);
        }
    }
    None
}

fn chunk_name(t: u32) -> &'static str {
    match t {
        0 => "zero",
        1 => "raw",
        2 => "ignore",
        0x8000_0004 => "adc",
        0x8000_0005 => "zlib",
        0x8000_0006 => "bzip2",
        0x8000_0007 => "lzfse",
        0x8000_0008 => "lzma",
        0x7fff_fffe => "comment",
        0xffff_ffff => "end",
        _ => "unknown",
    }
}

struct Partition {
    name: String,
    first_sector: u64,
    sectors: u64,
    data_offset: u64,
    chunks: Vec<[u64; 5]>, // type, sector, sector_count, offset, length
}

fn parse_mish(b: &[u8]) -> Option<(u64, u64, u64, Vec<[u64; 5]>)> {
    if !b.starts_with(b"mish") {
        return None;
    }
    let count = u32be(b, 200)? as usize;
    let mut chunks = Vec::with_capacity(count.min(b.len() / CHUNK));
    for i in 0..count {
        let off = MISH_HEADER.checked_add(i.checked_mul(CHUNK)?)?;
        let c = slice(b, off, CHUNK)?;
        chunks.push([
            u32be(c, 0)? as u64,
            u64be(c, 8)?,
            u64be(c, 16)?,
            u64be(c, 24)?,
            u64be(c, 32)?,
        ]);
    }
    Some((u64be(b, 8)?, u64be(b, 16)?, u64be(b, 24)?, chunks))
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if bytes.starts_with(b"encrcdsa") || bytes.starts_with(b"cdsaencr") {
        return Err(FormatError::Unsupported(
            "encrypted DMG; contents cannot be inspected".into(),
        ));
    }
    let bad = |m: String| FormatError::malformed(KIND, m);
    let koly = bytes
        .len()
        .checked_sub(512)
        .and_then(|o| slice(bytes, o, 512))
        .filter(|k| k.starts_with(b"koly"))
        .ok_or_else(|| bad("no koly trailer".into()))?;
    let field = |o| u64be(koly, o).unwrap_or(0);
    let (data_fork, xml_off, xml_len, koly_sectors) =
        (field(24), field(216), field(224), field(492));
    let plist = usize::try_from(xml_off)
        .ok()
        .zip(usize::try_from(xml_len).ok())
        .and_then(|(o, l)| slice(bytes, o, l))
        .filter(|p| !p.is_empty())
        .ok_or_else(|| bad("plist offset/length outside the file".into()))?;
    let plist = String::from_utf8_lossy(plist);
    let doc = xml(&plist).map_err(|e| bad(format!("plist: {e}")))?;
    let blkx = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("dict"))
        .and_then(|d| dict_get(d, "resource-fork"))
        .and_then(|r| dict_get(r, "blkx"))
        .ok_or_else(|| bad("plist has no resource-fork/blkx".into()))?;

    let mut sink = Sink::new(KIND, limits, bytes.len());
    let mut parts = Vec::new();
    for entry in blkx.children().filter(|n| n.has_tag_name("dict")) {
        let name = dict_get(entry, "Name")
            .or_else(|| dict_get(entry, "CFName"))
            .and_then(|n| n.text())
            .unwrap_or("")
            .to_owned();
        let data: String = dict_get(entry, "Data")
            .and_then(|d| d.text())
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(data) else {
            sink.problem(format!("dmg: partition {name:?} has invalid base64 data"));
            continue;
        };
        match parse_mish(&raw) {
            Some((first_sector, sectors, data_offset, chunks)) => parts.push(Partition {
                name,
                first_sector,
                sectors,
                data_offset,
                chunks,
            }),
            None => sink.problem(format!(
                "dmg: partition {name:?} has a malformed mish table"
            )),
        }
    }

    // Size the image from partition extents, then clamp to limits before
    // allocating anything.
    let sectors = parts
        .iter()
        .map(|p| p.first_sector.saturating_add(p.sectors))
        .max()
        .unwrap_or(koly_sectors);
    let want = sectors.saturating_mul(SECTOR);
    let cap = sink.entry_cap(bytes.len() as u64);
    if want > cap {
        sink.truncate(format!(
            "dmg: image of {want} bytes exceeds the size/ratio limit; disk.img cut to {cap} bytes"
        ));
    }
    let mut image = vec![0u8; want.min(cap) as usize];

    let mut counts: Vec<(&str, usize)> = Vec::new();
    for p in &parts {
        sink.meta("dmg.partition", p.name.clone());
        for &[ctype, sector, count, off, len] in &p.chunks {
            let t = chunk_name(ctype as u32);
            match counts.iter_mut().find(|(n, _)| *n == t) {
                Some((_, c)) => *c += 1,
                None => counts.push((t, 1)),
            }
            let start = p
                .first_sector
                .checked_add(sector)
                .and_then(|s| s.checked_mul(SECTOR))
                .unwrap_or(u64::MAX);
            let size = count.saturating_mul(SECTOR);
            let room = (image.len() as u64).saturating_sub(start).min(size);
            if matches!(t, "zero" | "ignore" | "comment" | "end") || room == 0 {
                continue;
            }
            let src = data_fork
                .checked_add(p.data_offset)
                .and_then(|o| o.checked_add(off))
                .and_then(|o| usize::try_from(o).ok())
                .zip(usize::try_from(len).ok())
                .and_then(|(o, l)| slice(bytes, o, l));
            let Some(src) = src else {
                sink.problem(format!("dmg: chunk in {:?} lies outside the file", p.name));
                continue;
            };
            let out = match t {
                "raw" => src[..src.len().min(room as usize)].to_vec(),
                "zlib" => zlib(src, room).data,
                "bzip2" => decompress(ContainerKind::Bzip2, src, room).data,
                "lzma" => {
                    let b = decompress(ContainerKind::Xz, src, room);
                    if b.data.is_empty() {
                        decompress(ContainerKind::Lzma, src, room).data
                    } else {
                        b.data
                    }
                }
                other => {
                    sink.problem(format!(
                        "dmg: {other} chunks are not supported; left zeroed"
                    ));
                    continue;
                }
            };
            if (out.len() as u64) < room {
                sink.problem(format!(
                    "dmg: {t} chunk in {:?} decoded short or corrupt",
                    p.name
                ));
            }
            let s = start as usize;
            image[s..s + out.len()].copy_from_slice(&out);
        }
    }
    for (t, c) in counts {
        sink.meta(format!("dmg.chunks.{t}"), c.to_string());
    }
    sink.problem("DMG filesystem (HFS+/APFS) was not parsed; disk.img returned raw");
    sink.push("disk.img", EntryKind::File, None, image);
    Ok(sink.finish())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// One partition: sector 0 raw, sectors 1-2 zlib, sector 3 zero-fill.
    pub(crate) fn build(total_sectors: u64) -> Vec<u8> {
        let raw = vec![0xAAu8; 512];
        let z = deflate(&[0xBBu8; 1024]);
        let mut data = raw.clone();
        data.extend(&z);
        let chunks: [[u64; 5]; 4] = [
            [1, 0, 1, 0, 512],
            [0x8000_0005, 1, 2, 512, z.len() as u64],
            [0, 3, 1, 0, 0],
            [0xffff_ffff, 4, 0, 0, 0],
        ];
        let mut mish = b"mish".to_vec();
        mish.extend(1u32.to_be_bytes());
        mish.extend(0u64.to_be_bytes());
        mish.extend(total_sectors.to_be_bytes());
        mish.extend(0u64.to_be_bytes());
        mish.resize(200, 0);
        mish.extend((chunks.len() as u32).to_be_bytes());
        for c in chunks {
            mish.extend((c[0] as u32).to_be_bytes());
            mish.extend(0u32.to_be_bytes());
            for v in &c[1..] {
                mish.extend(v.to_be_bytes());
            }
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&mish);
        let plist = format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Attributes</key><string>0x0050</string><key>Data</key><data>\n{b64}\n</data><key>Name</key><string>disk image (Apple_HFS : 1)</string></dict></array></dict></dict></plist>"
        );
        let mut out = data;
        let xml_off = out.len() as u64;
        out.extend(plist.as_bytes());
        let mut koly = vec![0u8; 512];
        koly[..4].copy_from_slice(b"koly");
        koly[4..8].copy_from_slice(&4u32.to_be_bytes());
        koly[8..12].copy_from_slice(&512u32.to_be_bytes());
        koly[32..40].copy_from_slice(&xml_off.to_be_bytes());
        koly[216..224].copy_from_slice(&xml_off.to_be_bytes());
        koly[224..232].copy_from_slice(&(plist.len() as u64).to_be_bytes());
        koly[492..500].copy_from_slice(&total_sectors.to_be_bytes());
        out.extend(koly);
        out
    }

    #[test]
    fn assembles_disk_image() {
        let out = expand(&build(4), &Limits::default()).unwrap();
        let img = &out.child("disk.img").unwrap().data;
        assert_eq!(img.len(), 2048);
        assert!(img[..512].iter().all(|&b| b == 0xAA));
        assert!(img[512..1536].iter().all(|&b| b == 0xBB));
        assert!(img[1536..].iter().all(|&b| b == 0));
        assert_eq!(
            out.meta("dmg.partition"),
            Some("disk image (Apple_HFS : 1)")
        );
        assert_eq!(out.meta("dmg.chunks.zlib"), Some("1"));
        assert!(out.problems.iter().any(|p| p.contains("not parsed")));
        assert!(!out.truncated);
    }

    #[test]
    fn absurd_sector_counts_are_clamped() {
        let out = expand(&build(u64::MAX / 2), &Limits::default()).unwrap();
        assert!(out.truncated);
        assert!(out.child("disk.img").unwrap().data.len() as u64 <= crate::util::RATIO_FLOOR);
    }

    #[test]
    fn hostile_inputs_never_panic() {
        let good = build(4);
        for n in 0..good.len() {
            let _ = expand(&good[..n], &Limits::default());
        }
        let mut flipped = good.clone();
        for i in (0..flipped.len()).step_by(5) {
            flipped[i] ^= 0x33;
            let _ = expand(&flipped, &Limits::default());
        }
        let mut enc = good;
        enc[..8].copy_from_slice(b"encrcdsa");
        assert!(matches!(
            expand(&enc, &Limits::default()),
            Err(FormatError::Unsupported(_))
        ));
    }

    /// `BYTEBOUNCER_DMG_SAMPLE=/path/x.dmg cargo test -- --ignored real_dmg`.
    #[test]
    #[ignore]
    fn real_dmg() {
        let path = std::env::var("BYTEBOUNCER_DMG_SAMPLE").expect("set BYTEBOUNCER_DMG_SAMPLE");
        let out = expand(&std::fs::read(path).unwrap(), &Limits::default()).unwrap();
        eprintln!("{:#?}\n{:#?}", out.metadata, out.problems);
        let img = &out.child("disk.img").unwrap().data;
        let fs = [&b"H+\0\x04"[..], b"HX\0\x05", b"NXSB"]
            .iter()
            .any(|m| img.windows(m.len()).any(|w| w == *m));
        eprintln!(
            "disk.img {} bytes, HFS+/APFS signature found: {fs}",
            img.len()
        );
        assert!(!img.is_empty());
    }
}

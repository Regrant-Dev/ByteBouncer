//! Bounded, in-memory tar reading (gzip / zstd / plain). Nothing is written to
//! disk; entry paths are only used as strings.

use std::io::Read;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    /// Total bytes of retained file contents.
    pub max_total: u64,
    pub max_file: u64,
    /// Total decompressed stream bytes read (decompression-bomb bound).
    pub max_stream: u64,
}

#[derive(Debug, Default)]
pub struct TarContents {
    /// Regular files: (normalized path, bytes).
    pub files: Vec<(String, Vec<u8>)>,
    /// Entries skipped, with reasons (symlinks, devices, oversize…).
    pub skipped: Vec<String>,
}

fn decompressor<'a>(bytes: &'a [u8]) -> Result<Box<dyn Read + 'a>, String> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(flate2::read::GzDecoder::new(bytes)))
    } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let d = ruzstd::decoding::StreamingDecoder::new(bytes).map_err(|e| format!("zstd: {e}"))?;
        Ok(Box::new(d))
    } else if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        Ok(Box::new(bytes))
    } else {
        Err("unrecognized archive compression (expected gzip, zstd or tar)".to_string())
    }
}

/// Visit every regular-file entry; `want` decides whether its contents are
/// read (others are skipped without buffering).
pub fn read_tar(
    bytes: &[u8],
    limits: Limits,
    want: &dyn Fn(&str) -> bool,
) -> Result<TarContents, String> {
    let reader = decompressor(bytes)?.take(limits.max_stream);
    let mut archive = tar::Archive::new(reader);
    let mut out = TarContents::default();
    let mut total = 0u64;
    let mut count = 0usize;
    for entry in archive.entries().map_err(|e| format!("tar: {e}"))? {
        let mut entry = entry.map_err(|e| format!("tar: {e}"))?;
        count += 1;
        if count > limits.max_entries {
            return Err(format!(
                "archive has more than {} entries",
                limits.max_entries
            ));
        }
        let path = entry
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .to_string_lossy()
            .into_owned();
        let path = path.trim_start_matches("./").to_string();
        let kind = entry.header().entry_type();
        if kind.is_dir() || kind.is_pax_global_extensions() || kind.is_pax_local_extensions() {
            continue;
        }
        if path.split('/').any(|c| c == "..") || path.starts_with('/') {
            out.skipped
                .push(format!("{path}: path escapes the archive root"));
            continue;
        }
        if !kind.is_file() {
            out.skipped
                .push(format!("{path}: not a regular file ({kind:?})"));
            continue;
        }
        if !want(&path) {
            continue;
        }
        let size = entry.header().size().unwrap_or(u64::MAX);
        if size > limits.max_file || total.saturating_add(size) > limits.max_total {
            out.skipped
                .push(format!("{path}: exceeds size budget ({size} bytes)"));
            continue;
        }
        let mut buf = Vec::with_capacity(size as usize);
        (&mut entry)
            .take(limits.max_file + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("tar read {path}: {e}"))?;
        total += buf.len() as u64;
        out.files.push((path, buf));
    }
    Ok(out)
}

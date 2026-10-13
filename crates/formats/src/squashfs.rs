//! Minimal read-only SquashFS 4.0 reader (little-endian `hsqs`), used for
//! standalone images and AppImage payloads. Self-written rather than a crate
//! so every allocation is bounded by [`Limits`] and only pure-Rust
//! decompressors are involved. Metadata and data blocks are decompressed on
//! demand; directory cycles, out-of-range offsets and absurd sizes become
//! problems, never panics.

use std::collections::{HashMap, HashSet};

use crate::compress::{decompress, zlib};
use crate::util::{RATIO_FLOOR, Sink, slice, u16le, u32le, u64le};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

const MAGIC: &[u8; 4] = b"hsqs";
const SUPERBLOCK_LEN: usize = 96;
const META_BLOCK: usize = 8192;
const MAX_DEPTH: usize = 256;
const NO_FRAGMENT: u32 = 0xFFFF_FFFF;

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    let mut sink = Sink::new(ContainerKind::Squashfs, limits, bytes.len());
    read_into(bytes, &mut sink, "")
        .map_err(|e| FormatError::malformed(ContainerKind::Squashfs, e))?;
    Ok(sink.finish())
}

/// Name of the image's compressor, if the superblock is readable.
pub(crate) fn compression_name(bytes: &[u8]) -> Option<&'static str> {
    Some(match u16le(bytes, 20)? {
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => "unknown",
    })
}

/// True if `bytes` starts with a plausible SquashFS 4.0 superblock.
pub(crate) fn looks_valid(bytes: &[u8]) -> bool {
    Superblock::parse(bytes).is_ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Comp {
    Gzip,
    Lzma,
    Xz,
    Lz4,
    Zstd,
}

struct Superblock {
    block_size: u32,
    fragment_count: u32,
    comp_id: u16,
    root_inode: u64,
    bytes_used: u64,
    inode_table: u64,
    dir_table: u64,
    fragment_table: u64,
}

impl Superblock {
    fn parse(b: &[u8]) -> Result<Self, String> {
        if !b.starts_with(MAGIC) {
            return Err("missing hsqs magic (big-endian or pre-4.0 images are unsupported)".into());
        }
        if b.len() < SUPERBLOCK_LEN {
            return Err("truncated superblock".into());
        }
        let field = |off| u16le(b, off).ok_or("truncated superblock");
        let (major, minor) = (field(28)?, field(30)?);
        if (major, minor) != (4, 0) {
            return Err(format!("unsupported squashfs version {major}.{minor}"));
        }
        let block_size = u32le(b, 12).ok_or("truncated superblock")?;
        let block_log = field(22)?;
        if !(12..=20).contains(&block_log) || block_size != 1 << block_log {
            return Err(format!("invalid block size {block_size}"));
        }
        let get = |off| u64le(b, off).ok_or("truncated superblock");
        Ok(Self {
            block_size,
            fragment_count: u32le(b, 16).ok_or("truncated superblock")?,
            comp_id: field(20)?,
            root_inode: get(32)?,
            bytes_used: get(40)?,
            inode_table: get(64)?,
            dir_table: get(72)?,
            fragment_table: get(80)?,
        })
    }
}

/// A decompressed metadata block and the absolute offset of the next one.
struct MetaBlock {
    data: Vec<u8>,
    next: u64,
}

struct Reader<'a> {
    img: &'a [u8],
    comp: Comp,
    sb: Superblock,
    meta: HashMap<u64, MetaBlock>,
    /// Remaining bytes we are willing to decompress for metadata.
    meta_budget: u64,
    fragments: HashMap<u32, Vec<u8>>,
}

/// Position inside a metadata stream: block start (absolute) + offset.
#[derive(Clone, Copy)]
struct Cursor {
    pos: u64,
    off: usize,
}

impl<'a> Reader<'a> {
    fn decompress(&self, data: &[u8], cap: u64) -> Result<Vec<u8>, String> {
        let b = match self.comp {
            Comp::Gzip => zlib(data, cap),
            Comp::Lzma => decompress(ContainerKind::Lzma, data, cap),
            Comp::Xz => decompress(ContainerKind::Xz, data, cap),
            Comp::Zstd => decompress(ContainerKind::Zstd, data, cap),
            Comp::Lz4 => {
                let mut out = vec![0u8; cap as usize];
                let n =
                    lz4_flex::block::decompress_into(data, &mut out).map_err(|e| e.to_string())?;
                out.truncate(n);
                return Ok(out);
            }
        };
        if b.capped {
            return Err(format!("block expands beyond {cap} bytes"));
        }
        match b.error {
            Some(e) => Err(e),
            None => Ok(b.data),
        }
    }

    fn meta_block(&mut self, pos: u64) -> Result<&MetaBlock, String> {
        if !self.meta.contains_key(&pos) {
            let start = usize::try_from(pos).map_err(|_| "offset overflow")?;
            let header = u16le(self.img, start).ok_or("metadata block out of range")?;
            let len = (header & 0x7FFF) as usize;
            let raw = slice(self.img, start + 2, len).ok_or("metadata block truncated")?;
            let data = if header & 0x8000 != 0 {
                if len > META_BLOCK {
                    return Err("oversized metadata block".into());
                }
                raw.to_vec()
            } else {
                self.decompress(raw, META_BLOCK as u64)?
            };
            if data.is_empty() {
                return Err("empty metadata block".into());
            }
            self.meta_budget = self
                .meta_budget
                .checked_sub(data.len() as u64)
                .ok_or("metadata expansion limit reached")?;
            let next = pos + 2 + len as u64;
            self.meta.insert(pos, MetaBlock { data, next });
        }
        Ok(&self.meta[&pos])
    }

    /// Read `len` bytes of metadata at `cur`, advancing it across blocks.
    fn read(&mut self, cur: &mut Cursor, len: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(len.min(META_BLOCK));
        while out.len() < len {
            let block = self.meta_block(cur.pos)?;
            if cur.off >= block.data.len() {
                if cur.off > block.data.len() {
                    return Err("metadata offset past end of block".into());
                }
                cur.pos = block.next;
                cur.off = 0;
                continue;
            }
            let take = (len - out.len()).min(block.data.len() - cur.off);
            out.extend_from_slice(&block.data[cur.off..cur.off + take]);
            cur.off += take;
        }
        Ok(out)
    }

    fn inode_cursor(&self, inode_ref: u64) -> Cursor {
        Cursor {
            pos: self.sb.inode_table.saturating_add(inode_ref >> 16),
            off: (inode_ref & 0xFFFF) as usize,
        }
    }

    /// Read one on-disk data block (`size` uses the squashfs size encoding).
    fn data_block(&self, start: u64, size: u32) -> Result<Vec<u8>, String> {
        let len = (size & 0x00FF_FFFF) as usize;
        let start = usize::try_from(start).map_err(|_| "offset overflow")?;
        let raw = slice(self.img, start, len).ok_or("data block out of range")?;
        if size & (1 << 24) != 0 {
            if len > self.sb.block_size as usize {
                return Err("oversized data block".into());
            }
            Ok(raw.to_vec())
        } else {
            self.decompress(raw, self.sb.block_size as u64)
        }
    }

    fn fragment(&mut self, index: u32) -> Result<&Vec<u8>, String> {
        if !self.fragments.contains_key(&index) {
            if index >= self.sb.fragment_count {
                return Err(format!("fragment index {index} out of range"));
            }
            let ptr_off = self
                .sb
                .fragment_table
                .saturating_add(u64::from(index / 512) * 8);
            let ptr = u64le(
                self.img,
                usize::try_from(ptr_off).map_err(|_| "offset overflow")?,
            )
            .ok_or("fragment table out of range")?;
            let mut cur = Cursor {
                pos: ptr,
                off: (index % 512) as usize * 16,
            };
            let entry = self.read(&mut cur, 16)?;
            let (start, size) = (u64le(&entry, 0).unwrap_or(0), u32le(&entry, 8).unwrap_or(0));
            let block = self.data_block(start, size)?;
            // Fragments are shared by neighbouring files; keep the cache small.
            if self.fragments.len() >= 16 {
                self.fragments.clear();
            }
            self.fragments.insert(index, block);
        }
        Ok(&self.fragments[&index])
    }
}

enum Inode {
    Dir {
        cur: Cursor,
        size: u64,
    },
    File {
        blocks_start: u64,
        size: u64,
        frag: u32,
        frag_off: u32,
        block_list: Cursor,
    },
    Symlink(String),
    Special(&'static str),
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32le(b, off).unwrap_or(0)
}

impl Reader<'_> {
    /// Parse the inode at `inode_ref`; returns it and its permission bits.
    fn inode(&mut self, inode_ref: u64) -> Result<(Inode, u32), String> {
        let mut cur = self.inode_cursor(inode_ref);
        let h = self.read(&mut cur, 16)?;
        let kind = u16le(&h, 0).unwrap_or(0);
        let mode = u32::from(u16le(&h, 2).unwrap_or(0) & 0o7777);
        let dir_cursor = |block: u32, off: u16, sb: &Superblock| Cursor {
            pos: sb.dir_table.saturating_add(u64::from(block)),
            off: off as usize,
        };
        let inode = match kind {
            1 => {
                let b = self.read(&mut cur, 16)?;
                let size = u16le(&b, 8).unwrap_or(0);
                let cur = dir_cursor(le32(&b, 0), u16le(&b, 10).unwrap_or(0), &self.sb);
                Inode::Dir {
                    cur,
                    size: u64::from(size),
                }
            }
            8 => {
                let b = self.read(&mut cur, 24)?;
                let cur = dir_cursor(le32(&b, 8), u16le(&b, 18).unwrap_or(0), &self.sb);
                Inode::Dir {
                    cur,
                    size: u64::from(le32(&b, 4)),
                }
            }
            2 => {
                let b = self.read(&mut cur, 16)?;
                Inode::File {
                    blocks_start: u64::from(le32(&b, 0)),
                    frag: le32(&b, 4),
                    frag_off: le32(&b, 8),
                    size: u64::from(le32(&b, 12)),
                    block_list: cur,
                }
            }
            9 => {
                let b = self.read(&mut cur, 40)?;
                Inode::File {
                    blocks_start: u64le(&b, 0).unwrap_or(0),
                    size: u64le(&b, 8).unwrap_or(0),
                    frag: le32(&b, 28),
                    frag_off: le32(&b, 32),
                    block_list: cur,
                }
            }
            3 | 10 => {
                let b = self.read(&mut cur, 8)?;
                let len = le32(&b, 4) as usize;
                if len > 4096 {
                    return Err(format!("symlink target of {len} bytes"));
                }
                Inode::Symlink(String::from_utf8_lossy(&self.read(&mut cur, len)?).into_owned())
            }
            4 | 11 => Inode::Special("block device"),
            5 | 12 => Inode::Special("character device"),
            6 | 13 => Inode::Special("fifo"),
            7 | 14 => Inode::Special("socket"),
            k => return Err(format!("unknown inode type {k}")),
        };
        Ok((inode, mode))
    }

    /// Directory entries as `(name, inode_ref)`.
    fn dir_entries(&mut self, mut cur: Cursor, size: u64) -> Result<Vec<(String, u64)>, String> {
        // The stored size counts 3 bytes for the implicit `.` and `..`.
        let mut left = size.saturating_sub(3);
        let mut out = Vec::new();
        while left >= 12 {
            let h = self.read(&mut cur, 12)?;
            left -= 12;
            let count = u64::from(le32(&h, 0)) + 1;
            if count > 256 {
                return Err(format!("directory header claims {count} entries"));
            }
            let start = u64::from(le32(&h, 4));
            for _ in 0..count {
                if left < 8 {
                    return Err("directory listing truncated".into());
                }
                let e = self.read(&mut cur, 8)?;
                let name_len = usize::from(u16le(&e, 6).unwrap_or(0)) + 1;
                let name = self.read(&mut cur, name_len)?;
                left = left.saturating_sub(8 + name_len as u64);
                let inode_ref = (start << 16) | u64::from(u16le(&e, 0).unwrap_or(0));
                out.push((String::from_utf8_lossy(&name).into_owned(), inode_ref));
            }
        }
        Ok(out)
    }

    /// File contents, capped at `cap` bytes. Returns the data and whether it
    /// was cut short by the cap.
    fn file_data(
        &mut self,
        blocks_start: u64,
        size: u64,
        frag: u32,
        frag_off: u32,
        block_list: Cursor,
        cap: u64,
    ) -> Result<(Vec<u8>, bool), String> {
        let mut out = Vec::with_capacity(size.min(cap).min(1 << 20) as usize);
        let capped = self.file_stream(
            blocks_start,
            size,
            frag,
            frag_off,
            block_list,
            cap,
            &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            },
        )?;
        Ok((out, capped))
    }

    /// Decode a file block by block, handing each piece to `emit`, stopping
    /// after `cap` bytes. Returns whether the file was larger than `cap`.
    #[allow(clippy::too_many_arguments)]
    fn file_stream(
        &mut self,
        blocks_start: u64,
        size: u64,
        frag: u32,
        frag_off: u32,
        mut block_list: Cursor,
        cap: u64,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<bool, String> {
        let bs = u64::from(self.sb.block_size);
        let want = size.min(cap);
        let full_blocks = if frag == NO_FRAGMENT {
            size.div_ceil(bs)
        } else {
            size / bs
        };
        let mut done = 0u64;
        let mut put = |piece: &[u8], done: &mut u64| -> Result<(), String> {
            let take = (want - *done).min(piece.len() as u64) as usize;
            emit(&piece[..take])?;
            *done += take as u64;
            Ok(())
        };
        let mut pos = blocks_start;
        let mut i = 0;
        while i < full_blocks && done < want {
            let sz = le32(&self.read(&mut block_list, 4)?, 0);
            let block_len = bs.min(size - i * bs);
            if sz & 0x00FF_FFFF == 0 {
                put(&vec![0u8; block_len as usize], &mut done)?;
            } else {
                let block = self.data_block(pos, sz)?;
                if block.len() as u64 != block_len {
                    return Err(format!(
                        "data block {i} has {} bytes, expected {block_len}",
                        block.len()
                    ));
                }
                put(&block, &mut done)?;
                pos = pos.saturating_add(u64::from(sz & 0x00FF_FFFF));
            }
            i += 1;
        }
        if frag != NO_FRAGMENT && done < want {
            let tail = (size % bs) as usize;
            let block = self.fragment(frag)?;
            let piece =
                slice(block, frag_off as usize, tail).ok_or("fragment slice out of range")?;
            let piece = piece.to_vec();
            put(&piece, &mut done)?;
        }
        Ok(size > cap)
    }
}

/// Walk the image in `bytes`, pushing every entry under `prefix`. Errors are
/// fatal header problems (bad superblock, unsupported compressor, unreadable
/// root); per-entry damage is recorded on the sink and skipped.
pub(crate) fn read_into(bytes: &[u8], sink: &mut Sink, prefix: &str) -> Result<(), String> {
    walk(bytes, sink, prefix, None)
}

/// A single file to stream out instead of expanding the whole image.
pub(crate) struct Target<'w> {
    path: &'w str,
    out: &'w mut dyn std::io::Write,
    max: u64,
    written: Option<u64>,
}

/// Stream the regular file at normalized `path` into `out`.
pub(crate) fn extract(
    bytes: &[u8],
    prefix: &str,
    path: &str,
    out: &mut dyn std::io::Write,
    max: u64,
) -> Result<u64, String> {
    let limits = Limits::default();
    let mut sink = Sink::new(ContainerKind::Squashfs, &limits, bytes.len());
    let mut target = Target {
        path,
        out,
        max,
        written: None,
    };
    walk(bytes, &mut sink, prefix, Some(&mut target))?;
    target.written.ok_or_else(|| format!("{path:?} not found"))
}

fn walk(
    bytes: &[u8],
    sink: &mut Sink,
    prefix: &str,
    mut target: Option<&mut Target>,
) -> Result<(), String> {
    let sb = Superblock::parse(bytes)?;
    let comp = match sb.comp_id {
        1 => Comp::Gzip,
        2 => Comp::Lzma,
        4 => Comp::Xz,
        5 => Comp::Lz4,
        6 => Comp::Zstd,
        3 => return Err("unsupported squashfs compression: lzo (no pure-Rust decoder)".into()),
        n => return Err(format!("unknown squashfs compression id {n}")),
    };
    let img = if sb.bytes_used > bytes.len() as u64 {
        sink.problem(format!(
            "squashfs: image claims {} bytes but only {} are present",
            sb.bytes_used,
            bytes.len()
        ));
        bytes
    } else {
        &bytes[..sb.bytes_used as usize]
    };
    let meta_budget = sink.limits.max_total_bytes.min(
        (img.len() as u64)
            .saturating_mul(sink.limits.max_ratio)
            .max(RATIO_FLOOR),
    );
    let root = sb.root_inode;
    let mut r = Reader {
        img,
        comp,
        sb,
        meta: HashMap::new(),
        meta_budget,
        fragments: HashMap::new(),
    };
    let (Inode::Dir { cur, size }, _) = r.inode(root).map_err(|e| format!("root inode: {e}"))?
    else {
        return Err("root inode is not a directory".into());
    };
    let mut visited = HashSet::from([root]);
    let mut stack = vec![(cur, size, prefix.to_owned(), 0usize)];
    while let Some((cur, size, dir_path, depth)) = stack.pop() {
        let entries = match r.dir_entries(cur, size) {
            Ok(e) => e,
            Err(e) => {
                sink.problem(format!("squashfs: directory {dir_path:?}: {e}"));
                continue;
            }
        };
        for (name, inode_ref) in entries {
            if target.is_none() && sink.full() {
                return Ok(());
            }
            let clean = if name.contains(['/', '\\']) || name == ".." || name == "." {
                sink.problem(format!(
                    "squashfs: illegal entry name {name:?} in {dir_path:?}"
                ));
                name.replace(['/', '\\', '.'], "_")
            } else {
                name
            };
            let path = if dir_path.is_empty() {
                clean
            } else {
                format!("{dir_path}/{clean}")
            };
            let (inode, mode) = match r.inode(inode_ref) {
                Ok(i) => i,
                Err(e) => {
                    sink.problem(format!("squashfs: {path:?}: {e}"));
                    continue;
                }
            };
            let pushed = match inode {
                Inode::Dir { cur, size } => {
                    if !visited.insert(inode_ref) {
                        sink.problem(format!("squashfs: directory cycle at {path:?}"));
                        continue;
                    }
                    if depth + 1 >= MAX_DEPTH {
                        sink.problem(format!("squashfs: directory nesting too deep at {path:?}"));
                        continue;
                    }
                    stack.push((cur, size, path.clone(), depth + 1));
                    if target.is_some() {
                        continue;
                    }
                    sink.push(&path, EntryKind::Directory, Some(mode), Vec::new())
                }
                Inode::File {
                    blocks_start,
                    size,
                    frag,
                    frag_off,
                    block_list,
                } => {
                    if let Some(t) = target.as_deref_mut() {
                        if crate::util::normalize_path(&path).0 != t.path {
                            continue;
                        }
                        if size > t.max {
                            return Err(format!(
                                "{path:?} is {size} bytes, over the {}-byte extraction limit",
                                t.max
                            ));
                        }
                        let out = &mut *t.out;
                        r.file_stream(
                            blocks_start,
                            size,
                            frag,
                            frag_off,
                            block_list,
                            size,
                            &mut |b| out.write_all(b).map_err(|e| e.to_string()),
                        )?;
                        t.written = Some(size);
                        return Ok(());
                    }
                    if size > sink.limits.max_entry_bytes {
                        sink.oversized(&path, size);
                        continue;
                    }
                    let cap = sink.entry_budget();
                    match r.file_data(blocks_start, size, frag, frag_off, block_list, cap) {
                        Ok((data, capped)) => {
                            if capped {
                                sink.truncate(format!("squashfs: {path:?} exceeds the size limit"));
                            }
                            sink.push(&path, EntryKind::File, Some(mode), data)
                        }
                        Err(e) => {
                            sink.problem(format!("squashfs: {path:?}: {e}"));
                            sink.push(&path, EntryKind::File, Some(mode), Vec::new())
                        }
                    }
                }
                Inode::Symlink(_) if target.is_some() => continue,
                Inode::Symlink(link) => sink.push(
                    &path,
                    EntryKind::Symlink { target: link },
                    Some(mode),
                    Vec::new(),
                ),
                Inode::Special(_) if target.is_some() => continue,
                Inode::Special(what) => sink.push(
                    &path,
                    EntryKind::Special(what.into()),
                    Some(mode),
                    Vec::new(),
                ),
            };
            if !pushed {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) enum Node {
        Dir(Vec<(&'static str, Node)>),
        File(Vec<u8>),
        Link(&'static str),
        Fifo,
    }

    /// Test image builder. `comp` is the squashfs compressor id (0 = store
    /// everything uncompressed but label it gzip). Metadata is compressed
    /// only when each table fits one block, which keeps refs simple.
    pub(crate) fn build(root: Node, comp: u16, block_log: u16) -> Vec<u8> {
        let bs = 1usize << block_log;
        let compress = |data: &[u8]| -> Option<Vec<u8>> {
            let out = match comp {
                1 => {
                    let mut e =
                        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    e.write_all(data).unwrap();
                    e.finish().unwrap()
                }
                4 => {
                    let mut w = lzma_rust2::XzWriter::new(
                        Vec::new(),
                        lzma_rust2::XzOptions::with_preset(1),
                    )
                    .unwrap();
                    w.write_all(data).unwrap();
                    w.finish().unwrap()
                }
                5 => lz4_flex::block::compress(data),
                6 => ruzstd::encoding::compress_to_vec(
                    data,
                    ruzstd::encoding::CompressionLevel::Fastest,
                ),
                _ => return None,
            };
            (out.len() < data.len()).then_some(out)
        };
        // Flatten the tree: items[0] is the root.
        enum Item {
            Dir(Vec<(String, usize)>),
            File(Vec<u8>),
            Link(String),
            Fifo,
        }
        fn flatten(node: Node, items: &mut Vec<Item>) -> usize {
            let idx = items.len();
            match node {
                Node::Dir(children) => {
                    items.push(Item::Dir(Vec::new()));
                    let mut list = Vec::new();
                    for (name, child) in children {
                        list.push((name.to_string(), flatten(child, items)));
                    }
                    items[idx] = Item::Dir(list);
                }
                Node::File(d) => items.push(Item::File(d)),
                Node::Link(t) => items.push(Item::Link(t.into())),
                Node::Fifo => items.push(Item::Fifo),
            }
            idx
        }
        let mut items = Vec::new();
        flatten(root, &mut items);

        // Data blocks and fragments.
        let mut img = vec![0u8; SUPERBLOCK_LEN];
        let mut frag_buf = Vec::new();
        let mut file_info = HashMap::new(); // idx -> (start, sizes, frag, frag_off)
        for (i, item) in items.iter().enumerate() {
            if let Item::File(data) = item {
                let start = img.len() as u64;
                let mut sizes = Vec::new();
                let tail_frag = !data.is_empty() && data.len() % bs != 0 && data.len() < bs;
                let body = if tail_frag { &data[..0] } else { &data[..] };
                for chunk in body.chunks(bs) {
                    if chunk.iter().all(|&b| b == 0) && chunk.len() == bs {
                        sizes.push(0u32);
                    } else if let Some(c) = compress(chunk) {
                        sizes.push(c.len() as u32);
                        img.extend_from_slice(&c);
                    } else {
                        sizes.push(chunk.len() as u32 | 1 << 24);
                        img.extend_from_slice(chunk);
                    }
                }
                let (frag, off) = if tail_frag {
                    let off = frag_buf.len() as u32;
                    frag_buf.extend_from_slice(data);
                    (0u32, off)
                } else {
                    (NO_FRAGMENT, 0)
                };
                file_info.insert(i, (start, sizes, frag, off));
            }
        }
        let mut frag_entry = None;
        if !frag_buf.is_empty() {
            assert!(frag_buf.len() <= bs);
            let start = img.len() as u64;
            let size = match compress(&frag_buf) {
                Some(c) => {
                    img.extend_from_slice(&c);
                    c.len() as u32
                }
                None => {
                    img.extend_from_slice(&frag_buf);
                    frag_buf.len() as u32 | 1 << 24
                }
            };
            frag_entry = Some((start, size));
        }

        // Inode sizes and positions within the uncompressed inode stream.
        let inode_size = |i: usize| -> usize {
            match &items[i] {
                Item::Dir(_) => 32,
                Item::File(_) => 32 + 4 * file_info[&i].1.len(),
                Item::Link(t) => 24 + t.len(),
                Item::Fifo => 20,
            }
        };
        let mut inode_pos = Vec::new();
        let mut p = 0;
        for i in 0..items.len() {
            inode_pos.push(p);
            p += inode_size(i);
        }
        let inode_stream_len = p;
        let compress_meta = comp != 0 && inode_stream_len <= META_BLOCK;
        let block_disk = |idx: usize| {
            if compress_meta {
                0
            } else {
                idx * (META_BLOCK + 2)
            }
        };
        let iref = |i: usize| {
            ((block_disk(inode_pos[i] / META_BLOCK) as u64) << 16)
                | (inode_pos[i] % META_BLOCK) as u64
        };

        // Directory listings.
        let mut dir_pos = HashMap::new();
        let mut dir_stream = Vec::new();
        for (i, item) in items.iter().enumerate() {
            if let Item::Dir(list) = item {
                let start = dir_stream.len();
                // A header covers up to 256 entries sharing one inode block.
                let mut groups: Vec<Vec<(String, usize)>> = Vec::new();
                for (name, c) in list {
                    let blk = inode_pos[*c] / META_BLOCK;
                    match groups.last_mut() {
                        Some(g) if g.len() < 256 && inode_pos[g[0].1] / META_BLOCK == blk => {
                            g.push((name.clone(), *c))
                        }
                        _ => groups.push(vec![(name.clone(), *c)]),
                    }
                }
                for group in &groups {
                    let block = block_disk(inode_pos[group[0].1] / META_BLOCK) as u32;
                    dir_stream.extend_from_slice(&(group.len() as u32 - 1).to_le_bytes());
                    dir_stream.extend_from_slice(&block.to_le_bytes());
                    dir_stream.extend_from_slice(&1u32.to_le_bytes());
                    for (name, c) in group {
                        let t: u16 = match items[*c] {
                            Item::Dir(_) => 1,
                            Item::File(_) => 2,
                            Item::Link(_) => 3,
                            Item::Fifo => 6,
                        };
                        dir_stream.extend_from_slice(
                            &((inode_pos[*c] % META_BLOCK) as u16).to_le_bytes(),
                        );
                        dir_stream.extend_from_slice(&(*c as i16).to_le_bytes());
                        dir_stream.extend_from_slice(&t.to_le_bytes());
                        dir_stream.extend_from_slice(&(name.len() as u16 - 1).to_le_bytes());
                        dir_stream.extend_from_slice(name.as_bytes());
                    }
                }
                dir_pos.insert(i, (start, dir_stream.len() - start));
            }
        }
        let dir_compress = comp != 0 && dir_stream.len() <= META_BLOCK;
        let dir_block_disk = |idx: usize| {
            if dir_compress {
                0
            } else {
                idx * (META_BLOCK + 2)
            }
        };

        // Inode stream.
        let mut inodes = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let (t, perm) = match item {
                Item::Dir(_) => (1u16, 0o755u16),
                Item::File(_) => (2, 0o644),
                Item::Link(_) => (3, 0o777),
                Item::Fifo => (6, 0o644),
            };
            inodes.extend_from_slice(&t.to_le_bytes());
            inodes.extend_from_slice(&perm.to_le_bytes());
            inodes.extend_from_slice(&[0; 8]);
            inodes.extend_from_slice(&(i as u32 + 1).to_le_bytes());
            match item {
                Item::Dir(_) => {
                    let (pos, len) = dir_pos[&i];
                    inodes.extend_from_slice(
                        &(dir_block_disk(pos / META_BLOCK) as u32).to_le_bytes(),
                    );
                    inodes.extend_from_slice(&2u32.to_le_bytes());
                    inodes.extend_from_slice(&(len as u16 + 3).to_le_bytes());
                    inodes.extend_from_slice(&((pos % META_BLOCK) as u16).to_le_bytes());
                    inodes.extend_from_slice(&1u32.to_le_bytes());
                }
                Item::File(data) => {
                    let (start, sizes, frag, off) = &file_info[&i];
                    inodes.extend_from_slice(&(*start as u32).to_le_bytes());
                    inodes.extend_from_slice(&frag.to_le_bytes());
                    inodes.extend_from_slice(&off.to_le_bytes());
                    inodes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    for s in sizes {
                        inodes.extend_from_slice(&s.to_le_bytes());
                    }
                }
                Item::Link(t) => {
                    inodes.extend_from_slice(&1u32.to_le_bytes());
                    inodes.extend_from_slice(&(t.len() as u32).to_le_bytes());
                    inodes.extend_from_slice(t.as_bytes());
                }
                Item::Fifo => inodes.extend_from_slice(&1u32.to_le_bytes()),
            }
        }
        assert_eq!(inodes.len(), inode_stream_len);

        let meta_blocks = |stream: &[u8], allow: bool| -> Vec<u8> {
            let mut out = Vec::new();
            for chunk in stream.chunks(META_BLOCK) {
                match compress(chunk).filter(|_| allow) {
                    Some(c) => {
                        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
                        out.extend_from_slice(&c);
                    }
                    None => {
                        out.extend_from_slice(&(chunk.len() as u16 | 0x8000).to_le_bytes());
                        out.extend_from_slice(chunk);
                    }
                }
            }
            out
        };
        let inode_table = img.len() as u64;
        img.extend(meta_blocks(&inodes, compress_meta));
        let dir_table = img.len() as u64;
        img.extend(meta_blocks(&dir_stream, dir_compress));
        let mut fragment_table = u64::MAX;
        if let Some((start, size)) = frag_entry {
            let block_at = img.len() as u64;
            let mut e = start.to_le_bytes().to_vec();
            e.extend_from_slice(&size.to_le_bytes());
            e.extend_from_slice(&[0; 4]);
            img.extend(meta_blocks(&e, false));
            fragment_table = img.len() as u64;
            img.extend_from_slice(&block_at.to_le_bytes());
        }
        let id_block = img.len() as u64;
        img.extend(meta_blocks(&0u32.to_le_bytes(), false));
        let id_table = img.len() as u64;
        img.extend_from_slice(&id_block.to_le_bytes());

        let mut sb = Vec::new();
        sb.extend_from_slice(MAGIC);
        sb.extend_from_slice(&(items.len() as u32).to_le_bytes());
        sb.extend_from_slice(&0u32.to_le_bytes());
        sb.extend_from_slice(&(bs as u32).to_le_bytes());
        sb.extend_from_slice(&(frag_entry.is_some() as u32).to_le_bytes());
        sb.extend_from_slice(&(if comp == 0 { 1 } else { comp }).to_le_bytes());
        sb.extend_from_slice(&block_log.to_le_bytes());
        sb.extend_from_slice(&0u16.to_le_bytes());
        sb.extend_from_slice(&1u16.to_le_bytes());
        sb.extend_from_slice(&4u16.to_le_bytes());
        sb.extend_from_slice(&0u16.to_le_bytes());
        sb.extend_from_slice(&iref(0).to_le_bytes());
        sb.extend_from_slice(&(img.len() as u64).to_le_bytes());
        sb.extend_from_slice(&id_table.to_le_bytes());
        sb.extend_from_slice(&u64::MAX.to_le_bytes());
        sb.extend_from_slice(&inode_table.to_le_bytes());
        sb.extend_from_slice(&dir_table.to_le_bytes());
        sb.extend_from_slice(&fragment_table.to_le_bytes());
        sb.extend_from_slice(&u64::MAX.to_le_bytes());
        img[..SUPERBLOCK_LEN].copy_from_slice(&sb);
        img
    }

    pub(crate) fn sample_tree() -> Node {
        let big: Vec<u8> = (0..10_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut sparse = vec![0u8; 3 * 4096];
        sparse.extend_from_slice(b"tail");
        Node::Dir(vec![
            (
                "AppRun",
                Node::File(b"#!/bin/sh\nexec \"$APPDIR/usr/bin/app\" \"$@\"\n".to_vec()),
            ),
            (
                "app.desktop",
                Node::File(
                    b"[Desktop Entry]\nName=Demo\nExec=app %U\nCategories=Utility;\n".to_vec(),
                ),
            ),
            (
                "usr",
                Node::Dir(vec![(
                    "bin",
                    Node::Dir(vec![
                        ("app", Node::File(big)),
                        ("sparse", Node::File(sparse)),
                        ("small", Node::File(b"tiny".to_vec())),
                        ("link", Node::Link("app")),
                        ("escape", Node::Link("../../../../etc/passwd")),
                        ("pipe", Node::Fifo),
                    ]),
                )]),
            ),
        ])
    }

    fn check(img: &[u8]) {
        let out = expand(img, &Limits::default()).unwrap();
        let paths: Vec<_> = out.children.iter().map(|c| c.path.as_str()).collect();
        for p in [
            "AppRun",
            "app.desktop",
            "usr",
            "usr/bin",
            "usr/bin/app",
            "usr/bin/small",
            "usr/bin/link",
            "usr/bin/pipe",
        ] {
            assert!(
                paths.contains(&p),
                "missing {p} in {paths:?}: {:?}",
                out.problems
            );
        }
        let big: Vec<u8> = (0..10_000u32).flat_map(|i| i.to_le_bytes()).collect();
        assert_eq!(out.child("usr/bin/app").unwrap().data, big);
        assert_eq!(out.child("usr/bin/small").unwrap().data, b"tiny");
        let sparse = &out.child("usr/bin/sparse").unwrap().data;
        assert_eq!(sparse.len(), 3 * 4096 + 4);
        assert!(sparse.ends_with(b"tail"));
        assert_eq!(
            out.child("usr/bin/link").unwrap().kind,
            EntryKind::Symlink {
                target: "app".into()
            }
        );
        assert!(
            out.problems.iter().any(|p| p.contains("escapes")),
            "{:?}",
            out.problems
        );
        assert!(out.problems.iter().any(|p| p.contains("special")));
        assert!(!out.truncated);
    }

    #[test]
    fn reads_all_compressors() {
        for comp in [0, 1, 4, 5, 6] {
            check(&build(sample_tree(), comp, 12));
        }
    }

    #[test]
    fn reads_multi_block_metadata() {
        // Enough entries to spill the inode and directory tables past 8 KiB.
        let names: Vec<&'static str> = (0..600)
            .map(|i| &*Box::leak(format!("file-{i:04}").into_boxed_str()))
            .collect();
        let children = names
            .iter()
            .map(|n| (*n, Node::File(n.as_bytes().to_vec())))
            .collect();
        let img = build(Node::Dir(children), 1, 13);
        let out = expand(&img, &Limits::default()).unwrap();
        assert_eq!(out.children.len(), 600, "{:?}", out.problems);
        assert_eq!(out.child("file-0599").unwrap().data, b"file-0599");
    }

    #[test]
    fn rejects_bad_superblocks() {
        let mut img = build(sample_tree(), 1, 12);
        assert!(expand(b"hsqs", &Limits::default()).is_err());
        img[20] = 3; // lzo
        let err = expand(&img, &Limits::default()).unwrap_err();
        assert!(err.to_string().contains("lzo"));
        img[20] = 1;
        img[12] = 7; // block size no longer matches block_log
        assert!(expand(&img, &Limits::default()).is_err());
    }

    #[test]
    fn truncations_and_corruption_never_panic() {
        for comp in [0, 1, 6] {
            let img = build(sample_tree(), comp, 12);
            for n in 0..img.len() {
                let _ = expand(&img[..n], &Limits::default());
            }
            for i in (SUPERBLOCK_LEN..img.len()).step_by(3) {
                let mut bad = img.clone();
                bad[i] ^= 0xA5;
                let _ = expand(&bad, &Limits::default());
            }
            for i in 0..SUPERBLOCK_LEN {
                let mut bad = img.clone();
                bad[i] = 0xFF;
                let _ = expand(&bad, &Limits::default());
            }
        }
    }

    #[test]
    fn directory_cycle_is_reported() {
        // Point the `usr` entry's inode ref at the root directory inode.
        let tree = Node::Dir(vec![(
            "loop",
            Node::Dir(vec![("f", Node::File(b"x".to_vec()))]),
        )]);
        let mut img = build(tree, 0, 12);
        let dir_table = u64le(&img, 72).unwrap() as usize;
        // Root listing: header(12) then entry offset u16, inode_offset i16.
        img[dir_table + 2 + 12..dir_table + 2 + 14].copy_from_slice(&0u16.to_le_bytes());
        let out = expand(&img, &Limits::default()).unwrap();
        assert!(
            out.problems.iter().any(|p| p.contains("cycle")),
            "{:?}",
            out.problems
        );
    }

    #[test]
    fn limits_cap_files_and_entries() {
        let img = build(sample_tree(), 1, 12);
        let out = expand(
            &img,
            &Limits {
                max_entry_bytes: 100,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(out.child("usr/bin/app").is_none());
        assert!(out.oversized.iter().any(|o| o.path == "usr/bin/app"));
        let out = expand(
            &img,
            &Limits {
                max_entries: 3,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(out.children.len(), 3);
        assert!(out.truncated);
    }

    /// Manual validation against a real image:
    /// `BYTEBOUNCER_SQUASHFS_SAMPLE=/path/to/file.AppImage cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn real_sample_from_env() {
        let Ok(path) = std::env::var("BYTEBOUNCER_SQUASHFS_SAMPLE") else {
            return;
        };
        let bytes = std::fs::read(path).unwrap();
        let out = crate::expand(&bytes, ContainerKind::AppImage, &Limits::default()).unwrap();
        eprintln!(
            "{} children, problems {:?}",
            out.children.len(),
            out.problems
        );
        eprintln!("metadata {:?}", out.metadata);
        for s in &out.scripts {
            eprintln!("script {} {:?}", s.path, s.interpreter);
        }
        if std::env::var_os("BYTEBOUNCER_SQUASHFS_DUMP").is_some() {
            use sha2::Digest;
            for c in out.children.iter().filter(|c| c.kind == EntryKind::File) {
                println!("{} {}", hex::encode(sha2::Sha256::digest(&c.data)), c.path);
            }
        }
        assert!(out.children.len() > 1);
    }
}

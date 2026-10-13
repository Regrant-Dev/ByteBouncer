//! RPM packages: lead, signature header, main header and the compressed
//! cpio payload, which is expanded inline into children. Scriptlets
//! (`%pre`, `%post`, triggers, ...) become [`Script`](crate::Script)s with
//! their declared interpreter.

use crate::compress::{decompress, note_stream};
use crate::detect::compression;
use crate::util::{Sink, slice, u16be, u32be, u64be};
use crate::{ContainerKind, Expanded, FormatError, Limits};

const HEADER_MAGIC: [u8; 3] = [0x8E, 0xAD, 0xE8];
/// Sanity cap on header index entries; real packages have a few hundred.
const MAX_INDEX: usize = 65_536;

const T_INT16: u32 = 3;
const T_INT32: u32 = 4;
const T_INT64: u32 = 5;
const T_STRING: u32 = 6;
const T_BIN: u32 = 7;
const T_STRING_ARRAY: u32 = 8;
const T_I18NSTRING: u32 = 9;

/// A parsed header: index entries plus the data store they point into.
struct Header<'a> {
    entries: Vec<(u32, u32, usize, usize)>,
    store: &'a [u8],
}

enum Value {
    Strings(Vec<String>),
    Ints(Vec<u64>),
}

impl<'a> Header<'a> {
    /// Parse a header at `off`; returns it and the offset just past it.
    fn parse(b: &'a [u8], off: usize) -> Result<(Self, usize), String> {
        let magic = slice(b, off, 16).ok_or("truncated header intro")?;
        if magic[..3] != HEADER_MAGIC {
            return Err(format!("bad header magic at offset {off}"));
        }
        let n = u32be(magic, 8).unwrap_or(0) as usize;
        let size = u32be(magic, 12).unwrap_or(0) as usize;
        if n > MAX_INDEX {
            return Err(format!("implausible header index count {n}"));
        }
        let index = slice(b, off + 16, n * 16).ok_or("truncated header index")?;
        let store = slice(b, off + 16 + n * 16, size).ok_or("truncated header store")?;
        let entries = index
            .chunks_exact(16)
            .map(|e| {
                let f = |i| u32be(e, i).unwrap_or(0);
                (f(0), f(4), f(8) as usize, f(12) as usize)
            })
            .collect();
        Ok((Self { entries, store }, off + 16 + n * 16 + size))
    }

    fn get(&self, tag: u32) -> Option<Value> {
        let &(_, ty, off, count) = self.entries.iter().find(|e| e.0 == tag)?;
        let s = self.store.get(off..)?;
        let count = count.min(s.len());
        Some(match ty {
            T_STRING | T_STRING_ARRAY | T_I18NSTRING => {
                let n = if ty == T_STRING { 1 } else { count };
                Value::Strings(
                    s.split(|&c| c == 0)
                        .take(n)
                        .map(|x| String::from_utf8_lossy(x).into_owned())
                        .collect(),
                )
            }
            T_INT16 => Value::Ints(
                (0..count)
                    .filter_map(|i| u16be(s, i * 2))
                    .map(u64::from)
                    .collect(),
            ),
            T_INT32 => Value::Ints(
                (0..count)
                    .filter_map(|i| u32be(s, i * 4))
                    .map(u64::from)
                    .collect(),
            ),
            T_INT64 => Value::Ints((0..count).filter_map(|i| u64be(s, i * 8)).collect()),
            T_BIN => Value::Ints(Vec::new()),
            _ => Value::Ints(Vec::new()),
        })
    }

    fn strings(&self, tag: u32) -> Vec<String> {
        match self.get(tag) {
            Some(Value::Strings(v)) => v,
            _ => Vec::new(),
        }
    }

    fn string(&self, tag: u32) -> Option<String> {
        self.strings(tag).into_iter().next()
    }

    fn ints(&self, tag: u32) -> Vec<u64> {
        match self.get(tag) {
            Some(Value::Ints(v)) => v,
            _ => Vec::new(),
        }
    }

    fn has(&self, tag: u32) -> bool {
        self.entries.iter().any(|e| e.0 == tag)
    }
}

const SIMPLE_TAGS: &[(u32, &str)] = &[
    (1000, "name"),
    (1001, "version"),
    (1002, "release"),
    (1004, "summary"),
    (1011, "vendor"),
    (1014, "license"),
    (1015, "packager"),
    (1020, "url"),
    (1021, "os"),
    (1022, "arch"),
    (1044, "sourcerpm"),
    (1124, "payload_format"),
    (1125, "payload_compressor"),
];

/// (script tag, interpreter tag, script kind)
const SCRIPTLETS: &[(u32, u32, &str)] = &[
    (1151, 1153, "rpm.%pretrans"),
    (1023, 1085, "rpm.%pre"),
    (1024, 1086, "rpm.%post"),
    (1025, 1087, "rpm.%preun"),
    (1026, 1088, "rpm.%postun"),
    (1152, 1154, "rpm.%posttrans"),
    (5102, 5104, "rpm.%preuntrans"),
    (5103, 5105, "rpm.%postuntrans"),
    (1079, 1091, "rpm.%verifyscript"),
];

/// Signature-header tags worth reporting (presence only; not verified).
const SIG_TAGS: &[(u32, &str)] = &[
    (267, "dsa"),
    (268, "rsa"),
    (269, "sha1"),
    (273, "sha256"),
    (1002, "pgp"),
    (1004, "md5"),
    (1005, "gpg"),
];

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    let bad = |m: String| FormatError::malformed(ContainerKind::Rpm, m);
    if !bytes.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) || bytes.len() < 96 {
        return Err(bad("no RPM lead".into()));
    }
    let mut sink = Sink::new(ContainerKind::Rpm, limits, bytes.len());
    if u16be(bytes, 6) == Some(1) {
        sink.meta("rpm.type", "source");
    }
    let (sig, end) = Header::parse(bytes, 96).map_err(|e| bad(format!("signature header: {e}")))?;
    let present: Vec<&str> = SIG_TAGS
        .iter()
        .filter(|(t, _)| sig.has(*t))
        .map(|(_, n)| *n)
        .collect();
    sink.meta(
        "rpm.signature",
        if present.is_empty() {
            "none".into()
        } else {
            present.join(",")
        },
    );
    let (h, payload_off) = Header::parse(bytes, end.next_multiple_of(8))
        .map_err(|e| bad(format!("main header: {e}")))?;

    for (tag, key) in SIMPLE_TAGS {
        if let Some(v) = h.string(*tag) {
            sink.meta(format!("rpm.{key}"), v);
        }
    }
    if let Some(epoch) = h.ints(1003).first() {
        sink.meta("rpm.epoch", epoch.to_string());
    }
    for (name_tag, flags_tag, ver_tag, key) in [
        (1049, 1048, 1050, "requires"),
        (1047, 1112, 1113, "provides"),
        (1054, 1053, 1055, "conflicts"),
        (1090, 1114, 1115, "obsoletes"),
    ] {
        for dep in deps(&h, name_tag, flags_tag, ver_tag) {
            sink.meta(format!("rpm.{key}"), dep);
        }
    }
    for &(script, prog, kind) in SCRIPTLETS {
        if let Some(text) = h.string(script) {
            sink.script(
                kind,
                interpreter(&h, prog),
                kind.trim_start_matches("rpm."),
                text,
            );
        }
    }
    triggers(&h, &mut sink);
    for (scripts, prog, kind) in [
        (5066, 5067, "rpm.%filetrigger"),
        (5076, 5077, "rpm.%transfiletrigger"),
    ] {
        let progs = h.strings(prog);
        for (i, text) in h.strings(scripts).into_iter().enumerate() {
            sink.script(
                kind,
                progs.get(i).cloned(),
                &format!("{}/{i}", kind.trim_start_matches("rpm.")),
                text,
            );
        }
    }

    let payload = &bytes[payload_off.min(bytes.len())..];
    let format = h.string(1124).unwrap_or_else(|| "cpio".into());
    if format != "cpio" {
        sink.problem(format!("rpm: payload format {format:?} not expanded"));
        return Ok(sink.finish());
    }
    let declared = h.string(1125).unwrap_or_else(|| "gzip".into());
    let kind = compression(payload).or(match declared.as_str() {
        "lzma" => Some(ContainerKind::Lzma),
        _ => None,
    });
    let cpio = match kind {
        Some(kind) => {
            let b = decompress(kind, payload, sink.entry_cap(payload.len() as u64));
            note_stream(&mut sink, &b, "rpm payload");
            b.data
        }
        None if crate::cpio::is_cpio(payload) => payload.to_vec(),
        None => {
            sink.problem(format!(
                "rpm: unsupported or unrecognized payload compression {declared:?}"
            ));
            return Ok(sink.finish());
        }
    };
    crate::cpio::read_into(&cpio, &mut sink, "");
    Ok(sink.finish())
}

fn interpreter(h: &Header, tag: u32) -> Option<String> {
    let parts = h.strings(tag);
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Dependencies rendered as `name op version`.
fn deps(h: &Header, name: u32, flags: u32, ver: u32) -> Vec<String> {
    let (flags, vers) = (h.ints(flags), h.strings(ver));
    h.strings(name)
        .into_iter()
        .enumerate()
        .map(|(i, n)| {
            let f = flags.get(i).copied().unwrap_or(0);
            let op = match f & 0xE {
                0x2 => "<",
                0xA => "<=",
                0x8 => "=",
                0xC => ">=",
                0x4 => ">",
                _ => "",
            };
            match vers.get(i).filter(|v| !v.is_empty() && !op.is_empty()) {
                Some(v) => format!("{n} {op} {v}"),
                None => n,
            }
        })
        .fold(Vec::new(), |mut out: Vec<String>, d| {
            if !out.contains(&d) {
                out.push(d);
            }
            out
        })
}

/// `%trigger*` scriptlets: TRIGGERINDEX maps each trigger condition to a
/// script in TRIGGERSCRIPTS; flags say which trigger kind it is.
fn triggers(h: &Header, sink: &mut Sink) {
    let scripts = h.strings(1065);
    if scripts.is_empty() {
        return;
    }
    let (progs, names, flags, index) =
        (h.strings(1092), h.strings(1066), h.ints(1068), h.ints(1069));
    for (i, text) in scripts.into_iter().enumerate() {
        let conds: Vec<usize> = (0..names.len())
            .filter(|&j| index.get(j) == Some(&(i as u64)))
            .collect();
        let f = conds
            .first()
            .and_then(|&j| flags.get(j))
            .copied()
            .unwrap_or(0);
        let kind = match f {
            f if f & 0x0200_0000 != 0 => "rpm.%triggerprein",
            f if f & 0x1_0000 != 0 => "rpm.%triggerin",
            f if f & 0x2_0000 != 0 => "rpm.%triggerun",
            f if f & 0x4_0000 != 0 => "rpm.%triggerpostun",
            _ => "rpm.%trigger",
        };
        let on: Vec<&str> = conds.iter().map(|&j| names[j].as_str()).collect();
        sink.script(
            kind,
            progs.get(i).cloned(),
            &format!("{}/{}", kind.trim_start_matches("rpm."), on.join(",")),
            text,
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    enum V<'a> {
        S(&'a str),
        A(&'a [&'a str]),
        I(&'a [u32]),
    }

    fn header(entries: &[(u32, V)]) -> Vec<u8> {
        let (mut index, mut store) = (Vec::new(), Vec::new());
        for (tag, v) in entries {
            let (ty, count, data): (u32, usize, Vec<u8>) = match v {
                V::S(s) => (T_STRING, 1, [s.as_bytes(), &[0]].concat()),
                V::A(a) => (
                    T_STRING_ARRAY,
                    a.len(),
                    a.iter()
                        .flat_map(|s| [s.as_bytes(), &[0]].concat())
                        .collect(),
                ),
                V::I(i) => {
                    while store.len() % 4 != 0 {
                        store.push(0);
                    }
                    (
                        T_INT32,
                        i.len(),
                        i.iter().flat_map(|x| x.to_be_bytes()).collect(),
                    )
                }
            };
            for x in [*tag, ty, store.len() as u32, count as u32] {
                index.extend_from_slice(&x.to_be_bytes());
            }
            store.extend(data);
        }
        let mut out = vec![0x8E, 0xAD, 0xE8, 1, 0, 0, 0, 0];
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(store.len() as u32).to_be_bytes());
        out.extend(index);
        out.extend(store);
        out
    }

    pub(crate) fn sample_rpm() -> Vec<u8> {
        let mut out = vec![0xED, 0xAB, 0xEE, 0xDB, 3, 0, 0, 0];
        out.resize(96, 0);
        let sig = header(&[(1000, V::I(&[1234])), (273, V::S("abcd"))]);
        out.extend(&sig);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out.extend(header(&[
            (1000, V::S("hello")),
            (1001, V::S("1.0")),
            (1002, V::S("1.fc40")),
            (1022, V::S("x86_64")),
            (1004, V::S("Says hello")),
            (1049, V::A(&["bash", "glibc"])),
            (1048, V::I(&[0, 0xC])),
            (1050, V::A(&["", "2.34"])),
            (1024, V::S("systemctl enable hello.service")),
            (1086, V::S("/bin/sh")),
            (1026, V::S("print('bye')")),
            (1088, V::S("<lua>")),
            (1065, V::A(&["echo triggered"])),
            (1066, V::A(&["glibc"])),
            (1068, V::I(&[0x10000])),
            (1069, V::I(&[0])),
            (1092, V::A(&["/bin/sh"])),
            (1124, V::S("cpio")),
            (1125, V::S("gzip")),
        ]));
        let cpio = crate::cpio::tests::newc(&[
            ("./usr/bin/hello", 0o100755, b"\x7fELF"),
            ("./etc/hello.conf", 0o100644, b"x=1\n"),
        ]);
        out.extend(crate::compress::tests::gz(&cpio));
        out
    }

    #[test]
    fn parses_headers_scripts_and_payload() {
        let out = expand(&sample_rpm(), &Limits::default()).unwrap();
        assert_eq!(out.meta("rpm.name"), Some("hello"));
        assert_eq!(out.meta("rpm.arch"), Some("x86_64"));
        assert_eq!(out.meta("rpm.signature"), Some("sha256"));
        let req: Vec<_> = out
            .metadata
            .iter()
            .filter(|(k, _)| k == "rpm.requires")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(req, ["bash", "glibc >= 2.34"]);
        let s: Vec<_> = out
            .scripts
            .iter()
            .map(|s| (s.kind.as_str(), s.interpreter.as_deref()))
            .collect();
        assert_eq!(
            s,
            [
                ("rpm.%post", Some("/bin/sh")),
                ("rpm.%postun", Some("<lua>")),
                ("rpm.%triggerin", Some("/bin/sh"))
            ]
        );
        assert_eq!(out.scripts[2].path, "%triggerin/glibc");
        assert_eq!(out.child("usr/bin/hello").unwrap().data, b"\x7fELF");
        assert!(out.problems.is_empty(), "{:?}", out.problems);
    }

    #[test]
    fn hostile_rpms_never_panic() {
        let rpm = sample_rpm();
        for n in 0..rpm.len() {
            let _ = expand(&rpm[..n], &Limits::default());
        }
        let mut huge = rpm.clone();
        huge[96 + 8..96 + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(expand(&huge, &Limits::default()).is_err());
        let mut lie = rpm.clone();
        // Point the name's offset far outside the store.
        let main = (96 + 16 + 2 * 16 + 9usize).next_multiple_of(8);
        lie[main + 16 + 8..main + 16 + 12].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        let out = expand(&lie, &Limits::default()).unwrap();
        assert_eq!(out.meta("rpm.name"), None);
    }
}

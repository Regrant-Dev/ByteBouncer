//! Windows Installer (`.msi`) databases: an OLE compound file whose stream
//! names are packed with a base64-like encoding and whose tables are stored
//! column-major against a shared string pool.
//!
//! What is reported:
//! - metadata from `SummaryInformation`, `Property`, `CustomAction`, the
//!   install sequences, `ServiceInstall` and `Media`;
//! - every `CustomAction` row as a [`crate::Script`] (custom actions are the
//!   MSI equivalent of maintainer scripts);
//! - non-table streams as children (`Binary.X` becomes `Binary/X`), with
//!   embedded cabinets expanded inline under `cab/<stream>/`.
//!
//! Table streams themselves are parsed, not returned as children.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::util::{Sink, read_bounded, u16le, u32le};
use crate::{ContainerKind, EntryKind, Expanded, FormatError, Limits};

/// Bound on any single table or string stream we parse.
const MAX_TABLE_BYTES: u64 = 64 << 20;
/// Prefix character marking table streams.
const TABLE_PREFIX: char = '\u{4840}';
const MIME: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

/// Decode a packed MSI stream name. Returns the name and whether it is a
/// table stream.
pub(crate) fn decode_name(raw: &str) -> (String, bool) {
    let mut out = String::new();
    let mut table = false;
    for (i, ch) in raw.chars().enumerate() {
        let c = ch as u32;
        if i == 0 && ch == TABLE_PREFIX {
            table = true;
        } else if (0x3800..0x4800).contains(&c) {
            let c = c - 0x3800;
            out.push(MIME[(c & 0x3f) as usize] as char);
            out.push(MIME[((c >> 6) & 0x3f) as usize] as char);
        } else if (0x4800..0x4840).contains(&c) {
            out.push(MIME[(c - 0x4800) as usize] as char);
        } else {
            out.push(ch);
        }
    }
    (out, table)
}

/// A decoded table cell.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Int(i64),
    Str(String),
}

impl Value {
    fn text(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Int(i) => i.to_string(),
            Value::Str(s) => s.clone(),
        }
    }
    fn int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
}

struct Column {
    name: String,
    ty: u16,
}

struct Table {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

impl Table {
    fn get<'a>(&self, row: &'a [Value], col: &str) -> Option<&'a Value> {
        row.get(self.columns.iter().position(|c| c == col)?)
    }
    fn text(&self, row: &[Value], col: &str) -> String {
        self.get(row, col).map(Value::text).unwrap_or_default()
    }
}

struct Strings {
    strings: Vec<String>,
    ref_size: usize,
}

impl Strings {
    fn parse(pool: &[u8], data: &[u8]) -> Result<Self, String> {
        let header = u32le(pool, 0).ok_or("string pool header missing")?;
        let ref_size = if header & 0x8000_0000 != 0 { 3 } else { 2 };
        let entries = pool.len() / 4;
        let word = |i: usize| u16le(pool, i * 2).unwrap_or(0) as usize;
        // String ids start at 1; id 0 is the null string.
        let mut strings = vec![String::new()];
        let (mut i, mut offset) = (1usize, 0usize);
        while i < entries {
            let (len, refs) = (word(i * 2), word(i * 2 + 1));
            if len == 0 && refs == 0 {
                strings.push(String::new());
                i += 1;
                continue;
            }
            let len = if len == 0 {
                // Strings over 64 KiB: the next entry carries the length.
                let l = (word(i * 2 + 3) << 16) | word(i * 2 + 2);
                i += 2;
                l
            } else {
                i += 1;
                len
            };
            let Some(bytes) = data.get(offset..offset.saturating_add(len)) else {
                return Err("string data shorter than the string pool claims".into());
            };
            strings.push(decode_text(bytes));
            offset += len;
        }
        Ok(Self { strings, ref_size })
    }

    fn get(&self, id: usize) -> Value {
        match id {
            0 => Value::Null,
            id => Value::Str(
                self.strings
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| format!("<bad string id {id}>")),
            ),
        }
    }
}

/// MSI strings use the database codepage; UTF-8 covers modern packages and
/// Latin-1 is a lossless fallback for the rest.
fn decode_text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_owned(),
        Err(_) => b.iter().map(|&c| c as char).collect(),
    }
}

const VALID: u16 = 0x0100;
const STRING: u16 = 0x0800;
const NULLABLE: u16 = 0x1000;

/// Binary columns hold a 2-byte stream reference, not a string id.
fn is_binary(ty: u16) -> bool {
    ty & !NULLABLE == STRING | VALID
}

fn column_width(ty: u16, ref_size: usize) -> usize {
    if is_binary(ty) {
        2
    } else if ty & STRING != 0 {
        ref_size
    } else if ty & 0xff <= 2 {
        2
    } else {
        4
    }
}

fn read_cell(b: &[u8], off: usize, width: usize, is_string: bool, strings: &Strings) -> Value {
    let raw = match width {
        2 => u16le(b, off).map(u32::from),
        3 => u16le(b, off).and_then(|lo| Some(lo as u32 | (*b.get(off + 2)? as u32) << 16)),
        _ => u32le(b, off),
    };
    let Some(raw) = raw else { return Value::Null };
    if is_string {
        return strings.get(raw as usize);
    }
    match (raw, width) {
        (0, _) => Value::Null,
        (r, 2) => Value::Int((r ^ 0x8000) as u16 as i16 as i64),
        (r, _) => Value::Int((r ^ 0x8000_0000) as i32 as i64),
    }
}

/// Decode a column-major table stream.
fn decode_table(b: &[u8], columns: &[Column], strings: &Strings) -> (Vec<Vec<Value>>, bool) {
    let widths: Vec<usize> = columns
        .iter()
        .map(|c| column_width(c.ty, strings.ref_size))
        .collect();
    let row_size: usize = widths.iter().sum();
    if row_size == 0 {
        return (Vec::new(), false);
    }
    let rows = b.len() / row_size;
    let mut out = vec![Vec::with_capacity(columns.len()); rows];
    let mut col_off = 0;
    for (col, &w) in columns.iter().zip(&widths) {
        let is_string = col.ty & STRING != 0 && !is_binary(col.ty);
        for (r, row) in out.iter_mut().enumerate() {
            row.push(read_cell(b, col_off + r * w, w, is_string, strings));
        }
        col_off += rows * w;
    }
    (out, b.len() % row_size != 0)
}

struct Db<'d, 's, 'l> {
    tables: &'d HashMap<String, Vec<u8>>,
    streams: &'d HashMap<String, Vec<u8>>,
    strings: Strings,
    columns: HashMap<String, Vec<Column>>,
    sink: &'s mut Sink<'l>,
}

fn custom_action_kind(ty: i64) -> (&'static str, &'static str) {
    match ty & 0x3f {
        1 => ("dll", "DLL from Binary table"),
        2 => ("exe", "EXE from Binary table"),
        5 => ("jscript", "JScript from Binary table"),
        6 => ("vbscript", "VBScript from Binary table"),
        17 => ("dll", "DLL from installed file"),
        18 => ("exe", "EXE from installed file"),
        19 => ("msi.error", "display error and abort"),
        21 => ("jscript", "JScript from installed file"),
        22 => ("vbscript", "VBScript from installed file"),
        34 => ("exe", "EXE with working directory"),
        35 => ("msi.set-directory", "set directory"),
        37 => ("jscript", "inline JScript"),
        38 => ("vbscript", "inline VBScript"),
        50 => ("exe", "EXE named by property"),
        51 => ("msi.set-property", "set property"),
        53 => ("jscript", "JScript from property"),
        54 => ("vbscript", "VBScript from property"),
        7 | 23 | 39 => ("msi.nested-install", "nested installation"),
        _ => ("unknown", "unknown custom action type"),
    }
}

fn custom_action_flags(ty: i64) -> Vec<&'static str> {
    let mut f = Vec::new();
    if ty & 0x400 != 0 {
        f.push(match ty & 0x300 {
            0x100 => "rollback",
            0x200 => "commit",
            _ => "deferred",
        });
        if ty & 0x800 != 0 {
            f.push("noimpersonate(system)");
        }
    }
    if ty & 0x80 != 0 {
        f.push("async");
    }
    if ty & 0x40 != 0 {
        f.push("ignore-exit-code");
    }
    if ty & 0x2000 != 0 {
        f.push("hide-target");
    }
    if ty & 0x1000 != 0 {
        f.push("64bit");
    }
    f
}

impl Db<'_, '_, '_> {
    fn table(&mut self, name: &str) -> Option<Table> {
        let cols = self.columns.get(name)?;
        let b = self.tables.get(name).map(Vec::as_slice).unwrap_or(&[]);
        let (rows, ragged) = decode_table(b, cols, &self.strings);
        let columns = cols.iter().map(|c| c.name.clone()).collect();
        if ragged {
            self.sink.problem(format!(
                "msi: table {name} size is not a multiple of its row size"
            ));
        }
        Some(Table { columns, rows })
    }

    fn report(&mut self) {
        let mut tables: Vec<&String> = self.columns.keys().collect();
        tables.sort();
        let list = tables
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        self.sink.meta("msi.tables", list);

        if let Some(t) = self.table("Property") {
            for row in &t.rows {
                let (k, v) = (t.text(row, "Property"), t.text(row, "Value"));
                if !k.is_empty() {
                    self.sink.meta(format!("msi.Property.{k}"), v);
                }
            }
        }

        let mut sequence: HashMap<String, Vec<String>> = HashMap::new();
        for seq in [
            "InstallExecuteSequence",
            "InstallUISequence",
            "AdminExecuteSequence",
            "AdvtExecuteSequence",
        ] {
            if let Some(t) = self.table(seq) {
                for row in &t.rows {
                    let cond = t.text(row, "Condition");
                    let n = t.text(row, "Sequence");
                    sequence
                        .entry(t.text(row, "Action"))
                        .or_default()
                        .push(format!("{seq} seq={n} condition={cond:?}"));
                }
            }
        }

        if let Some(t) = self.table("CustomAction") {
            for row in &t.rows {
                let action = t.text(row, "Action");
                let ty = t.get(row, "Type").and_then(Value::int).unwrap_or(0);
                let source = t.text(row, "Source");
                let target = t.text(row, "Target");
                let (interp, desc) = custom_action_kind(ty);
                let flags = custom_action_flags(ty).join(",");
                self.sink.meta(
                    "msi.CustomAction",
                    format!("{action} type={ty} ({desc}) flags=[{flags}] source={source:?} target={target:?}"),
                );
                for s in sequence.get(&action).into_iter().flatten() {
                    self.sink
                        .meta("msi.CustomAction.sequence", format!("{action} {s}"));
                }
                let text = match ty & 0x3f {
                    5 | 6 => match self.streams.get(&format!("Binary.{source}")) {
                        Some(b) => decode_text(b),
                        None => format!("<Binary.{source} stream missing> entry={target}"),
                    },
                    1 | 2 => format!("Binary:{source} entry={target}"),
                    17 | 18 | 21 | 22 => format!("File:{source} {target}"),
                    _ if source.is_empty() => target,
                    _ => format!("{source} {target}"),
                };
                self.sink.script(
                    "msi.CustomAction",
                    Some(interp.into()),
                    &format!("CustomAction/{action}"),
                    text,
                );
            }
        }

        if let Some(t) = self.table("ServiceInstall") {
            for row in &t.rows {
                self.sink.meta(
                    "msi.ServiceInstall",
                    format!(
                        "{} display={:?} start_type={} service_type={} account={:?}",
                        t.text(row, "Name"),
                        t.text(row, "DisplayName"),
                        t.text(row, "StartType"),
                        t.text(row, "ServiceType"),
                        t.text(row, "StartName"),
                    ),
                );
            }
        }

        if let Some(t) = self.table("Media") {
            for row in &t.rows {
                let cab = t.text(row, "Cabinet");
                if let Some(stream) = cab.strip_prefix('#') {
                    self.sink
                        .meta("msi.Media.Cabinet", format!("embedded:{stream}"));
                } else if !cab.is_empty() {
                    self.sink
                        .meta("msi.Media.Cabinet", format!("external:{cab}"));
                }
            }
        }
        if let Some(t) = self.table("File") {
            self.sink.meta("msi.File.count", t.rows.len().to_string());
        }
    }
}

/// Parse an OLE property set (`SummaryInformation`) into metadata.
fn summary_info(b: &[u8], sink: &mut Sink) {
    let Some(section) = u32le(b, 44).map(|o| o as usize) else {
        return;
    };
    let Some(count) = u32le(b, section + 4) else {
        return;
    };
    for i in 0..count.min(64) as usize {
        let (Some(id), Some(off)) = (
            u32le(b, section + 8 + i * 8),
            u32le(b, section + 12 + i * 8),
        ) else {
            return;
        };
        let name = match id {
            2 => "title",
            3 => "subject",
            4 => "author",
            5 => "keywords",
            6 => "comments",
            7 => "template",
            8 => "last_saved_by",
            9 => "revision",
            18 => "application",
            14 => "page_count",
            15 => "word_count",
            19 => "security",
            _ => continue,
        };
        let p = section + off as usize;
        let value = match u32le(b, p) {
            Some(30) => u32le(b, p + 4)
                .and_then(|len| b.get(p + 8..(p + 8).checked_add(len as usize)?))
                .map(crate::util::text),
            Some(2) => u16le(b, p + 4).map(|v| (v as i16).to_string()),
            Some(3) => u32le(b, p + 4).map(|v| (v as i32).to_string()),
            _ => None,
        };
        if let Some(v) = value {
            sink.meta(format!("msi.summary.{name}"), v);
        }
    }
}

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    let mut cf = cfb::CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| FormatError::malformed(ContainerKind::Msi, e.to_string()))?;
    let mut sink = Sink::new(ContainerKind::Msi, limits, bytes.len());

    let entries: Vec<(String, bool, u64)> = cf
        .walk()
        .map(|e| {
            (
                e.path().to_string_lossy().into_owned(),
                e.is_stream(),
                e.len(),
            )
        })
        .collect();

    let mut streams: HashMap<String, Vec<u8>> = HashMap::new();
    let mut table_streams: HashMap<String, Vec<u8>> = HashMap::new();
    for (path, is_stream, len) in entries {
        let rel = path.trim_start_matches('/');
        if rel.is_empty() {
            continue;
        }
        if !is_stream {
            let (name, _) = decode_name(rel);
            sink.meta("msi.storage", name);
            continue;
        }
        let (name, is_table) = decode_name(rel);
        let cap = if is_table {
            MAX_TABLE_BYTES
        } else {
            sink.entry_budget()
        };
        let b = match cf.open_stream(&path) {
            Ok(s) => read_bounded(s.take(len), cap),
            Err(e) => {
                sink.problem(format!("msi: cannot open stream {name:?}: {e}"));
                continue;
            }
        };
        if let Some(e) = &b.error {
            sink.problem(format!("msi: stream {name:?} unreadable: {e}"));
        }
        if b.capped {
            sink.truncate(format!("msi: stream {name:?} exceeds the size limit"));
        }
        if is_table {
            table_streams.insert(name, b.data);
        } else {
            streams.insert(name, b.data);
        }
    }

    if let Some(si) = streams.get("\u{5}SummaryInformation") {
        summary_info(si, &mut sink);
    }

    match (
        table_streams.get("_StringPool"),
        table_streams.get("_StringData"),
    ) {
        (Some(pool), Some(data)) => match Strings::parse(pool, data) {
            Ok(strings) => parse_tables(&table_streams, &streams, strings, &mut sink),
            Err(e) => sink.problem(format!("msi: string pool: {e}")),
        },
        _ => sink.problem(
            "msi: no string pool; this compound file is not an MSI database (streams listed only)",
        ),
    }

    let mut names: Vec<&String> = streams.keys().collect();
    names.sort();
    for name in names {
        let data = &streams[name];
        if sink.full() {
            break;
        }
        if name.starts_with('\u{5}') {
            continue;
        }
        let path = match name.split_once('.') {
            Some((t @ ("Binary" | "Icon"), rest)) => format!("{t}/{rest}"),
            _ => name.clone(),
        };
        if data.starts_with(b"MSCF")
            && crate::cab::read_into(data, &mut sink, &format!("cab/{name}"))
        {
            continue;
        }
        if !sink.push(&path, EntryKind::File, None, data.clone()) {
            break;
        }
    }
    Ok(sink.finish())
}

fn parse_tables(
    tables: &HashMap<String, Vec<u8>>,
    streams: &HashMap<String, Vec<u8>>,
    strings: Strings,
    sink: &mut Sink,
) {
    // `_Columns` has a fixed schema: Table (s), Number (i2), Name (s), Type (i2).
    let schema = [
        ("Table", STRING | VALID | 64),
        ("Number", VALID | 2),
        ("Name", STRING | VALID | 64),
        ("Type", VALID | 2),
    ]
    .map(|(n, ty)| Column { name: n.into(), ty });
    let (rows, _) = decode_table(
        tables.get("_Columns").map(Vec::as_slice).unwrap_or(&[]),
        &schema,
        &strings,
    );
    let mut columns: HashMap<String, Vec<(i64, Column)>> = HashMap::new();
    for row in rows {
        let (Value::Str(table), Some(n), Value::Str(name), Some(ty)) =
            (&row[0], row[1].int(), &row[2], row[3].int())
        else {
            continue;
        };
        columns.entry(table.clone()).or_default().push((
            n,
            Column {
                name: name.clone(),
                ty: ty as u16,
            },
        ));
    }
    let columns = columns
        .into_iter()
        .map(|(t, mut cols)| {
            cols.sort_by_key(|(n, _)| *n);
            (t, cols.into_iter().map(|(_, c)| c).collect())
        })
        .collect();
    Db {
        tables,
        streams,
        strings,
        columns,
        sink,
    }
    .report();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    fn encode_name(name: &str, table: bool) -> String {
        let idx = |c: char| MIME.iter().position(|&m| m as char == c).map(|i| i as u32);
        let chars: Vec<char> = name.chars().collect();
        let mut out = String::new();
        if table {
            out.push(TABLE_PREFIX);
        }
        let mut i = 0;
        while i < chars.len() {
            match (idx(chars[i]), chars.get(i + 1).and_then(|&c| idx(c))) {
                (Some(a), Some(b)) => {
                    out.push(char::from_u32(0x3800 + a + (b << 6)).unwrap());
                    i += 2;
                }
                (Some(a), None) => {
                    out.push(char::from_u32(0x4800 + a).unwrap());
                    i += 1;
                }
                _ => {
                    out.push(chars[i]);
                    i += 1;
                }
            }
        }
        out
    }

    /// Minimal MSI writer: interned strings plus column-major tables.
    struct Builder {
        strings: Vec<String>,
        streams: Vec<(String, Vec<u8>)>,
        columns: Vec<(String, i16, String, u16)>,
    }

    enum Cell<'a> {
        S(&'a str),
        I(i16),
    }

    impl Builder {
        fn id(&mut self, s: &str) -> u16 {
            if s.is_empty() {
                return 0;
            }
            match self.strings.iter().position(|x| x == s) {
                Some(i) => i as u16 + 1,
                None => {
                    self.strings.push(s.into());
                    self.strings.len() as u16
                }
            }
        }

        fn table(&mut self, name: &str, cols: &[(&str, u16)], rows: &[Vec<Cell>]) {
            for (n, (c, ty)) in cols.iter().enumerate() {
                self.columns
                    .push((name.into(), n as i16 + 1, (*c).into(), *ty));
            }
            let mut data = Vec::new();
            for (n, _) in cols.iter().enumerate() {
                for row in rows {
                    let v = match row[n] {
                        Cell::S(s) => self.id(s),
                        Cell::I(i) => (i as u16) ^ 0x8000,
                    };
                    data.extend_from_slice(&v.to_le_bytes());
                }
            }
            self.streams.push((encode_name(name, true), data));
        }

        fn finish(mut self) -> Vec<u8> {
            let cols = std::mem::take(&mut self.columns);
            let tables: Vec<String> = {
                let mut t: Vec<String> = cols.iter().map(|c| c.0.clone()).collect();
                t.dedup();
                t
            };
            let mut data = Vec::new();
            let ids: Vec<(u16, u16, u16, u16)> = cols
                .iter()
                .map(|(t, n, c, ty)| (self.id(t), (*n as u16) ^ 0x8000, self.id(c), ty ^ 0x8000))
                .collect();
            for f in 0..4 {
                for r in &ids {
                    data.extend_from_slice(&[r.0, r.1, r.2, r.3][f].to_le_bytes());
                }
            }
            self.streams.push((encode_name("_Columns", true), data));
            let t: Vec<u8> = tables
                .iter()
                .flat_map(|t| self.id(t).to_le_bytes())
                .collect();
            self.streams.push((encode_name("_Tables", true), t));
            let mut pool = 0u32.to_le_bytes().to_vec();
            let mut sdata = Vec::new();
            for s in &self.strings {
                pool.extend_from_slice(&(s.len() as u16).to_le_bytes());
                pool.extend_from_slice(&1u16.to_le_bytes());
                sdata.extend_from_slice(s.as_bytes());
            }
            self.streams.push((encode_name("_StringPool", true), pool));
            self.streams.push((encode_name("_StringData", true), sdata));
            let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
            for (name, data) in &self.streams {
                cf.create_stream(format!("/{name}"))
                    .unwrap()
                    .write_all(data)
                    .unwrap();
            }
            cf.flush().unwrap();
            cf.into_inner().into_inner()
        }
    }

    const KEY_S: u16 = 0x2000 | STRING | VALID | 72;
    const OPT_S: u16 = NULLABLE | STRING | VALID | 255;
    const I2: u16 = VALID | 2;

    pub(crate) fn sample() -> Vec<u8> {
        let mut b = Builder {
            strings: Vec::new(),
            streams: Vec::new(),
            columns: Vec::new(),
        };
        b.table(
            "Property",
            &[("Property", KEY_S), ("Value", 0x0200 | STRING | VALID)],
            &[
                vec![Cell::S("ProductName"), Cell::S("Evil App")],
                vec![Cell::S("Manufacturer"), Cell::S("ACME")],
            ],
        );
        b.table(
            "CustomAction",
            &[
                ("Action", KEY_S),
                ("Type", I2),
                ("Source", OPT_S),
                ("Target", OPT_S),
            ],
            &[
                vec![
                    Cell::S("RunVbs"),
                    Cell::I(6),
                    Cell::S("Script1"),
                    Cell::S("Main"),
                ],
                vec![
                    Cell::S("Inline"),
                    Cell::I(38),
                    Cell::S(""),
                    Cell::S("MsgBox 1"),
                ],
                vec![
                    Cell::S("Sys"),
                    Cell::I(0x400 | 0x800 | 34),
                    Cell::S("INSTALLDIR"),
                    Cell::S("cmd /c whoami"),
                ],
            ],
        );
        b.table(
            "InstallExecuteSequence",
            &[
                ("Action", KEY_S),
                ("Condition", OPT_S),
                ("Sequence", NULLABLE | I2),
            ],
            &[vec![
                Cell::S("Sys"),
                Cell::S("NOT Installed"),
                Cell::I(6600),
            ]],
        );
        b.table(
            "Media",
            &[("DiskId", I2), ("Cabinet", OPT_S)],
            &[vec![Cell::I(1), Cell::S("#data.cab")]],
        );
        b.streams.push((
            encode_name("Binary.Script1", false),
            b"WScript.Echo \"hi\"".to_vec(),
        ));
        let cab = crate::cab::tests::build(
            cab::CompressionType::MsZip,
            &[("payload.exe", b"MZpayload")],
        );
        b.streams.push((encode_name("data.cab", false), cab));
        b.finish()
    }

    #[test]
    fn name_roundtrip() {
        for n in ["_StringPool", "Binary.Script1", "a", "x.y_z9"] {
            assert_eq!(decode_name(&encode_name(n, true)), (n.to_string(), true));
        }
    }

    #[test]
    fn parses_tables_custom_actions_and_cabs() {
        let out = expand(&sample(), &Limits::default()).unwrap();
        assert_eq!(out.meta("msi.Property.ProductName"), Some("Evil App"));
        assert_eq!(out.meta("msi.Media.Cabinet"), Some("embedded:data.cab"));
        let vbs = out
            .scripts
            .iter()
            .find(|s| s.path == "CustomAction/RunVbs")
            .unwrap();
        assert_eq!(vbs.interpreter.as_deref(), Some("vbscript"));
        assert!(vbs.text.contains("WScript.Echo"));
        let inline = out
            .scripts
            .iter()
            .find(|s| s.path == "CustomAction/Inline")
            .unwrap();
        assert_eq!(inline.text, "MsgBox 1");
        let sys = out
            .metadata
            .iter()
            .find(|(k, v)| k == "msi.CustomAction" && v.starts_with("Sys"))
            .unwrap();
        assert!(sys.1.contains("noimpersonate"), "{sys:?}");
        assert!(
            out.metadata
                .iter()
                .any(|(k, v)| k == "msi.CustomAction.sequence" && v.contains("NOT Installed"))
        );
        assert_eq!(
            out.child("cab/data.cab/payload.exe").unwrap().data,
            b"MZpayload"
        );
        assert!(out.child("Binary/Script1").is_some());
    }

    #[test]
    fn hostile_inputs_never_panic() {
        let bytes = sample();
        for n in (0..bytes.len()).step_by(97) {
            let _ = expand(&bytes[..n], &Limits::default());
        }
        let mut flipped = bytes.clone();
        for i in (512..flipped.len()).step_by(61) {
            flipped[i] ^= 0xA5;
            let _ = expand(&flipped, &Limits::default());
        }
        assert!(
            expand(
                b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1garbage",
                &Limits::default()
            )
            .is_err()
        );
    }

    /// `BYTEBOUNCER_MSI_SAMPLE=/path/to.msi cargo test -p bytebouncer-formats -- --ignored msi_sample --nocapture`
    #[test]
    #[ignore]
    fn msi_sample() {
        let path = std::env::var("BYTEBOUNCER_MSI_SAMPLE").expect("set BYTEBOUNCER_MSI_SAMPLE");
        let out = expand(&std::fs::read(path).unwrap(), &Limits::default()).unwrap();
        for (k, v) in out
            .metadata
            .iter()
            .filter(|(k, _)| !k.starts_with("msi.Property.") || k.ends_with("ProductName"))
        {
            println!("{k} = {v}");
        }
        for s in &out.scripts {
            println!("script {} {:?}: {:.120}", s.path, s.interpreter, s.text);
        }
        println!(
            "{} children, problems: {:?}",
            out.children.len(),
            out.problems
        );
        for c in out.children.iter().take(15) {
            println!("  {} ({} bytes)", c.path, c.data.len());
        }
    }
}

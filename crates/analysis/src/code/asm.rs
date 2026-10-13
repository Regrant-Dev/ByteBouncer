//! Bounded Intel-syntax disassembly text for selected functions, annotated
//! inline with import names, callee names, and string literals.

use std::collections::HashMap;
use std::fmt::Write as _;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, OpKind, Register};

use super::graph::Analysis;

/// Code bytes decoded per function.
const MAX_FUNCTION_BYTES: u64 = 16 * 1024;

pub(crate) struct AsmContext<'s> {
    strings: HashMap<u64, &'s str>,
}

impl<'s> AsmContext<'s> {
    pub fn new(a: &'s Analysis) -> Self {
        let mut strings = HashMap::new();
        for s in &a.strings {
            strings.entry(s.address).or_insert(s.text.as_str());
        }
        Self { strings }
    }
}

/// Disassemble function `f`, returning (text, truncated).
pub(crate) fn function_text(
    a: &Analysis,
    cx: &AsmContext,
    f: u32,
    max_chars: usize,
) -> (String, bool) {
    let start = a.starts[f as usize];
    let size = a.sizes[f as usize].min(MAX_FUNCTION_BYTES);
    let Some(code) = a.img.read(start, size as usize) else {
        return (String::new(), false);
    };
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_space_after_operand_separator(true);
    fmt.options_mut().set_branch_leading_zeros(false);
    fmt.options_mut().set_leading_zeros(false);
    let mut dec = Decoder::with_ip(a.img.bits, code, start, DecoderOptions::NONE);
    let mut out = String::new();
    let mut instr = Instruction::default();
    let mut line = String::new();
    let mut truncated = (a.sizes[f as usize]) > MAX_FUNCTION_BYTES;
    while dec.can_decode() {
        dec.decode_out(&mut instr);
        line.clear();
        let _ = write!(line, "{:x}  ", instr.ip());
        fmt.format(&instr, &mut line);
        if let Some(note) = annotate(a, cx, &instr) {
            let _ = write!(line, "  ; {note}");
        }
        if out.len() + line.len() + 1 > max_chars {
            truncated = true;
            break;
        }
        out.push_str(&line);
        out.push('\n');
    }
    (out, truncated)
}

fn annotate(a: &Analysis, cx: &AsmContext, i: &Instruction) -> Option<String> {
    let img = a.img;
    if i.is_call_near() || i.is_jmp_near() || i.is_jmp_short() {
        let t = i.near_branch_target();
        if let Some(api) = a.thunk_addrs.get(&t) {
            return Some(img.apis.get(*api as usize).cloned().unwrap_or_default());
        }
        let f = a.index_of(t)?;
        if let Some(api) = a.thunk_api.get(&f) {
            return Some(img.apis.get(*api as usize).cloned().unwrap_or_default());
        }
        return (i.is_call_near() || a.names[f as usize].is_some()).then(|| a.label(f));
    }
    let mem = (0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory);
    let ea = if mem && !matches!(i.memory_segment(), Register::FS | Register::GS) {
        if i.is_ip_rel_memory_operand() {
            Some(i.ip_rel_memory_address())
        } else if i.memory_base() == Register::None && i.memory_index() == Register::None {
            Some(i.memory_displacement64())
        } else if img.bits == 32
            && i.memory_base() == Register::EBX
            && i.memory_index() == Register::None
        {
            img.got_base
                .map(|g| g.wrapping_add(i.memory_displacement64() as u32 as i32 as i64 as u64))
        } else {
            None
        }
    } else {
        None
    };
    let describe = |addr: u64| -> Option<String> {
        if let Some(api) = img.slots.get(&addr) {
            return img.apis.get(*api as usize).cloned();
        }
        if let Some(s) = cx.strings.get(&addr) {
            return Some(quote(s));
        }
        if let Some(f) = a.index_of(addr) {
            return Some(format!("&{}", a.label(f)));
        }
        None
    };
    if let Some(ea) = ea {
        if let Some(d) = describe(ea) {
            return Some(d);
        }
        if let Some(p) = img
            .pointer_at(ea)
            .filter(|_| img.region_of(ea).is_some_and(|r| !r.exec))
            && let Some(d) = describe(p)
        {
            return Some(format!("-> {d}"));
        }
    }
    for n in 0..i.op_count() {
        let v = match i.op_kind(n) {
            OpKind::Immediate32 => i.immediate32() as u64,
            OpKind::Immediate32to64 => i.immediate32to64() as u64,
            OpKind::Immediate64 => i.immediate64(),
            _ => continue,
        };
        if v >= 0x10000
            && img.min_va() >= 0x10000
            && let Some(d) = describe(v)
        {
            return Some(d);
        }
    }
    None
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars().take(80) {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    if s.chars().count() > 80 {
        out.push('…');
    }
    out.push('"');
    out
}

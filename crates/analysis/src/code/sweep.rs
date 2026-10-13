//! Linear-sweep disassembly of executable regions, recording only the facts
//! the code map needs: direct calls / tail jumps, calls through import slots,
//! and references to strings or code addresses. Instructions are not stored.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use super::image::Image;
use super::text;

/// Bounds for one binary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SweepLimits {
    pub max_instructions: u64,
    pub max_events: usize,
    pub max_strings: usize,
}

impl Default for SweepLimits {
    fn default() -> Self {
        Self {
            max_instructions: 20_000_000,
            max_events: 6_000_000,
            max_strings: 200_000,
        }
    }
}

pub(crate) struct RefString {
    pub address: u64,
    pub text: String,
    pub truncated: bool,
    pub kind: &'static str,
}

#[derive(Default)]
pub(crate) struct Events {
    /// (instruction address, target) for direct `call rel`.
    pub calls: Vec<(u64, u64)>,
    /// (instruction address, target) for direct unconditional `jmp rel32`.
    pub jumps: Vec<(u64, u64)>,
    /// (instruction address, api index) for calls/jumps through an import slot.
    pub api_calls: Vec<(u64, u32)>,
    /// Address of a `jmp [slot]` (and a preceding `endbr`) → api index.
    pub thunks: HashMap<u64, u32>,
    /// (instruction address, string index).
    pub str_refs: Vec<(u64, u32)>,
    /// (instruction address, code address) whose address is taken.
    pub code_refs: Vec<(u64, u64)>,
    /// (instruction address, non-string data address) whose address is taken.
    pub data_refs: Vec<(u64, u64)>,
    /// Code that follows `ret`/`jmp` plus `int3` padding (MSVC-style function gaps).
    pub gap_starts: Vec<u64>,
    pub strings: Vec<RefString>,
    pub instructions: u64,
    pub exec_bytes: u64,
    pub truncated: Vec<String>,
}

struct Ctx<'i, 'a> {
    img: &'i Image<'a>,
    ev: Events,
    string_ids: HashMap<(u64, u32), Option<u32>>,
    limits: SweepLimits,
    /// Import loaded into a register (`mov reg,[IAT]`), by full register index.
    reg_api: [Option<u32>; 16],
    /// Go: string address awaiting its length immediate.
    /// Go string pointers awaiting their length.
    go: GoStrings,
    imm_refs: bool,
    events_full: bool,
    /// 0 = normal, 1 = after ret/jmp, 2 = in int3 padding after ret/jmp.
    gap: u8,
}

/// Substrings of (possibly mangled) function names worth disassembling
/// first: they are where data collection, transmission and persistence live.
const PRIORITY_KEYWORDS: &[&str] = &[
    "telemetry",
    "analytic",
    "metric",
    "track",
    "sentry",
    "crash",
    "report",
    "posthog",
    "segment",
    "mixpanel",
    "amplitude",
    "upload",
    "send",
    "post",
    "request",
    "http",
    "reqwest",
    "hyper",
    "ureq",
    "socket",
    "connect",
    "websocket",
    "grpc",
    "hostname",
    "machine",
    "device",
    "uuid",
    "fingerprint",
    "serial",
    "mac_addr",
    "credential",
    "keyring",
    "password",
    "token",
    "secret",
    "oauth",
    "auth",
    "cookie",
    "clipboard",
    "screenshot",
    "capture",
    "keyboard",
    "keylog",
    "autostart",
    "launchagent",
    "systemd",
    "registry",
    "update",
    "download",
    "install",
    "exec",
    "spawn",
    "command",
];

/// Address ranges of named functions matching [`PRIORITY_KEYWORDS`], merged.
fn priority_ranges(img: &Image) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = img
        .names
        .iter()
        .filter_map(|(va, name)| {
            let size = *img.sizes.get(va)?;
            let lower = name.to_ascii_lowercase();
            PRIORITY_KEYWORDS
                .iter()
                .any(|k| lower.contains(k))
                .then_some((*va, va.saturating_add(size)))
        })
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

pub(crate) fn sweep(img: &Image, limits: SweepLimits) -> Events {
    let mut cx = Ctx {
        img,
        ev: Events::default(),
        string_ids: HashMap::new(),
        limits,
        reg_api: [None; 16],
        go: GoStrings::default(),
        // Immediates are only trusted as addresses in non-relocatable-looking images.
        imm_refs: img.min_va() >= 0x10000,
        events_full: false,
        gap: 0,
    };
    let mut instr = Instruction::default();
    // Priority pass: likely-relevant named functions first, using at most
    // half the instruction budget, so huge binaries map what matters.
    let priority = priority_ranges(img);
    let priority_budget = limits.max_instructions / 2;
    'priority: for &(start, end) in &priority {
        let Some(r) = img
            .regions
            .iter()
            .find(|r| r.exec && start >= r.va && start < r.va + r.data.len() as u64)
        else {
            continue;
        };
        let lo = (start - r.va) as usize;
        let hi = ((end - r.va) as usize).min(r.data.len());
        let mut dec = Decoder::with_ip(img.bits, &r.data[lo..hi], start, DecoderOptions::NONE);
        cx.reg_api = [None; 16];
        while dec.can_decode() {
            if cx.ev.instructions >= priority_budget {
                break 'priority;
            }
            dec.decode_out(&mut instr);
            cx.ev.instructions += 1;
            if instr.is_invalid() {
                cx.reg_api = [None; 16];
                continue;
            }
            cx.step(&instr);
        }
    }
    // Small executable sections (PLT stubs, init code) first, so import thunks
    // are known even when the instruction bound stops the sweep of a huge .text.
    let mut exec: Vec<&super::image::Region> = img.regions.iter().filter(|r| r.exec).collect();
    exec.sort_by_key(|r| (r.data.len(), r.va));
    'regions: for r in exec {
        cx.ev.exec_bytes += r.data.len() as u64;
        let mut dec = Decoder::with_ip(img.bits, r.data, r.va, DecoderOptions::NONE);
        cx.reg_api = [None; 16];
        // Skip functions the priority pass already decoded.
        let mut skip = priority.partition_point(|&(_, end)| end <= r.va);
        while dec.can_decode() {
            let ip = dec.ip();
            while skip < priority.len() && priority[skip].1 <= ip {
                skip += 1;
            }
            if let Some(&(start, end)) = priority.get(skip)
                && ip >= start
                && ip < end
            {
                let next = ((end - r.va) as usize).min(r.data.len());
                if dec.set_position(next).is_err() {
                    break;
                }
                dec.set_ip(r.va + next as u64);
                cx.reg_api = [None; 16];
                continue;
            }
            if cx.ev.instructions >= limits.max_instructions {
                cx.ev.truncated.push(format!(
                    "disassembly stopped after {} instructions (bound); code after {:#x} not mapped",
                    limits.max_instructions,
                    dec.ip()
                ));
                break 'regions;
            }
            dec.decode_out(&mut instr);
            cx.ev.instructions += 1;
            if instr.is_invalid() {
                cx.reg_api = [None; 16];
                continue;
            }
            cx.step(&instr);
        }
    }
    if cx.events_full {
        cx.ev.truncated.push(format!(
            "event bound ({}) reached; later call sites and references not recorded",
            limits.max_events
        ));
    }
    if cx.ev.strings.len() >= limits.max_strings {
        cx.ev.truncated.push(format!(
            "referenced-string bound ({}) reached",
            limits.max_strings
        ));
    }
    cx.ev
}

/// Index of a general-purpose register's full-width form (0..16).
fn gpr_index(r: Register) -> Option<usize> {
    let full = r.full_register();
    let n = full as usize;
    let rax = Register::RAX as usize;
    if (rax..rax + 16).contains(&n) {
        return Some(n - rax);
    }
    let eax = Register::EAX as usize;
    if (eax..eax + 16).contains(&n) {
        return Some(n - eax);
    }
    None
}

impl Ctx<'_, '_> {
    fn full(&mut self) -> bool {
        let n = self.ev.calls.len()
            + self.ev.jumps.len()
            + self.ev.api_calls.len()
            + self.ev.str_refs.len()
            + self.ev.code_refs.len()
            + self.ev.data_refs.len();
        if n >= self.limits.max_events {
            self.events_full = true;
        }
        self.events_full
    }

    /// Effective address of the memory operand when it is static.
    fn mem_ea(&self, i: &Instruction) -> Option<u64> {
        if matches!(i.memory_segment(), Register::FS | Register::GS) {
            return None;
        }
        if i.is_ip_rel_memory_operand() {
            return Some(i.ip_rel_memory_address());
        }
        let (base, index) = (i.memory_base(), i.memory_index());
        if base == Register::None && index == Register::None {
            return Some(i.memory_displacement64());
        }
        if self.img.bits == 32 && base == Register::EBX && index == Register::None {
            return self
                .img
                .got_base
                .map(|g| g.wrapping_add(i.memory_displacement64() as u32 as i32 as i64 as u64));
        }
        None
    }

    fn has_mem(i: &Instruction) -> bool {
        (0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory)
    }

    fn step(&mut self, i: &Instruction) {
        let ip = i.ip();
        let full = self.full();
        let int3 = i.mnemonic() == Mnemonic::Int3;
        if self.gap == 2 && !int3 && !full {
            self.ev.gap_starts.push(ip);
        }
        self.gap = match (self.gap, int3) {
            (1 | 2, true) => 2,
            _ if i.mnemonic() == Mnemonic::Ret
                || i.is_jmp_near()
                || i.is_jmp_short()
                || i.is_jmp_near_indirect() =>
            {
                1
            }
            _ => 0,
        };
        if self.img.is_go && !full {
            for (ip, addr, len) in self.go.step(i) {
                match len {
                    Some(len) => {
                        self.string_or_data(ip, addr, Some(len as usize), true);
                    }
                    None => self.go_fallback(ip, addr),
                }
            }
        }
        if i.is_call_near() {
            if !full {
                self.ev.calls.push((ip, i.near_branch_target()));
            }
            self.clobber_volatile();
            return;
        }
        if i.is_jmp_near() {
            if !full && i.near_branch_target() != ip.wrapping_add(i.len() as u64) {
                self.ev.jumps.push((ip, i.near_branch_target()));
            }
            return;
        }
        if i.is_call_near_indirect() || i.is_jmp_near_indirect() {
            let is_call = i.is_call_near_indirect();
            let api = match i.op0_kind() {
                OpKind::Memory => self
                    .mem_ea(i)
                    .and_then(|ea| self.img.slots.get(&ea).copied()),
                OpKind::Register => gpr_index(i.op0_register()).and_then(|r| self.reg_api[r]),
                _ => None,
            };
            if let Some(api) = api {
                if !full {
                    self.ev.api_calls.push((ip, api));
                }
                if !is_call && i.op0_kind() == OpKind::Memory {
                    self.ev.thunks.insert(ip, api);
                    // `endbr64; [bnd] jmp [slot]` (.plt.sec) and `endbr32`.
                    if ip >= 4
                        && let Some(b) = self.img.read(ip - 4, 4)
                        && b.len() == 4
                        && b[..3] == [0xf3, 0x0f, 0x1e]
                        && (b[3] == 0xfa || b[3] == 0xfb)
                    {
                        self.ev.thunks.insert(ip - 4, api);
                    }
                }
            }
            if is_call {
                self.clobber_volatile();
            }
            return;
        }
        match i.mnemonic() {
            Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Int3 => {
                self.reg_api = [None; 16];
                return;
            }
            Mnemonic::Nop => return,
            _ => {}
        }

        // Track `mov reg, [IAT]` for a later `call reg`.
        let dest = if i.op_count() > 0 && i.op0_kind() == OpKind::Register {
            gpr_index(i.op0_register())
        } else {
            None
        };
        let mut loaded_api = None;
        if i.mnemonic() == Mnemonic::Mov
            && dest.is_some()
            && i.op_count() == 2
            && i.op1_kind() == OpKind::Memory
        {
            loaded_api = self
                .mem_ea(i)
                .and_then(|ea| self.img.slots.get(&ea).copied());
        }
        if let Some(d) = dest {
            self.reg_api[d] = loaded_api;
        }
        if full || loaded_api.is_some() {
            return;
        }

        // Data and code references.
        if Self::has_mem(i)
            && let Some(ea) = self.mem_ea(i)
        {
            let is_lea = i.mnemonic() == Mnemonic::Lea;
            if is_lea
                && self.img.is_go
                && self.img.region_of(ea).is_some_and(|r| !r.exec)
                && let Some(reg) = gpr_index(i.op0_register())
            {
                // Go strings have no terminator: wait for the length.
                if let Some(len) = self.go.lea(ip, ea, reg) {
                    self.string_or_data(ip, ea, Some(len as usize), true);
                }
            } else if is_lea {
                self.reference(ip, ea, true);
            } else if !self.reference(ip, ea, false)
                && let Some(p) = self.img.pointer_at(ea)
                && self.img.region_of(ea).is_some_and(|r| !r.exec)
            {
                // A load from a pointer slot: follow one level (string tables, PIC).
                self.reference(ip, p, true);
            }
        }
        if self.imm_refs {
            for n in 0..i.op_count() {
                let v = match i.op_kind(n) {
                    OpKind::Immediate32 => i.immediate32() as u64,
                    OpKind::Immediate32to64 => i.immediate32to64() as u64,
                    OpKind::Immediate64 => i.immediate64(),
                    _ => continue,
                };
                if v >= 0x10000 {
                    self.reference(ip, v, true);
                }
            }
        }
    }

    fn clobber_volatile(&mut self) {
        // rax, rcx, rdx and r8-r11 are caller-saved on every x86 ABI we see.
        for r in [0usize, 1, 2, 8, 9, 10, 11] {
            self.reg_api[r] = None;
        }
    }

    /// Record a reference to `addr` if it is a string start or (when
    /// `address_taken`) a code address. Returns whether anything was recorded.
    fn reference(&mut self, ip: u64, addr: u64, address_taken: bool) -> bool {
        let Some(region) = self.img.region_of(addr) else {
            return false;
        };
        if self.img.slots.contains_key(&addr) {
            return false;
        }
        if region.exec {
            if address_taken && self.img.names.contains_key(&addr) {
                self.ev.code_refs.push((ip, addr));
                return true;
            }
            // Older MSVC / some linkers merge read-only data into the code section.
            if let Some(id) = self.string_at(addr, None) {
                self.ev.str_refs.push((ip, id));
                return true;
            }
            if address_taken {
                self.ev.code_refs.push((ip, addr));
                return true;
            }
            return false;
        }
        if self.img.is_go && address_taken {
            self.go_fallback(ip, addr);
            return true;
        }
        self.string_or_data(ip, addr, None, address_taken)
    }

    fn string_or_data(
        &mut self,
        ip: u64,
        addr: u64,
        exact: Option<usize>,
        address_taken: bool,
    ) -> bool {
        match self.string_at(addr, exact) {
            Some(id) => {
                self.ev.str_refs.push((ip, id));
                true
            }
            None => {
                if address_taken {
                    // Possibly a table of code pointers (vtable, callbacks, Go funcval).
                    self.ev.data_refs.push((ip, addr));
                }
                false
            }
        }
    }

    /// No length found for a Go string pointer: accept a short NUL-terminated
    /// string (cgo / C data); Go string data is packed without terminators,
    /// so long reads are rejected and the address is kept as a data reference.
    fn go_fallback(&mut self, ip: u64, addr: u64) {
        match self.string_at(addr, None) {
            Some(id) if !self.ev.strings[id as usize].truncated => self.ev.str_refs.push((ip, id)),
            _ => self.ev.data_refs.push((ip, addr)),
        }
    }

    fn string_at(&mut self, addr: u64, exact: Option<usize>) -> Option<u32> {
        let key = (addr, exact.unwrap_or(0) as u32);
        if let Some(id) = self.string_ids.get(&key) {
            return *id;
        }
        let id = if self.ev.strings.len() >= self.limits.max_strings {
            None
        } else {
            let found = match exact {
                Some(e) => {
                    let want = e.min(text::MAX_CHARS);
                    self.img
                        .read(addr, want)
                        .filter(|d| d.len() == want)
                        .and_then(|d| text::read_string(d, Some(want)))
                        .map(|(t, _)| (t, e > text::MAX_CHARS))
                }
                None => self
                    .img
                    .read(addr, text::MAX_CHARS * 2 + 4)
                    .and_then(|d| text::read_string(d, None)),
            };
            found.map(|(t, truncated)| {
                let kind = text::classify(&t);
                self.ev.strings.push(RefString {
                    address: addr,
                    text: t,
                    truncated,
                    kind,
                });
                (self.ev.strings.len() - 1) as u32
            })
        };
        if self.string_ids.len() < self.limits.max_strings * 4 {
            self.string_ids.insert(key, id);
        }
        id
    }
}

/// Go ABIInternal integer argument registers (gpr indices): RAX, RBX, RCX,
/// RDI, RSI, R8, R9, R10, R11. A string's length follows its pointer.
const GO_ARGS: [usize; 9] = [0, 3, 1, 7, 6, 8, 9, 10, 11];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Reg(usize),
    Mem(Register, u64),
}

struct Pending {
    ip: u64,
    addr: u64,
    reg: usize,
    store: Option<(Register, u64)>,
    left: u8,
}

/// Recovers Go string lengths: `lea rax,[s]; mov ebx,len` (register ABI) or
/// `mov [p+d],reg` with `mov qword [p+d+8],len` (struct fields), in either order.
#[derive(Default)]
struct GoStrings {
    pending: Vec<Pending>,
    /// Recent small immediates: (slot, value, age).
    recent: Vec<(Slot, u64, u8)>,
}

fn next_arg(reg: usize) -> Option<usize> {
    GO_ARGS
        .iter()
        .position(|r| *r == reg)
        .and_then(|i| GO_ARGS.get(i + 1))
        .copied()
}

fn small_imm(i: &Instruction) -> Option<u64> {
    if i.mnemonic() != Mnemonic::Mov || i.op_count() != 2 {
        return None;
    }
    match i.op1_kind() {
        OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate8
        | OpKind::Immediate16 => Some(i.immediate(1)).filter(|l| (1..=4096).contains(l)),
        _ => None,
    }
}

fn mem_slot(i: &Instruction) -> Option<(Register, u64)> {
    (i.op0_kind() == OpKind::Memory
        && i.memory_base() != Register::None
        && i.memory_index() == Register::None)
        .then(|| (i.memory_base(), i.memory_displacement64()))
}

impl GoStrings {
    /// A `lea reg,[addr]` of data. Returns the length when it was set just before.
    fn lea(&mut self, ip: u64, addr: u64, reg: usize) -> Option<u64> {
        if let Some(next) = next_arg(reg)
            && let Some(pos) = self.recent.iter().position(|r| r.0 == Slot::Reg(next))
        {
            return Some(self.recent.remove(pos).1);
        }
        if self.pending.len() >= 4 {
            self.pending.remove(0);
        }
        self.pending.push(Pending {
            ip,
            addr,
            reg,
            store: None,
            left: 5,
        });
        None
    }

    /// Advance one instruction; returns resolved (ip, addr, length) and expired (length None).
    fn step(&mut self, i: &Instruction) -> Vec<(u64, u64, Option<u64>)> {
        let mut out = vec![];
        let imm = small_imm(i);
        let dest_reg = (i.op_count() > 0 && i.op0_kind() == OpKind::Register)
            .then(|| gpr_index(i.op0_register()))
            .flatten();
        let slot = match (dest_reg, mem_slot(i)) {
            (Some(r), _) => Some(Slot::Reg(r)),
            (None, Some((b, d))) => Some(Slot::Mem(b, d)),
            _ => None,
        };
        // `mov [b+d], reg` storing a pending pointer.
        let stored = (i.mnemonic() == Mnemonic::Mov
            && i.op_count() == 2
            && i.op1_kind() == OpKind::Register)
            .then(|| gpr_index(i.op1_register()).zip(mem_slot(i)))
            .flatten();
        let mut k = 0;
        while k < self.pending.len() {
            let p = &mut self.pending[k];
            let mut len = None;
            if let (Some(v), Some(s)) = (imm, slot) {
                let by_reg = next_arg(p.reg).is_some_and(|n| s == Slot::Reg(n));
                let by_mem = p
                    .store
                    .is_some_and(|(b, d)| s == Slot::Mem(b, d.wrapping_add(8)));
                if by_reg || by_mem {
                    len = Some(v);
                }
            }
            if len.is_none()
                && let Some((r, (b, d))) = stored
                && r == p.reg
            {
                p.store = Some((b, d));
                if let Some(pos) = self
                    .recent
                    .iter()
                    .position(|x| x.0 == Slot::Mem(b, d.wrapping_add(8)))
                {
                    len = Some(self.recent.remove(pos).1);
                }
            }
            let p = &mut self.pending[k];
            if len.is_some() {
                out.push((p.ip, p.addr, len));
                self.pending.remove(k);
                continue;
            }
            p.left = p.left.saturating_sub(1);
            if p.left == 0 {
                out.push((p.ip, p.addr, None));
                self.pending.remove(k);
                continue;
            }
            k += 1;
        }
        for r in &mut self.recent {
            r.2 += 1;
        }
        self.recent.retain(|r| r.2 <= 3 && Some(r.0) != slot);
        if let (Some(v), Some(s)) = (imm, slot)
            && !out.iter().any(|o| o.2 == Some(v))
        {
            self.recent.push((s, v, 0));
            if self.recent.len() > 8 {
                self.recent.remove(0);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &[u8]) -> Vec<(u64, u64, Option<u64>)> {
        let mut d = Decoder::with_ip(64, code, 0x1000, DecoderOptions::NONE);
        let mut g = GoStrings::default();
        let mut out = vec![];
        let mut i = Instruction::default();
        while d.can_decode() {
            d.decode_out(&mut i);
            out.extend(g.step(&i));
            if i.mnemonic() == Mnemonic::Lea
                && let Some(len) = g.lea(
                    i.ip(),
                    i.ip_rel_memory_address(),
                    gpr_index(i.op0_register()).unwrap(),
                )
            {
                out.push((i.ip(), i.ip_rel_memory_address(), Some(len)));
            }
        }
        out
    }

    #[test]
    fn go_string_lengths() {
        // lea rax,[rip+0]; mov ebx,5  (register ABI: length in the next arg register)
        let out = run(&[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xbb, 5, 0, 0, 0]);
        assert_eq!(out, vec![(0x1000, 0x1007, Some(5))]);
        // mov ebx,7; lea rax,[rip+0]  (length first)
        let out = run(&[0xbb, 7, 0, 0, 0, 0x48, 0x8d, 0x05, 0, 0, 0, 0]);
        assert_eq!(out, vec![(0x1005, 0x100c, Some(7))]);
        // mov qword [rax+8],0x18; lea rdx,[rip+0]; mov [rax],rdx  (struct field, length stored first)
        let out = run(&[
            0x48, 0xc7, 0x40, 0x08, 0x18, 0, 0, 0, 0x48, 0x8d, 0x15, 0, 0, 0, 0, 0x48, 0x89, 0x10,
        ]);
        assert_eq!(out, vec![(0x1008, 0x100f, Some(0x18))]);
        // lea rdx,[rip+0]; mov [rax],rdx; mov qword [rax+8],0x1a
        let out = run(&[
            0x48, 0x8d, 0x15, 0, 0, 0, 0, 0x48, 0x89, 0x10, 0x48, 0xc7, 0x40, 0x08, 0x1a, 0, 0, 0,
        ]);
        assert_eq!(out, vec![(0x1000, 0x1007, Some(0x1a))]);
        // No length: expires.
        let out = run(&[
            0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ]);
        assert_eq!(out, vec![(0x1000, 0x1007, None)]);
    }
}

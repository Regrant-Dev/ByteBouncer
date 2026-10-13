//! Loading a PE / ELF / Mach-O image into a flat, read-only view of mapped
//! regions plus everything the code map needs from the headers: entry points,
//! named functions, import slots (IAT / GOT / lazy pointers), and pointer
//! relocations. Pure parsing over borrowed bytes; never panics on bad input.

use std::collections::HashMap;

use goblin::Object;
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS};
use goblin::elf::sym::{STB_LOCAL, STT_FUNC, STT_GNU_IFUNC};

/// Upper bound on names taken from symbol tables / pclntab.
const MAX_SYMBOLS: usize = 400_000;
/// Upper bound on import slots and pointer relocations.
const MAX_SLOTS: usize = 200_000;
const MAX_RELOCS: usize = 2_000_000;

pub(crate) struct Region<'a> {
    pub va: u64,
    pub data: &'a [u8],
    pub exec: bool,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootKind {
    Entry,
    Main,
    Export,
    Initializer,
    TlsCallback,
}

impl RootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry_point",
            Self::Main => "main",
            Self::Export => "export",
            Self::Initializer => "initializer",
            Self::TlsCallback => "tls_callback",
        }
    }
}

pub(crate) struct Image<'a> {
    pub format: &'static str,
    pub bits: u32,
    /// Sorted by `va`; non-overlapping in practice (overlaps resolve to the first).
    pub regions: Vec<Region<'a>>,
    pub roots: Vec<(u64, RootKind)>,
    /// Function start → name (symbols, exports, Go pclntab).
    pub names: HashMap<u64, String>,
    /// Function start → known size (ELF symbol size, PE .pdata).
    pub sizes: HashMap<u64, u64>,
    /// Extra function starts without names (PE .pdata).
    pub seeds: Vec<u64>,
    /// Import slot VA → index into `apis`.
    pub slots: HashMap<u64, u32>,
    /// Imported API display names (`DLL!name` for PE/Mach-O, `name` for ELF).
    pub apis: Vec<String>,
    /// Pointer-sized slot VA → value after relocation (ELF RELATIVE etc.).
    pub pointers: HashMap<u64, u64>,
    /// i386 ELF: `.got.plt` base used by `[ebx+disp]` PIC addressing.
    pub got_base: Option<u64>,
    pub is_go: bool,
    pub notes: Vec<String>,
}

pub(crate) enum Load<'a> {
    Ok(Box<Image<'a>>),
    /// Recognized executable we do not disassemble (with reason).
    Unsupported(String),
    /// Not an executable format this module handles.
    NotExecutable,
}

impl<'a> Image<'a> {
    fn new(format: &'static str, bits: u32) -> Self {
        Self {
            format,
            bits,
            regions: vec![],
            roots: vec![],
            names: HashMap::new(),
            sizes: HashMap::new(),
            seeds: vec![],
            slots: HashMap::new(),
            apis: vec![],
            pointers: HashMap::new(),
            got_base: None,
            is_go: false,
            notes: vec![],
        }
    }

    pub fn region_of(&self, va: u64) -> Option<&Region<'a>> {
        let i = self.regions.partition_point(|r| r.va <= va);
        if i == 0 {
            return None;
        }
        let r = &self.regions[i - 1];
        (va - r.va < r.data.len() as u64).then_some(r)
    }

    pub fn is_exec(&self, va: u64) -> bool {
        self.region_of(va).is_some_and(|r| r.exec)
    }

    /// Up to `max` mapped bytes starting at `va` (stops at the region end).
    pub fn read(&self, va: u64, max: usize) -> Option<&'a [u8]> {
        let r = self.region_of(va)?;
        let off = (va - r.va) as usize;
        let end = off.saturating_add(max).min(r.data.len());
        r.data.get(off..end)
    }

    /// The pointer stored at `va`, honoring relocations.
    pub fn read_ptr(&self, va: u64) -> Option<u64> {
        if let Some(v) = self.pointers.get(&va) {
            return Some(*v);
        }
        let n = (self.bits / 8) as usize;
        let b = self.read(va, n)?;
        if b.len() < n {
            return None;
        }
        Some(if n == 8 {
            u64::from_le_bytes(b.try_into().ok()?)
        } else {
            u32::from_le_bytes(b.try_into().ok()?) as u64
        })
    }

    /// A pointer stored in data, trusting raw values only when the image is
    /// not position-independent (in a PIE, small integers look like code
    /// addresses, so only relocated slots count).
    pub fn pointer_at(&self, va: u64) -> Option<u64> {
        if self.min_va() < 0x10000 {
            return self.pointers.get(&va).copied();
        }
        self.read_ptr(va)
    }

    pub fn min_va(&self) -> u64 {
        self.regions.first().map_or(0, |r| r.va)
    }

    fn api(&mut self, name: String) -> u32 {
        if let Some(i) = self.apis.iter().rposition(|a| *a == name) {
            return i as u32;
        }
        self.apis.push(name);
        (self.apis.len() - 1) as u32
    }

    fn add_slot(&mut self, va: u64, name: String) {
        if self.slots.len() < MAX_SLOTS && !self.slots.contains_key(&va) {
            let id = self.api(name);
            self.slots.insert(va, id);
        }
    }

    fn add_name(&mut self, va: u64, name: &str) {
        if self.names.len() < MAX_SYMBOLS && !name.is_empty() {
            self.names.entry(va).or_insert_with(|| name.to_owned());
        }
    }

    fn finish(&mut self) {
        self.regions.retain(|r| !r.data.is_empty());
        self.regions.sort_by_key(|r| r.va);
        self.roots.sort_by_key(|r| r.0);
        self.roots.dedup_by_key(|r| r.0);
        self.roots.retain(|r| r.0 != 0);
    }
}

fn slice(bytes: &[u8], off: u64, len: u64) -> &[u8] {
    let start = off.min(bytes.len() as u64) as usize;
    let end = off.saturating_add(len).min(bytes.len() as u64) as usize;
    &bytes[start..end.max(start)]
}

pub(crate) fn load(bytes: &[u8]) -> Load<'_> {
    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => load_elf(bytes, &elf),
        Ok(Object::PE(pe)) => load_pe(bytes, &pe),
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => load_macho(&m),
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => {
            Load::Unsupported("universal (fat) Mach-O slices are not disassembled".into())
        }
        _ => Load::NotExecutable,
    }
}

fn load_elf<'a>(bytes: &'a [u8], elf: &goblin::elf::Elf<'a>) -> Load<'a> {
    let bits = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => 64,
        goblin::elf::header::EM_386 => 32,
        m => {
            return Load::Unsupported(format!(
                "code map not available for {} (ELF machine {m})",
                goblin::elf::header::machine_to_str(m)
            ));
        }
    };
    let mut img = Image::new("elf", bits);
    let shname = |sh: &goblin::elf::SectionHeader| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
    let has_sections = elf
        .section_headers
        .iter()
        .any(|s| s.sh_flags & SHF_EXECINSTR as u64 != 0 && s.sh_type != SHT_NOBITS);
    if has_sections {
        for sh in &elf.section_headers {
            if sh.sh_flags & SHF_ALLOC as u64 == 0 || sh.sh_type == SHT_NOBITS || sh.sh_addr == 0 {
                continue;
            }
            let name = shname(sh);
            if name == ".gopclntab" || name == ".note.go.buildid" {
                img.is_go = true;
            }
            img.regions.push(Region {
                va: sh.sh_addr,
                data: slice(bytes, sh.sh_offset, sh.sh_size),
                exec: sh.sh_flags & SHF_EXECINSTR as u64 != 0,
                name: name.to_owned(),
            });
        }
        img.got_base = elf
            .section_headers
            .iter()
            .find(|s| shname(s) == ".got.plt")
            .or_else(|| elf.section_headers.iter().find(|s| shname(s) == ".got"))
            .map(|s| s.sh_addr);
    } else {
        img.notes
            .push("no section headers; executable segments disassembled".into());
        for (i, ph) in elf.program_headers.iter().enumerate() {
            if ph.p_type != goblin::elf::program_header::PT_LOAD {
                continue;
            }
            img.regions.push(Region {
                va: ph.p_vaddr,
                data: slice(bytes, ph.p_offset, ph.p_filesz),
                exec: ph.p_flags & goblin::elf::program_header::PF_X != 0,
                name: format!("segment{i}"),
            });
        }
    }
    img.finish();

    if elf.entry != 0 {
        img.roots.push((elf.entry, RootKind::Entry));
    }
    let shared = elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_none();
    // Symbols: local+global functions from .symtab, defined functions from .dynsym.
    for (tab, strtab, dynamic) in [
        (&elf.syms, &elf.strtab, false),
        (&elf.dynsyms, &elf.dynstrtab, true),
    ] {
        for sym in tab.iter().take(MAX_SYMBOLS) {
            let ty = sym.st_type();
            if (ty != STT_FUNC && ty != STT_GNU_IFUNC) || sym.st_value == 0 || sym.st_shndx == 0 {
                continue;
            }
            let Some(name) = strtab.get_at(sym.st_name) else {
                continue;
            };
            if !img.is_exec(sym.st_value) {
                continue;
            }
            img.add_name(sym.st_value, name);
            if sym.st_size > 0 {
                img.sizes.insert(sym.st_value, sym.st_size);
            }
            if name == "main" {
                img.roots.push((sym.st_value, RootKind::Main));
            } else if dynamic && shared && sym.st_bind() != STB_LOCAL {
                img.roots.push((sym.st_value, RootKind::Export));
            }
        }
    }
    // Import slots and pointer relocations.
    // R_X86_64_* and R_386_* share these numbers: 64/32, GLOB_DAT, JUMP_SLOT, RELATIVE.
    let (r_abs, r_glob, r_jump, r_relative) = (1, 6, 7, 8);
    let mut relocs = 0usize;
    for rs in [&elf.pltrelocs, &elf.dynrelas, &elf.dynrels] {
        for r in rs.iter() {
            relocs += 1;
            // RELR (packed relative relocations, implicit addends kept in place).
            for sh in &elf.section_headers {
                if sh.sh_type != 19 && shname(sh) != ".relr.dyn" {
                    continue;
                }
                let data = slice(bytes, sh.sh_offset, sh.sh_size);
                let word = (bits / 8) as usize;
                let mut base = 0u64;
                for chunk in data.chunks_exact(word) {
                    if relocs > MAX_RELOCS {
                        break;
                    }
                    let e = if word == 8 {
                        u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]))
                    } else {
                        u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as u64
                    };
                    if e & 1 == 0 {
                        relocs += 1;
                        if let Some(v) = img.read_ptr(e) {
                            img.pointers.insert(e, v);
                        }
                        base = e.wrapping_add(word as u64);
                    } else {
                        for bit in 1..(word as u64 * 8) {
                            if (e >> bit) & 1 == 1 {
                                relocs += 1;
                                let at = base.wrapping_add((bit - 1) * word as u64);
                                if let Some(v) = img.read_ptr(at) {
                                    img.pointers.insert(at, v);
                                }
                            }
                        }
                        base = base.wrapping_add((word as u64 * 8 - 1) * word as u64);
                    }
                }
            }
            if relocs > MAX_RELOCS {
                break;
            }
            if r.r_sym != 0 {
                let Some(sym) = elf.dynsyms.get(r.r_sym) else {
                    continue;
                };
                if sym.st_shndx == 0
                    && (r.r_type == r_glob || r.r_type == r_jump || r.r_type == r_abs)
                {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name).filter(|n| !n.is_empty())
                    {
                        img.add_slot(r.r_offset, name.to_owned());
                    }
                } else if sym.st_value != 0 {
                    let v = sym.st_value.wrapping_add(r.r_addend.unwrap_or(0) as u64);
                    img.pointers.insert(r.r_offset, v);
                }
            } else if r.r_type == r_relative {
                // RELA carries the addend; REL (i386) keeps it in place.
                let v = match r.r_addend {
                    Some(addend) => Some(addend as u64),
                    None => img.read_ptr(r.r_offset),
                };
                if let Some(v) = v {
                    img.pointers.insert(r.r_offset, v);
                }
            }
        }
    }
    if relocs > MAX_RELOCS {
        img.notes
            .push(format!("only the first {MAX_RELOCS} relocations were read"));
    }
    // Initializers (.init_array) run before main.
    for sh in &elf.section_headers {
        if shname(sh) == ".init_array" {
            let n = (sh.sh_size / (bits as u64 / 8)).min(4096);
            for i in 0..n {
                if let Some(p) = img.read_ptr(sh.sh_addr.wrapping_add(i * (bits as u64 / 8)))
                    && img.is_exec(p)
                {
                    img.roots.push((p, RootKind::Initializer));
                }
            }
        }
    }
    if img.is_go {
        go_pclntab(
            &mut img,
            elf.section_headers
                .iter()
                .find(|s| shname(s) == ".gopclntab")
                .map(|s| s.sh_addr),
        );
    }
    img.finish();
    Load::Ok(Box::new(img))
}

fn load_pe<'a>(bytes: &'a [u8], pe: &goblin::pe::PE<'a>) -> Load<'a> {
    let machine = pe.header.coff_header.machine;
    let bits = match machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => 64,
        goblin::pe::header::COFF_MACHINE_X86 => 32,
        m => {
            return Load::Unsupported(format!(
                "code map not available for PE machine {m:#06x} ({})",
                match m {
                    0xaa64 => "arm64",
                    0x1c0 | 0x1c4 => "arm",
                    _ => "unknown",
                }
            ));
        }
    };
    if pe.clr_data.is_some() {
        return Load::Unsupported(
            ".NET (managed) code is not disassembled by the built-in code map".into(),
        );
    }
    let mut img = Image::new("pe", bits);
    let base = pe.image_base;
    for s in &pe.sections {
        let raw = slice(
            bytes,
            s.pointer_to_raw_data as u64,
            s.size_of_raw_data as u64,
        );
        let vsize = if s.virtual_size == 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size
        };
        let data = &raw[..raw.len().min(vsize as usize)];
        let exec = s.characteristics
            & (goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
                | goblin::pe::section_table::IMAGE_SCN_CNT_CODE)
            != 0;
        img.regions.push(Region {
            va: base.wrapping_add(s.virtual_address as u64),
            data,
            exec,
            name: s.name().unwrap_or("").to_owned(),
        });
    }
    img.finish();
    if pe.entry != 0 {
        img.roots
            .push((base.wrapping_add(pe.entry as u64), RootKind::Entry));
    }
    for imp in &pe.imports {
        img.add_slot(
            base.wrapping_add(imp.offset as u64),
            format!("{}!{}", imp.dll, imp.name),
        );
    }
    for e in pe.exports.iter().take(MAX_SYMBOLS) {
        if e.reexport.is_some() || e.rva == 0 {
            continue;
        }
        let va = base.wrapping_add(e.rva as u64);
        if img.is_exec(va) {
            if let Some(n) = e.name {
                img.add_name(va, n);
            }
            img.roots.push((va, RootKind::Export));
        }
    }
    if let Some(tls) = &pe.tls_data {
        for cb in tls.callbacks.iter().take(64) {
            if img.is_exec(*cb) {
                img.roots.push((*cb, RootKind::TlsCallback));
            }
        }
    }
    if bits == 64
        && let Some(ex) = &pe.exception_data
    {
        let mut n = 0usize;
        for rf in ex.functions().flatten() {
            n += 1;
            if n > MAX_SYMBOLS {
                img.notes.push(format!(
                    "only the first {MAX_SYMBOLS} .pdata entries were read"
                ));
                break;
            }
            let va = base.wrapping_add(rf.begin_address as u64);
            if rf.end_address > rf.begin_address && img.is_exec(va) {
                img.seeds.push(va);
                img.sizes
                    .entry(va)
                    .or_insert((rf.end_address - rf.begin_address) as u64);
            }
        }
    }
    delay_imports(&mut img, pe, base);
    img.is_go = memchr::memmem::find(bytes, b"\xff Go buildinf:").is_some();
    if img.is_go {
        go_pclntab(&mut img, None);
    }
    img.finish();
    Load::Ok(Box::new(img))
}

/// Delay-load import descriptors (data directory 13), which goblin does not parse.
fn delay_imports(img: &mut Image, pe: &goblin::pe::PE, base: u64) {
    let Some(opt) = &pe.header.optional_header else {
        return;
    };
    let Some(dd) = opt.data_directories.get_delay_import_descriptor() else {
        return;
    };
    let u32_at = |img: &Image, va: u64| -> Option<u32> {
        img.read(va, 4)
            .filter(|b| b.len() == 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let cstr = |img: &Image, va: u64| -> Option<String> {
        let b = img.read(va, 256)?;
        let end = b.iter().position(|&c| c == 0)?;
        let s = std::str::from_utf8(&b[..end]).ok()?;
        (!s.is_empty() && s.bytes().all(|c| c.is_ascii_graphic())).then(|| s.to_owned())
    };
    let ptr = (img.bits / 8) as u64;
    let mut desc = base.wrapping_add(dd.virtual_address as u64);
    for _ in 0..256 {
        let fields: Vec<u32> = (0..8).filter_map(|i| u32_at(img, desc + i * 4)).collect();
        if fields.len() < 8 || fields[1] == 0 {
            break;
        }
        // Version 1 descriptors hold RVAs; legacy (attr bit 0 clear) hold VAs.
        let rel = |v: u32| {
            if fields[0] & 1 != 0 {
                base.wrapping_add(v as u64)
            } else {
                v as u64
            }
        };
        let dll = cstr(img, rel(fields[1])).unwrap_or_else(|| "?".into());
        let (iat, int) = (rel(fields[3]), rel(fields[4]));
        for i in 0..4096u64 {
            let Some(entry) = img.read_ptr(int.wrapping_add(i * ptr)) else {
                break;
            };
            if entry == 0 {
                break;
            }
            let ordinal_flag = if ptr == 8 { 1u64 << 63 } else { 1u64 << 31 };
            let name = if entry & ordinal_flag != 0 {
                format!("ORDINAL {}", entry & 0xffff)
            } else {
                match cstr(img, rel(entry as u32).wrapping_add(2)) {
                    Some(n) => n,
                    None => break,
                }
            };
            img.add_slot(iat.wrapping_add(i * ptr), format!("{dll}!{name}"));
        }
        desc += 32;
    }
}

fn load_macho<'a>(m: &goblin::mach::MachO<'a>) -> Load<'a> {
    use goblin::mach::constants::cputype::{CPU_TYPE_X86, CPU_TYPE_X86_64};
    let bits = match m.header.cputype {
        CPU_TYPE_X86_64 => 64,
        CPU_TYPE_X86 => 32,
        c => {
            return Load::Unsupported(format!(
                "code map not available for {} (Mach-O)",
                goblin::mach::constants::cputype::get_arch_name_from_types(c, m.header.cpusubtype)
                    .unwrap_or("this architecture")
            ));
        }
    };
    let mut img = Image::new("mach-o", bits);
    for seg in m.segments.iter() {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (sec, data) in sections {
            let exec = sec.flags & 0x8000_0400 != 0;
            img.regions.push(Region {
                va: sec.addr,
                data,
                exec,
                name: format!(
                    "{},{}",
                    sec.segname().unwrap_or(""),
                    sec.name().unwrap_or("")
                ),
            });
        }
    }
    img.finish();
    if m.entry != 0 {
        img.roots.push((m.entry, RootKind::Entry));
    }
    match m.imports() {
        Ok(imports) => {
            for i in imports {
                img.add_slot(
                    i.address,
                    format!("{}!{}", i.dylib, i.name.trim_start_matches('_')),
                );
            }
        }
        Err(e) => img.notes.push(format!("Mach-O imports not resolved: {e}")),
    }
    // MH_DYLIB (6) and MH_BUNDLE (8).
    let dylib = matches!(m.header.filetype, 6 | 8);
    for (name, nl) in m.symbols().flatten().take(MAX_SYMBOLS) {
        if nl.is_stab() || nl.n_sect == 0 || nl.n_value == 0 || !img.is_exec(nl.n_value) {
            continue;
        }
        let name = name.strip_prefix('_').unwrap_or(name);
        img.add_name(nl.n_value, name);
        if name == "main" {
            img.roots.push((nl.n_value, RootKind::Main));
        } else if dylib && nl.n_type & 0x01 != 0 {
            // N_EXT symbol defined in a dylib / bundle: callable by the host.
            img.roots.push((nl.n_value, RootKind::Export));
        }
    }
    img.finish();
    Load::Ok(Box::new(img))
}

/// Go 1.18+ pclntab: function names and starts for (often stripped) Go binaries.
fn go_pclntab(img: &mut Image, at: Option<u64>) {
    let ptr = (img.bits / 8) as usize;
    let candidates: Vec<u64> = match at {
        Some(va) => vec![va],
        None => {
            // Search non-exec regions for the header magic.
            let mut v = vec![];
            for r in img.regions.iter().filter(|r| !r.exec) {
                for magic in [[0xf1u8, 0xff, 0xff, 0xff], [0xf0, 0xff, 0xff, 0xff]] {
                    let mut from = 0;
                    while let Some(p) = memchr::memmem::find(&r.data[from..], &magic) {
                        let off = from + p;
                        if matches!(r.data.get(off + 6), Some(1 | 2 | 4))
                            && r.data.get(off + 7) == Some(&(ptr as u8))
                            && r.data.get(off + 4..off + 6) == Some(&[0u8, 0][..])
                        {
                            v.push(r.va + off as u64);
                        }
                        from = off + 4;
                        if v.len() > 8 {
                            break;
                        }
                    }
                }
            }
            v
        }
    };
    for va in candidates {
        if parse_pclntab(img, va, ptr) {
            return;
        }
    }
    img.notes
        .push("Go binary: pclntab not parsed; Go function names unavailable".into());
}

/// `pkg.init` or `pkg.init.N` (not `pkg.init.func1` closures or methods).
fn is_go_init(name: &str) -> bool {
    let tail = name.rsplit('/').next().unwrap_or(name);
    let Some((_, rest)) = tail.split_once(".init") else {
        return false;
    };
    rest.is_empty()
        || rest
            .strip_prefix('.')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
}

/// `runtime.moduledata.text` of the moduledata whose first field points at
/// the pclntab header at `va`.
fn moduledata_text(img: &Image, va: u64, ptr: usize) -> Option<u64> {
    let needle: Vec<u8> = if ptr == 8 {
        va.to_le_bytes().to_vec()
    } else {
        (va as u32).to_le_bytes().to_vec()
    };
    for r in img.regions.iter().filter(|r| !r.exec) {
        let mut from = 0;
        while let Some(p) = memchr::memmem::find(&r.data[from..], &needle) {
            let at = r.va + (from + p) as u64;
            from += p + 1;
            if at % ptr as u64 != 0 {
                continue;
            }
            // pcHeader, 6 slices (3 words each), findfunctab, minpc, maxpc, text.
            if let Some(t) = img
                .read_ptr(at + 22 * ptr as u64)
                .filter(|t| img.is_exec(*t))
            {
                return Some(t);
            }
        }
    }
    None
}

fn parse_pclntab(img: &mut Image, va: u64, ptr: usize) -> bool {
    let Some(hdr) = img.read(va, 8 + 8 * ptr) else {
        return false;
    };
    if hdr.len() < 8 + 8 * ptr || hdr[4] != 0 || hdr[5] != 0 || hdr[7] as usize != ptr {
        return false;
    }
    let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if magic != 0xffff_fff1 && magic != 0xffff_fff0 {
        return false;
    }
    let word = |i: usize| -> u64 {
        let b = &hdr[8 + i * ptr..8 + (i + 1) * ptr];
        if ptr == 8 {
            u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
        } else {
            u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as u64
        }
    };
    let nfunc = word(0) as usize;
    let mut text_start = word(2);
    let (funcname_off, pcln_off) = (word(3), word(7));
    if nfunc == 0 || nfunc > MAX_SYMBOLS {
        return false;
    }
    // PIE: the header's textStart is filled in by a RELATIVE relocation.
    if let Some(v) = img.pointers.get(&va.wrapping_add(8 + 2 * ptr as u64)) {
        text_start = *v;
    }
    if text_start == 0 || !img.is_exec(text_start) {
        // Externally linked PIE: take `text` from the moduledata that points at this header.
        text_start = moduledata_text(img, va, ptr).unwrap_or(0);
    }
    if text_start == 0 || !img.is_exec(text_start) {
        match img
            .regions
            .iter()
            .find(|r| r.exec && (r.name == ".text" || r.name.ends_with(",__text")))
        {
            Some(r) => text_start = r.va,
            None => return false,
        }
    }
    let functab = va.wrapping_add(pcln_off);
    let Some(tab) = img.read(functab, (nfunc + 1) * 8) else {
        return false;
    };
    if tab.len() < nfunc * 8 {
        return false;
    }
    let u32le = |b: &[u8], o: usize| {
        b.get(o..o + 4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
    };
    let mut added = 0usize;
    for i in 0..nfunc {
        let (Some(entry_off), Some(func_off)) = (u32le(tab, i * 8), u32le(tab, i * 8 + 4)) else {
            break;
        };
        let entry = text_start.wrapping_add(entry_off as u64);
        let Some(fb) = img.read(functab.wrapping_add(func_off as u64), 8) else {
            continue;
        };
        let Some(name_off) = u32le(fb, 4) else {
            continue;
        };
        let Some(nb) = img.read(
            va.wrapping_add(funcname_off).wrapping_add(name_off as u64),
            256,
        ) else {
            continue;
        };
        let end = nb.iter().position(|&c| c == 0).unwrap_or(nb.len());
        let Ok(name) = std::str::from_utf8(&nb[..end]) else {
            continue;
        };
        if img.is_exec(entry) {
            img.add_name(entry, name);
            img.seeds.push(entry);
            if name == "main.main" {
                img.roots.push((entry, RootKind::Main));
            } else if is_go_init(name) {
                // Package initializers run before main.main (runtime.doInit).
                img.roots.push((entry, RootKind::Initializer));
            }
            added += 1;
        }
    }
    added > 0
}

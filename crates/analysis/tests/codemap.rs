//! Built-in code map: fixtures (gcc-built ELF, hand-assembled PE) and a
//! mutation loop. Fixture binaries are never executed.

use std::collections::HashMap;

use bytebouncer_analysis::code::{CodeMap, tools};
use bytebouncer_analysis::{AnalysisOutput, analyze_leaf_with_code};
use bytebouncer_core::{EvidenceKind, EvidenceStrength, Severity};
use serde_json::json;

const ELF64: &[u8] = include_bytes!("fixtures/telemetry-x86_64.elf");
const ELF64_STRIPPED: &[u8] = include_bytes!("fixtures/telemetry-x86_64-noplt-stripped.elf");
const ELF32: &[u8] = include_bytes!("fixtures/telemetry-i386.elf");
const URL: &str = "https://telemetry.example.com/v1/collect";

fn run(bytes: &[u8], path: &str) -> (AnalysisOutput, CodeMap) {
    let (out, map) = analyze_leaf_with_code(bytes, path, "0".repeat(64).as_str(), None);
    for f in &out.findings {
        for id in &f.evidence_ids {
            assert!(
                out.evidence.iter().any(|e| &e.id == id),
                "dangling evidence id {id}"
            );
        }
        assert!(
            f.evidence_ids.len() <= 12,
            "too much evidence on {}",
            f.title
        );
    }
    (out, map.expect("code map"))
}

fn finding<'a>(out: &'a AnalysisOutput, category: &str) -> &'a bytebouncer_core::Finding {
    out.findings
        .iter()
        .find(|f| {
            f.category == category
                && f.evidence_ids.iter().any(|id| {
                    out.evidence
                        .iter()
                        .any(|e| &e.id == id && e.producer.tool == "bytebouncer-codemap")
                })
        })
        .unwrap_or_else(|| {
            panic!(
                "no code-map finding in {category}: {:#?}",
                out.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
            )
        })
}

fn evidence_texts(
    out: &AnalysisOutput,
    f: &bytebouncer_core::Finding,
    kind: EvidenceKind,
) -> Vec<String> {
    f.evidence_ids
        .iter()
        .filter_map(|id| out.evidence.iter().find(|e| &e.id == id && e.kind == kind))
        .map(|e| e.snippet.clone().unwrap_or_default())
        .collect()
}

#[test]
fn elf64_with_symbols() {
    let (out, map) = run(ELF64, "telemetry");
    assert_eq!(map.arch, "x86-64");
    let upload = map
        .functions
        .iter()
        .find(|f| f.label == "upload")
        .expect("upload retained");
    assert!(upload.reachable);
    assert!(upload.apis.iter().any(|a| a == "send"), "{:?}", upload.apis);
    assert!(
        upload
            .strings
            .iter()
            .any(|s| s.text == URL && s.kind == "url")
    );
    assert!(
        upload
            .path_from_entry
            .iter()
            .any(|p| p.starts_with("collect_id@")),
        "{:?}",
        upload.path_from_entry
    );
    assert!(
        upload
            .asm
            .as_deref()
            .is_some_and(|t| t.contains("; send") && t.contains(URL)),
        "{:?}",
        upload.asm
    );

    let rec = finding(&out, "privacy.recipients");
    assert_eq!(rec.evidence_strength, EvidenceStrength::StaticReachability);
    assert_eq!(
        rec.recipient.as_ref().map(|r| r.domain.as_str()),
        Some("telemetry.example.com")
    );
    let paths = evidence_texts(&out, rec, EvidenceKind::CallPath);
    assert!(
        paths
            .iter()
            .any(|p| p.contains("main → collect_id → upload → send")
                || p.contains("collect_id → upload")),
        "{paths:?}"
    );
    assert!(evidence_texts(&out, rec, EvidenceKind::StringReference).contains(&URL.to_owned()));
    let ev = out
        .evidence
        .iter()
        .find(|e| {
            e.kind == EvidenceKind::StringReference && e.producer.tool == "bytebouncer-codemap"
        })
        .unwrap();
    assert!(
        ev.location
            .function
            .as_deref()
            .is_some_and(|f| f.starts_with("upload@"))
    );
    assert!(ev.location.address.is_some());

    let ids = finding(&out, "privacy.identifiers");
    assert_eq!(ids.severity, Severity::Medium);
    assert_eq!(ids.evidence_strength, EvidenceStrength::StaticReachability);
    assert_eq!(ids.data_types, vec!["hostname".to_owned()]);
    let paths = evidence_texts(&out, ids, EvidenceKind::CallPath);
    assert!(
        paths.iter().any(|p| p.ends_with("gethostname")),
        "{paths:?}"
    );
    assert!(paths.iter().any(|p| p.ends_with("send")), "{paths:?}");

    // Model tools.
    let maps = [map];
    let v = tools::call(&maps, "code_callers_of_api", &json!({"api": "send"})).unwrap();
    assert!(v["untrusted_sample_data"].is_string());
    assert!(
        v["result"]["apis"][0]["callers"][0]
            .as_str()
            .unwrap()
            .starts_with("upload@")
    );
    let v = tools::call(&maps, "code_call_path", &json!({"to_api": "send"})).unwrap();
    let p = v["result"]["paths"][0]["path"].as_str().unwrap();
    assert!(
        p.contains("main@") && p.contains("collect_id@") && p.ends_with("→ send"),
        "{p}"
    );
    let v = tools::call(
        &maps,
        "code_call_path",
        &json!({"to_api": "send", "from": "main"}),
    )
    .unwrap();
    assert!(
        v["result"]["paths"][0]["path"]
            .as_str()
            .unwrap()
            .contains("upload@")
    );
    let v = tools::call(
        &maps,
        "code_functions_referencing",
        &json!({"pattern": "telemetry.example"}),
    )
    .unwrap();
    assert_eq!(v["result"]["total"], 1);
    let v = tools::call(&maps, "code_get_function", &json!({"function": "upload"})).unwrap();
    assert!(
        v["result"]["disassembly"]["text"]
            .as_str()
            .unwrap()
            .contains("send")
    );
    let v = tools::call(
        &maps,
        "code_list_functions",
        &json!({"category": "identifiers", "reachable_only": true}),
    )
    .unwrap();
    assert!(
        v["result"]["functions"][0]["function"]
            .as_str()
            .unwrap()
            .starts_with("collect_id@")
    );
    let v = tools::call(&maps, "code_overview", &json!({})).unwrap();
    assert!(
        v["result"]["executables"][0]["stats"]["functions_discovered"]
            .as_u64()
            .unwrap()
            >= 5
    );
    let addr = format!(
        "{:#x}",
        maps[0]
            .functions
            .iter()
            .find(|f| f.label == "upload")
            .unwrap()
            .address
    );
    assert!(tools::call(&maps, "code_get_function", &json!({"function": addr})).is_ok());
    // Bad input is an error, never a panic.
    assert!(tools::call(&maps, "code_get_function", &json!({})).is_err());
    assert!(tools::call(&maps, "code_get_function", &json!({"function": 5})).is_err());
    assert!(tools::call(&maps, "code_list_functions", &json!({"limit": -1})).is_err());
    assert!(tools::call(&maps, "nope", &json!({})).is_err());
    assert!(tools::call(&maps, "code_overview", &json!([1])).is_err());
    assert!(tools::call(&[], "code_overview", &json!({})).is_err());
    assert!(
        tools::call(
            &maps,
            "code_overview",
            &json!({"artifact": "x".repeat(500)})
        )
        .is_err()
    );
    for (name, _, schema) in tools::tool_specs() {
        assert!(name.starts_with("code_"));
        assert_eq!(schema["type"], "object");
    }
}

#[test]
fn elf64_stripped_no_plt() {
    let (out, map) = run(ELF64_STRIPPED, "telemetry-stripped");
    // `call [rip+GOT]` resolves without PLT stubs or symbols.
    let send = map
        .apis
        .iter()
        .find(|a| a.name == "send")
        .expect("send resolved");
    assert!(send.reachable_callers >= 1);
    let rec = finding(&out, "privacy.recipients");
    assert_eq!(
        rec.evidence_strength,
        EvidenceStrength::StaticReachability,
        "{rec:#?}"
    );
    assert_eq!(
        finding(&out, "privacy.identifiers").severity,
        Severity::Medium
    );
}

#[test]
fn elf32_pic_plt() {
    let (out, map) = run(ELF32, "telemetry32");
    assert_eq!(map.arch, "x86");
    let upload = map
        .functions
        .iter()
        .find(|f| f.label == "upload")
        .expect("upload");
    assert!(upload.apis.iter().any(|a| a == "send"), "{:?}", upload.apis);
    assert!(
        upload.strings.iter().any(|s| s.text == URL),
        "{:?}",
        upload.strings
    );
    assert_eq!(
        finding(&out, "privacy.recipients").evidence_strength,
        EvidenceStrength::StaticReachability
    );
    assert_eq!(
        finding(&out, "privacy.identifiers").severity,
        Severity::Medium
    );
}

#[test]
fn pe64_and_pe32() {
    for bits in [64, 32] {
        let pe = build_pe(bits);
        let (out, map) = run(&pe, "agent.exe");
        assert_eq!(map.format, format!("pe-{bits}"));
        let rec = finding(&out, "privacy.recipients");
        assert_eq!(
            rec.evidence_strength,
            EvidenceStrength::StaticReachability,
            "pe{bits}"
        );
        assert_eq!(
            rec.recipient.as_ref().unwrap().domain,
            "telemetry.example.com"
        );
        let ids = finding(&out, "privacy.identifiers");
        assert_eq!(ids.severity, Severity::Medium);
        let paths = evidence_texts(&out, ids, EvidenceKind::CallPath);
        assert!(
            paths
                .iter()
                .any(|p| p.ends_with("KERNEL32.dll!GetComputerNameA")),
            "{paths:?}"
        );
        let per = finding(&out, "security.persistence");
        assert_eq!(per.severity, Severity::Medium);
        assert!(
            evidence_texts(&out, per, EvidenceKind::StringReference)[0]
                .contains("CurrentVersion\\Run")
        );
        // The import-only keyboard rule is upgraded in place, not duplicated.
        let kb: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.category == "privacy.sensitive_collection")
            .collect();
        assert_eq!(kb.len(), 1, "{kb:#?}");
        assert_eq!(
            kb[0].evidence_strength,
            EvidenceStrength::StaticReachability
        );
        assert!(
            !kb[0]
                .limitations
                .iter()
                .any(|l| l.starts_with("Import presence only"))
        );
        assert!(
            evidence_texts(&out, kb[0], EvidenceKind::CallPath)
                .iter()
                .any(|p| p.contains("SetWindowsHookExA"))
        );
        // `mov reg,[IAT]; call reg` and the unreachable sender.
        let send = map
            .apis
            .iter()
            .find(|a| a.name == "WS2_32.dll!send")
            .unwrap();
        assert_eq!(send.caller_count, 2);
        assert_eq!(send.reachable_callers, 1);
        let asm = map
            .functions
            .iter()
            .filter_map(|f| f.asm.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(asm.contains("; WS2_32.dll!send"), "{asm}");
        assert!(asm.contains(&format!("; \"{URL}\"")), "{asm}");
    }
}

#[test]
fn hostile_inputs_never_panic() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let inputs = [
        ELF64.to_vec(),
        ELF64_STRIPPED.to_vec(),
        ELF32.to_vec(),
        build_pe(64),
        build_pe(32),
    ];
    for base in &inputs {
        for round in 0..300 {
            let mut m = base.clone();
            match round % 4 {
                0 => m.truncate((rnd() as usize) % m.len()),
                1 => {
                    for _ in 0..1 + rnd() % 64 {
                        let i = (rnd() as usize) % m.len();
                        m[i] = rnd() as u8;
                    }
                }
                2 => {
                    // Corrupt header-ish regions harder.
                    for _ in 0..16 {
                        let i = (rnd() as usize) % m.len().min(1024);
                        m[i] = rnd() as u8;
                    }
                }
                _ => {
                    let i = (rnd() as usize) % m.len();
                    let n = ((rnd() as usize) % 4096).min(m.len() - i);
                    for b in &mut m[i..i + n] {
                        *b = 0xff;
                    }
                }
            }
            let (out, map) = analyze_leaf_with_code(&m, "mutant", "x", None);
            if let Some(map) = map {
                assert!(map.json_len() <= bytebouncer_analysis::code::MAX_CODE_MAP_BYTES);
                let _ = tools::call(&[map], "code_overview", &json!({}));
            }
            drop(out);
        }
    }
}

// ---------------------------------------------------------------------------
// Hand-assembled PE fixture: main → write_run_key (RegSetValueExA + Run key),
// main → collect_id (GetComputerNameA) → upload (connect, send + URL),
// main → hook (`mov reg,[IAT]; call reg` → SetWindowsHookExA), plus an
// unreferenced function that also calls send.

const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;

fn put(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
    if buf.len() < off + bytes.len() {
        buf.resize(off + bytes.len(), 0);
    }
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

struct Rdata {
    bytes: Vec<u8>,
    iat: HashMap<&'static str, u64>,
    strings: HashMap<&'static str, u64>,
    import_dir: (u32, u32),
}

fn build_rdata(base: u64, ps: usize) -> Rdata {
    let dlls: [(&str, &[&'static str]); 4] = [
        ("KERNEL32.dll", &["GetComputerNameA"]),
        ("WS2_32.dll", &["connect", "send"]),
        ("ADVAPI32.dll", &["RegSetValueExA"]),
        ("USER32.dll", &["SetWindowsHookExA"]),
    ];
    let texts: [&'static str; 3] = [
        URL,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "https://other.example.net/x",
    ];
    let mut b = Vec::new();
    let mut strings = HashMap::new();
    for t in texts {
        strings.insert(t, base + RDATA_RVA as u64 + b.len() as u64);
        b.extend_from_slice(t.as_bytes());
        b.push(0);
        while b.len() % 8 != 0 {
            b.push(0);
        }
    }
    let desc_off = b.len();
    let mut off = desc_off + 20 * (dlls.len() + 1);
    let mut iat = HashMap::new();
    let mut tables = vec![];
    for (_, names) in &dlls {
        let ilt = off;
        off += (names.len() + 1) * ps;
        let iat_off = off;
        off += (names.len() + 1) * ps;
        tables.push((ilt, iat_off));
    }
    let mut hint_names = vec![];
    for (dll, names) in &dlls {
        let mut hn = vec![];
        for n in names.iter() {
            hn.push(off);
            off += 2 + n.len() + 1;
            off += off % 2;
        }
        let dll_off = off;
        off += dll.len() + 1;
        hint_names.push((hn, dll_off));
    }
    b.resize(off, 0);
    let rva = |o: usize| RDATA_RVA + o as u32;
    for (i, (dll, names)) in dlls.iter().enumerate() {
        let (ilt, iat_off) = tables[i];
        let (hn, dll_off) = &hint_names[i];
        let d = desc_off + i * 20;
        put(&mut b, d, &rva(ilt).to_le_bytes());
        put(&mut b, d + 12, &rva(*dll_off).to_le_bytes());
        put(&mut b, d + 16, &rva(iat_off).to_le_bytes());
        put(&mut b, *dll_off, dll.as_bytes());
        for (j, n) in names.iter().enumerate() {
            put(&mut b, hn[j] + 2, n.as_bytes());
            let entry = rva(hn[j]) as u64;
            let bytes = entry.to_le_bytes();
            put(&mut b, ilt + j * ps, &bytes[..ps]);
            put(&mut b, iat_off + j * ps, &bytes[..ps]);
            iat.insert(*n, base + rva(iat_off + j * ps) as u64);
        }
    }
    Rdata {
        bytes: b,
        iat,
        strings,
        import_dir: (rva(desc_off), 20 * (dlls.len() as u32 + 1)),
    }
}

struct Asm {
    bits: u32,
    base: u64,
    code: Vec<u8>,
    labels: HashMap<&'static str, u64>,
    fixups: Vec<(usize, &'static str)>,
}

impl Asm {
    fn ip(&self) -> u64 {
        self.base + TEXT_RVA as u64 + self.code.len() as u64
    }
    fn label(&mut self, l: &'static str) {
        let ip = self.ip();
        self.labels.insert(l, ip);
    }
    fn raw(&mut self, b: &[u8]) {
        self.code.extend_from_slice(b);
    }
    fn call(&mut self, l: &'static str) {
        self.raw(&[0xe8]);
        self.fixups.push((self.code.len(), l));
        self.raw(&[0; 4]);
    }
    /// `[rip+disp]` (x64) or `[abs32]` (x86) operand ending the instruction.
    fn mem(&mut self, prefix: &[u8], target: u64) {
        self.raw(prefix);
        let v = if self.bits == 64 {
            (target as i64 - (self.ip() as i64 + 4)) as i32 as u32
        } else {
            target as u32
        };
        self.raw(&v.to_le_bytes());
    }
    fn call_iat(&mut self, slot: u64) {
        self.mem(&[0xff, 0x15], slot);
    }
    fn load_string(&mut self, s: u64) {
        if self.bits == 64 {
            self.mem(&[0x48, 0x8d, 0x15], s); // lea rdx, [rip+s]
        } else {
            self.raw(&[0x68]); // push s
            self.raw(&(s as u32).to_le_bytes());
        }
    }
    fn prologue(&mut self) {
        if self.bits == 64 {
            self.raw(&[0x48, 0x83, 0xec, 0x28])
        } else {
            self.raw(&[0x83, 0xec, 0x1c])
        }
    }
    fn epilogue(&mut self) {
        if self.bits == 64 {
            self.raw(&[0x48, 0x83, 0xc4, 0x28, 0xc3])
        } else {
            self.raw(&[0x83, 0xc4, 0x1c, 0xc3])
        }
        while self.code.len() % 16 != 0 {
            self.raw(&[0xcc]);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        for (pos, l) in std::mem::take(&mut self.fixups) {
            let target = self.labels[l];
            let next = self.base + TEXT_RVA as u64 + pos as u64 + 4;
            let rel = (target as i64 - next as i64) as i32;
            self.code[pos..pos + 4].copy_from_slice(&rel.to_le_bytes());
        }
        self.code
    }
}

fn build_pe(bits: u32) -> Vec<u8> {
    let base: u64 = if bits == 64 { 0x1_4000_0000 } else { 0x40_0000 };
    let ps = (bits / 8) as usize;
    let rd = build_rdata(base, ps);
    let mut a = Asm {
        bits,
        base,
        code: vec![],
        labels: HashMap::new(),
        fixups: vec![],
    };
    a.label("main");
    a.prologue();
    a.call("write_run_key");
    a.call("collect_id");
    a.call("hook");
    a.epilogue();
    a.label("collect_id");
    a.prologue();
    a.call_iat(rd.iat["GetComputerNameA"]);
    a.call("upload");
    a.epilogue();
    a.label("upload");
    a.prologue();
    a.call_iat(rd.iat["connect"]);
    a.load_string(rd.strings[URL]);
    a.call_iat(rd.iat["send"]);
    a.epilogue();
    a.label("write_run_key");
    a.prologue();
    a.load_string(rd.strings["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]);
    a.call_iat(rd.iat["RegSetValueExA"]);
    a.epilogue();
    a.label("hook");
    a.prologue();
    if bits == 64 {
        a.mem(&[0x48, 0x8b, 0x05], rd.iat["SetWindowsHookExA"]); // mov rax, [rip+slot]
    } else {
        a.mem(&[0xa1], rd.iat["SetWindowsHookExA"]); // mov eax, [slot]
    }
    a.raw(&[0xff, 0xd0]); // call rax / eax
    a.epilogue();
    a.label("orphan");
    a.prologue();
    a.load_string(rd.strings["https://other.example.net/x"]);
    a.call_iat(rd.iat["send"]);
    a.epilogue();
    let text = a.finish();
    assert!(text.len() <= 0x200 && rd.bytes.len() <= 0x400);

    let mut f = vec![0u8; 0x800];
    put(&mut f, 0, b"MZ");
    put(&mut f, 0x3c, &0x40u32.to_le_bytes());
    put(&mut f, 0x40, b"PE\0\0");
    let opt_size: u16 = if bits == 64 { 240 } else { 224 };
    let coff = 0x44;
    put(
        &mut f,
        coff,
        &(if bits == 64 { 0x8664u16 } else { 0x14c }).to_le_bytes(),
    );
    put(&mut f, coff + 2, &2u16.to_le_bytes());
    put(&mut f, coff + 16, &opt_size.to_le_bytes());
    put(
        &mut f,
        coff + 18,
        &(if bits == 64 { 0x22u16 } else { 0x102 }).to_le_bytes(),
    );
    let o = coff + 20;
    put(
        &mut f,
        o,
        &(if bits == 64 { 0x20bu16 } else { 0x10b }).to_le_bytes(),
    );
    put(&mut f, o + 4, &0x200u32.to_le_bytes()); // SizeOfCode
    put(&mut f, o + 16, &TEXT_RVA.to_le_bytes()); // AddressOfEntryPoint (main)
    put(&mut f, o + 20, &TEXT_RVA.to_le_bytes()); // BaseOfCode
    let w = if bits == 64 {
        put(&mut f, o + 24, &base.to_le_bytes());
        o + 32
    } else {
        put(&mut f, o + 24, &RDATA_RVA.to_le_bytes()); // BaseOfData
        put(&mut f, o + 28, &(base as u32).to_le_bytes());
        o + 32
    };
    put(&mut f, w, &0x1000u32.to_le_bytes()); // SectionAlignment
    put(&mut f, w + 4, &0x200u32.to_le_bytes()); // FileAlignment
    put(&mut f, w + 8, &6u16.to_le_bytes()); // OS major
    put(&mut f, w + 16, &6u16.to_le_bytes()); // Subsystem major
    put(&mut f, w + 24, &0x3000u32.to_le_bytes()); // SizeOfImage
    put(&mut f, w + 28, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(&mut f, w + 36, &3u16.to_le_bytes()); // Subsystem: console
    let (sizes, n_off) = if bits == 64 {
        (w + 40, w + 40 + 32 + 4)
    } else {
        (w + 40, w + 40 + 16 + 4)
    };
    let _ = sizes;
    put(&mut f, n_off, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let dirs = n_off + 4;
    put(&mut f, dirs + 8, &rd.import_dir.0.to_le_bytes());
    put(&mut f, dirs + 12, &rd.import_dir.1.to_le_bytes());
    assert_eq!(dirs + 128, o + opt_size as usize);
    let sec = o + opt_size as usize;
    let section =
        |f: &mut Vec<u8>, at: usize, name: &[u8], rva: u32, raw: u32, size: u32, ch: u32| {
            put(f, at, name);
            put(f, at + 8, &size.to_le_bytes());
            put(f, at + 12, &rva.to_le_bytes());
            put(f, at + 16, &size.to_le_bytes());
            put(f, at + 20, &raw.to_le_bytes());
            put(f, at + 36, &ch.to_le_bytes());
        };
    section(
        &mut f,
        sec,
        b".text\0\0\0",
        TEXT_RVA,
        0x200,
        0x200,
        0x6000_0020,
    );
    section(
        &mut f,
        sec + 40,
        b".rdata\0\0",
        RDATA_RVA,
        0x400,
        0x400,
        0x4000_0040,
    );
    put(&mut f, 0x200, &text);
    put(&mut f, 0x400, &rd.bytes);
    f
}

#[test]
fn artifact_analysis_retains_code_maps() {
    let a = bytebouncer_analysis::analyze_artifact(ELF64, "telemetry", &"1".repeat(64), None);
    assert_eq!(a.code.len(), 1);
    assert_eq!(a.code[0].artifact_path, "telemetry");
    assert_eq!(a.code[0].sha256, "1".repeat(64));
    let json = serde_json::to_string(&a).unwrap();
    let back: bytebouncer_analysis::ArtifactAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(back.code, a.code);
    // Older cached analyses without the field still load.
    let old: bytebouncer_analysis::ArtifactAnalysis =
        serde_json::from_str(r#"{"artifacts":[],"outputs":[]}"#).unwrap();
    assert!(old.code.is_empty());
    // Non-executables produce no map.
    assert!(
        bytebouncer_analysis::analyze_artifact(b"#!/bin/sh\necho hi\n", "x.sh", "2", None)
            .code
            .is_empty()
    );
    // Shrinking keeps the most relevant functions.
    let mut m = a.code[0].clone();
    assert!(m.shrink_to(m.json_len() / 2));
    assert!(m.json_len() <= a.code[0].json_len() / 2);
}

//! Live tests that run real, locally installed tools inside the sandbox.
//! Ignored by default; run with e.g.
//!
//! ```sh
//! BYTEBOUNCER_TEST_CAPA=/path/to/capa \
//! BYTEBOUNCER_TEST_CLAMSCAN=/path/to/clamscan \
//! BYTEBOUNCER_TEST_GHIDRA_DIR=/path/to/ghidra_12.1.4_PUBLIC \
//! BYTEBOUNCER_TEST_JAVA_HOME=/path/to/jdk-21 \
//! cargo test -p bytebouncer-deep --test live -- --ignored --nocapture
//! ```
//!
//! `BYTEBOUNCER_TEST_CLAMAV_DB` is optional: without it the ClamAV test
//! writes a one-signature database matching the EICAR test string.
//! Inputs are benign: a small C program compiled here, or /usr/bin/curl.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use bytebouncer_core::{EvidenceKind, EvidenceStrength};
use bytebouncer_deep::{DeepConfig, DeepInput, DeepResult, discover, run_deep};

const NET_C: &str = r#"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

static const char *ENDPOINT = "https://telemetry.example.invalid/v1/collect";

static int send_report(const char *host, const char *payload) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) return -1;
    if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) send(fd, payload, strlen(payload), 0);
    close(fd);
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv) {
    char msg[512];
    snprintf(msg, sizeof msg, "POST %s argc=%d", ENDPOINT, argc);
    if (argc > 1) send_report("telemetry.example.invalid", msg);
    puts("hello");
    return 0;
}
"#;

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn workdir(name: &str) -> bytebouncer_sandbox::testutil::TempDir {
    bytebouncer_sandbox::testutil::temp_dir("bb-deep-live", name)
}

/// Compile the network sample; `None` if no C compiler is available.
fn compile_sample(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("net.c");
    let bin = dir.join("net");
    std::fs::write(&src, NET_C).unwrap();
    let ok = Command::new("cc")
        .arg("-O0")
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .status()
        .ok()?
        .success();
    ok.then_some(bin)
}

fn base_config() -> DeepConfig {
    DeepConfig {
        // Never pick up tools other than the ones under test.
        capa: Some(PathBuf::from("/nonexistent")),
        clamscan: Some(PathBuf::from("/nonexistent")),
        ghidra_dir: Some(PathBuf::from("/nonexistent")),
        timeout_per_tool: Duration::from_secs(600),
        ..Default::default()
    }
}

fn run(cfg: &DeepConfig, input: &Path, format: &str, name: &str) -> DeepResult {
    let tools = discover(cfg);
    eprintln!("discovered: {tools:#?}");
    let scratch = workdir(&format!("{name}-scratch"));
    let display = input.display().to_string();
    let deep_input = DeepInput {
        path: input,
        display_path: &display,
        sha256: "0".repeat(64).leak(),
        format,
    };
    let t = Instant::now();
    let r = run_deep(&tools, &deep_input, &scratch, cfg, &AtomicBool::new(false));
    eprintln!("{name}: run_deep took {:.1}s", t.elapsed().as_secs_f64());
    eprintln!("timings: {:?}", r.timings);
    eprintln!("isolation: {:#?}", r.isolation);
    eprintln!("tools: {:?}", r.tools);
    eprintln!("coverage: {:#?}", r.output.coverage);
    for f in &r.output.findings {
        eprintln!(
            "finding: [{:?}/{:?}] {} — {}",
            f.severity, f.evidence_strength, f.category, f.title
        );
    }
    // Only the scratch directory may have been written.
    let _ = std::fs::remove_dir_all(&scratch);
    r
}

fn assert_fully_isolated(r: &DeepResult, tool: &str) {
    let (_, applied) = r
        .isolation
        .iter()
        .find(|(t, _)| t == tool)
        .expect("tool ran");
    for need in [
        "rlimits",
        "netns",
        "landlock_fs",
        "landlock_net",
        "seccomp_denylist",
    ] {
        assert!(
            applied.active.iter().any(|a| a == need),
            "{tool}: {need} not active: {applied:?}"
        );
    }
    assert!(applied.missing.is_empty(), "{tool}: missing {applied:?}");
}

#[test]
#[ignore = "needs capa (BYTEBOUNCER_TEST_CAPA)"]
fn capa_live() {
    let Some(capa) = env_path("BYTEBOUNCER_TEST_CAPA") else {
        return;
    };
    let cfg = DeepConfig {
        capa: Some(capa),
        ..base_config()
    };
    let r = run(&cfg, Path::new("/usr/bin/curl"), "elf-64", "capa-curl");
    assert_fully_isolated(&r, "capa");
    assert!(
        r.output
            .coverage
            .analyzed
            .iter()
            .any(|a| a.contains("capa")),
        "{:?}",
        r.output.coverage
    );
    assert!(!r.output.findings.is_empty());
    assert!(
        r.output
            .findings
            .iter()
            .all(|f| f.evidence_strength == EvidenceStrength::PatternMatch)
    );
    assert!(!r.retained.capa_rules.is_empty());
    assert!(
        r.tools
            .iter()
            .any(|t| t.name == "capa" && t.version.contains("rules"))
    );

    // Unsupported input: a failure is a limitation, not a clean result.
    let dir = workdir("capa-text");
    let txt = dir.join("notes.txt");
    std::fs::write(&txt, "just text\n").unwrap();
    let r = run(&cfg, &txt, "pe-32", "capa-text");
    assert!(r.output.findings.is_empty());
    assert!(
        r.output
            .coverage
            .limitations
            .iter()
            .any(|l| l.starts_with("capa failed")),
        "{:?}",
        r.output.coverage
    );
}

#[test]
#[ignore = "needs clamscan (BYTEBOUNCER_TEST_CLAMSCAN)"]
fn clamav_live() {
    let Some(clamscan) = env_path("BYTEBOUNCER_TEST_CLAMSCAN") else {
        return;
    };
    let dir = workdir("clam");
    let db = env_path("BYTEBOUNCER_TEST_CLAMAV_DB").unwrap_or_else(|| {
        let db = dir.join("db");
        std::fs::create_dir_all(&db).unwrap();
        let hex: String = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(
            db.join("bytebouncer-test.ndb"),
            format!("ByteBouncer.Test.EICAR:0:*:{hex}\n"),
        )
        .unwrap();
        db
    });
    let eicar = dir.join("eicar.com");
    std::fs::write(
        &eicar,
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let cfg = DeepConfig {
        clamscan: Some(clamscan),
        clamav_db: Some(db),
        ..base_config()
    };

    let r = run(&cfg, &eicar, "unknown", "clam-eicar");
    assert_fully_isolated(&r, "ClamAV");
    let f = r
        .output
        .findings
        .iter()
        .find(|f| f.category == "security.signature_match")
        .expect("detection");
    assert!(f.title.contains("EICAR"));
    let ev = r
        .output
        .evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::Signature)
        .unwrap();
    assert!(ev.producer.rule_id.as_deref().unwrap().contains("EICAR"));

    let r = run(&cfg, Path::new("/usr/bin/true"), "elf-64", "clam-clean");
    assert!(r.output.findings.is_empty());
    assert!(
        r.output
            .coverage
            .analyzed
            .iter()
            .any(|a| a.contains("no signature matched")),
        "{:?}",
        r.output.coverage
    );
}

#[test]
#[ignore = "needs Ghidra + JDK (BYTEBOUNCER_TEST_GHIDRA_DIR, optional BYTEBOUNCER_TEST_JAVA_HOME)"]
fn ghidra_live() {
    let Some(ghidra) = env_path("BYTEBOUNCER_TEST_GHIDRA_DIR") else {
        return;
    };
    let dir = workdir("ghidra");
    let Some(sample) = compile_sample(&dir) else {
        eprintln!("no C compiler; skipping");
        return;
    };
    let cfg = DeepConfig {
        ghidra_dir: Some(ghidra),
        java_home: env_path("BYTEBOUNCER_TEST_JAVA_HOME"),
        ..base_config()
    };
    let home_cfg = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/ghidra"));
    let before = home_cfg.as_ref().map(|p| p.exists());

    let r = run(&cfg, &sample, "elf-64", "ghidra-net");
    assert_fully_isolated(&r, "Ghidra");
    let rec = r
        .output
        .findings
        .iter()
        .find(|f| f.category == "privacy.recipients")
        .expect("recipient finding");
    assert_eq!(
        rec.recipient.as_ref().unwrap().domain,
        "telemetry.example.invalid"
    );
    assert_eq!(rec.evidence_strength, EvidenceStrength::StaticReachability);
    let net = r
        .output
        .findings
        .iter()
        .find(|f| f.title.starts_with("Calls network APIs"))
        .unwrap();
    assert_eq!(net.evidence_strength, EvidenceStrength::StaticReachability);
    assert!(
        r.output
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::CallPath)
    );
    assert!(
        r.output
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::DecompiledFunction)
    );
    let v = r
        .retained
        .call("callers_of", &serde_json::json!({"api": "connect"}))
        .unwrap();
    assert_eq!(
        v["result"]["callers"][0]
            .as_str()
            .unwrap()
            .split('@')
            .next(),
        Some("send_report")
    );
    // Ghidra's user settings went to the scratch HOME, not the real one.
    assert_eq!(home_cfg.as_ref().map(|p| p.exists()), before);

    // Stripped: main has no symbol; it is found via the entry stub.
    let stripped = dir.join("net-stripped");
    let ok = Command::new("strip")
        .arg("-o")
        .arg(&stripped)
        .arg(&sample)
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        let r = run(&cfg, &stripped, "elf-64", "ghidra-stripped");
        let net = r
            .output
            .findings
            .iter()
            .find(|f| f.title.starts_with("Calls network APIs"))
            .unwrap();
        assert_eq!(net.evidence_strength, EvidenceStrength::StaticReachability);
    }
}

#[test]
#[ignore = "needs Ghidra + JDK; slow"]
fn ghidra_live_curl() {
    let Some(ghidra) = env_path("BYTEBOUNCER_TEST_GHIDRA_DIR") else {
        return;
    };
    let cfg = DeepConfig {
        ghidra_dir: Some(ghidra),
        java_home: env_path("BYTEBOUNCER_TEST_JAVA_HOME"),
        ..base_config()
    };
    let r = run(&cfg, Path::new("/usr/bin/curl"), "elf-64", "ghidra-curl");
    assert_fully_isolated(&r, "Ghidra");
    assert!(
        r.output
            .coverage
            .analyzed
            .iter()
            .any(|a| a.contains("Ghidra")),
        "{:?}",
        r.output.coverage
    );
    assert!(r.retained.program.is_some());
}

#[test]
#[ignore = "needs a tool; checks timeout handling"]
fn ghidra_timeout_is_limitation() {
    let Some(ghidra) = env_path("BYTEBOUNCER_TEST_GHIDRA_DIR") else {
        return;
    };
    let cfg = DeepConfig {
        ghidra_dir: Some(ghidra),
        java_home: env_path("BYTEBOUNCER_TEST_JAVA_HOME"),
        timeout_per_tool: Duration::from_secs(2),
        ..base_config()
    };
    let t = Instant::now();
    let r = run(&cfg, Path::new("/usr/bin/curl"), "elf-64", "ghidra-timeout");
    assert!(
        t.elapsed() < Duration::from_secs(120),
        "timeout not enforced"
    );
    assert!(r.output.findings.is_empty());
    assert!(
        r.output
            .coverage
            .limitations
            .iter()
            .any(|l| l.contains("timed out")),
        "{:?}",
        r.output.coverage
    );
}

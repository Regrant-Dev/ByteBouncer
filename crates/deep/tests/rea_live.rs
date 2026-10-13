//! Live REA test: `BYTEBOUNCER_TEST_REA_COMMAND="rea mcp"` (space-separated),
//! with GHIDRA_INSTALL_DIR/JAVA_HOME in the environment, and
//! `BYTEBOUNCER_TEST_REA_SAMPLE` pointing at a small x86-64 executable.

use std::time::Duration;

use bytebouncer_deep::out::Builder;
use bytebouncer_deep::rea::{ReaConfig, ReaSession};

#[test]
#[ignore = "needs a REA MCP server (BYTEBOUNCER_TEST_REA_COMMAND)"]
fn rea_session_collects_evidence_and_records_model_calls() {
    let cmd = std::env::var("BYTEBOUNCER_TEST_REA_COMMAND").expect("command");
    let sample =
        std::path::PathBuf::from(std::env::var("BYTEBOUNCER_TEST_REA_SAMPLE").expect("sample"));
    let bytes = std::fs::read(&sample).unwrap();
    let sha = sha256_hex(&bytes);
    let mut words = cmd.split_whitespace().map(str::to_owned);
    let cfg = ReaConfig {
        program: words.next().unwrap().into(),
        args: words.collect(),
        env: std::env::vars_os().collect(),
        sandbox: None,
        staging_dir: None,
        open_timeout: Duration::from_secs(900),
        call_timeout: Duration::from_secs(300),
        allow_reduced: true,
        label: "test".into(),
    };
    let mut b = Builder::new(&sha, "sample", "elf-64");
    let (session, _) = ReaSession::open(cfg, &sample, "sample", &sha, &mut b).expect("open");
    assert!(
        b.out
            .coverage
            .analyzed
            .iter()
            .any(|c| c.contains("REA/Ghidra"))
    );
    let specs = session.tool_specs();
    assert!(specs.iter().all(|(n, _, _)| n.starts_with("rea_")));
    assert!(
        !specs
            .iter()
            .any(|(n, _, _)| n.contains("frida") || n.contains("adb") || n.contains("set_"))
    );
    let r = session
        .model_call("rea_binary_overview", &serde_json::json!({}))
        .expect("call");
    assert!(
        r["bytebouncer_evidence_id"]
            .as_str()
            .unwrap()
            .starts_with("evidence-rea-")
    );
    assert_eq!(session.drain_new_evidence().len(), 1);
    assert!(
        session
            .model_call("rea_start_frida_session", &serde_json::json!({}))
            .is_err()
    );
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(data);
    digest.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

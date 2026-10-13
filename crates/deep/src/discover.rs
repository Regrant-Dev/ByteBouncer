//! Locating locally installed analysis tools. Nothing is installed or
//! downloaded: a tool that is not found is skipped and reported.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use bytebouncer_sandbox::Profile;

use crate::DeepConfig;
use crate::runner::{self, RunSpec, Status};

/// One executable tool, with what the sandbox must grant for it to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInstall {
    pub path: PathBuf,
    pub version: Option<String>,
    /// Directories granted read+execute (the tool's installation prefix).
    pub grant_dirs: Vec<PathBuf>,
    /// Extra environment the tool needs (e.g. for relocated installs).
    pub env: Vec<(OsString, OsString)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamDb {
    pub dir: PathBuf,
    /// Human-readable database version/date, e.g. `daily 27400 (07 Oct 2024 08-36 +0000)`.
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraInstall {
    /// Installation directory containing `support/analyzeHeadless`.
    pub dir: PathBuf,
    pub version: Option<String>,
    /// A JDK (Ghidra compiles the export script at runtime, so a JRE is not enough).
    pub java_home: Option<PathBuf>,
}

impl GhidraInstall {
    pub fn headless(&self) -> PathBuf {
        self.dir.join("support").join("analyzeHeadless")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveredTools {
    pub capa: Option<ToolInstall>,
    pub clamscan: Option<ToolInstall>,
    pub clamav_db: Option<ClamDb>,
    pub ghidra: Option<GhidraInstall>,
    /// Why tools were not found or not usable; shown in coverage.
    pub notes: Vec<String>,
}

const VERSION_TIMEOUT: Duration = Duration::from_secs(60);

pub fn discover(cfg: &DeepConfig) -> DiscoveredTools {
    let mut found = DiscoveredTools::default();
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let home = std::env::var_os("HOME").map(PathBuf::from);

    // capa
    let capa_candidates = home
        .iter()
        .map(|h| h.join(".local/bin/capa"))
        .chain(["/usr/local/bin/capa", "/opt/capa/capa"].map(PathBuf::from));
    match locate(cfg.capa.as_deref(), "capa", &path_dirs, capa_candidates) {
        Ok(Some(path)) => {
            let mut tool = install(&path, home.as_deref());
            tool.version = query_version(&tool, &["--version"], &[], cfg)
                .map_err(|e| found.notes.push(format!("capa: version query failed: {e}")))
                .ok()
                .and_then(|out| parse_capa_version(&out));
            found.capa = Some(tool);
        }
        Ok(None) => found
            .notes
            .push("capa: not installed (not on PATH or in common locations)".into()),
        Err(e) => found.notes.push(format!("capa: {e}")),
    }

    // ClamAV database first: the version query reads it.
    let db_candidates = [
        "/var/lib/clamav",
        "/usr/local/share/clamav",
        "/usr/share/clamav",
        "/var/db/clamav",
        "/opt/homebrew/var/lib/clamav",
        "/usr/local/var/lib/clamav",
    ]
    .map(PathBuf::from);
    let db_dir = match &cfg.clamav_db {
        Some(d) => Some(d.clone()),
        None => db_candidates.into_iter().find(|d| has_clam_db(d)),
    };
    if let Some(dir) = db_dir {
        if has_clam_db(&dir) {
            let version = clam_db_version(&dir);
            found.clamav_db = Some(ClamDb { dir, version });
        } else {
            found.notes.push(format!(
                "ClamAV: {} contains no signature database files",
                dir.display()
            ));
        }
    }

    let clam_candidates = [
        "/usr/local/bin/clamscan",
        "/opt/homebrew/bin/clamscan",
        "/opt/clamav/bin/clamscan",
    ]
    .map(PathBuf::from);
    match locate(
        cfg.clamscan.as_deref(),
        "clamscan",
        &path_dirs,
        clam_candidates.into_iter(),
    ) {
        Ok(Some(path)) => {
            let mut tool = install(&path, home.as_deref());
            relocated_clamav_env(&mut tool);
            let db: Vec<PathBuf> = found.clamav_db.iter().map(|d| d.dir.clone()).collect();
            tool.version = query_version(&tool, &["--version"], &db, cfg)
                .map_err(|e| {
                    found
                        .notes
                        .push(format!("ClamAV: version query failed: {e}"))
                })
                .ok()
                .and_then(|out| parse_clamscan_version(&out).map(|(v, _)| v));
            found.clamscan = Some(tool);
            if found.clamav_db.is_none() {
                found.notes.push(
                    "ClamAV: clamscan found but no signature database (run freshclam yourself)"
                        .into(),
                );
            }
        }
        Ok(None) => found.notes.push("ClamAV: clamscan not installed".into()),
        Err(e) => found.notes.push(format!("ClamAV: {e}")),
    }

    // Ghidra
    match locate_ghidra(cfg, home.as_deref()) {
        Ok(Some(dir)) => {
            let version = ghidra_version(&dir);
            let java_home = cfg
                .java_home
                .clone()
                .or_else(|| find_jdk(&dir, version.as_deref(), home.as_deref(), &path_dirs));
            if java_home.is_none() {
                found.notes.push(
                    "Ghidra: found, but no JDK (with javac) was located; set JAVA_HOME to a JDK to enable it".into(),
                );
            }
            found.ghidra = Some(GhidraInstall {
                dir,
                version,
                java_home,
            });
        }
        Ok(None) => found
            .notes
            .push("Ghidra: not installed (set GHIDRA_INSTALL_DIR or pass its directory)".into()),
        Err(e) => found.notes.push(format!("Ghidra: {e}")),
    }
    found
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// An explicit override must exist; otherwise search PATH then candidates.
fn locate(
    explicit: Option<&Path>,
    name: &str,
    path_dirs: &[PathBuf],
    candidates: impl Iterator<Item = PathBuf>,
) -> Result<Option<PathBuf>, String> {
    if let Some(p) = explicit {
        return if is_executable(p) {
            Ok(Some(p.to_path_buf()))
        } else {
            Err(format!(
                "configured path {} is not an executable file",
                p.display()
            ))
        };
    }
    Ok(path_dirs
        .iter()
        .map(|d| d.join(name))
        .chain(candidates)
        .find(|p| is_executable(p)))
}

/// Resolve symlinks and pick the directories to grant: the installation
/// prefix (parent of `bin/`) when that is a dedicated directory, else just
/// the binary's own directory. Never grants `/` or the home directory itself.
fn install(path: &Path, home: Option<&Path>) -> ToolInstall {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = real.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut grant = dir.clone();
    if dir.file_name().is_some_and(|n| n == "bin") {
        if let Some(prefix) = dir
            .parent()
            .filter(|p| *p != Path::new("/") && Some(*p) != home)
        {
            grant = prefix.to_path_buf();
        }
    }
    let mut grant_dirs = vec![grant];
    // Script launchers (pip/pipx installs) need their interpreter's prefix.
    if let Some(interp) = shebang_interpreter(&real) {
        let interp = std::fs::canonicalize(&interp).unwrap_or(interp);
        let prefix = interp.parent().and_then(Path::parent);
        if let Some(d) = prefix.filter(|d| *d != Path::new("/") && Some(*d) != home) {
            if !grant_dirs.iter().any(|g| d.starts_with(g)) {
                grant_dirs.push(d.to_path_buf());
            }
        }
    }
    ToolInstall {
        path: real,
        version: None,
        grant_dirs,
        env: Vec::new(),
    }
}

fn shebang_interpreter(path: &Path) -> Option<PathBuf> {
    use std::io::Read;
    let mut buf = [0u8; 256];
    let n = std::fs::File::open(path).ok()?.read(&mut buf).ok()?;
    let head = std::str::from_utf8(&buf[..n]).ok()?;
    let line = head.strip_prefix("#!")?.lines().next()?.trim();
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    // `#!/usr/bin/env python3` → resolve via PATH-independent common dirs.
    if first.ends_with("/env") {
        let name = parts.next()?;
        return ["/usr/bin", "/usr/local/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(name))
            .find(|p| p.exists());
    }
    Some(PathBuf::from(first))
}

/// Relocated ClamAV installs (e.g. extracted under /opt) need their own
/// libraries and certificate directory.
fn relocated_clamav_env(tool: &mut ToolInstall) {
    let Some(prefix) = tool.path.parent().and_then(Path::parent) else {
        return;
    };
    if prefix == Path::new("/usr") || prefix == Path::new("/usr/local") {
        return;
    }
    let lib = prefix.join("lib");
    let has_lib = std::fs::read_dir(&lib)
        .map(|rd| {
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("libclamav.so"))
        })
        .unwrap_or(false);
    if has_lib {
        tool.env
            .push(("LD_LIBRARY_PATH".into(), lib.into_os_string()));
    }
    // An extracted distro package keeps /etc next to /usr.
    let sibling_etc = prefix.parent().map(|p| p.join("etc/clamav/certs"));
    let candidates = [
        Some(prefix.join("etc/clamav/certs")),
        Some(prefix.join("share/clamav/certs")),
        sibling_etc,
    ];
    if Path::new("/etc/clamav/certs").is_dir() {
        return;
    }
    if let Some(certs) = candidates.into_iter().flatten().find(|c| c.is_dir()) {
        if !tool.grant_dirs.iter().any(|g| certs.starts_with(g)) {
            tool.grant_dirs.push(certs.clone());
        }
        tool.env
            .push(("CVD_CERTS_DIR".into(), certs.into_os_string()));
    }
}

/// Run `<tool> <args>` sandboxed in a throwaway scratch directory.
fn query_version(
    tool: &ToolInstall,
    args: &[&str],
    inputs: &[PathBuf],
    cfg: &DeepConfig,
) -> Result<String, String> {
    let scratch = std::env::temp_dir().join(format!(
        "bytebouncer-deep-version-{}-{}",
        std::process::id(),
        tool.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let mut profile =
        Profile::external_tool(tool.grant_dirs.clone(), inputs.to_vec(), scratch.clone());
    profile.env.extend(scratch_env(&scratch));
    profile.env.extend(tool.env.iter().cloned());
    let result = runner::run(
        RunSpec {
            program: &tool.path,
            args: args.iter().map(OsString::from).collect(),
            profile,
            cwd: Some(scratch.clone()),
            timeout: VERSION_TIMEOUT,
            stdout_cap: 64 << 10,
            stderr_cap: 64 << 10,
            allow_reduced: cfg.allow_reduced_isolation,
        },
        &AtomicBool::new(false),
    );
    let _ = std::fs::remove_dir_all(&scratch);
    let out = result.map_err(|e| e.to_string())?;
    match out.status {
        Status::Exited(0) => Ok(format!("{}{}", out.stdout_text(), out.stderr_text())),
        other => Err(format!("{other:?}: {}", out.stderr_tail())),
    }
}

/// HOME/TMPDIR/XDG dirs inside the scratch directory, so tools never read
/// or write the user's real configuration.
pub(crate) fn scratch_env(scratch: &Path) -> Vec<(OsString, OsString)> {
    let home = scratch.join("home");
    let tmp = scratch.join("tmp");
    let _ = std::fs::create_dir_all(&home);
    let _ = std::fs::create_dir_all(&tmp);
    vec![
        ("HOME".into(), home.clone().into_os_string()),
        ("TMPDIR".into(), tmp.into_os_string()),
        (
            "XDG_CONFIG_HOME".into(),
            home.join(".config").into_os_string(),
        ),
        (
            "XDG_CACHE_HOME".into(),
            home.join(".cache").into_os_string(),
        ),
        (
            "XDG_DATA_HOME".into(),
            home.join(".local/share").into_os_string(),
        ),
    ]
}

pub fn parse_capa_version(text: &str) -> Option<String> {
    text.split_whitespace()
        .skip_while(|w| !w.eq_ignore_ascii_case("capa"))
        .nth(1)
        .map(|v| v.trim_start_matches('v').to_owned())
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
}

/// `ClamAV 1.4.1/27400/Mon Oct  7 08:36:00 2024` → ("1.4.1", Some("27400 (Mon Oct  7 08:36:00 2024)")).
pub fn parse_clamscan_version(text: &str) -> Option<(String, Option<String>)> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("ClamAV "))?;
    let rest = line.trim_start().strip_prefix("ClamAV ")?.trim();
    let mut parts = rest.splitn(3, '/');
    let engine = parts.next()?.trim().to_owned();
    let db = match (parts.next(), parts.next()) {
        (Some(v), Some(date)) => Some(format!("daily {} ({})", v.trim(), date.trim())),
        (Some(v), None) => Some(format!("daily {}", v.trim())),
        _ => None,
    };
    Some((engine, db))
}

const CLAM_DB_EXTS: &[&str] = &[
    "cvd", "cld", "cud", "ndb", "hdb", "hsb", "mdb", "msb", "ldb", "ndu", "ldu", "cdb", "ign2",
    "yar", "yara", "fp", "sfp",
];

fn clam_db_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| CLAM_DB_EXTS.contains(&e))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn has_clam_db(dir: &Path) -> bool {
    !clam_db_files(dir).is_empty()
}

/// Version from CVD/CLD headers (`ClamAV-VDB:<date>:<version>:...`), else a
/// description of a custom database with its newest modification date.
pub fn clam_db_version(dir: &Path) -> String {
    use std::io::Read;
    let files = clam_db_files(dir);
    let mut parts = Vec::new();
    for f in &files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "cvd" | "cld" | "cud") {
            continue;
        }
        let mut header = [0u8; 512];
        let Ok(n) = std::fs::File::open(f).and_then(|mut h| h.read(&mut header)) else {
            continue;
        };
        if let Some((date, version)) = parse_cvd_header(&header[..n]) {
            let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
            parts.push(format!("{stem} {version} ({date})"));
        }
    }
    if !parts.is_empty() {
        return parts.join(", ");
    }
    let newest = files
        .iter()
        .filter_map(|f| f.metadata().ok()?.modified().ok())
        .max()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| civil_date(d.as_secs() / 86_400))
        .unwrap_or_else(|| "unknown".into());
    format!(
        "custom database ({} file(s), newest modified {newest})",
        files.len()
    )
}

pub fn parse_cvd_header(header: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(header.split(|&b| b == 0).next()?).ok()?;
    let mut fields = text.strip_prefix("ClamAV-VDB:")?.split(':');
    let date = fields.next()?.trim().to_owned();
    let version = fields.next()?.trim().to_owned();
    version.parse::<u64>().ok()?;
    Some((date, version))
}

/// Days since 1970-01-01 → `YYYY-MM-DD` (proleptic Gregorian).
fn civil_date(days: u64) -> String {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn is_ghidra_dir(dir: &Path) -> bool {
    dir.join("support").join("analyzeHeadless").is_file()
}

fn locate_ghidra(cfg: &DeepConfig, home: Option<&Path>) -> Result<Option<PathBuf>, String> {
    if let Some(d) = &cfg.ghidra_dir {
        return if is_ghidra_dir(d) {
            Ok(Some(d.clone()))
        } else {
            Err(format!(
                "configured directory {} has no support/analyzeHeadless",
                d.display()
            ))
        };
    }
    if let Some(d) = std::env::var_os("GHIDRA_INSTALL_DIR")
        .map(PathBuf::from)
        .filter(|d| is_ghidra_dir(d))
    {
        return Ok(Some(d));
    }
    let mut roots: Vec<PathBuf> = vec![
        "/opt".into(),
        "/usr/share".into(),
        "/usr/local".into(),
        "/Applications".into(),
    ];
    if let Some(h) = home {
        roots.extend([
            h.to_path_buf(),
            h.join(".local/opt"),
            h.join("opt"),
            h.join("tools"),
        ]);
    }
    let mut found: Vec<(Option<String>, PathBuf)> = Vec::new();
    for root in roots {
        let Ok(rd) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if !name.starts_with("ghidra") {
                continue;
            }
            let path = entry.path();
            // Either the install itself or a wrapper dir containing it (/opt/ghidra/ghidra_x_PUBLIC).
            let mut dirs = vec![path.clone()];
            if let Ok(inner) = std::fs::read_dir(&path) {
                dirs.extend(inner.flatten().map(|e| e.path()).filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().to_lowercase().starts_with("ghidra"))
                }));
            }
            for d in dirs.into_iter().filter(|d| is_ghidra_dir(d)) {
                found.push((ghidra_version(&d), d));
            }
        }
    }
    found.sort_by_key(|a| version_key(a.0.as_deref()));
    Ok(found.pop().map(|(_, d)| d))
}

fn version_key(v: Option<&str>) -> Vec<u64> {
    v.unwrap_or("0")
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse().ok())
        .collect()
}

pub fn ghidra_version(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("Ghidra").join("application.properties")).ok()?;
    parse_properties_value(&text, "application.version")
}

pub fn parse_properties_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn is_jdk(home: &Path) -> bool {
    home.join("bin").join("java").is_file() && home.join("bin").join("javac").is_file()
}

fn find_jdk(
    ghidra: &Path,
    version: Option<&str>,
    home: Option<&Path>,
    path_dirs: &[PathBuf],
) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(j) = std::env::var_os("JAVA_HOME") {
        candidates.push(j.into());
    }
    // The JDK the user already chose for this Ghidra version.
    if let (Some(h), Some(v)) = (home, version) {
        let release = ghidra
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| n.starts_with("ghidra_"))
            .unwrap_or_else(|| format!("ghidra_{v}_PUBLIC"));
        for f in [
            h.join(".config/ghidra")
                .join(&release)
                .join("java_home.save"),
            h.join(".ghidra")
                .join(format!(".{release}"))
                .join("java_home.save"),
        ] {
            if let Ok(t) = std::fs::read_to_string(f) {
                candidates.push(PathBuf::from(t.trim()));
            }
        }
    }
    for d in path_dirs {
        if let Ok(real) = std::fs::canonicalize(d.join("javac")) {
            if let Some(h) = real.parent().and_then(Path::parent) {
                candidates.push(h.to_path_buf());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir("/usr/lib/jvm") {
        let mut jvms: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        jvms.sort();
        candidates.extend(jvms.into_iter().rev());
    }
    candidates
        .into_iter()
        .find(|c| is_jdk(c))
        .map(|c| std::fs::canonicalize(&c).unwrap_or(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capa_version_parses() {
        assert_eq!(parse_capa_version("capa 9.4.0\n").as_deref(), Some("9.4.0"));
        assert_eq!(parse_capa_version("capa v7.0.1").as_deref(), Some("7.0.1"));
        assert_eq!(parse_capa_version("usage: capa"), None);
    }

    #[test]
    fn clamscan_version_parses() {
        let (engine, db) =
            parse_clamscan_version("ClamAV 1.4.1/27400/Mon Oct  7 08:36:00 2024\n").unwrap();
        assert_eq!(engine, "1.4.1");
        assert_eq!(
            db.as_deref(),
            Some("daily 27400 (Mon Oct  7 08:36:00 2024)")
        );
        assert_eq!(
            parse_clamscan_version("ClamAV 1.5.4\n").unwrap(),
            ("1.5.4".into(), None)
        );
    }

    #[test]
    fn cvd_header_parses() {
        let mut h =
            b"ClamAV-VDB:07 Oct 2024 08-36 +0000:27400:2068411:90:abc:sig:raynman:1728289860"
                .to_vec();
        h.resize(512, b' ');
        assert_eq!(
            parse_cvd_header(&h),
            Some(("07 Oct 2024 08-36 +0000".into(), "27400".into()))
        );
        assert_eq!(parse_cvd_header(b"garbage"), None);
    }

    #[test]
    fn custom_db_version_mentions_file_count() {
        let dir = std::env::temp_dir().join(format!("bb-deep-clamdb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("test.ndb"), "X:0:*:41414141\n").unwrap();
        assert!(has_clam_db(&dir));
        let v = clam_db_version(&dir);
        assert!(
            v.starts_with("custom database (1 file(s), newest modified 20"),
            "{v}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(19_723), "2024-01-01");
        assert_eq!(civil_date(20_738), "2026-10-12");
    }

    #[test]
    fn ghidra_properties() {
        let text = "#x\napplication.name=Ghidra\napplication.version=12.1.4\n";
        assert_eq!(
            parse_properties_value(text, "application.version").as_deref(),
            Some("12.1.4")
        );
        assert!(version_key(Some("12.1.4")) > version_key(Some("11.3")));
    }

    #[test]
    fn install_never_grants_root_or_home() {
        let t = install(Path::new("/bin/sh"), None);
        assert!(t.grant_dirs.iter().all(|d| d != Path::new("/")));
    }
}

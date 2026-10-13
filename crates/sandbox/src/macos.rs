//! macOS backend: Seatbelt (the kernel sandbox behind App Sandbox).
//!
//! Profiles are written in SBPL, generated from [`Profile`]: deny by
//! default, then allow exactly the profile's paths, exec only from its
//! `executable` paths, and either no network or outbound TCP to specific
//! remote ports.
//!
//! - [`confine_self`] applies the profile in-process with `sandbox_init`
//!   (deprecated since 10.8 but still supported and used by major browsers).
//! - [`spawn`] runs tools under `/usr/bin/sandbox-exec -p <profile>`.
//!   `sandbox_init` cannot be used between fork and exec: it parses the
//!   profile, allocates and talks to the kernel through non-async-signal-safe
//!   library code, which can deadlock in a forked child of a multithreaded
//!   parent. `sandbox-exec` is a fresh single-threaded process that applies
//!   the profile and then execs the tool, so the tool is confined from its
//!   first instruction. Only `setrlimit` (async-signal-safe) runs in
//!   `pre_exec`.

use std::ffi::{CStr, CString, c_char, c_int};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use crate::{Applied, Limits, Network, Profile, SpawnError};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// SBPL string literal.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Seatbelt matches resolved paths (`/tmp` is `/private/tmp`, `/var` is
/// `/private/var`), so each path is emitted as given and canonicalized.
/// Paths that are not valid UTF-8 are skipped (granting nothing).
fn path_filters(paths: &[PathBuf]) -> String {
    let mut out = String::new();
    for p in paths {
        let mut forms = vec![p.clone()];
        if let Ok(c) = std::fs::canonicalize(p)
            && c != *p
        {
            forms.push(c);
        }
        for f in forms {
            if let Some(s) = f.to_str() {
                out.push_str(&format!(" (subpath {})", quote(s)));
            }
        }
    }
    out
}

/// System locations every non-Tier-1 process needs to load and run (dyld
/// shared cache, system libraries, frameworks, time zones). No user data.
const SYSTEM_READ: &[&str] = &[
    "/System",
    "/usr/lib",
    "/usr/share",
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/Library/Apple",
    "/Library/Preferences/Logging",
];

/// Generate the SBPL profile.
pub fn sbpl(profile: &Profile) -> String {
    let tier1 = profile.seccomp.is_tier1();
    let mut s = String::from("(version 1)\n(deny default)\n");
    if tier1 {
        // In-process Tier 1 worker: everything it needs is already loaded
        // and read. Only CPU-count queries (thread pools) are allowed; no
        // fork, exec, files, network, IPC or Mach services.
        s.push_str(
            "(allow sysctl-read (sysctl-name \"hw.ncpu\" \"hw.activecpu\" \"hw.logicalcpu\" \
             \"hw.logicalcpu_max\" \"hw.physicalcpu\" \"hw.pagesize\" \"hw.cachelinesize\" \"kern.osversion\"))\n",
        );
    } else {
        s.push_str("(allow sysctl-read)\n(allow file-read-metadata)\n");
        let sys: Vec<PathBuf> = SYSTEM_READ.iter().map(PathBuf::from).collect();
        s.push_str(&format!("(allow file-read*{})\n", path_filters(&sys)));
        // dyld must map the shared cache and system libraries as code;
        // without this every program is killed in the loader.
        s.push_str(&format!(
            "(allow file-map-executable{})\n",
            path_filters(&sys)
        ));
        // Programs read the root directory itself at start-up on macOS 26
        // (and abort without it); `literal` grants only the listing of `/`.
        s.push_str(
            "(allow file-read-data (literal \"/\"))\n\
             (allow file-read* file-write-data (literal \"/dev/null\") (literal \"/dev/zero\"))\n\
             (allow file-read* (literal \"/dev/urandom\") (literal \"/dev/random\"))\n\
             (allow signal (target same-sandbox))\n\
             (allow ipc-posix-sem)\n",
        );
        // Unified logging and the system logger are used implicitly by
        // many system libraries; failing those lookups is noisy but harmless,
        // so they stay denied.
    }
    if !profile.read_only.is_empty() {
        s.push_str(&format!(
            "(allow file-read*{})\n",
            path_filters(&profile.read_only)
        ));
    }
    if !profile.executable.is_empty() {
        let f = path_filters(&profile.executable);
        s.push_str(&format!("(allow file-read*{f})\n"));
        if !tier1 {
            s.push_str(&format!(
                "(allow process-exec{f})\n(allow process-fork)\n(allow file-map-executable{f})\n"
            ));
        }
    }
    if !profile.read_write.is_empty() {
        s.push_str(&format!(
            "(allow file-read* file-write*{})\n",
            path_filters(&profile.read_write)
        ));
    }
    if let Network::TcpConnectPorts(ports) = &profile.network {
        for port in ports {
            s.push_str(&format!(
                "(allow network-outbound (remote tcp \"*:{port}\"))\n"
            ));
        }
        // Name resolution goes through mDNSResponder and the system
        // configuration daemons, not direct UDP.
        s.push_str(
            "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n\
             (allow mach-lookup (global-name \"com.apple.dnssd.service\") \
             (global-name \"com.apple.SystemConfiguration.DNSConfiguration\") \
             (global-name \"com.apple.SystemConfiguration.configd\") \
             (global-name \"com.apple.system.opendirectoryd.libinfo\") \
             (global-name \"com.apple.system.notification_center\"))\n\
             (allow file-read* (literal \"/private/etc/hosts\") (literal \"/private/etc/resolv.conf\") \
             (literal \"/private/var/run/resolv.conf\") (literal \"/private/etc/services\") \
             (literal \"/private/etc/protocols\"))\n",
        );
    }
    s
}

fn set_rlimits(limits: &Limits) -> bool {
    let set = |res, value: Option<u64>| match value {
        None => true,
        Some(v) => {
            let lim = libc::rlimit {
                rlim_cur: v,
                rlim_max: v,
            };
            // SAFETY: setrlimit reads a valid, initialized rlimit struct.
            unsafe { libc::setrlimit(res, &lim) == 0 }
        }
    };
    // macOS does not enforce RLIMIT_AS for mmap; set it where accepted but
    // do not count it (documented in docs/platforms.md).
    let _ = set(libc::RLIMIT_AS, limits.address_space);
    set(libc::RLIMIT_CPU, limits.cpu_seconds)
        & set(libc::RLIMIT_FSIZE, limits.file_size)
        & set(libc::RLIMIT_NOFILE, limits.open_files)
        & set(libc::RLIMIT_CORE, Some(0))
}

fn record_seatbelt(applied: &mut Applied, ok: bool) {
    applied.record("seatbelt_fs", ok);
    applied.record("seatbelt_net", ok);
    applied.record("seatbelt_exec", ok);
}

/// Apply `profile` to the calling process. Returns the error text on failure.
pub fn apply(profile_text: &str) -> Result<(), String> {
    let c = CString::new(profile_text).map_err(|e| e.to_string())?;
    let mut err: *mut c_char = std::ptr::null_mut();
    // SAFETY: c is NUL-terminated; err receives a library-allocated string.
    let rc = unsafe { sandbox_init(c.as_ptr(), 0, &mut err) };
    if rc == 0 {
        return Ok(());
    }
    let msg = if err.is_null() {
        format!("sandbox_init returned {rc}")
    } else {
        // SAFETY: err is a NUL-terminated string owned by libsandbox.
        let m = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: err came from sandbox_init and is freed exactly once.
        unsafe { sandbox_free_error(err) };
        m
    };
    Err(msg)
}

pub fn confine_self(profile: &Profile) -> Applied {
    let mut applied = Applied::default();
    applied.record("rlimits", set_rlimits(&profile.limits));
    let ok = match apply(&sbpl(profile)) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("bytebouncer-sandbox: sandbox_init failed: {e}");
            false
        }
    };
    record_seatbelt(&mut applied, ok);
    applied
}

pub fn spawn(
    profile: &Profile,
    program: &Path,
    configure: impl Fn(&mut Command),
    allow_reduced: bool,
) -> Result<(Child, Applied), SpawnError> {
    let have_seatbelt = Path::new(SANDBOX_EXEC).is_file();
    let mut applied = Applied::default();
    applied.active.push("rlimits".into());
    record_seatbelt(&mut applied, have_seatbelt);
    if !applied.missing.is_empty() && !allow_reduced {
        return Err(SpawnError::Reduced(applied.missing));
    }

    let mut cmd = if have_seatbelt {
        let mut c = Command::new(SANDBOX_EXEC);
        c.arg("-p").arg(sbpl(profile)).arg(program);
        c
    } else {
        Command::new(program)
    };
    configure(&mut cmd);
    cmd.env_clear()
        .envs(profile.env.iter().map(|(k, v)| (k, v)));
    let limits = profile.limits.clone();
    // SAFETY: setrlimit is async-signal-safe and `limits` was prepared before fork.
    unsafe {
        cmd.pre_exec(move || {
            if set_rlimits(&limits) {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    cmd.spawn().map(|c| (c, applied)).map_err(SpawnError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote(r#"/a "b"\c"#), r#""/a \"b\"\\c""#);
    }

    #[test]
    fn tier1_profile_denies_exec_and_network() {
        let s = sbpl(&Profile::tier1(false));
        assert!(s.contains("(deny default)"));
        assert!(!s.contains("process-exec"));
        assert!(!s.contains("process-fork"));
        assert!(!s.contains("network"));
        assert!(!s.contains("file-read*"));
    }

    #[test]
    fn generated_profiles_compile() {
        // sandbox-exec parses the profile before exec: a syntax error fails here.
        let dir = std::env::temp_dir();
        let mut fetch = Profile::external_tool(vec![], vec![], dir.clone());
        fetch.network = Network::TcpConnectPorts(vec![80, 443]);
        fetch.executable.push("/usr/bin/true".into());
        let mut tool = Profile::external_tool(vec![], vec![], dir);
        tool.executable.push("/usr/bin/true".into());
        // The Tier 1 profile cannot exec anything, so let it run `true` only
        // to prove the rest of its text parses.
        let tier1 = format!(
            "{}(allow file-read*)\n(allow file-map-executable)\n(allow process-exec)\n",
            sbpl(&Profile::tier1(true))
        );
        for text in [tier1, sbpl(&tool), sbpl(&fetch)] {
            let out = Command::new(SANDBOX_EXEC)
                .arg("-p")
                .arg(&text)
                .arg("/usr/bin/true")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "profile rejected ({}): {}\n{text}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

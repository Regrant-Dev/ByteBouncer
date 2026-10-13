//! Kernel-level confinement for ByteBouncer analyzers (SPEC §9.2).
//!
//! Three entry points share one [`Profile`] description:
//!
//! - [`spawn_worker`]: start one of ByteBouncer's own worker processes
//!   (Tier 1 analysis, fetch). On Linux and macOS this is a plain spawn with a
//!   cleared environment; the worker confines itself. On Windows confinement
//!   has to be applied at process creation, so the worker is launched inside
//!   an AppContainer and a Job Object.
//! - [`confine_self`]: called by the worker after reading its input, before
//!   parsing anything. Linux: rlimits, network namespace, Landlock, seccomp.
//!   macOS: rlimits and a Seatbelt profile via `sandbox_init`. Windows:
//!   verifies the AppContainer token and job limits applied by the parent.
//! - [`spawn`]: deep mode runs locally installed tools (capa, ClamAV, Ghidra)
//!   confined from their first instruction (Linux: between fork and exec;
//!   macOS: `sandbox-exec`; Windows: AppContainer + Job Object).
//!
//! Every restriction that could not be applied is reported in
//! [`Applied::missing`]; callers decide whether that is acceptable.
//! Restriction names per platform are listed in `docs/platforms.md`.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// A confined child process. On Unix this is [`std::process::Child`]; on
/// Windows a wrapper with the same methods that also owns the Job Object
/// (killing the whole job) and removes the temporary ACL grants when dropped.
#[cfg(not(windows))]
pub use std::process::Child;
#[cfg(windows)]
pub use windows::Child;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// No network at all.
    Blocked,
    /// Only outbound TCP to these ports (used by the fetch worker). Linux:
    /// Landlock (DNS over UDP is not restricted). macOS: Seatbelt remote-port
    /// rules plus the system DNS resolver. Windows: AppContainer
    /// `internetClient` capability, which cannot filter by port.
    TcpConnectPorts(Vec<u16>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seccomp {
    /// Tight allow-list for the in-process Tier 1 worker (memory, write, exit).
    /// On macOS/Windows: the Tier 1 shape (no exec, no child processes).
    Tier1AllowList,
    /// Tier 1 allow-list plus what `bytebouncer doctor` escape probes use.
    Tier1Probe,
    /// Deny-list for general tools (JVMs, Python): blocks ptrace, mounts,
    /// namespaces, kernel modules, bpf, io_uring and similar. Linux only.
    DenyList,
}

impl Seccomp {
    pub fn is_tier1(self) -> bool {
        matches!(self, Self::Tier1AllowList | Self::Tier1Probe)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    pub address_space: Option<u64>,
    pub cpu_seconds: Option<u64>,
    pub file_size: Option<u64>,
    pub open_files: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Profile {
    /// Readable files/directories.
    pub read_only: Vec<PathBuf>,
    /// Readable and executable (tool installations, system libraries).
    pub executable: Vec<PathBuf>,
    /// Fully writable (scratch directories).
    pub read_write: Vec<PathBuf>,
    pub network: Network,
    pub limits: Limits,
    pub seccomp: Seccomp,
    /// Environment for spawned processes; the parent environment is never
    /// inherited (Windows additionally passes `SystemRoot`/`windir`, which
    /// system DLLs need).
    pub env: Vec<(OsString, OsString)>,
}

impl Profile {
    /// The Tier 1 worker profile: no filesystem, no network, tight limits.
    ///
    /// On Windows the parent must add the worker's input files to
    /// `read_only` before [`spawn_worker`], because the AppContainer is in
    /// force before the worker reads anything.
    pub fn tier1(probe: bool) -> Self {
        Self {
            read_only: vec![],
            executable: vec![],
            read_write: vec![],
            network: Network::Blocked,
            limits: Limits {
                address_space: Some(4 << 30),
                cpu_seconds: Some(120),
                file_size: Some(0),
                open_files: Some(16),
            },
            seccomp: if probe {
                Seccomp::Tier1Probe
            } else {
                Seccomp::Tier1AllowList
            },
            env: vec![],
        }
    }

    /// A profile for running an installed analysis tool offline. Grants
    /// read+exec on standard system locations plus `tool_dirs`, read on
    /// `inputs`, and write on `scratch`.
    pub fn external_tool(tool_dirs: Vec<PathBuf>, inputs: Vec<PathBuf>, scratch: PathBuf) -> Self {
        let (system_exec, system_read, mut env) = platform_tool_defaults(&scratch);
        let mut executable: Vec<PathBuf> = system_exec.iter().map(PathBuf::from).collect();
        executable.extend(tool_dirs);
        env.push(("LANG".into(), "C.UTF-8".into()));
        Self {
            read_only: [inputs, system_read.iter().map(PathBuf::from).collect()].concat(),
            executable,
            // Shell wrappers commonly redirect to /dev/null; writes there go nowhere.
            read_write: if cfg!(target_os = "linux") {
                vec![scratch, "/dev/null".into()]
            } else {
                vec![scratch]
            },
            network: Network::Blocked,
            limits: Limits {
                address_space: None,
                cpu_seconds: Some(1800),
                file_size: Some(4 << 30),
                open_files: Some(4096),
            },
            seccomp: Seccomp::DenyList,
            env,
        }
    }
}

type ToolDefaults = (
    &'static [&'static str],
    &'static [&'static str],
    Vec<(OsString, OsString)>,
);

#[cfg(target_os = "macos")]
fn platform_tool_defaults(_scratch: &Path) -> ToolDefaults {
    (
        &[
            "/usr",
            "/bin",
            "/sbin",
            "/opt/homebrew",
            "/Library/Java",
            "/System/Library",
        ],
        &["/private/etc", "/dev/null", "/dev/urandom", "/dev/random"],
        vec![(
            "PATH".into(),
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".into(),
        )],
    )
}

#[cfg(windows)]
fn platform_tool_defaults(scratch: &Path) -> ToolDefaults {
    // System directories are readable by every AppContainer already; tools
    // get a private TEMP because the user's TEMP is not accessible.
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let mut path = root.clone();
    path.push("\\System32;");
    path.push(&root);
    (
        &[],
        &[],
        vec![
            ("PATH".into(), path),
            ("TEMP".into(), scratch.as_os_str().to_owned()),
            ("TMP".into(), scratch.as_os_str().to_owned()),
        ],
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
fn platform_tool_defaults(_scratch: &Path) -> ToolDefaults {
    (
        &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt", "/etc"],
        &[
            "/proc",
            "/sys/devices/system/cpu",
            "/dev/null",
            "/dev/urandom",
        ],
        vec![("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into())],
    )
}

/// Restrictions a fully isolated Tier 1 worker must report active on this
/// platform. Any of them missing means reduced isolation.
#[cfg(target_os = "linux")]
pub const TIER1_REQUIRED: &[&str] = &["rlimits", "netns", "landlock_fs", "landlock_net", "seccomp"];
#[cfg(target_os = "macos")]
pub const TIER1_REQUIRED: &[&str] = &["rlimits", "seatbelt_fs", "seatbelt_net", "seatbelt_exec"];
#[cfg(windows)]
pub const TIER1_REQUIRED: &[&str] = &[
    "appcontainer_fs",
    "appcontainer_net",
    "job_limits",
    "job_no_child",
];
/// No backend: report the Linux names, all of which will be missing.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub const TIER1_REQUIRED: &[&str] = &["rlimits", "netns", "landlock_fs", "landlock_net", "seccomp"];

pub fn tier1_required() -> &'static [&'static str] {
    TIER1_REQUIRED
}

/// Which restrictions are in force. Names per platform:
/// Linux `rlimits`, `netns`, `landlock_fs`, `landlock_net`, `landlock_scope`,
/// `seccomp`, `seccomp_denylist`; macOS `rlimits`, `seatbelt_fs`,
/// `seatbelt_net`, `seatbelt_exec`; Windows `appcontainer_fs`,
/// `appcontainer_net`, `job_limits`, `job_no_child`, `port_restriction`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub active: Vec<String>,
    pub missing: Vec<String>,
}

impl Applied {
    #[allow(dead_code)]
    fn record(&mut self, name: &str, ok: bool) {
        if ok {
            self.active.push(name.into());
        } else {
            self.missing.push(name.into());
        }
    }

    #[allow(dead_code)]
    fn all_missing(names: &[&str]) -> Self {
        Self {
            active: vec![],
            missing: names.iter().map(|n| n.to_string()).collect(),
        }
    }
}

/// What the host supports, without changing anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub platform: String,
    /// Linux only; 0 elsewhere.
    pub landlock_abi: i32,
    /// Linux only; false elsewhere.
    pub seccomp: bool,
}

pub fn host_capabilities() -> HostCapabilities {
    #[cfg(target_os = "linux")]
    {
        HostCapabilities {
            platform: "linux".into(),
            landlock_abi: linux::landlock_abi(),
            seccomp: linux::seccomp_arch().is_some(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostCapabilities {
            platform: std::env::consts::OS.into(),
            landlock_abi: 0,
            seccomp: false,
        }
    }
}

/// Confine the current process. On Linux this must be called while
/// single-threaded (the user namespace step requires it). On Windows it
/// only verifies what [`spawn_worker`] applied. Never fails: unavailable
/// restrictions are reported as missing.
pub fn confine_self(profile: &Profile) -> Applied {
    #[cfg(target_os = "linux")]
    {
        linux::confine_self(profile)
    }
    #[cfg(target_os = "macos")]
    {
        macos::confine_self(profile)
    }
    #[cfg(windows)]
    {
        windows::confine_self(profile)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = profile;
        Applied::all_missing(TIER1_REQUIRED)
    }
}

/// Start one of ByteBouncer's own worker processes (`exe args…`) with
/// stdin/stdout/stderr piped and the environment replaced by `profile.env`.
/// `label` names the worker kind (`tier1`, `fetch`) for the Windows
/// AppContainer. The worker must still call [`confine_self`] and check the
/// result: on Linux/macOS that is where confinement happens, and on Windows
/// a failed AppContainer launch falls back to a plain process whose
/// `confine_self` then reports everything missing.
pub fn spawn_worker(
    label: &str,
    profile: &Profile,
    exe: &Path,
    args: &[&OsStr],
) -> io::Result<Child> {
    #[cfg(windows)]
    {
        windows::spawn_worker(label, profile, exe, args)
    }
    #[cfg(not(windows))]
    {
        let _ = label;
        use std::process::Stdio;
        Command::new(exe)
            .args(args)
            .env_clear()
            .envs(profile.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
}

#[derive(Debug)]
pub enum SpawnError {
    /// Restrictions are unavailable and the caller did not allow reduced isolation.
    Reduced(Vec<String>),
    Io(io::Error),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reduced(m) => write!(f, "sandbox restrictions unavailable: {}", m.join(", ")),
            Self::Io(e) => write!(f, "spawning sandboxed process: {e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// Spawn `program` confined by `profile`. `configure` sets args/stdio/cwd;
/// the environment is always replaced by `profile.env`.
///
/// On Windows only the program, arguments and working directory are taken
/// from `configure`: stdin is always empty and stdout/stderr are always
/// piped (the AppContainer launch cannot reuse `Command`'s stdio setup).
pub fn spawn(
    profile: &Profile,
    program: &Path,
    configure: impl Fn(&mut Command),
    allow_reduced: bool,
) -> Result<(Child, Applied), SpawnError> {
    #[cfg(target_os = "linux")]
    {
        linux::spawn(profile, program, configure, allow_reduced)
    }
    #[cfg(target_os = "macos")]
    {
        macos::spawn(profile, program, configure, allow_reduced)
    }
    #[cfg(windows)]
    {
        windows::spawn(profile, program, configure, allow_reduced)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let applied = Applied::all_missing(&[
            "rlimits",
            "netns",
            "landlock_fs",
            "landlock_net",
            "seccomp_denylist",
        ]);
        if !allow_reduced {
            return Err(SpawnError::Reduced(applied.missing));
        }
        let mut cmd = Command::new(program);
        configure(&mut cmd);
        cmd.env_clear()
            .envs(profile.env.iter().map(|(k, v)| (k, v)));
        cmd.spawn().map(|c| (c, applied)).map_err(SpawnError::Io)
    }
}

/// File the parent places in the probe directory; a confined worker must
/// not be able to read it.
pub const PROBE_SECRET: &str = "probe-secret.txt";

/// Parent side of `doctor`: create `dir` with a secret file in it. The
/// directory is ordinary user-owned space, deliberately not granted to the
/// worker.
pub fn prepare_probe_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(PROBE_SECRET), b"bytebouncer probe secret\n")
}

/// Attempt things a confined Tier 1 worker must not be able to do, after
/// [`confine_self`]. `true` means the escape was blocked. `dir` is a
/// directory prepared by [`prepare_probe_dir`].
///
/// On Linux this only uses syscalls in the `Tier1Probe` seccomp allow-list
/// or ones whose denial is the point.
pub fn escape_probes(dir: &Path) -> Vec<(String, bool)> {
    let mut results = Vec::new();
    let tcp = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([1, 1, 1, 1], 443)),
        std::time::Duration::from_secs(2),
    );
    results.push(("tcp_connect".into(), tcp.is_err()));
    let write = std::fs::write(dir.join("escape-probe.txt"), b"x");
    results.push(("file_write".into(), write.is_err()));
    let read = std::fs::read(dir.join(PROBE_SECRET));
    results.push(("file_read".into(), read.is_err()));
    let (program, args) = exec_probe_command();
    let exec = Command::new(program).args(args).status();
    results.push(("exec".into(), exec.is_err()));
    results
}

/// A harmless system program that exists on every host of this platform.
fn exec_probe_command() -> (PathBuf, &'static [&'static str]) {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        (
            Path::new(&root).join("System32").join("cmd.exe"),
            &["/d", "/c", "exit 0"],
        )
    }
    #[cfg(target_os = "macos")]
    {
        (PathBuf::from("/usr/bin/true"), &[])
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        (PathBuf::from("/bin/true"), &[])
    }
}

/// Cross-platform qualification tests: these run on every CI host and must
/// show real blocking by the OS backend. The test binary re-executes itself
/// as the sandboxed child (`helper_entry`), so no external tools are needed.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const HELPER_ENV: &str = "BB_SANDBOX_HELPER";

    /// Child side: does nothing unless the helper variable is set.
    #[test]
    fn helper_entry() {
        let Some(op) = std::env::var_os(HELPER_ENV) else {
            return;
        };
        let op = op.to_string_lossy().into_owned();
        let (verb, arg) = op.split_once(':').unwrap_or((&op, ""));
        let ok = match verb {
            "read" => std::fs::read(arg).is_ok(),
            "write" => std::fs::write(arg, b"x").is_ok(),
            "connect" => {
                use std::net::ToSocketAddrs;
                arg.to_socket_addrs()
                    .ok()
                    .and_then(|mut a| a.next())
                    .is_some_and(|addr| {
                        std::net::TcpStream::connect_timeout(
                            &addr,
                            std::time::Duration::from_secs(5),
                        )
                        .is_ok()
                    })
            }
            "worker" => {
                // Tier 1 worker: confine, report, probe.
                let applied = confine_self(&Profile::tier1(true));
                let probes = escape_probes(Path::new(arg));
                println!("ACTIVE={}", applied.active.join(","));
                println!("MISSING={}", applied.missing.join(","));
                for (name, blocked) in probes {
                    println!(
                        "PROBE {name}={}",
                        if blocked { "blocked" } else { "ALLOWED" }
                    );
                }
                true
            }
            _ => false,
        };
        std::process::exit(if ok { 0 } else { 3 });
    }

    fn helper_args() -> Vec<&'static OsStr> {
        [
            "tests::helper_entry",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ]
        .into_iter()
        .map(OsStr::new)
        .collect()
    }

    fn scratch(name: &str) -> crate::testutil::TempDir {
        crate::testutil::temp_dir("bb-sandbox-lib", name)
    }

    /// Run the helper confined by `profile` (Tier 2 path); true if the
    /// operation succeeded inside the sandbox.
    fn run_tool(mut profile: Profile, op: String) -> bool {
        let exe = std::env::current_exe().unwrap();
        profile.executable.push(exe.clone());
        profile.env.push((HELPER_ENV.into(), op.clone().into()));
        let (child, applied) = spawn(
            &profile,
            &exe,
            |c| {
                c.args(helper_args())
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped());
                c.stderr(std::process::Stdio::piped());
            },
            true,
        )
        .unwrap();
        let out = child.wait_with_output().unwrap();
        let code = out.status.code();
        assert!(
            code == Some(0) || code == Some(3),
            "helper did not run ({op}): {:?} applied={applied:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        code == Some(0)
    }

    fn backend_available() -> bool {
        cfg!(any(target_os = "macos", windows))
            || (cfg!(target_os = "linux") && host_capabilities().landlock_abi >= 4)
    }

    #[test]
    fn tool_filesystem_is_confined() {
        if !backend_available() {
            return;
        }
        let dir = scratch("tool-fs");
        let input = dir.join("input.txt");
        std::fs::write(&input, "hello").unwrap();
        let secret = dir.join("secret.txt");
        std::fs::write(&secret, "secret").unwrap();
        let work = dir.join("work");
        std::fs::create_dir(&work).unwrap();
        let profile = || Profile::external_tool(vec![], vec![input.clone()], work.clone());

        assert!(
            run_tool(profile(), format!("read:{}", input.display())),
            "granted input must be readable"
        );
        assert!(
            run_tool(
                profile(),
                format!("write:{}", work.join("out.txt").display())
            ),
            "scratch must be writable"
        );
        assert!(
            !run_tool(profile(), format!("read:{}", secret.display())),
            "ungranted file must not be readable"
        );
        assert!(
            !run_tool(
                profile(),
                format!("write:{}", dir.join("escape.txt").display())
            ),
            "outside scratch must not be writable"
        );
        assert!(!dir.join("escape.txt").exists());
    }

    /// A local listener gives a deterministic positive control: the same
    /// connection must succeed when its port is allowed (where the backend
    /// can express that) and fail when the network is blocked.
    #[test]
    fn tool_network_is_confined() {
        if !backend_available() {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                drop(s);
            }
        });
        let work = scratch("tool-net");
        let target = format!("connect:127.0.0.1:{port}");
        let blocked = Profile::external_tool(vec![], vec![], work.clone());
        assert!(
            !run_tool(blocked, target.clone()),
            "blocked profile must not reach localhost"
        );

        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let mut allowed = Profile::external_tool(vec![], vec![], work.clone());
            allowed.network = Network::TcpConnectPorts(vec![port]);
            assert!(
                run_tool(allowed.clone(), target),
                "allowed port must be reachable (positive control)"
            );
            let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let other_port = other.local_addr().unwrap().port();
            std::thread::spawn(move || {
                for s in other.incoming() {
                    drop(s);
                }
            });
            assert!(
                !run_tool(allowed, format!("connect:127.0.0.1:{other_port}")),
                "ports outside the allow-list must be blocked"
            );
        }
    }

    /// Fetch-shaped profile against the real internet (DNS + TLS port),
    /// when the unconfined test process itself has connectivity.
    #[test]
    fn fetch_profile_reaches_https() {
        if !cfg!(any(target_os = "macos", windows)) {
            return;
        }
        let target = "github.com:443";
        let reachable = {
            use std::net::ToSocketAddrs;
            target
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
                .is_some_and(|a| {
                    std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(5))
                        .is_ok()
                })
        };
        if !reachable {
            eprintln!("skipping: no internet from the test host");
            return;
        }
        let work = scratch("fetch-net");
        let mut p = Profile::external_tool(vec![], vec![], work.to_path_buf());
        p.network = Network::TcpConnectPorts(vec![80, 443]);
        assert!(
            run_tool(p.clone(), format!("connect:{target}")),
            "fetch profile must reach port 443"
        );
        let mut blocked = p;
        blocked.network = Network::Blocked;
        assert!(
            !run_tool(blocked, format!("connect:{target}")),
            "blocked profile must not reach the internet"
        );
    }

    /// The Tier 1 worker path end to end: spawn_worker + confine_self +
    /// escape probes, as `bytebouncer doctor` does. On Linux this is covered
    /// by `doctor` in CI instead (unshare needs a single-threaded process,
    /// which the test harness is not).
    #[test]
    fn tier1_worker_is_confined() {
        if !cfg!(any(target_os = "macos", windows)) {
            return;
        }
        let dir = scratch("tier1");
        prepare_probe_dir(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut profile = Profile::tier1(true);
        profile.env.push((
            HELPER_ENV.into(),
            format!("worker:{}", dir.display()).into(),
        ));
        let mut child = spawn_worker("tier1", &profile, &exe, &helper_args()).unwrap();
        drop(child.stdin.take());
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "worker failed: {status:?}\n{out}\n{err}");

        let active: Vec<&str> = out
            .lines()
            .find_map(|l| l.strip_prefix("ACTIVE="))
            .unwrap_or_default()
            .split(',')
            .collect();
        for r in TIER1_REQUIRED {
            assert!(
                active.contains(r),
                "restriction {r} not active:\n{out}\n{err}"
            );
        }
        let probes: Vec<&str> = out.lines().filter(|l| l.starts_with("PROBE ")).collect();
        assert_eq!(probes.len(), 4, "{out}");
        for p in probes {
            assert!(p.ends_with("=blocked"), "escape not blocked: {p}\n{out}");
        }
        assert!(!dir.join("escape-probe.txt").exists());
    }

    #[test]
    fn reduced_isolation_is_refused_by_default() {
        let exe = std::env::current_exe().unwrap();
        let reduced_dir = scratch("reduced");
        let mut profile = Profile::external_tool(vec![], vec![], reduced_dir.to_path_buf());
        profile.executable.push(exe.clone());
        let fully_supported = cfg!(any(target_os = "macos", windows))
            || (cfg!(target_os = "linux") && host_capabilities().landlock_abi >= 4);
        let result = spawn(
            &profile,
            &exe,
            |c| {
                c.args(helper_args()).stdout(std::process::Stdio::null());
            },
            false,
        );
        if fully_supported {
            let (mut child, applied) =
                result.expect("strict spawn must succeed on a fully supported host");
            assert!(applied.missing.is_empty(), "{applied:?}");
            assert!(child.wait().unwrap().success());
        } else {
            assert!(matches!(result, Err(SpawnError::Reduced(_))));
        }
    }
}

/// Test support shared across crates: a per-test directory removed on drop.
#[doc(hidden)]
pub mod testutil {
    use std::path::PathBuf;

    pub struct TempDir(PathBuf);

    impl std::ops::Deref for TempDir {
        type Target = PathBuf;
        fn deref(&self) -> &PathBuf {
            &self.0
        }
    }

    impl AsRef<std::path::Path> for TempDir {
        fn as_ref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `<tmp>/<prefix>-<pid>-<name>`, emptied first.
    pub fn temp_dir(prefix: &str, name: &str) -> TempDir {
        let d = std::env::temp_dir().join(format!("{prefix}-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("create test dir");
        TempDir(d)
    }
}

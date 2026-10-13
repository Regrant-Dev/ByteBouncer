//! Linux backend. Landlock is driven through raw syscalls so the ruleset can
//! be built in the parent and applied in a forked child between fork and
//! exec, where only async-signal-safe operations are allowed. Everything the
//! child does is a plain syscall on data prepared beforehand.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

use crate::{Applied, Limits, Network, Profile, Seccomp, SpawnError};

// Landlock UAPI (include/uapi/linux/landlock.h).
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const RULE_NET_PORT: u32 = 2;

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;
/// Rights that may be granted on a regular file (others are directory-only).
const FS_FILE_RIGHTS: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

pub fn landlock_abi() -> i32 {
    // SAFETY: the version query takes no attribute pointer.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    abi.max(0) as i32
}

fn fs_rights(abi: i32) -> u64 {
    let mut rights = (1u64 << 13) - 1; // ABI 1: bits 0..=12
    if abi >= 2 {
        rights |= 1 << 13; // REFER
    }
    if abi >= 3 {
        rights |= FS_TRUNCATE;
    }
    if abi >= 5 {
        rights |= FS_IOCTL_DEV;
    }
    rights
}

/// A Landlock ruleset built in the parent, ready for `landlock_restrict_self`.
struct Ruleset {
    fd: Option<OwnedFd>,
    fs: bool,
    net: bool,
    scope: bool,
}

fn build_ruleset(profile: &Profile) -> Ruleset {
    let abi = landlock_abi();
    if abi < 1 {
        return Ruleset {
            fd: None,
            fs: false,
            net: false,
            scope: false,
        };
    }
    let handled_fs = fs_rights(abi);
    let net = abi >= 4;
    let scope = abi >= 6;
    let attr = RulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: if net {
            NET_BIND_TCP | NET_CONNECT_TCP
        } else {
            0
        },
        scoped: if scope {
            SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL
        } else {
            0
        },
    };
    let size = match abi {
        1..=3 => 8,
        4 | 5 => 16,
        _ => 24,
    };
    // SAFETY: attr outlives the call and `size` never exceeds its size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            size as usize,
            0u32,
        )
    };
    if fd < 0 {
        return Ruleset {
            fd: None,
            fs: false,
            net: false,
            scope: false,
        };
    }
    // SAFETY: the kernel returned a new file descriptor we now own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };

    let read = FS_READ_FILE | FS_READ_DIR;
    let grants: [(&Vec<PathBuf>, u64); 3] = [
        (&profile.read_only, read),
        (&profile.executable, read | FS_EXECUTE),
        (&profile.read_write, handled_fs),
    ];
    for (paths, rights) in grants {
        for path in paths {
            add_path_rule(&fd, path, rights & handled_fs);
        }
    }
    if let (true, Network::TcpConnectPorts(ports)) = (net, &profile.network) {
        for &port in ports {
            let rule = NetPortAttr {
                allowed_access: NET_CONNECT_TCP,
                port: port as u64,
            };
            // SAFETY: rule is a valid landlock_net_port_attr for the duration of the call.
            unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    fd.as_raw_fd(),
                    RULE_NET_PORT,
                    &rule as *const NetPortAttr,
                    0u32,
                )
            };
        }
    }
    Ruleset {
        fd: Some(fd),
        fs: true,
        net,
        scope,
    }
}

fn add_path_rule(ruleset: &OwnedFd, path: &Path, rights: u64) {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: c is a valid NUL-terminated path.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return; // Nonexistent paths simply grant nothing.
    }
    // SAFETY: fd was just opened and is owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
    let rights = if is_dir {
        rights
    } else {
        rights & FS_FILE_RIGHTS
    };
    let rule = PathBeneathAttr {
        allowed_access: rights,
        parent_fd: fd.as_raw_fd(),
    };
    // SAFETY: rule is a valid landlock_path_beneath_attr for the duration of the call.
    unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr,
            0u32,
        )
    };
}

pub fn seccomp_arch() -> Option<TargetArch> {
    match std::env::consts::ARCH {
        "x86_64" => Some(TargetArch::x86_64),
        "aarch64" => Some(TargetArch::aarch64),
        _ => None,
    }
}

fn compile(
    rules: Vec<libc::c_long>,
    mismatch: SeccompAction,
    matched: SeccompAction,
) -> Option<BpfProgram> {
    let rules: BTreeMap<i64, Vec<SeccompRule>> =
        rules.into_iter().map(|s| (s, Vec::new())).collect();
    SeccompFilter::new(rules, mismatch, matched, seccomp_arch()?)
        .ok()?
        .try_into()
        .ok()
}

/// Filters to install, in order. Installing a filter needs `prctl`, which the
/// Tier 1 allow-list forbids, so the allow-list always goes last.
fn seccomp_programs(mode: Seccomp) -> Option<Vec<BpfProgram>> {
    match mode {
        Seccomp::Tier1AllowList | Seccomp::Tier1Probe => {
            let mut allowed = vec![
                libc::SYS_read,
                libc::SYS_write,
                libc::SYS_close,
                libc::SYS_brk,
                libc::SYS_mmap,
                libc::SYS_munmap,
                libc::SYS_mremap,
                libc::SYS_mprotect,
                libc::SYS_madvise,
                libc::SYS_futex,
                libc::SYS_getrandom,
                libc::SYS_clock_gettime,
                libc::SYS_rt_sigaction,
                libc::SYS_rt_sigprocmask,
                libc::SYS_rt_sigreturn,
                libc::SYS_sigaltstack,
                libc::SYS_sched_yield,
                libc::SYS_sched_getaffinity,
                libc::SYS_exit,
                libc::SYS_exit_group,
                libc::SYS_openat,
                // musl's open() uses the legacy syscall where it exists.
                #[cfg(target_arch = "x86_64")]
                libc::SYS_open,
            ];
            let mut programs = Vec::new();
            if mode == Seccomp::Tier1Probe {
                // Let escape probes reach Landlock and the empty netns, which
                // are what the probes exist to test.
                allowed.extend([
                    libc::SYS_socket,
                    libc::SYS_ioctl,
                    libc::SYS_connect,
                    libc::SYS_fcntl,
                    #[cfg(target_arch = "x86_64")]
                    libc::SYS_poll,
                    libc::SYS_ppoll,
                    libc::SYS_getsockopt,
                    libc::SYS_statx,
                    libc::SYS_newfstatat,
                    libc::SYS_execve,
                    libc::SYS_clone3,
                    libc::SYS_clone,
                    libc::SYS_pipe2,
                    libc::SYS_wait4,
                    libc::SYS_waitid,
                ]);
            } else {
                // Runtime libraries may lazily open files (e.g. under /sys):
                // fail those with EACCES rather than killing the worker.
                // Landlock denies the access regardless.
                programs.push(compile(
                    vec![
                        libc::SYS_openat,
                        #[cfg(target_arch = "x86_64")]
                        libc::SYS_open,
                    ],
                    SeccompAction::Allow,
                    SeccompAction::Errno(libc::EACCES as u32),
                )?);
            }
            programs.push(compile(
                allowed,
                SeccompAction::KillProcess,
                SeccompAction::Allow,
            )?);
            Some(programs)
        }
        Seccomp::DenyList => {
            let denied = vec![
                libc::SYS_ptrace,
                libc::SYS_process_vm_readv,
                libc::SYS_process_vm_writev,
                libc::SYS_mount,
                libc::SYS_umount2,
                libc::SYS_pivot_root,
                libc::SYS_chroot,
                libc::SYS_unshare,
                libc::SYS_setns,
                libc::SYS_kexec_load,
                libc::SYS_init_module,
                libc::SYS_finit_module,
                libc::SYS_delete_module,
                libc::SYS_bpf,
                libc::SYS_perf_event_open,
                libc::SYS_keyctl,
                libc::SYS_add_key,
                libc::SYS_request_key,
                libc::SYS_userfaultfd,
                libc::SYS_io_uring_setup,
                libc::SYS_io_uring_enter,
                libc::SYS_io_uring_register,
                libc::SYS_open_by_handle_at,
                libc::SYS_name_to_handle_at,
                libc::SYS_swapon,
                libc::SYS_swapoff,
                libc::SYS_reboot,
                libc::SYS_acct,
                libc::SYS_quotactl,
                libc::SYS_fanotify_init,
                libc::SYS_fsopen,
                libc::SYS_fsmount,
                libc::SYS_move_mount,
                libc::SYS_open_tree,
            ];
            Some(vec![compile(
                denied,
                SeccompAction::Allow,
                SeccompAction::Errno(libc::EPERM as u32),
            )?])
        }
    }
}

/// Byte strings for the user-namespace id maps, prepared before fork.
struct IdMaps {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
}

impl IdMaps {
    fn new() -> Self {
        // SAFETY: getuid/getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
        }
    }
}

fn write_proc(path: &std::ffi::CStr, data: &[u8]) -> bool {
    // SAFETY: plain open/write/close on a NUL-terminated path; async-signal-safe.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return false;
        }
        let ok = libc::write(fd, data.as_ptr().cast(), data.len()) == data.len() as isize;
        libc::close(fd);
        ok
    }
}

/// New user namespace (so this works unprivileged) with our own ids mapped,
/// plus an empty network namespace.
fn enter_netns(maps: &IdMaps) -> bool {
    // SAFETY: unshare has no memory-safety preconditions.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return false;
    }
    write_proc(c"/proc/self/setgroups", b"deny")
        && write_proc(c"/proc/self/uid_map", &maps.uid_map)
        && write_proc(c"/proc/self/gid_map", &maps.gid_map)
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
    set(libc::RLIMIT_AS, limits.address_space)
        & set(libc::RLIMIT_CPU, limits.cpu_seconds)
        & set(libc::RLIMIT_FSIZE, limits.file_size)
        & set(libc::RLIMIT_NOFILE, limits.open_files)
        & set(libc::RLIMIT_CORE, Some(0))
}

fn restrict_self(ruleset: &Ruleset) -> bool {
    let Some(fd) = &ruleset.fd else { return false };
    // SAFETY: prctl and landlock_restrict_self take plain integer arguments.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) == 0
    }
}

fn seccomp_name(mode: Seccomp) -> &'static str {
    match mode {
        Seccomp::DenyList => "seccomp_denylist",
        _ => "seccomp",
    }
}

pub fn confine_self(profile: &Profile) -> Applied {
    let mut applied = Applied::default();
    let ruleset = build_ruleset(profile);
    let programs = seccomp_programs(profile.seccomp);

    applied.record("rlimits", set_rlimits(&profile.limits));
    if profile.network == Network::Blocked {
        applied.record("netns", enter_netns(&IdMaps::new()));
    }
    let restricted = restrict_self(&ruleset);
    applied.record("landlock_fs", restricted && ruleset.fs);
    applied.record("landlock_net", restricted && ruleset.net);
    if restricted && ruleset.scope {
        applied.active.push("landlock_scope".into());
    }
    // Close the ruleset fd before seccomp: dropping it later would need
    // syscalls (e.g. debug-build fcntl checks) the allow-list forbids.
    drop(ruleset);
    let seccomp_ok =
        programs.is_some_and(|ps| ps.iter().all(|p| seccompiler::apply_filter(p).is_ok()));
    applied.record(seccomp_name(profile.seccomp), seccomp_ok);
    applied
}

pub fn spawn(
    profile: &Profile,
    program: &Path,
    configure: impl Fn(&mut Command),
    allow_reduced: bool,
) -> Result<(Child, Applied), SpawnError> {
    let mut with_netns = profile.network == Network::Blocked;
    loop {
        let ruleset = build_ruleset(profile);
        let programs = seccomp_programs(profile.seccomp);

        let mut applied = Applied::default();
        applied.active.push("rlimits".into());
        if profile.network == Network::Blocked {
            applied.record("netns", with_netns);
        }
        applied.record("landlock_fs", ruleset.fs);
        applied.record("landlock_net", ruleset.net);
        if ruleset.scope {
            applied.active.push("landlock_scope".into());
        }
        applied.record(seccomp_name(profile.seccomp), programs.is_some());
        if !applied.missing.is_empty() && !allow_reduced {
            return Err(SpawnError::Reduced(applied.missing));
        }

        let mut cmd = Command::new(program);
        configure(&mut cmd);
        cmd.env_clear()
            .envs(profile.env.iter().map(|(k, v)| (k, v)));
        let maps = IdMaps::new();
        let limits = profile.limits.clone();
        let programs = programs.unwrap_or_default();
        // SAFETY: the closure performs only async-signal-safe syscalls on data
        // prepared before fork (no allocation, no locks).
        unsafe {
            cmd.pre_exec(move || {
                if !set_rlimits(&limits) {
                    return Err(io::Error::last_os_error());
                }
                if with_netns && !enter_netns(&maps) {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                if ruleset.fd.is_some() && !restrict_self(&ruleset) {
                    return Err(io::Error::last_os_error());
                }
                for p in &programs {
                    if seccompiler::apply_filter(p).is_err() {
                        return Err(io::Error::from_raw_os_error(libc::EPERM));
                    }
                }
                Ok(())
            });
        }
        match cmd.spawn() {
            Ok(child) => return Ok((child, applied)),
            // User namespaces can be disabled (sysctl, AppArmor): retry without
            // the network namespace; Landlock still denies TCP when available.
            Err(e) if with_netns && e.raw_os_error() == Some(libc::EPERM) => with_netns = false,
            Err(e) => return Err(SpawnError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn scratch(name: &str) -> crate::testutil::TempDir {
        crate::testutil::temp_dir("bb-sandbox", name)
    }

    fn sh(profile: &Profile, script: &str) -> (i32, String) {
        let (child, _) = spawn(
            profile,
            Path::new("/bin/sh"),
            |c| {
                c.arg("-c")
                    .arg(script)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null());
            },
            true,
        )
        .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    #[test]
    fn external_tool_profile_confines_filesystem() {
        if landlock_abi() < 1 {
            return;
        }
        let dir = scratch("fs");
        let input = dir.join("input.txt");
        std::fs::write(&input, "hello").unwrap();
        let work = dir.join("work");
        std::fs::create_dir(&work).unwrap();
        let profile = Profile::external_tool(vec![], vec![input.clone()], work.clone());

        let (code, out) = sh(&profile, &format!("cat {}", input.display()));
        assert_eq!((code, out.as_str()), (0, "hello"));
        let (code, _) = sh(&profile, &format!("echo x > {}/out.txt", work.display()));
        assert_eq!(code, 0, "scratch should be writable");
        let home = std::env::var("HOME").unwrap();
        let (code, _) = sh(&profile, &format!("ls {home}"));
        assert_ne!(code, 0, "home must not be readable");
        let (code, _) = sh(&profile, &format!("echo x > {}/escape.txt", dir.display()));
        assert_ne!(code, 0, "outside scratch must not be writable");
    }

    #[test]
    fn external_tool_profile_has_no_network() {
        let dir = scratch("net");
        let profile = Profile::external_tool(vec![], vec![], dir.to_path_buf());
        // bash's /dev/tcp needs bash; use it when present.
        if !Path::new("/bin/bash").exists() {
            return;
        }
        let (child, applied) = spawn(
            &profile,
            Path::new("/bin/bash"),
            |c| {
                c.arg("-c")
                    .arg("exec 3<>/dev/tcp/1.1.1.1/443")
                    .stderr(Stdio::null());
            },
            true,
        )
        .unwrap();
        let status = child.wait_with_output().unwrap().status;
        assert!(!status.success(), "connect must fail; applied={applied:?}");
    }

    #[test]
    fn reduced_isolation_is_refused_by_default() {
        let reduced_dir = scratch("reduced");
        let mut profile = Profile::external_tool(vec![], vec![], reduced_dir.to_path_buf());
        profile.seccomp = Seccomp::DenyList;
        if landlock_abi() >= 4 {
            // Fully supported host: strict spawn must succeed.
            assert!(spawn(&profile, Path::new("/bin/true"), |_| {}, false).is_ok());
        } else {
            assert!(matches!(
                spawn(&profile, Path::new("/bin/true"), |_| {}, false),
                Err(SpawnError::Reduced(_))
            ));
        }
    }
}

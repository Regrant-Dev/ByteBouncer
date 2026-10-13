//! Windows backend: AppContainer + Job Object.
//!
//! An AppContainer process runs with a lowbox token: every access check on
//! files, registry keys and other securable objects additionally requires an
//! ACE for the container's SID (or for "ALL APPLICATION PACKAGES", which
//! covers system directories), and the network is unreachable unless the
//! token carries a network capability. That is the only unprivileged file
//! and network isolation Windows offers, and it can only be applied when the
//! process is created, so the parent launches confined processes itself:
//!
//! 1. derive a fresh AppContainer SID for this launch
//!    (`bytebouncer.<label>.<pid>.<n>`; no profile registration needed);
//! 2. grant that SID access to exactly the profile's paths via ACL entries
//!    (removed again when the [`Child`] is dropped);
//! 3. create the process suspended with `SECURITY_CAPABILITIES` (no
//!    capabilities, or only `internetClient` for the fetch worker) and an
//!    explicit inherited-handle list (its three pipes only);
//! 4. assign it to a Job Object (kill on close, memory and CPU limits, UI
//!    restrictions, and for workers an active-process limit of 1 so it cannot
//!    start other programs), then resume it.
//!
//! [`confine_self`] in the worker only verifies the token and job.

use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, CopySid, DACL_SECURITY_INFORMATION, FreeSid, GetLengthSid, GetTokenInformation,
    NO_INHERITANCE, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_GROUPS, TOKEN_QUERY, TokenCapabilities,
    TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use crate::{Applied, Limits, Network, Profile, SpawnError};

/// Well-known capability SID for outbound internet access.
const INTERNET_CLIENT: &str = "S-1-15-3-1";

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn hresult(hr: i32) -> io::Result<()> {
    if hr >= 0 {
        Ok(())
    } else if (hr as u32 >> 16) & 0x1fff == 7 {
        // FACILITY_WIN32: the low word is a Win32 error code.
        Err(io::Error::from_raw_os_error(hr & 0xffff))
    } else {
        Err(io::Error::other(format!("HRESULT {:#010x}", hr as u32)))
    }
}

/// An owned SID (u32 storage keeps it suitably aligned).
struct Sid(Vec<u32>);

impl Sid {
    fn as_psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }

    /// # Safety
    /// `p` must point to a valid SID.
    unsafe fn copy_from(p: PSID) -> io::Result<Self> {
        // SAFETY: p is a valid SID per the caller.
        let len = unsafe { GetLengthSid(p) };
        let mut buf = vec![0u32; (len as usize).div_ceil(4)];
        // SAFETY: buf holds at least `len` bytes.
        if unsafe { CopySid(len, buf.as_mut_ptr() as PSID, p) } == 0 {
            return Err(last_error());
        }
        Ok(Self(buf))
    }

    fn from_string(s: &str) -> io::Result<Self> {
        let w = wide(OsStr::new(s));
        let mut p: PSID = null_mut();
        // SAFETY: w is NUL-terminated; p receives a LocalAlloc'd SID.
        if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut p) } == 0 {
            return Err(last_error());
        }
        // SAFETY: p is a valid SID allocated by the call above, freed once.
        let sid = unsafe { Self::copy_from(p) };
        unsafe { LocalFree(p) };
        sid
    }

    fn app_container(name: &[u16]) -> io::Result<Self> {
        let mut p: PSID = null_mut();
        // SAFETY: name is NUL-terminated; p receives a SID freed with FreeSid.
        hresult(unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut p) })?;
        // SAFETY: p is valid until FreeSid below.
        let sid = unsafe { Self::copy_from(p) };
        unsafe { FreeSid(p) };
        sid
    }
}

/// Serializes read-modify-write cycles on DACLs within this process.
static ACL_LOCK: Mutex<()> = Mutex::new(());

fn set_ace(path: &[u16], sid: &Sid, mode: i32, mask: u32, inherit: u32) -> io::Result<()> {
    let _guard = ACL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut dacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: path is NUL-terminated; out-pointers are valid; sd is freed below.
    let e = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if e != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(e as i32));
    }
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: mode,
        grfInheritance: inherit,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.as_psid() as *mut u16,
        },
    };
    let mut new_acl: *mut ACL = null_mut();
    // SAFETY: entry and dacl are valid; new_acl is LocalAlloc'd by the call.
    let e = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut new_acl) };
    let result = if e != ERROR_SUCCESS {
        Err(io::Error::from_raw_os_error(e as i32))
    } else {
        // SAFETY: path and new_acl are valid.
        let e = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                new_acl,
                null(),
            )
        };
        // SAFETY: allocated by SetEntriesInAclW.
        unsafe { LocalFree(new_acl as *mut c_void) };
        if e == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(e as i32))
        }
    };
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    result
}

const READ: u32 = FILE_GENERIC_READ;
const READ_EXEC: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const READ_WRITE: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD;

/// ACL entries granted to one AppContainer SID; revoked on drop.
struct Grants {
    sid: Sid,
    paths: Vec<Vec<u16>>,
}

impl Grants {
    /// Grant `sid` access to the profile's paths plus `extra_exec`. Missing
    /// paths are skipped. A failed grant (e.g. a directory the user cannot
    /// re-ACL, such as Program Files, which every AppContainer can already
    /// read) only ever leaves the sandbox with less access.
    fn apply(sid: Sid, profile: &Profile, extra_exec: &[&Path]) -> Self {
        let mut grants = Self { sid, paths: vec![] };
        let sets: [(Vec<&Path>, u32); 3] = [
            (
                profile.read_only.iter().map(PathBuf::as_path).collect(),
                READ,
            ),
            (
                profile
                    .executable
                    .iter()
                    .map(PathBuf::as_path)
                    .chain(extra_exec.iter().copied())
                    .collect(),
                READ_EXEC,
            ),
            (
                profile.read_write.iter().map(PathBuf::as_path).collect(),
                READ_WRITE,
            ),
        ];
        for (paths, mask) in sets {
            for path in paths {
                let Ok(meta) = std::fs::metadata(path) else {
                    continue;
                };
                let inherit = if meta.is_dir() {
                    SUB_CONTAINERS_AND_OBJECTS_INHERIT
                } else {
                    NO_INHERITANCE
                };
                let w = wide(path.as_os_str());
                if set_ace(&w, &grants.sid, GRANT_ACCESS, mask, inherit).is_ok() {
                    grants.paths.push(w);
                }
            }
        }
        grants
    }
}

impl Drop for Grants {
    fn drop(&mut self) {
        for p in &self.paths {
            let _ = set_ace(p, &self.sid, REVOKE_ACCESS, 0, NO_INHERITANCE);
        }
    }
}

fn create_job(limits: &Limits, single_process: bool) -> io::Result<OwnedHandle> {
    // SAFETY: anonymous job with default security.
    let h = unsafe { CreateJobObjectW(null(), null()) };
    if h.is_null() {
        return Err(last_error());
    }
    // SAFETY: h is a new handle we own.
    let job = unsafe { OwnedHandle::from_raw_handle(h) };
    // SAFETY: plain-old-data struct.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    let mut flags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if let Some(m) = limits.address_space {
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = usize::try_from(m).unwrap_or(usize::MAX);
    }
    if let Some(c) = limits.cpu_seconds {
        flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        info.BasicLimitInformation.PerProcessUserTimeLimit = (c as i64).saturating_mul(10_000_000);
    }
    if single_process {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
    }
    info.BasicLimitInformation.LimitFlags = flags;
    // SAFETY: info is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
    if unsafe {
        SetInformationJobObject(
            h,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    // SAFETY: ui is a valid JOBOBJECT_BASIC_UI_RESTRICTIONS.
    if unsafe {
        SetInformationJobObject(
            h,
            JobObjectBasicUIRestrictions,
            &ui as *const _ as *const c_void,
            size_of_val(&ui) as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(job)
}

/// Anonymous pipe; both ends start non-inheritable.
fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut r, mut w): (HANDLE, HANDLE) = (null_mut(), null_mut());
    // SAFETY: out-pointers are valid; default (non-inheritable) security.
    if unsafe { CreatePipe(&mut r, &mut w, null(), 0) } == 0 {
        return Err(last_error());
    }
    // SAFETY: both handles were just created and are owned here.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(r),
            OwnedHandle::from_raw_handle(w),
        )
    })
}

/// Append one argument using the MSVC runtime's quoting rules.
fn push_arg(cmd: &mut Vec<u16>, arg: &OsStr, force_quote: bool) {
    if !cmd.is_empty() {
        cmd.push(b' ' as u16);
    }
    let units: Vec<u16> = arg.encode_wide().collect();
    let quote = force_quote
        || units.is_empty()
        || units.iter().any(|&c| c == b' ' as u16 || c == b'\t' as u16);
    if quote {
        cmd.push(b'"' as u16);
    }
    let mut backslashes = 0;
    for &c in &units {
        if c == b'\\' as u16 {
            backslashes += 1;
        } else {
            if c == b'"' as u16 {
                cmd.extend(std::iter::repeat_n(b'\\' as u16, backslashes + 1));
            }
            backslashes = 0;
        }
        cmd.push(c);
    }
    if quote {
        cmd.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        cmd.push(b'"' as u16);
    }
}

fn command_line(program: &Path, args: &[&OsStr]) -> Vec<u16> {
    let mut cmd = Vec::new();
    push_arg(&mut cmd, program.as_os_str(), true);
    for a in args {
        push_arg(&mut cmd, a, false);
    }
    cmd.push(0);
    cmd
}

/// `profile.env` plus what system DLLs need, as a sorted Unicode block.
fn env_block(env: &[(OsString, OsString)]) -> Vec<u16> {
    let mut vars: std::collections::BTreeMap<String, (OsString, OsString)> = Default::default();
    for key in ["SystemRoot", "windir"] {
        if let Some(v) = std::env::var_os(key) {
            vars.insert(key.to_uppercase(), (key.into(), v));
        }
    }
    for (k, v) in env {
        vars.insert(k.to_string_lossy().to_uppercase(), (k.clone(), v.clone()));
    }
    let mut block = Vec::new();
    for (k, v) in vars.values() {
        block.extend(k.encode_wide());
        block.push(b'=' as u16);
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0);
    block.push(0);
    block
}

fn default_cwd(profile: &Profile) -> PathBuf {
    // An inaccessible working directory can break process start-up inside
    // an AppContainer; System32 is readable by every AppContainer.
    if let Some(d) = profile.read_write.iter().find(|d| d.is_dir()) {
        return d.clone();
    }
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    Path::new(&root).join("System32")
}

static LAUNCH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A confined process launched by this module. Mirrors the parts of
/// [`std::process::Child`] that ByteBouncer uses.
pub struct Child {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    process: OwnedHandle,
    pid: u32,
    job: Option<OwnedHandle>,
    grants: Option<Grants>,
    /// Registered AppContainer profile to delete.
    registered: Option<Vec<u16>>,
    status: Option<ExitStatus>,
}

impl Child {
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Kill the process and everything else in its job.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        // SAFETY: valid job/process handles owned by self.
        let ok = match &self.job {
            Some(job) => unsafe { TerminateJobObject(job.as_raw_handle(), 1) },
            None => unsafe { TerminateProcess(self.process.as_raw_handle(), 1) },
        };
        if ok == 0 { Err(last_error()) } else { Ok(()) }
    }

    fn wait_ms(&mut self, ms: u32) -> io::Result<Option<ExitStatus>> {
        if let Some(s) = self.status {
            return Ok(Some(s));
        }
        // SAFETY: valid process handle.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: valid process handle and out-pointer.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(last_error());
                }
                let status = ExitStatus::from_raw(code);
                self.status = Some(status);
                Ok(Some(status))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(last_error()),
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.wait_ms(0)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdin.take());
        self.wait_ms(INFINITE)?
            .ok_or_else(|| io::Error::other("wait returned without exit status"))
    }

    pub fn wait_with_output(mut self) -> io::Result<Output> {
        use std::io::Read;
        drop(self.stdin.take());
        let err = self.stderr.take().map(|mut e| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                e.read_to_end(&mut buf).map(|_| buf)
            })
        });
        let mut stdout = Vec::new();
        if let Some(mut o) = self.stdout.take() {
            o.read_to_end(&mut stdout)?;
        }
        let stderr = match err {
            Some(h) => h
                .join()
                .map_err(|_| io::Error::other("stderr reader panicked"))??,
            None => Vec::new(),
        };
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // Closing the job kills anything still running in it (kill-on-close);
        // wait for that before removing the ACL grants.
        if let Some(job) = self.job.take() {
            drop(job);
            let _ = self.wait_ms(5_000);
        }
        drop(self.grants.take());
        if let Some(name) = self.registered.take() {
            // SAFETY: name is NUL-terminated.
            unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        }
    }
}

/// Register an AppContainer profile named `name` (already existing is fine).
fn register_profile(name: &[u16]) -> io::Result<()> {
    const ALREADY_EXISTS: i32 = 0x800700B7_u32 as i32;
    let disp = wide(OsStr::new("ByteBouncer sandbox"));
    let mut p: PSID = null_mut();
    // SAFETY: strings are NUL-terminated; p receives a SID freed below.
    let hr = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            disp.as_ptr(),
            disp.as_ptr(),
            null(),
            0,
            &mut p,
        )
    };
    if hr == ALREADY_EXISTS {
        return Ok(());
    }
    hresult(hr)
        .map_err(|e| io::Error::new(e.kind(), format!("registering AppContainer profile: {e}")))?;
    // SAFETY: p was allocated by CreateAppContainerProfile.
    unsafe { FreeSid(p) };
    Ok(())
}

struct Launch<'a> {
    label: &'a str,
    profile: &'a Profile,
    program: &'a Path,
    args: Vec<&'a OsStr>,
    cwd: Option<PathBuf>,
    single_process: bool,
}

fn launch(l: Launch<'_>) -> io::Result<Child> {
    let n = LAUNCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = wide(OsStr::new(&format!(
        "bytebouncer.{}.{}.{n}",
        l.label,
        std::process::id()
    )));
    let sid = Sid::app_container(&name)?;
    let caps: Vec<Sid> = match l.profile.network {
        Network::Blocked => vec![],
        Network::TcpConnectPorts(_) => vec![Sid::from_string(INTERNET_CLIENT)?],
    };
    let job = create_job(&l.profile.limits, l.single_process)?;
    let grants = Grants::apply(Sid(sid.0.clone()), l.profile, &[l.program]);

    let (in_r, in_w) = pipe()?;
    let (out_r, out_w) = pipe()?;
    let (err_r, err_w) = pipe()?;
    let child_ends = [
        in_r.as_raw_handle(),
        out_w.as_raw_handle(),
        err_w.as_raw_handle(),
    ];

    let app = wide(l.program.as_os_str());
    let cwd = wide(l.cwd.unwrap_or_else(|| default_cwd(l.profile)).as_os_str());
    let env = env_block(&l.profile.env);

    // Register the AppContainer profile up front: starting a process in an
    // unregistered container fails on current Windows (with a misleading
    // ERROR_ENVVAR_NOT_FOUND), and registration errors are worth reporting
    // as themselves. The profile is deleted when the child is dropped.
    register_profile(&name)?;
    let pi = match create_process(
        &app,
        &command_line(l.program, &l.args),
        &env,
        &cwd,
        &sid,
        &caps,
        child_ends,
    ) {
        Ok(pi) => pi,
        Err(e) => {
            // SAFETY: name is NUL-terminated.
            unsafe { DeleteAppContainerProfile(name.as_ptr()) };
            return Err(e);
        }
    };
    // SAFETY: CreateProcessW returned these handles; we own them.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(pi.hProcess),
            OwnedHandle::from_raw_handle(pi.hThread),
        )
    };
    // SAFETY: valid job and process handles.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let e = last_error();
        // SAFETY: valid process handle; it never ran (still suspended).
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        // SAFETY: name is NUL-terminated.
        unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        return Err(e);
    }
    // SAFETY: valid thread handle of the suspended main thread.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        let e = last_error();
        // SAFETY: valid job handle.
        unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
        // SAFETY: name is NUL-terminated.
        unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        return Err(e);
    }
    drop((in_r, out_w, err_w));
    Ok(Child {
        stdin: Some(ChildStdin::from(in_w)),
        stdout: Some(ChildStdout::from(out_r)),
        stderr: Some(ChildStderr::from(err_r)),
        process,
        pid: pi.dwProcessId,
        job: Some(job),
        grants: Some(grants),
        registered: Some(name),
        status: None,
    })
}

/// Process creation guarded so the child ends of our pipes are inheritable
/// only for the duration of the call, and only these three are inherited.
static INHERIT_LOCK: Mutex<()> = Mutex::new(());

fn create_process(
    app: &[u16],
    cmdline: &[u16],
    env: &[u16],
    cwd: &[u16],
    sid: &Sid,
    caps: &[Sid],
    stdio: [HANDLE; 3],
) -> io::Result<PROCESS_INFORMATION> {
    let mut cmdline = cmdline.to_vec();
    let mut size = 0usize;
    // SAFETY: size query with a null list is the documented first call.
    unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
    let mut list_buf = vec![0u64; size.div_ceil(8)];
    let list = list_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: list points to `size` writable bytes.
    if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
        return Err(last_error());
    }
    struct ListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for ListGuard {
        fn drop(&mut self) {
            // SAFETY: the list was initialized above.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _list_guard = ListGuard(list);

    let mut cap_attrs: Vec<SID_AND_ATTRIBUTES> = caps
        .iter()
        .map(|c| SID_AND_ATTRIBUTES {
            Sid: c.as_psid(),
            Attributes: 4, /* SE_GROUP_ENABLED */
        })
        .collect();
    let sc = SECURITY_CAPABILITIES {
        AppContainerSid: sid.as_psid(),
        Capabilities: if cap_attrs.is_empty() {
            null_mut()
        } else {
            cap_attrs.as_mut_ptr()
        },
        CapabilityCount: cap_attrs.len() as u32,
        Reserved: 0,
    };
    // SAFETY: sc and stdio outlive CreateProcessW below (the list stores pointers).
    unsafe {
        if UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &sc as *const _ as *const c_void,
            size_of::<SECURITY_CAPABILITIES>(),
            null_mut(),
            null(),
        ) == 0
        {
            return Err(last_error());
        }
        if UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            stdio.as_ptr() as *const c_void,
            size_of_val(&stdio),
            null_mut(),
            null(),
        ) == 0
        {
            return Err(last_error());
        }
    }

    // SAFETY: plain-old-data structs.
    let mut si: STARTUPINFOEXW = unsafe { zeroed() };
    si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = stdio[0];
    si.StartupInfo.hStdOutput = stdio[1];
    si.StartupInfo.hStdError = stdio[2];
    si.lpAttributeList = list;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let _inherit = INHERIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for h in stdio {
        // SAFETY: h is a valid handle owned by the caller.
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    }
    // SAFETY: all pointers are valid, NUL-terminated where required, and
    // outlive the call; cmdline is a mutable copy as the API requires.
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            1,
            // No console: stdio is the pipes, and no conhost.exe is started
            // (which would otherwise count against the job's process limit).
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED
                | DETACHED_PROCESS,
            env.as_ptr() as *const c_void,
            cwd.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    let err = (ok == 0).then(last_error);
    for h in stdio {
        // SAFETY: as above.
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) };
    }
    drop(cap_attrs);
    match err {
        Some(e) => Err(e),
        None => Ok(pi),
    }
}

/// Fallback when the AppContainer launch fails: a plain process in a job.
/// The worker's `confine_self` then reports the AppContainer as missing.
fn plain_worker(profile: &Profile, exe: &Path, args: &[&OsStr]) -> io::Result<Child> {
    let mut child = Command::new(exe)
        .args(args)
        .env_clear()
        .envs(profile.env.iter().map(|(k, v)| (k, v)))
        .envs(
            ["SystemRoot", "windir"]
                .iter()
                .filter_map(|k| Some((*k, std::env::var_os(k)?))),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let pid = child.id();
    // SAFETY: into_raw_handle transfers ownership of the process handle.
    let process = unsafe { OwnedHandle::from_raw_handle(child.into_raw_handle()) };
    let job = create_job(&profile.limits, true).ok().filter(|job| {
        // SAFETY: valid handles.
        unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) != 0 }
    });
    Ok(Child {
        stdin,
        stdout,
        stderr,
        process,
        pid,
        job,
        grants: None,
        registered: None,
        status: None,
    })
}

pub fn spawn_worker(
    label: &str,
    profile: &Profile,
    exe: &Path,
    args: &[&OsStr],
) -> io::Result<Child> {
    let confined = launch(Launch {
        label,
        profile,
        program: exe,
        args: args.to_vec(),
        cwd: None,
        single_process: true,
    });
    match confined {
        Ok(c) => Ok(c),
        Err(e) => {
            eprintln!(
                "bytebouncer-sandbox: AppContainer launch failed ({e}); worker will report reduced isolation"
            );
            plain_worker(profile, exe, args)
        }
    }
}

fn expected(
    profile: &Profile,
    applied: &mut Applied,
    appcontainer: bool,
    net_ok: bool,
    job_ok: bool,
) {
    applied.record("appcontainer_fs", appcontainer);
    applied.record("appcontainer_net", appcontainer && net_ok);
    applied.record("job_limits", job_ok);
    if let Network::TcpConnectPorts(_) = profile.network {
        // internetClient allows any remote port.
        applied.record("port_restriction", false);
    }
}

pub fn spawn(
    profile: &Profile,
    program: &Path,
    configure: impl Fn(&mut Command),
    allow_reduced: bool,
) -> Result<(Child, Applied), SpawnError> {
    let mut applied = Applied::default();
    expected(profile, &mut applied, true, true, true);
    if !applied.missing.is_empty() && !allow_reduced {
        return Err(SpawnError::Reduced(applied.missing));
    }
    let mut cmd = Command::new(program);
    configure(&mut cmd);
    let child = launch(Launch {
        label: "tool",
        profile,
        program,
        args: cmd.get_args().collect(),
        cwd: cmd.get_current_dir().map(Path::to_path_buf),
        single_process: false,
    })
    .map_err(SpawnError::Io)?;
    Ok((child, applied))
}

/// Read a token information class into a u64-aligned buffer.
fn token_info(token: HANDLE, class: i32) -> Option<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: size query.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: buf holds at least len bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8) as u32,
            &mut len,
        )
    };
    (ok != 0).then_some(buf)
}

/// Worker side: verify the confinement the parent applied.
pub fn confine_self(profile: &Profile) -> Applied {
    let mut token: HANDLE = null_mut();
    // SAFETY: pseudo-handle for the current process; out-pointer valid.
    let have_token = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0;
    let (mut appcontainer, mut caps) = (false, usize::MAX);
    if have_token {
        // SAFETY: token was just opened and is owned here.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let t = token.as_raw_handle();
        appcontainer = token_info(t, TokenIsAppContainer).is_some_and(|b| b[0] as u32 != 0);
        if let Some(b) = token_info(t, TokenCapabilities) {
            // SAFETY: the buffer holds a TOKEN_GROUPS header.
            caps = unsafe { (*(b.as_ptr() as *const TOKEN_GROUPS)).GroupCount as usize };
        }
    }
    let net_ok = match profile.network {
        Network::Blocked => caps == 0,
        Network::TcpConnectPorts(_) => caps <= 1,
    };

    // SAFETY: plain-old-data struct; a null job handle queries the job of
    // the calling process.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    let queried = unsafe {
        QueryInformationJobObject(
            null_mut(),
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut c_void,
            size_of_val(&info) as u32,
            null_mut(),
        )
    } != 0;
    let flags = info.BasicLimitInformation.LimitFlags;
    let mut want = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if profile.limits.address_space.is_some() {
        want |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    }
    if profile.limits.cpu_seconds.is_some() {
        want |= JOB_OBJECT_LIMIT_PROCESS_TIME;
    }
    let job_ok = queried && flags & want == want;
    let no_child = queried
        && flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0
        && info.BasicLimitInformation.ActiveProcessLimit == 1;

    let mut applied = Applied::default();
    expected(profile, &mut applied, appcontainer, net_ok, job_ok);
    applied.record("job_no_child", no_child);
    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(program: &str, args: &[&str]) -> String {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let mut v = command_line(Path::new(program), &args);
        v.pop();
        String::from_utf16(&v).unwrap()
    }

    #[test]
    fn quoting_follows_msvc_rules() {
        assert_eq!(line(r"C:\a b\x.exe", &["plain"]), r#""C:\a b\x.exe" plain"#);
        assert_eq!(line("x", &["a b", ""]), r#""x" "a b" """#);
        assert_eq!(line("x", &[r#"a"b"#]), r#""x" a\"b"#);
        assert_eq!(line("x", &[r"dir\ "]), r#""x" "dir\ ""#);
        assert_eq!(line("x", &[r"c:\path with\"]), r#""x" "c:\path with\\""#);
    }

    #[test]
    fn env_block_is_double_terminated_and_deduplicated() {
        let b = env_block(&[("Path".into(), "a".into()), ("PATH".into(), "b".into())]);
        assert_eq!(&b[b.len() - 2..], &[0, 0]);
        let s = String::from_utf16_lossy(&b);
        assert!(s.contains("PATH=b") && !s.contains("Path=a"));
    }
}

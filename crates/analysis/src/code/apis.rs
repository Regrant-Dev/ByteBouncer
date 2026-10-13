//! API classification for the code map: which imported (or named, statically
//! linked) functions matter for "where does my data go, what is stored, what
//! is sent". Categories are capabilities, not intent.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Category names (stable strings used in the `CodeMap` and model tools).
pub(crate) const NETWORK_SEND: &str = "network_send";
pub(crate) const NETWORK_SETUP: &str = "network_setup";
pub(crate) const NETWORK_RECEIVE: &str = "network_receive";
pub(crate) const FILE_WRITE: &str = "file_write";
pub(crate) const FILE_READ: &str = "file_read";
pub(crate) const FILE_OPEN: &str = "file_open";
pub(crate) const REGISTRY_WRITE: &str = "registry_write";
pub(crate) const REGISTRY_READ: &str = "registry_read";
pub(crate) const IDENTIFIERS: &str = "identifiers";
pub(crate) const CLIPBOARD: &str = "clipboard";
pub(crate) const INPUT_CAPTURE: &str = "input_capture";
pub(crate) const SCREEN_CAPTURE: &str = "screen_capture";
pub(crate) const DISPLAY_CONTEXT: &str = "display_context";
pub(crate) const MEDIA_CAPTURE: &str = "media_capture";
pub(crate) const PROCESS_CREATE: &str = "process_create";
pub(crate) const PROCESS_INJECTION: &str = "process_injection";
pub(crate) const CREDENTIALS: &str = "credentials";
pub(crate) const CRYPTO: &str = "crypto";
pub(crate) const PERSISTENCE: &str = "persistence";
pub(crate) const DYNAMIC_LOAD: &str = "dynamic_load";
pub(crate) const PRIVILEGE: &str = "privilege";
pub(crate) const ANTI_ANALYSIS: &str = "anti_analysis";

pub(crate) const ALL: &[&str] = &[
    NETWORK_SEND,
    NETWORK_SETUP,
    NETWORK_RECEIVE,
    FILE_WRITE,
    FILE_READ,
    FILE_OPEN,
    REGISTRY_WRITE,
    REGISTRY_READ,
    IDENTIFIERS,
    CLIPBOARD,
    INPUT_CAPTURE,
    SCREEN_CAPTURE,
    DISPLAY_CONTEXT,
    MEDIA_CAPTURE,
    PROCESS_CREATE,
    PROCESS_INJECTION,
    CREDENTIALS,
    CRYPTO,
    PERSISTENCE,
    DYNAMIC_LOAD,
    PRIVILEGE,
    ANTI_ANALYSIS,
];

/// Relevance weight of a category when ranking functions for the model.
pub(crate) fn weight(cat: &str) -> u32 {
    match cat {
        NETWORK_SEND | IDENTIFIERS | INPUT_CAPTURE | SCREEN_CAPTURE | PROCESS_INJECTION
        | CREDENTIALS => 10,
        PERSISTENCE | CLIPBOARD | MEDIA_CAPTURE | REGISTRY_WRITE => 8,
        NETWORK_SETUP | NETWORK_RECEIVE | PROCESS_CREATE => 6,
        FILE_WRITE | DYNAMIC_LOAD | PRIVILEGE | ANTI_ANALYSIS => 4,
        CRYPTO | REGISTRY_READ | FILE_OPEN => 3,
        FILE_READ => 2,
        _ => 1,
    }
}

/// (name without A/W suffix, category). Windows names are listed once;
/// `classify` also accepts the `A`/`W` variants.
const TABLE: &[(&str, &str)] = &[
    // Network: sending data.
    ("send", NETWORK_SEND),
    ("sendto", NETWORK_SEND),
    ("sendmsg", NETWORK_SEND),
    ("sendmmsg", NETWORK_SEND),
    ("WSASend", NETWORK_SEND),
    ("WSASendTo", NETWORK_SEND),
    ("WSASendMsg", NETWORK_SEND),
    ("WinHttpSendRequest", NETWORK_SEND),
    ("WinHttpWriteData", NETWORK_SEND),
    ("InternetWriteFile", NETWORK_SEND),
    ("HttpSendRequest", NETWORK_SEND),
    ("HttpSendRequestEx", NETWORK_SEND),
    ("InternetOpenUrl", NETWORK_SEND),
    ("FtpPutFile", NETWORK_SEND),
    ("curl_easy_perform", NETWORK_SEND),
    ("curl_multi_perform", NETWORK_SEND),
    ("curl_easy_send", NETWORK_SEND),
    ("SSL_write", NETWORK_SEND),
    ("SSL_write_ex", NETWORK_SEND),
    ("gnutls_record_send", NETWORK_SEND),
    ("mbedtls_ssl_write", NETWORK_SEND),
    ("soup_session_send", NETWORK_SEND),
    ("soup_session_send_message", NETWORK_SEND),
    ("CFReadStreamOpen", NETWORK_SEND),
    // Network: connection setup / name resolution.
    ("socket", NETWORK_SETUP),
    ("connect", NETWORK_SETUP),
    ("WSASocket", NETWORK_SETUP),
    ("WSAConnect", NETWORK_SETUP),
    ("WSAStartup", NETWORK_SETUP),
    ("getaddrinfo", NETWORK_SETUP),
    ("GetAddrInfo", NETWORK_SETUP),
    ("GetAddrInfoEx", NETWORK_SETUP),
    ("gethostbyname", NETWORK_SETUP),
    ("inet_pton", NETWORK_SETUP),
    ("inet_addr", NETWORK_SETUP),
    ("InternetOpen", NETWORK_SETUP),
    ("InternetConnect", NETWORK_SETUP),
    ("HttpOpenRequest", NETWORK_SETUP),
    ("WinHttpOpen", NETWORK_SETUP),
    ("WinHttpConnect", NETWORK_SETUP),
    ("WinHttpOpenRequest", NETWORK_SETUP),
    ("DnsQuery_", NETWORK_SETUP),
    ("curl_easy_init", NETWORK_SETUP),
    ("curl_easy_setopt", NETWORK_SETUP),
    ("SSL_connect", NETWORK_SETUP),
    // Network: receiving / downloading.
    ("recv", NETWORK_RECEIVE),
    ("recvfrom", NETWORK_RECEIVE),
    ("recvmsg", NETWORK_RECEIVE),
    ("WSARecv", NETWORK_RECEIVE),
    ("WSARecvFrom", NETWORK_RECEIVE),
    ("InternetReadFile", NETWORK_RECEIVE),
    ("WinHttpReadData", NETWORK_RECEIVE),
    ("WinHttpReceiveResponse", NETWORK_RECEIVE),
    ("URLDownloadToFile", NETWORK_RECEIVE),
    ("URLDownloadToCacheFile", NETWORK_RECEIVE),
    ("SSL_read", NETWORK_RECEIVE),
    // Files.
    ("WriteFile", FILE_WRITE),
    ("WriteFileEx", FILE_WRITE),
    ("NtWriteFile", FILE_WRITE),
    ("CopyFile", FILE_WRITE),
    ("CopyFileEx", FILE_WRITE),
    ("MoveFile", FILE_WRITE),
    ("MoveFileEx", FILE_WRITE),
    ("DeleteFile", FILE_WRITE),
    ("CreateDirectory", FILE_WRITE),
    ("SHFileOperation", FILE_WRITE),
    ("SetFileAttributes", FILE_WRITE),
    ("fwrite", FILE_WRITE),
    ("fputs", FILE_WRITE),
    ("fputc", FILE_WRITE),
    ("write", FILE_WRITE),
    ("pwrite", FILE_WRITE),
    ("pwrite64", FILE_WRITE),
    ("rename", FILE_WRITE),
    ("renameat", FILE_WRITE),
    ("unlink", FILE_WRITE),
    ("unlinkat", FILE_WRITE),
    ("mkdir", FILE_WRITE),
    ("creat", FILE_WRITE),
    ("ftruncate", FILE_WRITE),
    ("chmod", FILE_WRITE),
    ("ReadFile", FILE_READ),
    ("NtReadFile", FILE_READ),
    ("FindFirstFile", FILE_READ),
    ("FindFirstFileEx", FILE_READ),
    ("FindNextFile", FILE_READ),
    ("fread", FILE_READ),
    ("fgets", FILE_READ),
    ("read", FILE_READ),
    ("pread", FILE_READ),
    ("pread64", FILE_READ),
    ("opendir", FILE_READ),
    ("readdir", FILE_READ),
    ("readdir64", FILE_READ),
    ("CreateFile", FILE_OPEN),
    ("CreateFile2", FILE_OPEN),
    ("NtCreateFile", FILE_OPEN),
    ("OpenFile", FILE_OPEN),
    ("fopen", FILE_OPEN),
    ("fopen64", FILE_OPEN),
    ("_wfopen", FILE_OPEN),
    ("open", FILE_OPEN),
    ("open64", FILE_OPEN),
    ("openat", FILE_OPEN),
    ("openat64", FILE_OPEN),
    // Registry.
    ("RegSetValue", REGISTRY_WRITE),
    ("RegSetValueEx", REGISTRY_WRITE),
    ("RegSetKeyValue", REGISTRY_WRITE),
    ("RegCreateKey", REGISTRY_WRITE),
    ("RegCreateKeyEx", REGISTRY_WRITE),
    ("RegDeleteKey", REGISTRY_WRITE),
    ("RegDeleteKeyEx", REGISTRY_WRITE),
    ("RegDeleteValue", REGISTRY_WRITE),
    ("SHSetValue", REGISTRY_WRITE),
    ("RegOpenKey", REGISTRY_READ),
    ("RegOpenKeyEx", REGISTRY_READ),
    ("RegQueryValue", REGISTRY_READ),
    ("RegQueryValueEx", REGISTRY_READ),
    ("RegGetValue", REGISTRY_READ),
    ("RegEnumKey", REGISTRY_READ),
    ("RegEnumKeyEx", REGISTRY_READ),
    ("RegEnumValue", REGISTRY_READ),
    ("SHGetValue", REGISTRY_READ),
    // Host / user identifiers.
    ("GetComputerName", IDENTIFIERS),
    ("GetComputerNameEx", IDENTIFIERS),
    ("GetUserName", IDENTIFIERS),
    ("GetUserNameEx", IDENTIFIERS),
    ("GetVolumeInformation", IDENTIFIERS),
    ("GetVolumeInformationByHandle", IDENTIFIERS),
    ("GetAdaptersInfo", IDENTIFIERS),
    ("GetAdaptersAddresses", IDENTIFIERS),
    ("GetCurrentHwProfile", IDENTIFIERS),
    ("GetSystemFirmwareTable", IDENTIFIERS),
    ("NetWkstaGetInfo", IDENTIFIERS),
    ("UuidCreateSequential", IDENTIFIERS),
    ("WTSQuerySessionInformation", IDENTIFIERS),
    ("gethostname", IDENTIFIERS),
    ("gethostid", IDENTIFIERS),
    ("uname", IDENTIFIERS),
    ("getuid", IDENTIFIERS),
    ("getlogin", IDENTIFIERS),
    ("getlogin_r", IDENTIFIERS),
    ("getpwuid", IDENTIFIERS),
    ("getpwuid_r", IDENTIFIERS),
    ("getifaddrs", IDENTIFIERS),
    ("if_nameindex", IDENTIFIERS),
    ("IORegistryEntryCreateCFProperty", IDENTIFIERS),
    ("gethostuuid", IDENTIFIERS),
    // Clipboard (reads; SetClipboardData is a write and not listed).
    ("GetClipboardData", CLIPBOARD),
    ("XConvertSelection", CLIPBOARD),
    ("gtk_clipboard_wait_for_text", CLIPBOARD),
    // Input capture.
    ("SetWindowsHookEx", INPUT_CAPTURE),
    ("GetAsyncKeyState", INPUT_CAPTURE),
    ("GetKeyboardState", INPUT_CAPTURE),
    ("RegisterRawInputDevices", INPUT_CAPTURE),
    ("GetRawInputData", INPUT_CAPTURE),
    ("XQueryKeymap", INPUT_CAPTURE),
    ("XRecordEnableContext", INPUT_CAPTURE),
    ("XRecordEnableContextAsync", INPUT_CAPTURE),
    ("XGrabKeyboard", INPUT_CAPTURE),
    ("CGEventTapCreate", INPUT_CAPTURE),
    // Screen capture (BitBlt alone is ordinary GUI drawing; see display_context).
    ("BitBlt", SCREEN_CAPTURE),
    ("StretchBlt", SCREEN_CAPTURE),
    ("PrintWindow", SCREEN_CAPTURE),
    ("XGetImage", SCREEN_CAPTURE),
    ("XShmGetImage", SCREEN_CAPTURE),
    ("CGWindowListCreateImage", SCREEN_CAPTURE),
    ("CGDisplayCreateImage", SCREEN_CAPTURE),
    ("GetDC", DISPLAY_CONTEXT),
    ("GetWindowDC", DISPLAY_CONTEXT),
    ("GetDesktopWindow", DISPLAY_CONTEXT),
    ("CreateDC", DISPLAY_CONTEXT),
    ("XGetWindowAttributes", DISPLAY_CONTEXT),
    // Microphone / camera.
    ("waveInOpen", MEDIA_CAPTURE),
    ("waveInStart", MEDIA_CAPTURE),
    ("capCreateCaptureWindow", MEDIA_CAPTURE),
    ("MFEnumDeviceSources", MEDIA_CAPTURE),
    ("snd_pcm_open", MEDIA_CAPTURE),
    ("pa_simple_new", MEDIA_CAPTURE),
    // Processes.
    ("CreateProcess", PROCESS_CREATE),
    ("CreateProcessAsUser", PROCESS_CREATE),
    ("CreateProcessWithLogon", PROCESS_CREATE),
    ("CreateProcessWithToken", PROCESS_CREATE),
    ("ShellExecute", PROCESS_CREATE),
    ("ShellExecuteEx", PROCESS_CREATE),
    ("WinExec", PROCESS_CREATE),
    ("system", PROCESS_CREATE),
    ("popen", PROCESS_CREATE),
    ("execve", PROCESS_CREATE),
    ("execv", PROCESS_CREATE),
    ("execvp", PROCESS_CREATE),
    ("execvpe", PROCESS_CREATE),
    ("execl", PROCESS_CREATE),
    ("execlp", PROCESS_CREATE),
    ("posix_spawn", PROCESS_CREATE),
    ("posix_spawnp", PROCESS_CREATE),
    ("WriteProcessMemory", PROCESS_INJECTION),
    ("CreateRemoteThread", PROCESS_INJECTION),
    ("CreateRemoteThreadEx", PROCESS_INJECTION),
    ("VirtualAllocEx", PROCESS_INJECTION),
    ("NtWriteVirtualMemory", PROCESS_INJECTION),
    ("QueueUserAPC", PROCESS_INJECTION),
    ("SetThreadContext", PROCESS_INJECTION),
    ("NtUnmapViewOfSection", PROCESS_INJECTION),
    ("process_vm_writev", PROCESS_INJECTION),
    ("ptrace", PROCESS_INJECTION),
    // Credentials and crypto.
    ("CryptUnprotectData", CREDENTIALS),
    ("CredRead", CREDENTIALS),
    ("CredEnumerate", CREDENTIALS),
    ("LsaRetrievePrivateData", CREDENTIALS),
    ("SecKeychainFindGenericPassword", CREDENTIALS),
    ("SecItemCopyMatching", CREDENTIALS),
    ("secret_password_lookup_sync", CREDENTIALS),
    ("CryptEncrypt", CRYPTO),
    ("CryptDecrypt", CRYPTO),
    ("CryptProtectData", CRYPTO),
    ("CryptAcquireContext", CRYPTO),
    ("BCryptEncrypt", CRYPTO),
    ("BCryptDecrypt", CRYPTO),
    ("EVP_EncryptInit_ex", CRYPTO),
    ("EVP_DecryptInit_ex", CRYPTO),
    ("EVP_CipherInit_ex", CRYPTO),
    // Persistence.
    ("CreateService", PERSISTENCE),
    ("ChangeServiceConfig", PERSISTENCE),
    ("ChangeServiceConfig2", PERSISTENCE),
    ("NetScheduleJobAdd", PERSISTENCE),
    // Dynamic loading (APIs resolved this way are invisible to the static map).
    ("LoadLibrary", DYNAMIC_LOAD),
    ("LoadLibraryEx", DYNAMIC_LOAD),
    ("GetProcAddress", DYNAMIC_LOAD),
    ("LdrLoadDll", DYNAMIC_LOAD),
    ("LdrGetProcedureAddress", DYNAMIC_LOAD),
    ("dlopen", DYNAMIC_LOAD),
    ("dlsym", DYNAMIC_LOAD),
    ("dlvsym", DYNAMIC_LOAD),
    // Privilege and anti-analysis.
    ("AdjustTokenPrivileges", PRIVILEGE),
    ("setuid", PRIVILEGE),
    ("setgid", PRIVILEGE),
    ("setresuid", PRIVILEGE),
    ("IsDebuggerPresent", ANTI_ANALYSIS),
    ("CheckRemoteDebuggerPresent", ANTI_ANALYSIS),
    ("NtQueryInformationProcess", ANTI_ANALYSIS),
];

/// Go standard-library functions (pclntab / symtab names), by exact name or
/// `prefix*`.
const GO_TABLE: &[(&str, &str)] = &[
    ("net/http.(*Client).Do", NETWORK_SEND),
    ("net/http.(*Client).Post", NETWORK_SEND),
    ("net/http.(*Client).PostForm", NETWORK_SEND),
    ("net/http.(*Client).Get", NETWORK_SEND),
    ("net/http.Post", NETWORK_SEND),
    ("net/http.PostForm", NETWORK_SEND),
    ("net/http.Get", NETWORK_SEND),
    ("net.(*conn).Write", NETWORK_SEND),
    ("net.(*UDPConn).WriteTo", NETWORK_SEND),
    ("net.(*UDPConn).WriteToUDP", NETWORK_SEND),
    ("crypto/tls.(*Conn).Write", NETWORK_SEND),
    ("net.Dial", NETWORK_SETUP),
    ("net.DialTimeout", NETWORK_SETUP),
    ("net.(*Dialer).Dial", NETWORK_SETUP),
    ("net.(*Dialer).DialContext", NETWORK_SETUP),
    ("net.LookupHost", NETWORK_SETUP),
    ("net/http.NewRequest", NETWORK_SETUP),
    ("net/http.NewRequestWithContext", NETWORK_SETUP),
    ("os.Hostname", IDENTIFIERS),
    ("os/user.Current", IDENTIFIERS),
    ("os.Getuid", IDENTIFIERS),
    ("net.Interfaces", IDENTIFIERS),
    ("os.WriteFile", FILE_WRITE),
    ("io/ioutil.WriteFile", FILE_WRITE),
    ("os.(*File).Write", FILE_WRITE),
    ("os.(*File).WriteString", FILE_WRITE),
    ("os.Create", FILE_WRITE),
    ("os.Rename", FILE_WRITE),
    ("os.Remove", FILE_WRITE),
    ("os.RemoveAll", FILE_WRITE),
    ("os.MkdirAll", FILE_WRITE),
    ("os.OpenFile", FILE_OPEN),
    ("os.Open", FILE_OPEN),
    ("os.ReadFile", FILE_READ),
    ("io/ioutil.ReadFile", FILE_READ),
    ("os.ReadDir", FILE_READ),
    ("os/exec.Command", PROCESS_CREATE),
    ("os/exec.CommandContext", PROCESS_CREATE),
    ("os/exec.(*Cmd).Start", PROCESS_CREATE),
    ("os.StartProcess", PROCESS_CREATE),
    ("syscall.Exec", PROCESS_CREATE),
    ("golang.org/x/sys/windows/registry.Key.Set*", REGISTRY_WRITE),
    (
        "golang.org/x/sys/windows/registry.CreateKey",
        REGISTRY_WRITE,
    ),
    ("golang.org/x/sys/windows/registry.Key.Get*", REGISTRY_READ),
    ("golang.org/x/sys/windows/registry.OpenKey", REGISTRY_READ),
    ("plugin.Open", DYNAMIC_LOAD),
    ("syscall.LoadLibrary", DYNAMIC_LOAD),
    ("syscall.(*LazyDLL).Load", DYNAMIC_LOAD),
    ("golang.org/x/sys/windows.(*LazyDLL).Load", DYNAMIC_LOAD),
];

static INDEX: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| TABLE.iter().copied().collect());

/// The bare function name of an import display name (`DLL!name` → `name`),
/// without stdcall decoration or a leading underscore from Mach-O / x86 C names.
pub(crate) fn base_name(api: &str) -> &str {
    let name = api.rsplit_once('!').map_or(api, |(_, n)| n);
    let name = name.split('@').next().unwrap_or(name);
    name.strip_prefix("__imp_").unwrap_or(name)
}

/// Category of a function name, if it is one we track.
pub(crate) fn classify(api: &str) -> Option<&'static str> {
    let name = base_name(api);
    if name.is_empty() {
        return None;
    }
    let lookup = |n: &str| INDEX.get(n).copied();
    if let Some(c) = lookup(name) {
        return Some(c);
    }
    let trimmed = name.trim_start_matches('_');
    if trimmed != name
        && let Some(c) = lookup(trimmed)
    {
        return Some(c);
    }
    if let Some(stem) = trimmed
        .strip_suffix('A')
        .or_else(|| trimmed.strip_suffix('W'))
        && let Some(c) = lookup(stem)
    {
        return Some(c);
    }
    if trimmed.starts_with("DnsQuery_") {
        return Some(NETWORK_SETUP);
    }
    if name.contains('.') {
        return classify_go(name);
    }
    None
}

fn classify_go(name: &str) -> Option<&'static str> {
    GO_TABLE.iter().find_map(|(pat, cat)| {
        let hit = match pat.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == *pat,
        };
        hit.then_some(*cat)
    })
}

/// Whether a named function belongs to a language runtime / standard library
/// (Go std packages, Rust `std`/`core`/`alloc`, libc-internal names). Such
/// functions can be APIs but are not reported as the subject of a finding.
pub(crate) fn is_runtime_function(name: &str, is_go: bool) -> bool {
    const RUST_STD: &[&str] = &[
        "_ZN3std",
        "_ZN4core",
        "_ZN5alloc",
        "std::",
        "core::",
        "alloc::",
        "<std::",
        "<core::",
        "<alloc::",
    ];
    if RUST_STD.iter().any(|p| name.starts_with(p))
        || name.starts_with("__")
        || name.starts_with("_dl_")
        || name.starts_with("_IO_")
    {
        return true;
    }
    if !is_go {
        return false;
    }
    // Go: package path ends at the first '.' after the last '/'.
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    let Some(dot) = name[slash..].find('.').map(|d| d + slash) else {
        return false;
    };
    let pkg = &name[..dot];
    if pkg == "main" || pkg.starts_with("main.") {
        return false;
    }
    let first = pkg.split('/').next().unwrap_or(pkg);
    // Standard library: first path element has no dot (net/http, os, runtime).
    !first.contains('.') || first == "golang.org"
}

/// Identifier APIs that are routinely used for other purposes (home
/// directory lookup, permission checks); they never trigger findings alone.
pub(crate) fn is_weak_identifier(api: &str) -> bool {
    matches!(
        base_name(api).trim_start_matches('_'),
        "getuid"
            | "getpwuid"
            | "getpwuid_r"
            | "getlogin"
            | "getlogin_r"
            | "uname"
            | "os.Getuid"
            | "if_nameindex"
    )
}

/// Data types implied by an identifier API (for `Finding::data_types`).
pub(crate) fn identifier_data_type(api: &str) -> &'static str {
    let n = base_name(api).trim_start_matches('_');
    let n = n
        .strip_suffix('A')
        .or_else(|| n.strip_suffix('W'))
        .unwrap_or(n);
    match n {
        "GetComputerName" | "GetComputerNameEx" | "gethostname" | "uname" | "os.Hostname"
        | "NetWkstaGetInfo" => "hostname",
        "GetUserName"
        | "GetUserNameEx"
        | "getuid"
        | "getlogin"
        | "getlogin_r"
        | "getpwuid"
        | "getpwuid_r"
        | "os/user.Current"
        | "os.Getuid"
        | "WTSQuerySessionInformation" => "user_account",
        "GetVolumeInformation" | "GetVolumeInformationByHandle" => "volume_serial",
        "GetAdaptersInfo"
        | "GetAdaptersAddresses"
        | "getifaddrs"
        | "if_nameindex"
        | "net.Interfaces"
        | "UuidCreateSequential" => "network_adapter_address",
        "GetCurrentHwProfile"
        | "GetSystemFirmwareTable"
        | "IORegistryEntryCreateCFProperty"
        | "gethostuuid"
        | "gethostid" => "hardware_identifier",
        _ => "host_identifier",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_variants() {
        assert_eq!(classify("WS2_32.dll!send"), Some(NETWORK_SEND));
        assert_eq!(
            classify("KERNEL32.dll!GetComputerNameExW"),
            Some(IDENTIFIERS)
        );
        assert_eq!(
            classify("ADVAPI32.dll!RegSetValueExA"),
            Some(REGISTRY_WRITE)
        );
        assert_eq!(classify("_gethostname"), Some(IDENTIFIERS));
        assert_eq!(classify("_send@16"), Some(NETWORK_SEND));
        assert_eq!(classify("net/http.(*Client).Do"), Some(NETWORK_SEND));
        assert_eq!(
            classify("golang.org/x/sys/windows/registry.Key.SetStringValue"),
            Some(REGISTRY_WRITE)
        );
        assert_eq!(classify("printf"), None);
        assert_eq!(classify("Sendmail"), None);
    }

    #[test]
    fn runtime_detection() {
        assert!(is_runtime_function("net/http.(*Client).Do", true));
        assert!(is_runtime_function("runtime.main", true));
        assert!(!is_runtime_function("main.upload", true));
        assert!(!is_runtime_function(
            "github.com/acme/agent.(*Client).Send",
            true
        ));
        assert!(!is_runtime_function("upload.part.0", false));
        assert!(is_runtime_function(
            "_ZN3std3net3tcp9TcpStream7connect17h0123456789abcdefE",
            false
        ));
    }
}

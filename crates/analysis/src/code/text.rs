//! Strings referenced from code: reading a string at an address and deciding
//! what kind of thing it is (URL, path, registry key, ...).

/// Minimum characters for a referenced string.
const MIN_CHARS: usize = 5;
/// Characters kept per string.
pub(crate) const MAX_CHARS: usize = 200;

/// Read a printable ASCII or UTF-16LE string starting exactly at `data[0]`.
/// `exact_len` (Go strings) reads that many bytes instead of to a NUL.
/// Returns (text, truncated).
pub(crate) fn read_string(data: &[u8], exact_len: Option<usize>) -> Option<(String, bool)> {
    let printable = |c: u8| (0x20..0x7f).contains(&c) || c == b'\t' || c == b'\n' || c == b'\r';
    if let Some(len) = exact_len {
        let bytes = data.get(..len)?;
        if len < MIN_CHARS.min(4) || !bytes.iter().all(|&c| printable(c)) {
            return None;
        }
        let text = String::from_utf8_lossy(&bytes[..len.min(MAX_CHARS)]).into_owned();
        return Some((text, len > MAX_CHARS));
    }
    // ASCII, NUL-terminated.
    let n = data
        .iter()
        .take(MAX_CHARS + 1)
        .take_while(|&&c| printable(c))
        .count();
    if n >= MIN_CHARS && (data.get(n) == Some(&0) || n > MAX_CHARS) {
        let text = String::from_utf8_lossy(&data[..n.min(MAX_CHARS)]).into_owned();
        return useful(&text).then_some((text, n > MAX_CHARS));
    }
    // UTF-16LE (ASCII range), NUL-terminated.
    let mut chars = String::new();
    let mut i = 0;
    while i + 1 < data.len() && chars.len() <= MAX_CHARS {
        let (lo, hi) = (data[i], data[i + 1]);
        if hi != 0 || !printable(lo) {
            break;
        }
        chars.push(lo as char);
        i += 2;
    }
    let terminated = data.get(i) == Some(&0) && data.get(i + 1) == Some(&0);
    if chars.len() >= MIN_CHARS && (terminated || chars.len() > MAX_CHARS) {
        let cut = chars.len() > MAX_CHARS;
        chars.truncate(MAX_CHARS);
        return useful(&chars).then_some((chars, cut));
    }
    None
}

/// Reject strings that are almost certainly not text (byte noise).
fn useful(s: &str) -> bool {
    let letters = s.bytes().filter(|c| c.is_ascii_alphabetic()).count();
    letters * 2 >= s.len().min(16)
}

/// Kinds of referenced strings, roughly in order of interest.
pub(crate) fn classify(s: &str) -> &'static str {
    let lower = s.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    if has(&[
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "machineguid",
        "product_uuid",
        "product_serial",
        "board_serial",
        "ioplatformuuid",
        "ioplatformserialnumber",
        "win32_baseboard",
        "win32_bios",
        "win32_computersystemproduct",
        "win32_diskdrive",
        "/sys/class/net/",
        "hwprofileguid",
    ]) {
        return "identifier_source";
    }
    if let Some(i) = lower.find("://")
        && i > 0
        && lower[..i]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'.' || c == b'-')
    {
        return "url";
    }
    if lower.starts_with("hkey_")
        || lower.starts_with("hklm\\")
        || lower.starts_with("hkcu\\")
        || has(&[
            "software\\",
            "\\currentversion\\",
            "system\\currentcontrolset",
        ])
    {
        return "registry";
    }
    if has(&[
        "cmd.exe",
        "powershell",
        "/bin/sh",
        "/bin/bash",
        "schtasks",
        "crontab",
        "systemctl ",
        "launchctl",
        "rundll32",
        "regsvr32",
        "reg add",
        "sh -c",
        "wget ",
        "curl ",
        "vssadmin",
        "bcdedit",
        "netsh ",
    ]) {
        return "command";
    }
    if has(&[
        "password",
        "passwd",
        "api_key",
        "apikey",
        "secret",
        "access_token",
        "refresh_token",
        "bearer ",
        "cookies",
        "login data",
        "wallet",
        "keychain",
        ".ssh/",
        "id_rsa",
        "credential",
    ]) {
        return "credential";
    }
    if has(&[
        "mozilla/",
        "user-agent",
        "content-type",
        "authorization",
        "application/json",
        "x-www-form-urlencoded",
        "post ",
        "get /",
        "http/1.",
    ]) {
        return "protocol";
    }
    if is_ip(s) {
        return "ip";
    }
    if lower.starts_with("select ")
        || lower.starts_with("insert into")
        || lower.starts_with("update ")
        || lower.starts_with("delete from")
        || lower.starts_with("create table")
    {
        return "sql";
    }
    if is_path(s, &lower) {
        return "path";
    }
    if is_host(&lower) {
        return "host";
    }
    if (s.starts_with('{') && s.contains("\":")) || (s.contains("\"%s\"") && s.contains(':')) {
        return "json";
    }
    if s.len() <= 40
        && s.len() >= 3
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
        && s.contains('_')
    {
        return "env";
    }
    "other"
}

/// Relevance of a string kind when ranking functions.
pub(crate) fn weight(kind: &str) -> u32 {
    match kind {
        "url" | "identifier_source" | "credential" => 6,
        "host" | "ip" | "registry" | "command" => 5,
        "protocol" | "sql" => 3,
        "path" | "json" => 2,
        "env" => 1,
        _ => 0,
    }
}

fn is_ip(s: &str) -> bool {
    let host = s
        .rsplit_once(':')
        .filter(|(_, p)| p.parse::<u16>().is_ok())
        .map_or(s, |(h, _)| h);
    host.parse::<std::net::Ipv4Addr>().is_ok()
        && host != "0.0.0.0"
        && host != "127.0.0.1"
        && !host.starts_with("255.")
}

fn is_path(s: &str, lower: &str) -> bool {
    let unix = s.starts_with('/') && s.len() > 4 && s[1..].contains('/') && !s.contains(' ');
    let unix_known = [
        "/etc/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/var/",
        "/tmp/",
        "/home/",
        "/usr/",
        "/root/",
        "/opt/",
        "/run/",
        "/library/",
        "/users/",
        "/private/",
    ]
    .iter()
    .any(|p| lower.starts_with(p));
    let home = s.starts_with("~/")
        || lower.contains("/.config/")
        || lower.starts_with(".config/")
        || lower.contains("/.local/")
        || lower.contains("/.cache/");
    let windows = s.len() > 3
        && s.as_bytes()[1] == b':'
        && s.as_bytes()[2] == b'\\'
        && s.as_bytes()[0].is_ascii_alphabetic();
    let env = [
        "%appdata%",
        "%localappdata%",
        "%temp%",
        "%programdata%",
        "%userprofile%",
        "%windir%",
        "%systemroot%",
        "%programfiles%",
        "$home",
    ]
    .iter()
    .any(|p| lower.contains(p));
    let unc = s.starts_with("\\\\");
    unix_known || (unix && s.matches('/').count() >= 2) || home || windows || env || unc
}

fn is_host(lower: &str) -> bool {
    const FILE_EXT: &[&str] = &[
        "so",
        "dll",
        "exe",
        "sys",
        "txt",
        "json",
        "dat",
        "log",
        "cfg",
        "ini",
        "xml",
        "html",
        "htm",
        "py",
        "go",
        "c",
        "h",
        "rs",
        "js",
        "png",
        "jpg",
        "gif",
        "ico",
        "conf",
        "pem",
        "crt",
        "key",
        "db",
        "tmp",
        "bak",
        "lock",
        "pid",
        "sock",
        "zip",
        "gz",
        "tar",
        "md",
        "yaml",
        "yml",
        "toml",
        "plist",
        "framework",
        "dylib",
        "lib",
        "obj",
        "pdb",
        "cpp",
        "hpp",
        "cc",
        "lnk",
        "bat",
        "cmd",
        "ps1",
        "sh",
        "mui",
        "manifest",
        "msi",
        "inf",
        "cat",
        "mo",
        "qm",
        "ttf",
        "otf",
        "css",
        "svg",
        "wav",
        "mp3",
        "mp4",
    ];
    if lower.len() < 4
        || lower.len() > 253
        || !lower.contains('.')
        || lower.starts_with('.')
        || lower.ends_with('.')
    {
        return false;
    }
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|l| {
            l.is_empty()
                || l.len() > 63
                || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return false;
    }
    let tld = labels[labels.len() - 1];
    if FILE_EXT.contains(&tld) || !labels[0].bytes().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // Known generic TLDs anywhere; country codes only with 3+ labels or a common ccTLD,
    // so identifiers like `container.id` or `config.name` are not taken for hosts.
    GENERIC_TLDS.contains(&tld)
        || (tld.len() == 2
            && tld.bytes().all(|c| c.is_ascii_alphabetic())
            && (labels.len() >= 3 || COMMON_CCTLDS.contains(&tld)))
}

const GENERIC_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "ai", "co", "cloud", "info", "biz", "xyz", "gov",
    "edu", "mil", "onion",
];

const COMMON_CCTLDS: &[&str] = &[
    "us", "uk", "de", "fr", "jp", "cn", "ru", "br", "in", "nl", "eu", "ca", "au", "it", "es", "se",
    "no", "fi", "pl", "ch", "at", "be", "dk", "cz", "kr", "tw", "hk", "sg", "nz", "za", "ie", "il",
    "mx", "ar", "tr", "ua", "pt", "gr", "ro", "hu", "sk", "lt", "lv", "ee", "by", "kz", "vn", "th",
    "my", "ph", "cl", "pe", "ir", "pk", "ng", "ke", "eg", "sa", "ae", "fm", "im", "is", "lu", "uz",
    "su", "ws", "la", "st", "gl",
];

/// Host part of a URL / host / ip string, for recipient grouping.
pub(crate) fn host_of(s: &str) -> Option<String> {
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host
        .rsplit_once(':')
        .filter(|(_, p)| p.parse::<u16>().is_ok())
        .map_or(host, |(h, _)| h);
    let host = host.to_ascii_lowercase();
    (host.len() >= 3 && !host.contains(['%', '{', ' '])).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(classify("https://telemetry.example.com/v1"), "url");
        assert_eq!(classify("/etc/machine-id"), "identifier_source");
        assert_eq!(
            classify("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            "registry"
        );
        assert_eq!(classify("203.0.113.7"), "ip");
        assert_eq!(classify("api.example.org"), "host");
        assert_eq!(classify("libc.so"), "other");
        assert_eq!(classify("container.id"), "other");
        assert_eq!(classify("libnet.resolver.upstream.proto"), "other");
        assert_eq!(classify("www.example.de"), "host");
        assert_eq!(classify("%APPDATA%\\Vendor"), "path");
        assert_eq!(classify("HTTP_PROXY"), "env");
    }

    #[test]
    fn reads_ascii_and_utf16() {
        assert_eq!(
            read_string(b"hello world\0zz", None).unwrap().0,
            "hello world"
        );
        assert!(read_string(b"hi\0", None).is_none());
        let w: Vec<u8> = "C:\\Users\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(read_string(&w, None).unwrap().0, "C:\\Users");
        assert_eq!(read_string(b"abcdefghij", Some(5)).unwrap().0, "abcde");
    }
}

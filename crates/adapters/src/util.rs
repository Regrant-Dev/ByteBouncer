//! Small pure helpers shared by the resolvers.

use std::cmp::Ordering;

use base64::Engine;

/// Generic version ordering used to pick "the highest version" (winget,
/// Chocolatey). Splits into runs of digits and non-digits; digit runs compare
/// numerically, text runs lexically (case-insensitive); separators
/// (`.`, `-`, `_`, `+`) delimit runs. A version that has extra segments after
/// the common prefix sorts higher if the extra starts with a number
/// (`1.2.1 > 1.2`) and lower if it starts with text (`1.2-beta < 1.2`).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let sa = segments(a);
    let sb = segments(b);
    for i in 0..sa.len().max(sb.len()) {
        match (sa.get(i), sb.get(i)) {
            (Some(x), Some(y)) => {
                let o = match (x, y) {
                    (Seg::Num(x), Seg::Num(y)) => cmp_num(x, y),
                    (Seg::Text(x), Seg::Text(y)) => x.cmp(y),
                    (Seg::Num(_), Seg::Text(_)) => Ordering::Greater,
                    (Seg::Text(_), Seg::Num(_)) => Ordering::Less,
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some(Seg::Num(_)), None) => return Ordering::Greater,
            (Some(Seg::Text(_)), None) => return Ordering::Less,
            (None, Some(Seg::Num(_))) => return Ordering::Less,
            (None, Some(Seg::Text(_))) => return Ordering::Greater,
            (None, None) => break,
        }
    }
    Ordering::Equal
}

#[derive(Debug)]
enum Seg {
    Num(String),
    Text(String),
}

fn segments(v: &str) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_num = false;
    let flush = |cur: &mut String, num: bool, out: &mut Vec<Seg>| {
        if !cur.is_empty() {
            let s = std::mem::take(cur);
            out.push(if num {
                Seg::Num(s.trim_start_matches('0').to_string())
            } else {
                Seg::Text(s.to_ascii_lowercase())
            });
        }
    };
    for c in v.trim_start_matches(['v', 'V']).chars() {
        if c.is_ascii_digit() {
            if !cur_num {
                flush(&mut cur, false, &mut out);
                cur_num = true;
            }
            cur.push(c);
        } else if c.is_alphanumeric() {
            if cur_num {
                flush(&mut cur, true, &mut out);
                cur_num = false;
            }
            cur.push(c);
        } else {
            flush(&mut cur, cur_num, &mut out);
        }
    }
    flush(&mut cur, cur_num, &mut out);
    out
}

fn cmp_num(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Last path component of a URL, without query/fragment.
pub fn url_file_name(url: &str) -> String {
    let no_frag = url.split(['#', '?']).next().unwrap_or(url);
    let name = no_frag.rsplit('/').next().unwrap_or(no_frag);
    let name = percent_decode(name);
    if name.is_empty() {
        "download".to_string()
    } else {
        sanitize_file_name(&name)
    }
}

/// Keep file names display/filesystem safe (no separators or control chars).
pub fn sanitize_file_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_control() || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    if s == "." || s == ".." || s.is_empty() {
        "download".to_string()
    } else {
        s
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3])
            && let Ok(v) = u8::from_str_radix(hex, 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Minimal percent-encoding for a URL path segment or query value.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Lowercase hex if `s` is a hex digest of exactly `len` hex chars.
pub fn hex_digest(s: &str, len: usize) -> Option<String> {
    let t = s.trim();
    (t.len() == len && t.chars().all(|c| c.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .ok()
}

/// `YYYY-MM-DD` for a Unix timestamp (UTC), without a date library.
pub fn ymd(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn source_ref(url: &str, file_name: Option<&str>) -> bytebouncer_core::SourceRef {
    bytebouncer_core::SourceRef {
        url: url.to_string(),
        file_name: file_name
            .map(sanitize_file_name)
            .unwrap_or_else(|| url_file_name(url)),
        expected_sha256: None,
        expected_sha512: None,
        signature_url: None,
    }
}

/// True for http(s) URLs (the only schemes a fetch worker should be asked for).
pub fn is_http_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("https://") || l.starts_with("http://")
}

/// Short, single-line excerpt for notes.
pub fn excerpt(s: &str, max: usize) -> String {
    let one: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let one = one.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > max {
        let cut: String = one.chars().take(max).collect();
        format!("{cut}…")
    } else {
        one
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        let lt = |a: &str, b: &str| {
            assert_eq!(compare_versions(a, b), Ordering::Less, "{a} < {b}");
            assert_eq!(compare_versions(b, a), Ordering::Greater, "{b} > {a}");
        };
        lt("1.2", "1.10");
        lt("9.0", "10.0");
        lt("1.2", "1.2.1");
        lt("1.2-beta", "1.2");
        lt("1.2.0-beta", "1.2.0-rc");
        lt("0.94.2", "0.94.10");
        lt("24.09", "26.04");
        lt("16.04", "16.4.0.20170403");
        lt("v1.0", "1.1");
        assert_eq!(compare_versions("1.02", "1.2"), Ordering::Equal);
    }

    #[test]
    fn file_names_and_dates() {
        assert_eq!(
            url_file_name("https://x/a/Firefox%20157.dmg?x=1#y"),
            "Firefox 157.dmg"
        );
        assert_eq!(url_file_name("https://x/"), "download");
        assert_eq!(url_file_name("https://x/%2e%2e"), "download");
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(1_788_342_649), "2026-09-02");
        assert_eq!(percent_encode("arg[]"), "arg%5B%5D");
    }
}

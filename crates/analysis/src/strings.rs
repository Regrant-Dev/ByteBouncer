use regex::bytes::Regex;
use std::sync::LazyLock;

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"https?://[A-Za-z0-9.-]{3,253}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?",
    )
    .expect("valid regex")
});

pub struct Url {
    pub text: String,
    pub offset: u64,
}

/// Extract HTTP(S) URLs from ASCII and UTF-16LE text, deduplicated by text.
pub fn extract_urls(bytes: &[u8]) -> Vec<Url> {
    let mut out: Vec<Url> = Vec::new();
    let mut push = |text: String, offset: u64| {
        if plausible_host(url_host(&text)) && !out.iter().any(|u| u.text == text) {
            out.push(Url { text, offset });
        }
    };
    for m in URL_RE.find_iter(bytes) {
        push(
            String::from_utf8_lossy(m.as_bytes()).into_owned(),
            m.start() as u64,
        );
    }
    // UTF-16LE: collapse "x\0" pairs at both alignments and rescan. Work in
    // bounded windows (overlapping so URLs on a boundary are still seen) so
    // memory stays constant for very large inputs; the byte offset of a
    // narrowed index k is `window_start + align + 2k`.
    const WINDOW_CHARS: usize = 32 << 20;
    const OVERLAP_CHARS: usize = 8 << 10;
    let mut narrowed = Vec::with_capacity(WINDOW_CHARS.min(bytes.len() / 2 + 1));
    for align in 0..2 {
        let total_chars = bytes.len().saturating_sub(align) / 2;
        let mut first = 0;
        while first < total_chars {
            let last = (first + WINDOW_CHARS).min(total_chars);
            narrowed.clear();
            narrowed.extend((first..last).map(|k| {
                let i = align + 2 * k;
                let (lo, hi) = (bytes[i], bytes[i + 1]);
                if hi == 0 && lo.is_ascii() && lo != 0 {
                    lo
                } else {
                    b'\n'
                }
            }));
            for m in URL_RE.find_iter(&narrowed) {
                push(
                    String::from_utf8_lossy(m.as_bytes()).into_owned(),
                    (align + 2 * (first + m.start())) as u64,
                );
            }
            if last == total_chars {
                break;
            }
            first = last - OVERLAP_CHARS.min(last - first);
        }
    }
    out
}

/// Reject strings that only look like URLs because unrelated strings are
/// packed together (common in Go binaries): the host must be an IP address
/// or a dotted name ending in an alphabetic TLD.
pub fn plausible_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() || host == "localhost" {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last().copied().unwrap_or_default();
    labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
        && (2..=24).contains(&tld.len())
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && (tld.bytes().all(|b| b.is_ascii_lowercase())
            || tld.bytes().all(|b| b.is_ascii_uppercase()))
}

pub fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let end = rest.find(['/', ':', '?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_and_utf16_urls() {
        let mut data = b"xx https://api.example.com/v1/events yy".to_vec();
        for c in "http://wide.example.org/a".bytes() {
            data.push(c);
            data.push(0);
        }
        let urls = extract_urls(&data);
        let texts: Vec<_> = urls.iter().map(|u| u.text.as_str()).collect();
        assert!(texts.contains(&"https://api.example.com/v1/events"));
        assert!(texts.contains(&"http://wide.example.org/a"));
    }

    #[test]
    fn junk_hosts_rejected() {
        assert!(plausible_host("api.example.com"));
        assert!(plausible_host("10.0.0.1"));
        assert!(!plausible_host("I90"));
        assert!(!plausible_host("upgradechunkednosniffCreatedIM"));
        assert!(!plausible_host("json-schema.org.minimum0"));
        assert!(!plausible_host("example.Com"));
    }

    #[test]
    fn host_parsing() {
        assert_eq!(url_host("https://a.b.c:443/x"), "a.b.c");
        assert_eq!(url_host("http://x.y"), "x.y");
    }
}

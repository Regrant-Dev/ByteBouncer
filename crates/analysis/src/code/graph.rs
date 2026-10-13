//! Function discovery, call graph, API attribution and reachability, built
//! from the sweep's events.

use std::collections::{HashMap, HashSet, VecDeque};

use super::apis;
use super::image::{Image, RootKind};
use super::sweep::{Events, RefString};

/// Upper bound on functions in the graph.
pub(crate) const MAX_FUNCTIONS: usize = 300_000;
/// Upper bound on call-graph edges.
pub(crate) const MAX_EDGES: usize = 4_000_000;
const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EdgeKind {
    Call = 0,
    TailJump = 1,
    AddressTaken = 2,
}

pub(crate) struct Api {
    pub name: String,
    pub category: Option<&'static str>,
    /// Resolved from a string literal naming the API (GetProcAddress-style).
    pub dynamic: bool,
    pub call_sites: u32,
}

pub(crate) struct Csr {
    offsets: Vec<u32>,
    targets: Vec<(u32, EdgeKind)>,
}

impl Csr {
    fn build(n: usize, edges: &[(u32, u32, EdgeKind)], reverse: bool) -> Self {
        let mut counts = vec![0u32; n + 1];
        for &(a, b, _) in edges {
            counts[if reverse { b } else { a } as usize + 1] += 1;
        }
        for i in 0..n {
            counts[i + 1] += counts[i];
        }
        let mut fill = counts.clone();
        let mut targets = vec![(0u32, EdgeKind::Call); edges.len()];
        for &(a, b, k) in edges {
            let (from, to) = if reverse { (b, a) } else { (a, b) };
            targets[fill[from as usize] as usize] = (to, k);
            fill[from as usize] += 1;
        }
        Self {
            offsets: counts,
            targets,
        }
    }

    pub fn of(&self, f: u32) -> &[(u32, EdgeKind)] {
        let (a, b) = (
            self.offsets[f as usize] as usize,
            self.offsets[f as usize + 1] as usize,
        );
        &self.targets[a..b]
    }
}

pub(crate) struct Analysis<'i, 'a> {
    pub img: &'i Image<'a>,
    pub starts: Vec<u64>,
    pub sizes: Vec<u64>,
    /// Display names (demangled), parallel to `starts`.
    pub names: Vec<Option<String>>,
    /// Function index → API it forwards to (import thunk / PLT stub).
    pub thunk_api: HashMap<u32, u32>,
    pub apis: Vec<Api>,
    pub edges: usize,
    pub fwd: Csr,
    pub rev: Csr,
    /// (function, api), sorted and unique.
    pub func_apis: Vec<(u32, u32)>,
    /// (function, string index), sorted and unique.
    pub func_strs: Vec<(u32, u32)>,
    pub strings: Vec<RefString>,
    /// BFS parent toward a root; `NONE` when unreachable; self for roots.
    pub parent: Vec<u32>,
    pub roots: Vec<(u32, RootKind)>,
    pub thunk_addrs: HashMap<u64, u32>,
    pub instructions: u64,
    pub exec_bytes: u64,
    pub api_call_sites: u64,
    pub truncated: Vec<String>,
}

impl<'i, 'a> Analysis<'i, 'a> {
    pub fn build(img: &'i Image<'a>, mut ev: Events) -> Self {
        let mut truncated = std::mem::take(&mut ev.truncated);
        // Code pointers stored in data referenced from code (vtables, callback
        // tables, Go funcvals) count as address-taken references.
        let table_refs = scan_pointer_tables(img, &ev.data_refs, &mut truncated);
        ev.code_refs.extend(table_refs);
        // Function starts.
        let mut primary: Vec<u64> = img
            .names
            .keys()
            .copied()
            .chain(img.seeds.iter().copied())
            .chain(img.roots.iter().map(|r| r.0))
            .chain(ev.thunks.keys().copied())
            .filter(|a| img.is_exec(*a))
            .collect();
        primary.sort_unstable();
        primary.dedup();
        let mut discovered: Vec<u64> = ev
            .calls
            .iter()
            .map(|c| c.1)
            .chain(ev.code_refs.iter().map(|c| c.1))
            .chain(ev.gap_starts.iter().copied())
            .filter(|a| img.is_exec(*a))
            .collect();
        discovered.sort_unstable();
        discovered.dedup();
        let mut starts = primary;
        let room = MAX_FUNCTIONS.saturating_sub(starts.len());
        if discovered.len() > room {
            truncated.push(format!("function bound ({MAX_FUNCTIONS}) reached; some call targets were not treated as functions"));
            discovered.truncate(room);
        }
        starts.truncate(MAX_FUNCTIONS);
        starts.extend(discovered);
        starts.sort_unstable();
        starts.dedup();
        // Tail-jump targets that land in a different function start functions too.
        let mut tail: Vec<u64> = {
            let func_of = |a: u64| starts.partition_point(|s| *s <= a);
            ev.jumps
                .iter()
                .filter(|(ip, t)| {
                    img.is_exec(*t)
                        && starts.binary_search(t).is_err()
                        && func_of(*ip) != func_of(*t)
                })
                .map(|j| j.1)
                .collect()
        };
        tail.sort_unstable();
        tail.dedup();
        tail.truncate(MAX_FUNCTIONS.saturating_sub(starts.len()));
        starts.extend(tail);
        starts.sort_unstable();
        starts.dedup();
        let n = starts.len();

        let sizes: Vec<u64> = (0..n)
            .map(|i| {
                let s = starts[i];
                let region_end = img.region_of(s).map_or(s, |r| r.va + r.data.len() as u64);
                let next = starts
                    .get(i + 1)
                    .copied()
                    .unwrap_or(u64::MAX)
                    .min(region_end);
                let gap = next.saturating_sub(s);
                img.sizes.get(&s).map_or(gap, |k| (*k).min(gap).max(1))
            })
            .collect();
        let names: Vec<Option<String>> = starts
            .iter()
            .map(|s| img.names.get(s).map(|n| demangle(n)))
            .collect();

        let index_of = |a: u64| -> Option<u32> { starts.binary_search(&a).ok().map(|i| i as u32) };
        let func_of = |a: u64| -> Option<u32> {
            let i = starts.partition_point(|s| *s <= a);
            (i > 0).then(|| (i - 1) as u32)
        };

        let mut apis: Vec<Api> = img
            .apis
            .iter()
            .map(|n| Api {
                name: n.clone(),
                category: apis::classify(n),
                dynamic: false,
                call_sites: 0,
            })
            .collect();
        let mut thunk_api = HashMap::new();
        for (addr, api) in &ev.thunks {
            if let Some(f) = index_of(*addr) {
                thunk_api.insert(f, *api);
            }
        }
        // Named functions that are themselves APIs (static libc, Go std).
        let mut named_api: HashMap<u32, u32> = HashMap::new();
        let mut api_ids: HashMap<String, u32> = HashMap::new();
        for (i, name) in names.iter().enumerate() {
            let Some(name) = name else { continue };
            if thunk_api.contains_key(&(i as u32)) {
                continue;
            }
            if let Some(cat) = apis::classify(name) {
                let id = *api_ids.entry(name.clone()).or_insert_with(|| {
                    apis.push(Api {
                        name: name.clone(),
                        category: Some(cat),
                        dynamic: false,
                        call_sites: 0,
                    });
                    (apis.len() - 1) as u32
                });
                named_api.insert(i as u32, id);
            }
        }

        let mut edges: Vec<(u32, u32, EdgeKind)> = Vec::new();
        let mut func_apis: Vec<(u32, u32)> = Vec::new();
        let mut api_call_sites = 0u64;
        let site = |func_apis: &mut Vec<(u32, u32)>, apis: &mut Vec<Api>, f: u32, api: u32| {
            if let Some(a) = apis.get_mut(api as usize) {
                a.call_sites = a.call_sites.saturating_add(1);
                func_apis.push((f, api));
            }
        };
        for (ip, api) in &ev.api_calls {
            if let Some(f) = func_of(*ip) {
                site(&mut func_apis, &mut apis, f, *api);
                api_call_sites += 1;
            }
        }
        let mut edge_full = false;
        for (list, kind) in [
            (&ev.calls, EdgeKind::Call),
            (&ev.jumps, EdgeKind::TailJump),
            (&ev.code_refs, EdgeKind::AddressTaken),
        ] {
            for (ip, t) in list.iter() {
                let Some(from) = func_of(*ip) else { continue };
                if let Some(api) = ev.thunks.get(t) {
                    site(&mut func_apis, &mut apis, from, *api);
                    api_call_sites += 1;
                    continue;
                }
                let Some(to) = index_of(*t) else { continue };
                if to == from {
                    continue;
                }
                if let Some(api) = thunk_api.get(&to) {
                    site(&mut func_apis, &mut apis, from, *api);
                    api_call_sites += 1;
                    continue;
                }
                if kind != EdgeKind::AddressTaken
                    && let Some(api) = named_api.get(&to)
                {
                    site(&mut func_apis, &mut apis, from, *api);
                }
                if edges.len() >= MAX_EDGES {
                    edge_full = true;
                    continue;
                }
                edges.push((from, to, kind));
            }
        }
        if edge_full {
            truncated.push(format!(
                "call-edge bound ({MAX_EDGES}) reached; call graph is partial"
            ));
        }
        edges.sort_unstable();
        edges.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

        // Strings: attribute to functions; strings that name an API are
        // dynamic-resolution hints (GetProcAddress / dlsym / Go LazyProc).
        let mut func_strs = Vec::with_capacity(ev.str_refs.len());
        let mut dyn_ids: HashMap<u32, Option<u32>> = HashMap::new();
        for (ip, s) in &ev.str_refs {
            let Some(f) = func_of(*ip) else { continue };
            func_strs.push((f, *s));
            let dyn_api = *dyn_ids.entry(*s).or_insert_with(|| {
                let text = &ev.strings[*s as usize].text;
                let ident = text.len() <= 64
                    && text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
                let cat = if ident { apis::classify(text) } else { None }?;
                // Short generic names (send, read, open, ...) are too ambiguous as strings.
                if text.len() < 7 {
                    return None;
                }
                apis.push(Api {
                    name: format!("dynamic!{text}"),
                    category: Some(cat),
                    dynamic: true,
                    call_sites: 0,
                });
                Some((apis.len() - 1) as u32)
            });
            if let Some(api) = dyn_api {
                site(&mut func_apis, &mut apis, f, api);
            }
        }
        func_apis.sort_unstable();
        func_apis.dedup();
        func_strs.sort_unstable();
        func_strs.dedup();

        let fwd = Csr::build(n, &edges, false);
        let rev = Csr::build(n, &edges, true);
        let roots: Vec<(u32, RootKind)> = img
            .roots
            .iter()
            .filter_map(|(a, k)| index_of(*a).map(|f| (f, *k)))
            .collect();
        // 0-1 BFS: paths prefer direct calls over taken addresses.
        let mut parent = vec![NONE; n];
        let mut cost = vec![u32::MAX; n];
        let mut queue = VecDeque::new();
        for (r, _) in &roots {
            if cost[*r as usize] != 0 {
                cost[*r as usize] = 0;
                parent[*r as usize] = *r;
                queue.push_back(*r);
            }
        }
        while let Some(f) = queue.pop_front() {
            let c = cost[f as usize];
            for &(t, kind) in fwd.of(f) {
                let w = u32::from(kind == EdgeKind::AddressTaken);
                if c + w < cost[t as usize] {
                    cost[t as usize] = c + w;
                    parent[t as usize] = f;
                    if w == 0 {
                        queue.push_front(t)
                    } else {
                        queue.push_back(t)
                    }
                }
            }
        }
        let thunk_addrs = ev.thunks;
        Self {
            img,
            starts,
            sizes,
            names,
            thunk_api,
            apis,
            edges: edges.len(),
            fwd,
            rev,
            func_apis,
            func_strs,
            strings: ev.strings,
            parent,
            roots,
            thunk_addrs,
            instructions: ev.instructions,
            exec_bytes: ev.exec_bytes,
            api_call_sites,
            truncated,
        }
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn index_of(&self, a: u64) -> Option<u32> {
        self.starts.binary_search(&a).ok().map(|i| i as u32)
    }

    pub fn reachable(&self, f: u32) -> bool {
        self.parent[f as usize] != NONE
    }

    pub fn is_thunk(&self, f: u32) -> bool {
        self.thunk_api.contains_key(&f)
    }

    pub fn label(&self, f: u32) -> String {
        match &self.names[f as usize] {
            Some(n) => n.clone(),
            None => format!("sub_{:x}", self.starts[f as usize]),
        }
    }

    /// `name@0xaddr` for named functions, `sub_<hex>` otherwise.
    pub fn reference(&self, f: u32) -> String {
        match &self.names[f as usize] {
            Some(n) => format!("{n}@{:#x}", self.starts[f as usize]),
            None => format!("sub_{:x}", self.starts[f as usize]),
        }
    }

    pub fn is_runtime(&self, f: u32) -> bool {
        self.names[f as usize]
            .as_deref()
            .is_some_and(|n| apis::is_runtime_function(n, self.img.is_go))
            || self
                .img
                .names
                .get(&self.starts[f as usize])
                .is_some_and(|n| apis::is_runtime_function(n, self.img.is_go))
    }

    pub fn apis_of(&self, f: u32) -> &[(u32, u32)] {
        let a = self.func_apis.partition_point(|x| x.0 < f);
        let b = self.func_apis.partition_point(|x| x.0 <= f);
        &self.func_apis[a..b]
    }

    pub fn strings_of(&self, f: u32) -> &[(u32, u32)] {
        let a = self.func_strs.partition_point(|x| x.0 < f);
        let b = self.func_strs.partition_point(|x| x.0 <= f);
        &self.func_strs[a..b]
    }

    pub fn categories_of(&self, f: u32) -> Vec<&'static str> {
        let mut cats: Vec<&'static str> = self
            .apis_of(f)
            .iter()
            .filter_map(|(_, a)| self.apis[*a as usize].category)
            .collect();
        cats.sort_unstable();
        cats.dedup();
        cats
    }

    /// Functions from a root to `f` along BFS parents (root first).
    pub fn path_from_root(&self, f: u32) -> Vec<u32> {
        let mut path = vec![f];
        let mut cur = f;
        while self.parent[cur as usize] != cur
            && self.parent[cur as usize] != NONE
            && path.len() < 64
        {
            cur = self.parent[cur as usize];
            path.push(cur);
        }
        path.reverse();
        path
    }

    /// Shortest direct-call path from `from` to a function satisfying `goal`,
    /// within `max_depth` edges and `max_visits` functions.
    pub fn path_to(
        &self,
        from: u32,
        max_depth: usize,
        max_visits: usize,
        goal: impl Fn(u32) -> bool,
    ) -> Option<Vec<u32>> {
        let mut prev: HashMap<u32, u32> = HashMap::new();
        let mut queue = VecDeque::from([(from, 0usize)]);
        prev.insert(from, from);
        while let Some((f, d)) = queue.pop_front() {
            if goal(f) {
                let mut path = vec![f];
                let mut cur = f;
                while prev[&cur] != cur {
                    cur = prev[&cur];
                    path.push(cur);
                }
                path.reverse();
                return Some(path);
            }
            if d >= max_depth || prev.len() >= max_visits {
                continue;
            }
            for &(t, kind) in self.fwd.of(f) {
                if kind != EdgeKind::AddressTaken && !prev.contains_key(&t) {
                    prev.insert(t, f);
                    queue.push_back((t, d + 1));
                }
            }
        }
        None
    }

    /// Callers of `f` up to `depth` levels (including `f`), bounded.
    pub fn ancestors(&self, f: u32, depth: usize, max: usize) -> Vec<u32> {
        let mut seen: HashSet<u32> = HashSet::from([f]);
        let mut out = vec![f];
        let mut frontier = vec![f];
        for _ in 0..depth {
            let mut next = vec![];
            for g in frontier {
                for &(c, kind) in self.rev.of(g) {
                    if kind != EdgeKind::AddressTaken && out.len() < max && seen.insert(c) {
                        out.push(c);
                        next.push(c);
                    }
                }
            }
            frontier = next;
        }
        out
    }

    /// Render a call chain like `main → upload → WS2_32!send`.
    pub fn render_path(&self, path: &[u32], api: Option<u32>) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (i, f) in path.iter().enumerate() {
            if i > 0 {
                let kind = self
                    .fwd
                    .of(path[i - 1])
                    .iter()
                    .find(|(t, _)| t == f)
                    .map(|x| x.1);
                parts.push(if kind == Some(EdgeKind::AddressTaken) {
                    "⇢".into()
                } else {
                    "→".into()
                });
            }
            parts.push(self.label(*f));
        }
        if let Some(a) = api {
            parts.push("→".into());
            parts.push(self.apis[a as usize].name.clone());
        }
        parts.join(" ")
    }
}

/// Upper bound on pointer-table entries read in total.
const MAX_TABLE_READS: usize = 4_000_000;

/// For each referenced data address, read consecutive pointers and keep those
/// that point into code: (referencing instruction, code address).
fn scan_pointer_tables(
    img: &Image,
    data_refs: &[(u64, u64)],
    truncated: &mut Vec<String>,
) -> Vec<(u64, u64)> {
    let ps = (img.bits / 8) as u64;
    let mut cache: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut reads = 0usize;
    let mut out = Vec::new();
    for (ip, addr) in data_refs {
        if !cache.contains_key(addr) && cache.len() < 1_000_000 {
            let mut targets = vec![];
            let mut misses = 0;
            for k in 0..64u64 {
                if reads >= MAX_TABLE_READS {
                    break;
                }
                reads += 1;
                let Some(p) = img.pointer_at(addr.wrapping_add(k * ps)) else {
                    break;
                };
                if p != 0 && img.is_exec(p) && !img.slots.contains_key(&p) {
                    targets.push(p);
                    misses = 0;
                    // Go funcvals are packed back to back: only the referenced one counts.
                    if img.is_go && k == 0 {
                        break;
                    }
                } else {
                    misses += 1;
                    // Allow a short header (RTTI / itab fields) before the first code pointer.
                    if misses >= if targets.is_empty() { 4 } else { 2 } {
                        break;
                    }
                }
            }
            cache.insert(*addr, targets);
        }
        if let Some(targets) = cache.get(addr) {
            out.extend(targets.iter().map(|t| (*ip, *t)));
        }
        if out.len() > 4_000_000 {
            truncated.push(
                "pointer-table bound reached; some address-taken functions were not linked".into(),
            );
            break;
        }
    }
    if reads >= MAX_TABLE_READS {
        truncated.push(format!(
            "pointer-table read bound ({MAX_TABLE_READS}) reached"
        ));
    }
    out
}

/// Minimal Itanium / Rust-legacy demangling of nested names (`_ZN3foo3barE`
/// → `foo::bar`), dropping Rust hash suffixes. Anything else is returned as is.
pub(crate) fn demangle(name: &str) -> String {
    let Some(rest) = name
        .strip_prefix("_ZN")
        .or_else(|| name.strip_prefix("__ZN"))
    else {
        if let Some(rest) = name.strip_prefix("_Z") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(len) = digits.parse::<usize>()
                && let Some(ident) = rest.get(digits.len()..digits.len().saturating_add(len))
            {
                return ident.to_owned();
            }
        }
        return name.to_owned();
    };
    let mut parts = vec![];
    let mut s = rest;
    while !s.is_empty() && !s.starts_with('E') && parts.len() < 32 {
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(len) = digits.parse::<usize>() else {
            return name.to_owned();
        };
        let end = digits.len().saturating_add(len);
        let Some(ident) = s.get(digits.len()..end) else {
            return name.to_owned();
        };
        parts.push(ident);
        s = &s[end..];
    }
    if parts.is_empty() {
        return name.to_owned();
    }
    if let Some(last) = parts.last()
        && last.len() == 17
        && last.starts_with('h')
        && last[1..].bytes().all(|c| c.is_ascii_hexdigit())
    {
        parts.pop();
    }
    let joined = parts.join("::");
    let mut out = joined.replace("..", "::");
    for (from, to) in [
        ("$LT$", "<"),
        ("$GT$", ">"),
        ("$RF$", "&"),
        ("$BP$", "*"),
        ("$C$", ","),
        ("$u20$", " "),
        ("$u7b$", "{"),
        ("$u7d$", "}"),
        ("$u27$", "'"),
        ("$u5b$", "["),
        ("$u5d$", "]"),
        ("$SP$", "@"),
    ] {
        out = out.replace(from, to);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn demangles() {
        assert_eq!(
            super::demangle("_ZN3std3net3tcp9TcpStream7connect17h0123456789abcdefE"),
            "std::net::tcp::TcpStream::connect"
        );
        assert_eq!(super::demangle("_ZN3foo3barEv"), "foo::bar");
        assert_eq!(super::demangle("_Z6uploadPKc"), "upload");
        assert_eq!(super::demangle("_ZN99"), "_ZN99");
        assert_eq!(super::demangle("main"), "main");
    }
}

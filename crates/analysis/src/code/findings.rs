//! Findings backed by the code map. Kept few and grouped (one per category
//! per artifact, at most 8 evidence items each), with honest strengths:
//! `static_reachability` only when the subject function is reachable from an
//! entry point, otherwise `static_reference`. Nothing here traces data flow.

use std::collections::{HashMap, HashSet, VecDeque};

use bytebouncer_core::{EvidenceKind, EvidenceStrength, Location, Recipient, Severity};

use super::apis::{self, base_name};
use super::graph::{Analysis, EdgeKind};
use crate::Builder;
use crate::rules::IMPORT_RULES;

const TOOL: &str = "bytebouncer-codemap";
const MAX_EVIDENCE: usize = 8;
/// Depth of call chains searched from a subject function.
const CHAIN_DEPTH: usize = 4;
/// Subject functions examined per finding kind (each costs one bounded search).
const MAX_CANDIDATES: usize = 1000;
const STATIC_LIMIT: &str = "Static call graph only (direct calls, tail jumps, taken function addresses); whether and when this code runs is not established";
const NO_DATAFLOW: &str =
    "No data-flow tracking: which data reaches the network call was not traced";

pub(crate) fn add(b: &mut Builder, a: &Analysis) {
    let send = reach_set(a, &[apis::NETWORK_SEND]);
    let net = reach_set(a, &[apis::NETWORK_SEND, apis::NETWORK_SETUP]);
    recipients(b, a, &net);
    identifiers(b, a, &send);
    let covered = upgrade_import_rules(b, a);
    sensitive(b, a, &covered);
    persistence(b, a);
}

fn subject(a: &Analysis, f: u32) -> bool {
    !a.is_thunk(f) && !a.is_runtime(f)
}

/// First API called by `f` in the earliest-listed matching category.
fn calls_category(a: &Analysis, f: u32, cats: &[&str]) -> Option<u32> {
    let calls = a.apis_of(f);
    cats.iter().find_map(|cat| {
        calls
            .iter()
            .find(|(_, x)| a.apis[*x as usize].category == Some(*cat))
            .map(|x| x.1)
    })
}

/// Functions from which a caller of `cats` is reachable within `CHAIN_DEPTH`
/// direct calls (reverse BFS from the callers), bounded.
fn reach_set(a: &Analysis, cats: &[&str]) -> HashSet<u32> {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<(u32, usize)> = VecDeque::new();
    for (f, x) in &a.func_apis {
        if a.apis[*x as usize]
            .category
            .is_some_and(|c| cats.contains(&c))
            && seen.insert(*f)
        {
            queue.push_back((*f, 0));
        }
    }
    while let Some((f, d)) = queue.pop_front() {
        if d >= CHAIN_DEPTH || seen.len() > 500_000 {
            continue;
        }
        for &(c, kind) in a.rev.of(f) {
            if kind != EdgeKind::AddressTaken && seen.insert(c) {
                queue.push_back((c, d + 1));
            }
        }
    }
    seen
}

/// Root path to `from` (if reachable) followed by `chain` (which starts at `from`).
fn full_path(a: &Analysis, chain: &[u32]) -> Vec<u32> {
    let Some(&first) = chain.first() else {
        return vec![];
    };
    let mut p = if a.reachable(first) {
        a.path_from_root(first)
    } else {
        vec![first]
    };
    p.extend_from_slice(&chain[1..]);
    if p.len() > 12 {
        let tail = p.split_off(p.len() - 9);
        p.truncate(2);
        p.extend(tail);
    }
    p
}

fn call_path_evidence(
    b: &mut Builder,
    a: &Analysis,
    subject: u32,
    path: &[u32],
    api: Option<u32>,
    rule: &str,
) -> String {
    let text = a.render_path(path, api);
    let id = b.add_evidence(
        EvidenceKind::CallPath,
        Location {
            function: Some(a.reference(subject)),
            address: Some(a.starts[subject as usize]),
            ..Default::default()
        },
        &text,
        TOOL,
        Some(rule),
    );
    if let Some(ev) = b.evidence.last_mut() {
        ev.notes = Some(format!(
            "{} reachable from an entry point; direct calls only",
            if a.reachable(subject) {
                "Subject function is"
            } else {
                "Subject function is NOT"
            }
        ));
    }
    id
}

fn string_evidence(b: &mut Builder, a: &Analysis, f: u32, s: u32, rule: &str) -> String {
    let st = &a.strings[s as usize];
    let section = a
        .img
        .region_of(st.address)
        .map(|r| r.name.clone())
        .filter(|n| !n.is_empty());
    b.add_evidence(
        EvidenceKind::StringReference,
        Location {
            function: Some(a.reference(f)),
            address: Some(st.address),
            section,
            ..Default::default()
        },
        &st.text,
        TOOL,
        Some(rule),
    )
}

fn set_strength(b: &mut Builder, i: usize, reachable: bool) {
    b.findings[i].evidence_strength = if reachable {
        EvidenceStrength::StaticReachability
    } else {
        EvidenceStrength::StaticReference
    };
}

struct NetHit {
    f: u32,
    chain: Vec<u32>,
    api: u32,
    strings: Vec<u32>,
}

fn recipients(b: &mut Builder, a: &Analysis, net: &HashSet<u32>) {
    let is_net =
        |g: u32| calls_category(a, g, &[apis::NETWORK_SEND, apis::NETWORK_SETUP]).is_some();
    let mut hits: Vec<NetHit> = vec![];
    let mut examined = 0;
    for f in 0..a.len() as u32 {
        if !net.contains(&f) || !subject(a, f) {
            continue;
        }
        let strings: Vec<u32> = a
            .strings_of(f)
            .iter()
            .map(|x| x.1)
            .filter(|s| {
                let st = &a.strings[*s as usize];
                matches!(st.kind, "url" | "host" | "ip")
                    && super::text::host_of(&st.text)
                        .is_some_and(|h| h != "localhost" && !h.starts_with("127."))
            })
            .collect();
        if strings.is_empty() {
            continue;
        }
        examined += 1;
        if examined > MAX_CANDIDATES {
            break;
        }
        if let Some(chain) = a.path_to(f, CHAIN_DEPTH, 1024, is_net)
            && let Some(api) = chain
                .last()
                .and_then(|g| calls_category(a, *g, &[apis::NETWORK_SEND, apis::NETWORK_SETUP]))
        {
            hits.push(NetHit {
                f,
                chain,
                api,
                strings,
            });
        }
    }
    if hits.is_empty() {
        return;
    }
    hits.sort_by_key(|h| (!a.reachable(h.f), h.chain.len(), h.f));
    let total = hits.len();
    // Report reachable code when there is any; unreachable matches are only counted.
    if a.reachable(hits[0].f) {
        hits.retain(|h| a.reachable(h.f));
    }
    let mut hosts: Vec<String> = vec![];
    for h in &hits {
        for s in &h.strings {
            if let Some(host) = super::text::host_of(&a.strings[*s as usize].text)
                && !hosts.contains(&host)
            {
                hosts.push(host);
            }
        }
    }
    let reachable = a.reachable(hits[0].f);
    let mut ids = vec![];
    for h in hits.iter().take(MAX_EVIDENCE / 2) {
        let path = full_path(a, &h.chain);
        ids.push(call_path_evidence(
            b,
            a,
            h.f,
            &path,
            Some(h.api),
            "codemap-network-endpoint",
        ));
        ids.push(string_evidence(
            b,
            a,
            h.f,
            h.strings[0],
            "codemap-network-endpoint",
        ));
    }
    let shown: Vec<&str> = hosts.iter().take(3).map(String::as_str).collect();
    let more = if hosts.len() > 3 {
        format!(" (+{} more)", hosts.len() - 3)
    } else {
        String::new()
    };
    let title = format!(
        "{} that opens network connections references endpoint(s): {}{more}",
        if reachable {
            "Code reachable from entry"
        } else {
            "Code"
        },
        shown.join(", ")
    );
    let recipient = (hosts.len() == 1).then(|| Recipient {
        domain: hosts[0].clone(),
        ownership: "unknown".into(),
    });
    b.add_finding(
        "privacy.recipients",
        title,
        if reachable { Severity::Low } else { Severity::Info },
        ids,
        recipient,
        Some("Update checks, licensing, telemetry, or user-requested network features"),
        vec![
            STATIC_LIMIT.into(),
            "The endpoint string and the network call co-occur in one call chain; that the endpoint is the destination, and what is transmitted, are not established".into(),
            format!("{} function(s) matched ({} reachable from an entry point); at most {} shown as evidence", total, hits.iter().filter(|h| a.reachable(h.f)).count(), MAX_EVIDENCE / 2),
        ],
    );
    let i = b.findings.len() - 1;
    set_strength(b, i, reachable);
}

fn identifiers(b: &mut Builder, a: &Analysis, send: &HashSet<u32>) {
    let mut sources: Vec<(u32, Option<u32>, Option<u32>)> = vec![];
    for f in 0..a.len() as u32 {
        if !subject(a, f) {
            continue;
        }
        let api = a.apis_of(f).iter().map(|x| x.1).find(|x| {
            a.apis[*x as usize].category == Some(apis::IDENTIFIERS)
                && !apis::is_weak_identifier(&a.apis[*x as usize].name)
        });
        let s = a
            .strings_of(f)
            .iter()
            .map(|x| x.1)
            .find(|s| a.strings[*s as usize].kind == "identifier_source");
        if api.is_some() || s.is_some() {
            sources.push((f, api, s));
        }
    }
    if sources.is_empty() {
        return;
    }
    sources.sort_by_key(|(f, ..)| (!a.reachable(*f), *f));
    let has_send = |g: u32| calls_category(a, g, &[apis::NETWORK_SEND]).is_some();
    // (common caller, identifier function, chain to identifier, chain to sender)
    let mut chains = vec![];
    for (i, api, s) in sources.iter().take(64) {
        let mut ancestors = a.ancestors(*i, 2, 32);
        ancestors.sort_by_key(|g| (!a.reachable(*g), *g != *i));
        for anc in ancestors {
            if !send.contains(&anc) {
                continue;
            }
            let Some(to_id) = a.path_to(anc, 3, 512, |g| g == *i) else {
                continue;
            };
            let Some(to_send) = a.path_to(anc, CHAIN_DEPTH, 2048, has_send) else {
                continue;
            };
            chains.push((anc, *i, *api, *s, to_id, to_send));
            break;
        }
        if chains.len() >= 8 {
            break;
        }
    }
    let data_type = |api: Option<u32>, s: Option<u32>| -> String {
        match (api, s) {
            (Some(x), _) => apis::identifier_data_type(&a.apis[x as usize].name).to_owned(),
            (None, Some(_)) => "machine_identifier".to_owned(),
            _ => "host_identifier".to_owned(),
        }
    };
    if !chains.is_empty() {
        chains.sort_by_key(|c| !a.reachable(c.0));
        let reachable = a.reachable(chains[0].0);
        let mut ids = vec![];
        let mut types: Vec<String> = vec![];
        for (anc, i, api, s, to_id, to_send) in chains.iter().take(MAX_EVIDENCE / 2) {
            let ty = data_type(*api, *s);
            if !types.contains(&ty) {
                types.push(ty);
            }
            ids.push(call_path_evidence(
                b,
                a,
                *anc,
                &full_path(a, to_id),
                *api,
                "codemap-identifier-source",
            ));
            if api.is_none()
                && let Some(s) = s
            {
                ids.push(string_evidence(b, a, *i, *s, "codemap-identifier-source"));
            }
            let send_api = to_send
                .last()
                .and_then(|g| calls_category(a, *g, &[apis::NETWORK_SEND]));
            ids.push(call_path_evidence(
                b,
                a,
                *anc,
                &full_path(a, to_send),
                send_api,
                "codemap-identifier-send-chain",
            ));
        }
        ids.truncate(MAX_EVIDENCE);
        b.add_finding(
            "privacy.identifiers",
            format!("Reads {} and sends network data in the same call chain", types.join(", ")),
            if reachable { Severity::Medium } else { Severity::Low },
            ids,
            None,
            Some("Diagnostics, licensing/activation, or device registration"),
            vec![NO_DATAFLOW.into(), STATIC_LIMIT.into(), "A common caller reaches both the identifier source and a network send; whether the identifier is transmitted is not established".into()],
        );
        let i = b.findings.len() - 1;
        b.findings[i].data_types = types;
        set_strength(b, i, reachable);
        return;
    }
    let reachable: Vec<&(u32, Option<u32>, Option<u32>)> =
        sources.iter().filter(|(f, ..)| a.reachable(*f)).collect();
    if reachable.is_empty() {
        return;
    }
    let mut ids = vec![];
    let mut types: Vec<String> = vec![];
    for (f, api, s) in reachable.iter().take(4) {
        let ty = data_type(*api, *s);
        if !types.contains(&ty) {
            types.push(ty);
        }
        ids.push(call_path_evidence(
            b,
            a,
            *f,
            &full_path(a, &[*f]),
            *api,
            "codemap-identifier-source",
        ));
        if api.is_none()
            && let Some(s) = s
        {
            ids.push(string_evidence(b, a, *f, *s, "codemap-identifier-source"));
        }
    }
    b.add_finding(
        "privacy.identifiers",
        format!(
            "Reads {} (no network send found in the same call chain)",
            types.join(", ")
        ),
        Severity::Info,
        ids,
        None,
        Some("Display, logging, configuration, or local licensing"),
        vec![
            STATIC_LIMIT.into(),
            "Indirect calls are not followed, so a network path may still exist".into(),
        ],
    );
    let i = b.findings.len() - 1;
    b.findings[i].data_types = types;
    set_strength(b, i, true);
}

/// Callers of APIs whose bare name is in `names`: (function, api).
fn callers_named(a: &Analysis, names: &[&str]) -> Vec<(u32, u32)> {
    let ids: HashSet<u32> = a
        .apis
        .iter()
        .enumerate()
        .filter(|(_, api)| {
            !api.dynamic
                && names
                    .iter()
                    .any(|n| base_name(&api.name).trim_start_matches('_') == *n)
        })
        .map(|(i, _)| i as u32)
        .collect();
    let mut out: Vec<(u32, u32)> = a
        .func_apis
        .iter()
        .filter(|(_, x)| ids.contains(x))
        .copied()
        .collect();
    out.sort_by_key(|(f, _)| (!a.reachable(*f), *f));
    out
}

/// Strengthen (or qualify) the import-presence findings from `rules.rs` with
/// call-site reachability instead of adding duplicates. Returns the API
/// categories now covered by those findings.
fn upgrade_import_rules(b: &mut Builder, a: &Analysis) -> HashSet<&'static str> {
    let mut covered = HashSet::new();
    let mut targets: Vec<(usize, &'static crate::rules::ImportRule)> = vec![];
    for (i, f) in b.findings.iter().enumerate() {
        let rule = f
            .evidence_ids
            .first()
            .and_then(|id| b.evidence.iter().find(|e| &e.id == id))
            .filter(|e| e.kind == EvidenceKind::Import)
            .and_then(|e| e.producer.rule_id.as_deref())
            .and_then(|r| IMPORT_RULES.iter().find(|x| x.id == r));
        if let Some(rule) = rule {
            targets.push((i, rule));
        }
    }
    for (i, rule) in targets {
        for imp in rule.imports {
            if let Some(c) = apis::classify(imp) {
                covered.insert(c);
            }
        }
        let sites = callers_named(a, rule.imports);
        let reachable_all = if rule.require_all {
            rule.imports.iter().all(|n| {
                sites.iter().any(|(f, x)| {
                    a.reachable(*f)
                        && base_name(&a.apis[*x as usize].name).trim_start_matches('_') == *n
                })
            })
        } else {
            sites.iter().any(|(f, _)| a.reachable(*f))
        };
        let mut new_ids = vec![];
        let mut seen = HashSet::new();
        for (f, x) in sites.iter() {
            if new_ids.len() >= 4 {
                break;
            }
            if seen.insert(*f) {
                let path = full_path(a, &[*f]);
                new_ids.push(call_path_evidence(b, a, *f, &path, Some(*x), rule.id));
            }
        }
        let f = &mut b.findings[i];
        f.evidence_ids.extend(new_ids);
        f.limitations
            .retain(|l| !l.starts_with("Import presence only"));
        if reachable_all {
            f.evidence_strength = EvidenceStrength::StaticReachability;
            f.limitations.push("Call sites are reachable from an entry point in the static call graph (direct calls only); runtime conditions are not established".into());
        } else if !sites.is_empty() {
            f.limitations.push("Call sites found, but not all required APIs are reachable from an entry point through the static call graph".into());
        } else {
            f.limitations.push("No direct call site found by the built-in code map (may be called indirectly or be unused)".into());
        }
    }
    covered
}

fn sensitive(b: &mut Builder, a: &Analysis, covered: &HashSet<&'static str>) {
    let groups: [(&str, &str, Severity, &str); 4] = [
        (
            apis::INPUT_CAPTURE,
            "Keyboard/input capture code reachable from entry",
            Severity::Medium,
            "Hotkeys, games, remote-desktop and accessibility tools",
        ),
        (
            apis::SCREEN_CAPTURE,
            "Screen capture code reachable from entry",
            Severity::Low,
            "Screenshot, screen-sharing, and remote-support features",
        ),
        (
            apis::CLIPBOARD,
            "Clipboard read reachable from entry",
            Severity::Low,
            "Paste support",
        ),
        (
            apis::MEDIA_CAPTURE,
            "Microphone/camera capture code reachable from entry",
            Severity::Low,
            "Calls, recording, and media features",
        ),
    ];
    for (cat, title, severity, purpose) in groups {
        if covered.contains(cat) {
            continue;
        }
        let mut sites: Vec<(u32, u32)> = vec![];
        for (f, x) in &a.func_apis {
            if a.apis[*x as usize].category != Some(cat) || !a.reachable(*f) || a.is_thunk(*f) {
                continue;
            }
            // BitBlt/StretchBlt are ordinary drawing unless paired with a screen/window DC.
            let n = base_name(&a.apis[*x as usize].name).trim_start_matches('_');
            if cat == apis::SCREEN_CAPTURE
                && (n == "BitBlt" || n == "StretchBlt")
                && calls_category(a, *f, &[apis::DISPLAY_CONTEXT]).is_none()
            {
                continue;
            }
            if !sites.iter().any(|s| s.0 == *f) {
                sites.push((*f, *x));
            }
        }
        if sites.is_empty() {
            continue;
        }
        let ids = sites
            .iter()
            .take(4)
            .map(|(f, x)| {
                call_path_evidence(
                    b,
                    a,
                    *f,
                    &full_path(a, &[*f]),
                    Some(*x),
                    "codemap-sensitive-collection",
                )
            })
            .collect();
        b.add_finding("privacy.sensitive_collection", title.to_owned(), severity, ids, None, Some(purpose), vec![STATIC_LIMIT.into(), "Capability reachable in code; whether captured data is stored or transmitted is not established".into()]);
        let i = b.findings.len() - 1;
        set_strength(b, i, true);
    }
}

/// (function, chain, api, string, severity, what)
type PersistHit = (
    u32,
    Vec<u32>,
    Option<u32>,
    Option<u32>,
    Severity,
    &'static str,
);

fn persistence(b: &mut Builder, a: &Analysis) {
    let reg_write = |g: u32| calls_category(a, g, &[apis::REGISTRY_WRITE]).is_some();
    let proc_create = |g: u32| calls_category(a, g, &[apis::PROCESS_CREATE]).is_some();
    let mut hits: Vec<PersistHit> = vec![];
    let mut seen: HashMap<u32, ()> = HashMap::new();
    let mut searched = 0;
    for (f, s) in &a.func_strs {
        if hits.len() >= 8 || seen.contains_key(f) || !subject(a, *f) {
            continue;
        }
        let st = &a.strings[*s as usize];
        let lower = st.text.to_ascii_lowercase();
        let run_key = st.kind == "registry"
            && (lower.contains("\\currentversion\\run")
                || lower.contains("\\winlogon")
                || lower.contains("\\image file execution options"));
        let task = st.kind == "command"
            && ((lower.contains("schtasks") && lower.contains("/create"))
                || lower.contains("crontab")
                || lower.contains("systemctl enable")
                || lower.contains("launchctl load"));
        let (goal, what): (&dyn Fn(u32) -> bool, &str) = if run_key {
            (&reg_write, "autostart registry key")
        } else if task {
            (&proc_create, "scheduled task / service command")
        } else {
            continue;
        };
        searched += 1;
        if searched > MAX_CANDIDATES {
            break;
        }
        if let Some(chain) = a.path_to(*f, 2, 256, goal) {
            let api = chain
                .last()
                .and_then(|g| calls_category(a, *g, &[apis::REGISTRY_WRITE, apis::PROCESS_CREATE]));
            seen.insert(*f, ());
            hits.push((
                *f,
                chain,
                api,
                Some(*s),
                if run_key {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                what,
            ));
        }
    }
    for (f, x) in callers_named(
        a,
        &[
            "CreateServiceA",
            "CreateServiceW",
            "ChangeServiceConfigA",
            "ChangeServiceConfigW",
            "NetScheduleJobAdd",
        ],
    ) {
        if hits.len() >= 8 || seen.contains_key(&f) || !subject(a, f) {
            continue;
        }
        seen.insert(f, ());
        hits.push((
            f,
            vec![f],
            Some(x),
            None,
            Severity::Low,
            "service installation",
        ));
    }
    if hits.is_empty() {
        return;
    }
    hits.sort_by_key(|h| (!a.reachable(h.0), std::cmp::Reverse(h.4)));
    let reachable = a.reachable(hits[0].0);
    let severity = hits.iter().map(|h| h.4).max().unwrap_or(Severity::Low);
    let mut whats: Vec<&str> = hits.iter().map(|h| h.5).collect();
    whats.dedup();
    let mut ids = vec![];
    for (f, chain, api, s, ..) in hits.iter().take(4) {
        ids.push(call_path_evidence(
            b,
            a,
            *f,
            &full_path(a, chain),
            *api,
            "codemap-persistence",
        ));
        if let Some(s) = s {
            ids.push(string_evidence(b, a, *f, *s, "codemap-persistence"));
        }
    }
    ids.truncate(MAX_EVIDENCE);
    b.add_finding(
        "security.persistence",
        format!("Code that installs persistence ({})", whats.join(", ")),
        if reachable { severity } else { Severity::Low },
        ids,
        None,
        Some("Installers, updaters, and background services register themselves to start automatically"),
        vec![STATIC_LIMIT.into(), "The persistence string and the registry/process call co-occur in one call chain; arguments were not traced".into()],
    );
    let i = b.findings.len() - 1;
    set_strength(b, i, reachable);
}

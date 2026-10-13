//! Developer tool: build the built-in code map for files and print a summary.
//! `cargo run --release -p bytebouncer-analysis --example codemap -- FILE... [--json] [--tool NAME ARGS_JSON]`
//! Never executes the inputs.

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let tool = args
        .iter()
        .position(|a| a == "--tool")
        .map(|i| (args[i + 1].clone(), args[i + 2].clone()));
    let files: Vec<&String> = args.iter().take_while(|a| !a.starts_with("--")).collect();
    let mut maps = vec![];
    for path in files {
        let bytes = std::fs::read(path).expect("read");
        let t = Instant::now();
        let (out, map) = bytebouncer_analysis::analyze_leaf_with_code(&bytes, path, "sha", None);
        let dt = t.elapsed();
        println!(
            "== {path} ({} bytes) in {:.3}s",
            bytes.len(),
            dt.as_secs_f64()
        );
        for c in out
            .coverage
            .analyzed
            .iter()
            .chain(&out.coverage.unsupported)
            .filter(|c| c.contains("code map"))
        {
            println!("   {c}");
        }
        for f in &out.findings {
            println!(
                "   [{:?}/{:?}] {}: {}",
                f.severity, f.evidence_strength, f.category, f.title
            );
            for id in &f.evidence_ids {
                if let Some(e) = out
                    .evidence
                    .iter()
                    .find(|e| &e.id == id && e.producer.tool == "bytebouncer-codemap")
                {
                    println!("       {:?} {}", e.kind, e.snippet.as_deref().unwrap_or(""));
                }
            }
        }
        if let Some(m) = map {
            println!(
                "   map: {} functions retained, {} apis, {} bytes json",
                m.functions.len(),
                m.apis.len(),
                m.json_len()
            );
            for f in m.functions.iter().take(8) {
                println!(
                    "     {:>4} {} reach={} cats={:?} strings={:?}",
                    f.relevance,
                    f.label,
                    f.reachable,
                    f.categories,
                    f.strings
                        .iter()
                        .take(3)
                        .map(|s| &s.text)
                        .collect::<Vec<_>>()
                );
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&m).unwrap());
            }
            maps.push(m);
        }
    }
    if let Some((name, a)) = tool {
        let v: serde_json::Value = serde_json::from_str(&a).expect("args json");
        match bytebouncer_analysis::code::tools::call(&maps, &name, &v) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(e) => println!("error: {e}"),
        }
    }
}

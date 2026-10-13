//! Manual validation against real-world files, which are not redistributable
//! and so not committed:
//! `BYTEBOUNCER_SAMPLE=/path/to/file cargo test -p bytebouncer-formats --test real_samples -- --ignored --nocapture`
//! Recurses through nested containers, printing a summary per level.

use bytebouncer_formats::{ContainerKind, Limits, detect, expand};

fn walk(bytes: &[u8], name: &str, depth: usize) {
    let Some(kind) = detect(bytes, name) else {
        return;
    };
    let indent = "  ".repeat(depth);
    match expand(bytes, kind, &Limits::default()) {
        Err(e) => println!("{indent}{name}: {kind:?}: error: {e}"),
        Ok(out) => {
            println!(
                "{indent}{name}: {kind:?}: {} children, truncated={}",
                out.children.len(),
                out.truncated
            );
            for (k, v) in out.metadata.iter().take(25) {
                println!(
                    "{indent}  meta {k} = {}",
                    v.chars().take(100).collect::<String>()
                );
            }
            for s in &out.scripts {
                println!(
                    "{indent}  script {} {:?} {} ({} bytes)",
                    s.kind,
                    s.interpreter,
                    s.path,
                    s.text.len()
                );
            }
            for p in out.problems.iter().take(10) {
                println!("{indent}  problem {p}");
            }
            if depth < 3 {
                for c in &out.children {
                    if kind != ContainerKind::Dmg {
                        walk(&c.data, &c.path, depth + 1);
                    }
                }
            }
        }
    }
}

#[test]
#[ignore]
fn real_sample() {
    let path = std::env::var("BYTEBOUNCER_SAMPLE").expect("set BYTEBOUNCER_SAMPLE");
    let bytes = std::fs::read(&path).unwrap();
    walk(&bytes, &path, 0);
}

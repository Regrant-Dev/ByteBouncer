//! Stage cache. Tier 1 results are keyed by the exact artifact
//! bytes plus everything that affects analysis: analyzer version and rule
//! digests. Display paths are not part of the key, so cached results are
//! re-labelled for the current scan.

use std::path::PathBuf;

use bytebouncer_analysis::ArtifactAnalysis;
use bytebouncer_analysis::yara::{BUNDLED_RULES, RuleSource};
use sha2::{Digest, Sha256};

pub struct Tier1Cache {
    dir: Option<PathBuf>,
    rules_digest: String,
}

impl Tier1Cache {
    pub fn new(enabled: bool, user_rules: &[RuleSource]) -> Self {
        let mut h = Sha256::new();
        h.update(bytebouncer_analysis::ANALYZER_VERSION);
        h.update(BUNDLED_RULES);
        for r in user_rules {
            h.update(r.name.as_bytes());
            h.update([0]);
            h.update(r.text.as_bytes());
        }
        let dir = enabled
            .then(|| directories::ProjectDirs::from("", "", "ByteBouncer"))
            .flatten()
            .map(|d| d.cache_dir().join("stages").join("tier1"));
        Self {
            dir,
            rules_digest: hex::encode(h.finalize()),
        }
    }

    pub fn rules_digest(&self) -> &str {
        &self.rules_digest
    }

    fn key(&self, sha256: &str) -> String {
        hex::encode(Sha256::digest(format!("{sha256}:{}", self.rules_digest)))
    }

    pub fn get(&self, sha256: &str, display: &str) -> Option<ArtifactAnalysis> {
        let path = self
            .dir
            .as_ref()?
            .join(format!("{}.json", self.key(sha256)));
        let cached: ArtifactAnalysis = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let old = cached.artifacts.first()?.path.clone();
        Some(relabel(cached, &old, display))
    }

    pub fn put(&self, sha256: &str, analysis: &ArtifactAnalysis) {
        let Some(dir) = &self.dir else { return };
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        if let Ok(json) = serde_json::to_vec(analysis) {
            let _ = crate::store::write_private_file(
                &dir.join(format!("{}.json", self.key(sha256))),
                &json,
            );
        }
    }
}

/// Replace the display-path prefix `old` with `new` throughout an analysis.
fn relabel(mut a: ArtifactAnalysis, old: &str, new: &str) -> ArtifactAnalysis {
    let fix = |p: &mut String| {
        if let Some(rest) = p.strip_prefix(old) {
            *p = format!("{new}{rest}");
        }
    };
    for art in &mut a.artifacts {
        fix(&mut art.path);
        if let Some(parent) = &mut art.parent {
            fix(parent);
        }
    }
    for map in &mut a.code {
        fix(&mut map.artifact_path);
    }
    for out in &mut a.outputs {
        for ev in &mut out.evidence {
            fix(&mut ev.artifact_path);
        }
        for list in [
            &mut out.coverage.analyzed,
            &mut out.coverage.skipped,
            &mut out.coverage.unsupported,
            &mut out.coverage.limitations,
        ] {
            for s in list.iter_mut() {
                fix(s);
            }
        }
    }
    a
}

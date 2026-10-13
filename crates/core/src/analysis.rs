//! Output contract for every analyzer (Tier 1 worker, Tier 2 VM, model broker),
//! and merging of per-analyzer outputs into one report with unique IDs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
use crate::finding::Finding;
use crate::report::Coverage;

/// What one analyzer produced for one or more artifacts. IDs only need to be
/// unique within this output; [`Merger`] renumbers them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisOutput {
    pub format: String,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub coverage: Coverage,
}

/// Accumulates outputs, assigning report-wide `finding-NNN` / `evidence-NNN` IDs.
#[derive(Debug, Default)]
pub struct Merger {
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub coverage: Coverage,
}

impl Merger {
    pub fn add(&mut self, out: AnalysisOutput) {
        let mut remap = HashMap::new();
        for mut ev in out.evidence {
            let new_id = format!("evidence-{:03}", self.evidence.len() + 1);
            remap.insert(ev.id.clone(), new_id.clone());
            ev.id = new_id;
            self.evidence.push(ev);
        }
        for mut f in out.findings {
            f.id = format!("finding-{:03}", self.findings.len() + 1);
            f.evidence_ids = f
                .evidence_ids
                .iter()
                .map(|id| {
                    remap
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| format!("missing:{id}"))
                })
                .collect();
            self.findings.push(f);
        }
        self.coverage.extend(out.coverage);
    }
}

impl Coverage {
    pub fn extend(&mut self, other: Coverage) {
        self.analyzed.extend(other.analyzed);
        self.skipped.extend(other.skipped);
        self.unsupported.extend(other.unsupported);
        self.limitations.extend(other.limitations);
    }
}

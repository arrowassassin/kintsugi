//! Wasm-safe UI view-model types — the shared data contract between the Kintsugi
//! data-binding engine (`kintsugi-app`, native) and the Dioxus frontend (wasm).
//!
//! Both sides depend on this crate, so the shape of every `invoke` payload is
//! checked by the compiler end-to-end — no hand-kept TypeScript/JSON contract to
//! drift. It carries **no** I/O dependencies (no rusqlite, no sockets), so it
//! compiles to `wasm32` for the frontend and links into the native host alike.
//!
//! Identifiers only — never secret contents (source ids are redacted upstream at
//! ingest, segment G). These are *view* types: presentation strings the daemon's
//! decisions already produced, not a place where any decision is made.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// One step of a provenance trail. Mirrors the daemon's `ProvStep` wire shape
/// (`{"step": "...", ...}`) so the same JSON round-trips on both sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum ProvStep {
    /// Untrusted content was read from a source.
    UntrustedRead {
        source_kind: String,
        source_id: String,
    },
    /// The command reads a sensitive path (identifier only).
    SensitiveRead { path: String },
    /// The command would send data to an egress target.
    EgressSink { target: String },
    /// A deterministic rule fired.
    RuleFired { rule: String },
}

impl ProvStep {
    /// The outline glyph + label the frontend pairs with the value (never color
    /// alone). The rule step is the one that earns the danger accent.
    pub fn glyph_label(&self) -> (&'static str, &'static str) {
        match self {
            ProvStep::UntrustedRead { .. } => ("↓", "untrusted read"),
            ProvStep::SensitiveRead { .. } => ("•", "sensitive read"),
            ProvStep::EgressSink { .. } => ("→", "egress sink"),
            ProvStep::RuleFired { .. } => ("⛔", "rule fired"),
        }
    }

    /// The identifier value shown in mono for this step.
    pub fn value(&self) -> &str {
        match self {
            ProvStep::UntrustedRead { source_id, .. } => source_id,
            ProvStep::SensitiveRead { path } => path,
            ProvStep::EgressSink { target } => target,
            ProvStep::RuleFired { rule } => rule,
        }
    }

    /// Whether this is the terminal rule step (drives the single danger accent).
    pub fn is_rule(&self) -> bool {
        matches!(self, ProvStep::RuleFired { .. })
    }
}

/// One row of the audit timeline — a logged command shaped for the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRow {
    pub id: String,
    /// RFC3339 timestamp (the frontend localizes it).
    pub ts: String,
    pub agent: String,
    pub session: Option<String>,
    /// The raw command, verbatim (already secret-redacted at capture).
    pub command: String,
    /// `safe` | `ambiguous` | `catastrophic`.
    pub class: String,
    /// `allowed` | `denied` | `held` — a word, never color alone.
    pub outcome: String,
    pub reason: String,
    /// Whether this row was a taint-driven (lethal-trifecta) block.
    pub provenance_block: bool,
    pub risk: Option<u8>,
    /// The model's one-line plain-English summary (Tier-2), when it scored this.
    pub summary: Option<String>,
    /// Working directory the command ran in.
    pub cwd: String,
    /// Which tier produced the decision: 1 = rules, 2 = local model.
    pub tier: u8,
}

/// A command held for the human's one-key decision (the approval queue).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueRow {
    pub id: String,
    pub ts: String,
    pub agent: String,
    pub session: Option<String>,
    pub command: String,
    pub class: String,
    pub reason: String,
    pub provenance_block: bool,
    /// The model's one-line plain-English summary from hold time, if it scored.
    pub summary: Option<String>,
    /// Working directory the command was proposed in (for the detail drawer).
    pub cwd: String,
}

/// The provenance view for a session: its taint state and the ordered trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceView {
    pub session: String,
    pub tainted: bool,
    pub trail: Vec<ProvStep>,
}

/// Top-of-window status: is the engine up, and on which scorer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStatus {
    pub running: bool,
    pub scorer: Option<String>,
}

/// Dashboard metric cards — counts across the recorded timeline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metrics {
    pub total: u64,
    pub allowed: u64,
    pub held: u64,
    pub denied: u64,
    /// Of the blocks, how many were taint-driven (lethal-trifecta) — the headline.
    pub trifecta_blocks: u64,
}

/// The tamper-evidence status of the append-only event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerify {
    pub intact: bool,
    pub length: u64,
    /// The sequence number of the first broken row, if any.
    pub broken_seq: Option<i64>,
    /// What went wrong, if the chain is broken.
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prov_step_round_trips_the_daemon_wire_shape() {
        // The JSON the daemon emits for a ProvStep must deserialize here unchanged.
        let json = r#"{"step":"rule_fired","rule":"TRIFECTA-01"}"#;
        let step: ProvStep = serde_json::from_str(json).unwrap();
        assert_eq!(
            step,
            ProvStep::RuleFired {
                rule: "TRIFECTA-01".into()
            }
        );
        assert!(step.is_rule());
        assert_eq!(step.glyph_label().1, "rule fired");
        assert_eq!(serde_json::to_string(&step).unwrap(), json);
    }

    #[test]
    fn untrusted_read_exposes_glyph_and_value() {
        let step = ProvStep::UntrustedRead {
            source_kind: "web".into(),
            source_id: "https://x/p".into(),
        };
        assert_eq!(step.glyph_label(), ("↓", "untrusted read"));
        assert_eq!(step.value(), "https://x/p");
        assert!(!step.is_rule());
    }
}

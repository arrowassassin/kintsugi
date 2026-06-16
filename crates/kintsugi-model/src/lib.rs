//! Kintsugi Tier-2 model wrapper.
//!
//! The model's only jobs are to **explain** (a one-sentence summary) and to
//! **score** the ambiguous band (a `risk` 0..=100). It is never in the path for a
//! catastrophic command, and its influence is escalation-only — it can add
//! caution but can never unlock a rule-based block (see `CLAUDE.md`).
//!
//! Two backends behind one [`Scorer`] trait:
//! - [`HeuristicScorer`] — deterministic, dependency-free, always available. This
//!   is also the graceful-degradation path when no real model is present.
//! - `LlamaScorer` (feature `llama`) — real CPU GGUF inference via `llama.cpp`.

#![forbid(unsafe_code)]

pub mod heuristic;
pub mod manage;

#[cfg(feature = "llama")]
pub mod llama;

use kintsugi_core::{Class, ProposedCommand};

pub use heuristic::HeuristicScorer;
pub use manage::{select_spec, ModelSpec, MODEL_FALLBACK, MODEL_PRIMARY};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The model's structured output for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelOutput {
    /// One plain-English sentence describing what the command does.
    pub summary: String,
    /// Severity score, 0..=100. Only meaningful for the ambiguous band.
    pub risk: u8,
}

/// A Tier-2 scorer. Kept warm in the daemon and shared across requests.
pub trait Scorer: Send + Sync {
    /// A stable identifier for the backend (`"heuristic"`, `"llama:qwen2.5-3b"`, …).
    fn name(&self) -> &str;

    /// Explain and score a command. `rule` is the Tier-1 rule id that fired, used
    /// for a faithful summary. The score is only consulted for the ambiguous band.
    fn score(&self, cmd: &ProposedCommand, class: Class, rule: &str) -> ModelOutput;
}

/// Whether a real (non-heuristic) model backend is compiled in.
pub fn model_available() -> bool {
    cfg!(feature = "llama")
}

/// Construct the best available scorer: the real model if the `llama` feature is
/// on and weights load, otherwise the heuristic scorer.
pub fn default_scorer() -> Box<dyn Scorer> {
    #[cfg(feature = "llama")]
    {
        match llama::LlamaScorer::autoload() {
            Ok(s) => return Box::new(s),
            Err(e) => eprintln!("kintsugi-model: falling back to heuristic scorer: {e}"),
        }
    }
    Box::new(HeuristicScorer::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scorer_is_usable() {
        let s = default_scorer();
        let cmd = ProposedCommand::new("t", "/tmp", vec!["rm".into()], "rm -rf build");
        let out = s.score(&cmd, Class::Ambiguous, "ambiguous:rm");
        assert!(!out.summary.is_empty());
        assert!(out.risk <= 100);
    }

    #[test]
    fn model_available_tracks_feature() {
        assert_eq!(model_available(), cfg!(feature = "llama"));
    }
}

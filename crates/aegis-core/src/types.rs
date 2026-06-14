//! Shared event types exchanged between the interception layer and the daemon.
//!
//! These are the wire contract for the local IPC channel: interception sends a
//! [`ProposedCommand`], the daemon answers with a [`Verdict`]. The raw command is
//! always preserved verbatim (`raw` / `argv`) — a summary never replaces it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A command an agent proposes to run, normalized from any interception source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedCommand {
    /// Stable identifier for this proposal.
    pub id: Uuid,
    /// When the proposal was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    /// Originating agent: `"claude-code" | "qwen" | "codex" | "shim" | ...`.
    pub agent: String,
    /// Working directory the command would run in.
    pub cwd: PathBuf,
    /// The argument vector — never lose the raw command.
    pub argv: Vec<String>,
    /// A human-readable rendering of the command exactly as proposed.
    pub raw: String,
}

impl ProposedCommand {
    /// Build a new proposal, stamping a fresh id and the current time.
    pub fn new(
        agent: impl Into<String>,
        cwd: impl Into<PathBuf>,
        argv: Vec<String>,
        raw: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            agent: agent.into(),
            cwd: cwd.into(),
            argv,
            raw: raw.into(),
        }
    }
}

/// Deterministic classification of a proposed command (Tier-1 rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Read-only or otherwise harmless; auto-allowed.
    Safe,
    /// Destructive / irreversible; a hard floor — never unlocked by the model.
    Catastrophic,
    /// Needs judgement; held in attended mode, scored by the model in unattended mode.
    Ambiguous,
}

impl Class {
    /// Stable lowercase token used in storage and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Safe => "safe",
            Class::Catastrophic => "catastrophic",
            Class::Ambiguous => "ambiguous",
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What Aegis decided to do with the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Run it.
    Allow,
    /// Block it.
    Deny,
    /// Pause and wait for a human (or unattended policy) to resolve.
    Hold,
}

impl Decision {
    /// Stable lowercase token used in storage and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Hold => "hold",
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The daemon's answer for a proposed command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// Rule-engine classification.
    pub class: Class,
    /// What to do.
    pub decision: Decision,
    /// Which tier produced the decision: `1` = rules, `2` = model.
    pub tier: u8,
    /// Rule name or model reason.
    pub reason: String,
    /// One-sentence summary; filled by the model in Phase 2.
    pub summary: Option<String>,
    /// Severity score `0..=100`; filled by the model in Phase 2.
    pub risk: Option<u8>,
}

impl Verdict {
    /// A Tier-1 (rules) verdict with no model fields populated.
    pub fn rules(class: Class, decision: Decision, reason: impl Into<String>) -> Self {
        Self {
            class,
            decision,
            tier: 1,
            reason: reason.into(),
            summary: None,
            risk: None,
        }
    }
}

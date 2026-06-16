//! Kintsugi core library.
//!
//! Houses the pieces that must never have surprising I/O side effects: the shared
//! event types exchanged between interception and the daemon, the deterministic
//! rule engine, policy and decision memory, and the append-only hash-chained
//! event log.
//!
//! Security spine (see `CLAUDE.md`): rules block, the model only explains. Nothing
//! in this crate ever lets a model downgrade a rule-based block.

#![forbid(unsafe_code)]

pub mod admin;
pub mod log;
pub mod memory;
pub mod parse;
pub mod policy;
pub mod redact;
pub mod rules;
pub mod shell;
pub mod snapshot;
pub mod types;

pub use log::{ChainStatus, EventLog, Filter, LogError, LoggedEvent, PendingItem, GENESIS_HASH};
pub use memory::command_hash;
pub use policy::{adjust_for_policy, Policy, PolicyAction};
pub use rules::{classify, classify_and_decide, classify_line, decide, RuleMatch};
pub use snapshot::{capture as capture_snapshot, restore as restore_snapshot, Manifest};
pub use types::{Class, Decision, Mode, ProposedCommand, Verdict};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

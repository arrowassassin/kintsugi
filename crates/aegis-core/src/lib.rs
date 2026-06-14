//! Aegis core library.
//!
//! Houses the pieces that must never have surprising I/O side effects: the shared
//! event types exchanged between interception and the daemon, the deterministic
//! rule engine, policy and decision memory, and the append-only hash-chained
//! event log.
//!
//! Security spine (see `CLAUDE.md`): rules block, the model only explains. Nothing
//! in this crate ever lets a model downgrade a rule-based block.

#![forbid(unsafe_code)]

pub mod log;
pub mod types;

pub use log::{ChainStatus, EventLog, LogError, LoggedEvent, GENESIS_HASH};
pub use types::{Class, Decision, ProposedCommand, Verdict};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

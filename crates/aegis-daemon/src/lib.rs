//! Aegis resident daemon library.
//!
//! Long-lived process that owns the event log and runs the decision loop. The
//! interception layer connects over a local socket, sends a [`ProposedCommand`],
//! and blocks on the returned [`Verdict`].
//!
//! In Phase 0 the daemon is a pure recorder: it logs every proposal and allows
//! it. The Tier-1 rule engine (Phase 1) plugs into [`Daemon::decide`] without
//! changing the IPC or logging paths.

#![forbid(unsafe_code)]

pub mod ipc;

use std::path::PathBuf;

use aegis_core::{Class, Decision, EventLog, ProposedCommand, Verdict};
use anyhow::{Context, Result};
use directories::ProjectDirs;

pub use ipc::{Client, Server};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Resolve the event-log database path. Override with `AEGIS_DB` (handy in tests).
pub fn default_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_DB") {
        return PathBuf::from(p);
    }
    if let Some(dirs) = ProjectDirs::from("", "", "aegis") {
        return dirs.data_dir().join("events.db");
    }
    std::env::temp_dir().join("aegis-events.db")
}

/// The resident decision loop: owns the event log, classifies, records.
pub struct Daemon {
    log: EventLog,
}

impl Daemon {
    /// Open the daemon backed by the event log at `db_path`, creating parent dirs.
    pub fn open(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
        let log = EventLog::open(&db_path)
            .with_context(|| format!("open event log at {}", db_path.display()))?;
        Ok(Self { log })
    }

    /// Open the daemon at the default database path.
    pub fn open_default() -> Result<Self> {
        Self::open(default_db_path())
    }

    /// Decide what to do with a proposed command (Tier-1 only in Phase 0/1).
    ///
    /// Phase 0 is a pure recorder: everything is allowed. Phase 1 replaces this
    /// body with the deterministic rule engine. The model never decides here.
    pub fn decide(&self, _cmd: &ProposedCommand) -> Verdict {
        Verdict::rules(
            Class::Safe,
            Decision::Allow,
            "recorder: allow-all (phase 0)",
        )
    }

    /// Handle one proposal: decide, record to the append-only log, return verdict.
    pub fn handle(&self, cmd: ProposedCommand) -> Verdict {
        let verdict = self.decide(&cmd);
        if let Err(e) = self.log.log_event(&cmd, &verdict, None) {
            // Recording is best-effort at the IPC boundary; never crash the daemon.
            eprintln!("aegis-daemon: failed to record event: {e}");
        }
        verdict
    }

    /// Borrow the underlying event log (read-only queries).
    pub fn log(&self) -> &EventLog {
        &self.log
    }
}

/// Run the daemon: open the default log, bind the socket, serve forever.
pub fn run() -> Result<()> {
    let daemon = Daemon::open_default()?;
    let server = Server::bind()?;
    eprintln!(
        "aegis-daemon {} listening on {}",
        VERSION,
        Server::endpoint().display()
    );
    server.serve(|cmd| daemon.handle(cmd))
}

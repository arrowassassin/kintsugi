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

use aegis_core::{Decision, EventLog, Mode, ProposedCommand, Verdict};
use anyhow::{Context, Result};
use directories::ProjectDirs;

pub use ipc::{Client, Resolution, Server};

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
    mode: Mode,
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
        Ok(Self {
            log,
            mode: Mode::default(),
        })
    }

    /// Open the daemon at the default database path.
    pub fn open_default() -> Result<Self> {
        Self::open(default_db_path())
    }

    /// Set the operating mode (attended / unattended / notify).
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// The current operating mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Decide what to do with a proposed command.
    ///
    /// Decision memory is consulted first (a per-repo always-allow / always-deny
    /// for the exact command), then the Tier-1 rule engine. The decision is
    /// deterministic — the model is never consulted here. In attended mode
    /// (default) Safe is allowed and Catastrophic/Ambiguous are held for a human.
    ///
    /// Security spine: memory can record an always-**allow**, but the rule engine
    /// still classifies the command, so a remembered allow never erases the fact
    /// that it was, say, catastrophic — it only changes the decision the human
    /// already made for this exact command in this repo.
    pub fn decide(&self, cmd: &ProposedCommand) -> Verdict {
        let mut verdict = aegis_core::classify_and_decide(cmd, self.mode);

        let repo = repo_key(&cmd.cwd);
        let hash = aegis_core::command_hash(&cmd.raw);
        match self.log.memory_lookup(&repo, &hash) {
            Ok(Some(Decision::Allow)) => {
                verdict.decision = Decision::Allow;
                verdict.reason = format!("memory:allow ({})", verdict.reason);
            }
            Ok(Some(Decision::Deny)) => {
                verdict.decision = Decision::Deny;
                verdict.reason = format!("memory:deny ({})", verdict.reason);
            }
            Ok(Some(Decision::Hold)) | Ok(None) => {}
            Err(e) => eprintln!("aegis-daemon: memory lookup failed: {e}"),
        }
        verdict
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

    /// Handle a human's resolution of a held command: record the final decision
    /// and, if requested, remember it for this exact command in this repo.
    pub fn resolve(&self, resolution: &ipc::Resolution) -> Result<()> {
        let cmd = &resolution.command;
        // Re-classify so the recorded class is accurate even though a human chose.
        let m = aegis_core::classify(cmd);
        let reason = match resolution.decision {
            Decision::Allow if resolution.remember => "human:always-allow",
            Decision::Allow => "human:allow",
            Decision::Deny if resolution.remember => "human:always-deny",
            Decision::Deny => "human:deny",
            Decision::Hold => "human:hold",
        };
        let verdict = Verdict::rules(m.class, resolution.decision, reason);
        self.log.log_event(cmd, &verdict, None)?;

        if resolution.remember && resolution.decision != Decision::Hold {
            let repo = repo_key(&cmd.cwd);
            let hash = aegis_core::command_hash(&cmd.raw);
            self.log.remember(&repo, &hash, resolution.decision)?;
        }
        Ok(())
    }

    /// Dispatch an IPC request to its handler.
    pub fn handle_request(&self, req: ipc::Request) -> ipc::Response {
        match req {
            ipc::Request::Propose(cmd) => ipc::Response::Verdict(self.handle(cmd)),
            ipc::Request::Resolve(resolution) => match self.resolve(&resolution) {
                Ok(()) => ipc::Response::Ack,
                Err(e) => ipc::Response::Error {
                    message: e.to_string(),
                },
            },
        }
    }

    /// Borrow the underlying event log (read-only queries).
    pub fn log(&self) -> &EventLog {
        &self.log
    }
}

/// Identify the "repo" a command runs in: the nearest ancestor containing a
/// `.git` directory, else the working directory itself.
pub fn repo_key(cwd: &std::path::Path) -> String {
    let mut dir = Some(cwd);
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return d.to_string_lossy().to_string();
        }
        dir = d.parent();
    }
    cwd.to_string_lossy().to_string()
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
    server.serve(|req| daemon.handle_request(req))
}

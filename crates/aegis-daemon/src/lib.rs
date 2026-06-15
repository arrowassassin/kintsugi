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
pub mod watch;

use std::path::PathBuf;

use aegis_core::{Decision, EventLog, Mode, ProposedCommand, Verdict};
use anyhow::{Context, Result};
use directories::ProjectDirs;

pub use ipc::{Client, Observation, Resolution, Server};

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

/// The resident decision loop: owns the event log, the warm scorer, classifies,
/// records.
pub struct Daemon {
    log: EventLog,
    mode: Mode,
    scorer: Box<dyn aegis_model::Scorer>,
    snapshot_dir: PathBuf,
}

impl Daemon {
    /// Open the daemon backed by the event log at `db_path`, creating parent dirs.
    pub fn open(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
        let snapshot_dir = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("snapshots");
        let log = EventLog::open(&db_path)
            .with_context(|| format!("open event log at {}", db_path.display()))?;
        Ok(Self {
            log,
            mode: Mode::default(),
            scorer: aegis_model::default_scorer(),
            snapshot_dir,
        })
    }

    /// The directory snapshots are stored under.
    pub fn snapshot_dir(&self) -> &std::path::Path {
        &self.snapshot_dir
    }

    /// Swap in a specific scorer (used by tests).
    pub fn with_scorer(mut self, scorer: Box<dyn aegis_model::Scorer>) -> Self {
        self.scorer = scorer;
        self
    }

    /// The name of the active Tier-2 scorer backend.
    pub fn scorer_name(&self) -> &str {
        self.scorer.name()
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
    /// Order: (1) load the effective policy (global ← repo) which may set the mode
    /// and risk threshold; (2) classify with the Tier-1 rule engine; (3) **Tier-2
    /// model** — for the ambiguous band only, fill `summary`+`risk` and, in
    /// unattended mode, apply the graduated threshold (below → allow, at/above →
    /// deny); the model summarizes a catastrophic command for the hold card but
    /// never changes its decision; (4) apply policy allow/deny (never a
    /// catastrophic downgrade); (5) apply decision memory.
    ///
    /// Security spine: rules classify; the model only explains and scores the
    /// ambiguous band, and its influence is escalation-only. Safe stays on the
    /// model-free fast path.
    pub fn decide(&self, cmd: &ProposedCommand) -> Verdict {
        let policy = load_policy(&cmd.cwd);
        let mode = policy.mode.unwrap_or(self.mode);

        let m = aegis_core::classify(cmd);
        let mut verdict = Verdict::rules(m.class, aegis_core::decide(m.class, mode), &m.rule);

        // Tier-2 model: ambiguous band gets summary + risk (+ graduated decision);
        // catastrophic gets a summary for the hold card. Safe is never scored.
        match m.class {
            aegis_core::Class::Ambiguous => {
                let out = self.scorer.score(cmd, m.class, &m.rule);
                verdict.summary = Some(out.summary);
                verdict.risk = Some(out.risk);
                verdict.tier = 2;
                if mode == Mode::Unattended {
                    let threshold = policy.risk_threshold();
                    verdict.decision = if out.risk >= threshold {
                        Decision::Deny
                    } else {
                        Decision::Allow
                    };
                    verdict.reason = format!(
                        "model:risk={} vs threshold={} ({})",
                        out.risk, threshold, m.rule
                    );
                }
            }
            aegis_core::Class::Catastrophic => {
                let out = self.scorer.score(cmd, m.class, &m.rule);
                verdict.summary = Some(out.summary);
                verdict.tier = 2;
            }
            aegis_core::Class::Safe => {}
        }

        // Policy can escalate (deny) or tame (allow) — never downgrade catastrophic.
        let action = policy.action_for(&cmd.raw);
        verdict = aegis_core::adjust_for_policy(verdict, action, mode);

        // Decision memory has the final say.
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

    /// Handle one proposal: decide, snapshot if destructive+allowed, record, return.
    pub fn handle(&self, cmd: ProposedCommand) -> Verdict {
        let verdict = self.decide(&cmd);
        let snapshot_id = self.maybe_snapshot(&cmd, &verdict);
        if let Err(e) = self.log.log_event(&cmd, &verdict, snapshot_id.as_deref()) {
            // Recording is best-effort at the IPC boundary; never crash the daemon.
            eprintln!("aegis-daemon: failed to record event: {e}");
        }
        verdict
    }

    /// Snapshot the paths a command will touch, when it is allowed and not Safe.
    /// Returns the snapshot id to attach to the event, if one was taken.
    fn maybe_snapshot(&self, cmd: &ProposedCommand, verdict: &Verdict) -> Option<String> {
        if verdict.decision != Decision::Allow || verdict.class == aegis_core::Class::Safe {
            return None;
        }
        match aegis_core::capture_snapshot(&self.snapshot_dir, cmd) {
            Ok(Some(manifest)) => {
                if let Err(e) = self.log.record_snapshot(&manifest) {
                    eprintln!("aegis-daemon: failed to record snapshot: {e}");
                    return None;
                }
                Some(manifest.id)
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("aegis-daemon: snapshot failed: {e}");
                None
            }
        }
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
        // Snapshot before a human-approved destructive command runs.
        let snapshot_id = self.maybe_snapshot(cmd, &verdict);
        self.log.log_event(cmd, &verdict, snapshot_id.as_deref())?;

        if resolution.remember && resolution.decision != Decision::Hold {
            let repo = repo_key(&cmd.cwd);
            let hash = aegis_core::command_hash(&cmd.raw);
            self.log.remember(&repo, &hash, resolution.decision)?;
        }
        Ok(())
    }

    /// Record an observed filesystem change from the backstop watcher. Logged as
    /// `agent = "fs-watch"`, decision Allow (it already happened) — its purpose is
    /// to keep the timeline and undo complete for actions that bypassed
    /// interception.
    pub fn observe(&self, obs: &ipc::Observation) -> Result<()> {
        let raw = format!("{} {}", obs.kind, obs.path);
        let cwd = std::path::Path::new(&obs.path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        let cmd = ProposedCommand::new(
            "fs-watch",
            cwd,
            vec![obs.kind.clone(), obs.path.clone()],
            raw,
        );
        let verdict = Verdict::rules(
            aegis_core::Class::Safe,
            Decision::Allow,
            format!("fs:{}", obs.kind),
        );
        self.log.log_event(&cmd, &verdict, None)?;
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
            ipc::Request::Observe(obs) => match self.observe(&obs) {
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

/// Load and merge the effective policy for a command's working directory:
/// global defaults (config dir) overridden by the repo's `.aegis.toml`.
pub fn load_policy(cwd: &std::path::Path) -> aegis_core::Policy {
    let global = read_policy_file(&global_policy_path()).unwrap_or_default();
    let repo = find_repo_policy(cwd)
        .and_then(|p| read_policy_file(&p))
        .unwrap_or_default();
    aegis_core::Policy::merge(global, repo)
}

/// Path to the global policy file. Override with `AEGIS_CONFIG` (used in tests).
fn global_policy_path() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_CONFIG") {
        return PathBuf::from(p);
    }
    if let Some(dirs) = ProjectDirs::from("", "", "aegis") {
        return dirs.config_dir().join("config.toml");
    }
    std::env::temp_dir().join("aegis-config.toml")
}

/// Find the nearest `.aegis.toml` from `cwd` upward.
fn find_repo_policy(cwd: &std::path::Path) -> Option<PathBuf> {
    let mut dir = Some(cwd);
    while let Some(d) = dir {
        let candidate = d.join(".aegis.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

fn read_policy_file(path: &std::path::Path) -> Option<aegis_core::Policy> {
    let text = std::fs::read_to_string(path).ok()?;
    match aegis_core::Policy::parse(&text) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!(
                "aegis-daemon: ignoring invalid policy {}: {e}",
                path.display()
            );
            None
        }
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

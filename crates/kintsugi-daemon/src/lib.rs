//! Kintsugi resident daemon library.
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

use std::cell::{Cell, RefCell};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use kintsugi_core::admin::{self, SealedVault, VaultState};
use kintsugi_core::{Decision, EventLog, Mode, ProposedCommand, Verdict};

pub use ipc::{Client, Observation, Resolution, Server};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The kill-switch flag file name, alongside the event-log database.
pub const KILL_SWITCH_FILE: &str = "panic.flag";

/// Path to the panic kill-switch flag (alongside the default event log).
pub fn kill_switch_path() -> PathBuf {
    default_db_path()
        .parent()
        .map(|p| p.join(KILL_SWITCH_FILE))
        .unwrap_or_else(|| std::env::temp_dir().join(KILL_SWITCH_FILE))
}

/// The fail-closed marker file name, alongside the event-log database.
pub const FAIL_CLOSED_FILE: &str = "fail-closed.flag";

/// Path to the fail-closed marker (alongside the default event log). Its mere
/// existence is the signal — the content is irrelevant. The interception layer
/// (shim/hook/MCP) reads it **without** the daemon, so that killing the daemon
/// can't be used to open the gate: with the marker present, an unreachable
/// daemon means *block*, not *run unguarded*.
pub fn fail_closed_marker_path() -> PathBuf {
    default_db_path().with_file_name(FAIL_CLOSED_FILE)
}

/// Whether the admin-set fail-closed marker is present. Cheap, daemon-free, and
/// callable from the interception fast path. In the locked posture the marker is
/// owned by the privileged account (root / a dedicated `kintsugi` user), so an
/// audited non-root agent cannot remove it to re-open the gate.
pub fn is_fail_closed_marked() -> bool {
    fail_closed_marker_path().exists()
}

/// Create or remove the fail-closed marker to match `on`. Best-effort, atomic
/// create; called by the admin flow when the locked `fail_closed` setting
/// changes so the posture survives a daemon restart and a kill.
pub fn set_fail_closed_marker(on: bool) -> std::io::Result<()> {
    let path = fail_closed_marker_path();
    if on {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // 0644: world-readable (the shim must read it) but, in the locked posture,
        // owned by the privileged account so the audited user can't delete it.
        std::fs::write(&path, b"fail-closed\n")?;
    } else if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Resolve the event-log database path. Override with `KINTSUGI_DB` (handy in tests).
pub fn default_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("KINTSUGI_DB") {
        return PathBuf::from(p);
    }
    if let Some(dirs) = ProjectDirs::from("", "", "kintsugi") {
        return dirs.data_dir().join("events.db");
    }
    std::env::temp_dir().join("kintsugi-events.db")
}

/// The resident decision loop: owns the event log, the warm scorer, classifies,
/// records.
pub struct Daemon {
    log: EventLog,
    mode: Mode,
    scorer: Box<dyn kintsugi_model::Scorer>,
    snapshot_dir: PathBuf,
    kill_path: PathBuf,
    /// The admin vault loaded at *daemon* startup (not at request time), so the
    /// auth decision is made against the path the daemon resolved — a caller's
    /// environment can't redirect it. `None` = unprovisioned (no lock).
    vault: Option<SealedVault>,
    /// The vault file exists but is unreadable/corrupt → stay locked (fail-closed):
    /// refuse authenticated shutdown rather than silently allow it.
    vault_degraded: bool,
    /// The last challenge nonce issued (and its op), consumed once by `Shutdown`.
    pending: RefCell<Option<(Vec<u8>, String)>>,
    /// Set when an authenticated shutdown has been accepted; the serve loop exits.
    shutdown: Cell<bool>,
    /// In-memory brute-force throttle for admin authentication.
    throttle: RefCell<AuthThrottle>,
}

/// Rate-limit + lockout for admin authentication. The daemon is the single
/// authority, so a process-local counter is enough: after a few consecutive
/// failures it locks out for an exponentially growing window (defeating a script
/// hammering the admin password), and a success resets it.
#[derive(Default)]
struct AuthThrottle {
    failures: u32,
    locked_until: Option<std::time::Instant>,
}

impl AuthThrottle {
    /// Failed attempts allowed before the first lockout.
    const FREE_ATTEMPTS: u32 = 5;

    /// Remaining lockout duration, if currently locked out.
    fn lockout_remaining(&self) -> Option<std::time::Duration> {
        self.locked_until
            .and_then(|t| t.checked_duration_since(std::time::Instant::now()))
    }

    /// Count a failed attempt; arm/extend the lockout once past the free budget.
    fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= Self::FREE_ATTEMPTS {
            // 30s, then doubling (60s, 120s, …) capped at one hour.
            let over = (self.failures - Self::FREE_ATTEMPTS).min(7);
            self.locked_until = Some(
                std::time::Instant::now()
                    + std::time::Duration::from_secs((30u64 << over).min(3600)),
            );
        }
    }

    fn reset(&mut self) {
        self.failures = 0;
        self.locked_until = None;
    }
}

impl Daemon {
    /// Open the daemon backed by the event log at `db_path`, creating parent dirs.
    pub fn open(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
        let data_dir = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        // Keep the data dir private to the owning user: the event log records raw
        // commands verbatim (spine #3), which can include secrets passed on a
        // command line. We never scrub the verbatim record, so we protect it at
        // rest (0700 dir, 0600 db) instead of leaving it world-readable.
        #[cfg(unix)]
        ipc::set_mode(&data_dir, 0o700);
        let snapshot_dir = data_dir.join("snapshots");
        let kill_path = data_dir.join(KILL_SWITCH_FILE);
        let log = EventLog::open(&db_path)
            .with_context(|| format!("open event log at {}", db_path.display()))?;
        // Owner-only on the db (and its WAL/SHM siblings) — it holds verbatim
        // commands that may contain secrets.
        #[cfg(unix)]
        for suffix in ["", "-wal", "-shm"] {
            let p = if suffix.is_empty() {
                db_path.clone()
            } else {
                PathBuf::from(format!("{}{suffix}", db_path.display()))
            };
            if p.exists() {
                ipc::set_mode(&p, 0o600);
            }
        }
        // Load the admin vault ONCE, here at daemon startup, from the path the
        // daemon resolves (the daemon is launched by the admin/systemd, so its
        // environment — not a later caller's — decides the vault location).
        let (vault, vault_degraded) = match admin::load_vault(&admin::default_vault_path()) {
            VaultState::Locked(v) => (Some(*v), false),
            VaultState::Unprovisioned => (None, false),
            VaultState::Degraded(_) => (None, true),
        };
        Ok(Self {
            log,
            mode: Mode::default(),
            scorer: kintsugi_model::default_scorer(),
            snapshot_dir,
            kill_path,
            vault,
            vault_degraded,
            pending: RefCell::new(None),
            shutdown: Cell::new(false),
            throttle: RefCell::new(AuthThrottle::default()),
        })
    }

    /// Whether an authenticated shutdown has been accepted (serve loop should exit).
    pub fn should_shutdown(&self) -> bool {
        self.shutdown.get()
    }

    /// Issue a challenge for a privileged op. `locked=false` means no vault, so the
    /// caller may proceed without a proof.
    fn auth_begin(&self, op: &str) -> ipc::Response {
        if self.vault_degraded {
            return ipc::Response::Error {
                message: "admin vault is degraded; refusing privileged operations".into(),
            };
        }
        match &self.vault {
            Some(v) => {
                let nonce = match admin::random_auth_nonce() {
                    Ok(n) => n,
                    Err(_) => {
                        return ipc::Response::Error {
                            message: "could not generate a challenge".into(),
                        }
                    }
                };
                let (salt, params) = v.auth_challenge();
                *self.pending.borrow_mut() = Some((nonce.clone(), op.to_string()));
                ipc::Response::Challenge {
                    locked: true,
                    nonce: hex::encode(&nonce),
                    salt,
                    params,
                }
            }
            None => ipc::Response::Challenge {
                locked: false,
                nonce: String::new(),
                salt: String::new(),
                params: kintsugi_core::admin::KdfParams::production(),
            },
        }
    }

    /// Complete an authenticated shutdown. Enforced against the daemon's own vault.
    fn shutdown_op(&self, op: &str, nonce_hex: &str, proof_hex: &str) -> ipc::Response {
        if self.vault_degraded {
            self.record_admin(op, false, "vault degraded");
            return ipc::Response::Error {
                message: "admin vault is degraded; refusing to stop".into(),
            };
        }
        let Some(vault) = &self.vault else {
            // Unprovisioned: there is no lock, so a clean shutdown is allowed.
            self.record_admin(op, true, "unprovisioned");
            self.shutdown.set(true);
            return ipc::Response::Ack;
        };
        // Brute-force lockout: after repeated failures, refuse without even
        // checking the proof until the window elapses (the attempt is still
        // logged). Defeats a script hammering the admin password.
        if let Some(rem) = self.throttle.borrow().lockout_remaining() {
            self.record_admin(op, false, "locked out");
            return ipc::Response::Error {
                message: format!(
                    "too many failed attempts; locked out for {}s",
                    rem.as_secs() + 1
                ),
            };
        }
        // The challenge is one-shot: take it regardless of the outcome.
        let pending = self.pending.borrow_mut().take();
        let ok = match (pending, hex::decode(nonce_hex), hex::decode(proof_hex)) {
            (Some((issued_nonce, issued_op)), Ok(nonce), Ok(proof)) => {
                issued_op == op
                    && issued_nonce == nonce
                    && vault.verify_proof(&nonce, op.as_bytes(), &proof)
            }
            _ => false,
        };
        if ok {
            self.throttle.borrow_mut().reset();
            self.record_admin(op, true, "authenticated");
            self.shutdown.set(true);
            ipc::Response::Ack
        } else {
            self.throttle.borrow_mut().record_failure();
            self.record_admin(op, false, "authentication failed");
            ipc::Response::Error {
                message: "authentication failed".into(),
            }
        }
    }

    /// Record a privileged-operation attempt as a hash-chained audit event, so a
    /// forced stop — successful or not — is always visible on the timeline.
    fn record_admin(&self, op: &str, ok: bool, reason: &str) {
        let raw = format!(
            "admin {op} — {}",
            if ok { "authenticated" } else { "denied" }
        );
        let cmd = ProposedCommand::new(
            "admin",
            std::path::Path::new("."),
            vec!["admin".to_string(), op.to_string()],
            raw,
        );
        let decision = if ok { Decision::Allow } else { Decision::Deny };
        let verdict = Verdict::rules(
            kintsugi_core::Class::Safe,
            decision,
            format!("admin:{op}:{reason}"),
        );
        let _ = self.log.log_event(&cmd, &verdict, None);
    }

    /// Whether the panic kill-switch is currently engaged.
    pub fn kill_switch_engaged(&self) -> bool {
        self.kill_path.exists()
    }

    /// The directory snapshots are stored under.
    pub fn snapshot_dir(&self) -> &std::path::Path {
        &self.snapshot_dir
    }

    /// Swap in a specific scorer (used by tests).
    pub fn with_scorer(mut self, scorer: Box<dyn kintsugi_model::Scorer>) -> Self {
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
        // Panic kill-switch: halt everything, including Safe, the instant it is
        // engaged. Checked first, before any other logic.
        if self.kill_switch_engaged() {
            let m = kintsugi_core::classify(cmd);
            return Verdict::rules(m.class, Decision::Deny, "kill-switch: all actions halted");
        }

        let policy = load_policy(&cmd.cwd);
        let mode = policy.mode.unwrap_or(self.mode);

        let m = kintsugi_core::classify(cmd);
        let mut verdict = Verdict::rules(m.class, kintsugi_core::decide(m.class, mode), &m.rule);

        // Tier-2 model: ambiguous band gets summary + risk (+ graduated decision);
        // catastrophic gets a summary for the hold card. Safe is never scored.
        match m.class {
            kintsugi_core::Class::Ambiguous => {
                let out = self.scorer.score(cmd, m.class, &m.rule);
                verdict.summary = Some(out.summary);
                verdict.risk = Some(out.risk);
                verdict.tier = 2;
                if mode == Mode::Unattended {
                    // Spine rule #2 (monotonic model influence): the model may only
                    // ADD caution. The unattended baseline for an ambiguous command
                    // is Deny (queued for a human); the model records risk for that
                    // review but NEVER downgrades Deny -> Allow. Auto-proceeding an
                    // ambiguous command unattended is only possible via an explicit
                    // human allowlist (.kintsugi.toml / decision memory) below — a human
                    // decision, not the model's.
                    verdict.reason = format!(
                        "model:risk={} ({}) — unattended holds ambiguous for review",
                        out.risk, m.rule
                    );
                }
            }
            kintsugi_core::Class::Catastrophic => {
                let out = self.scorer.score(cmd, m.class, &m.rule);
                verdict.summary = Some(out.summary);
                verdict.tier = 2;
            }
            kintsugi_core::Class::Safe => {}
        }

        // Policy can escalate (deny) or tame (allow) — never downgrade catastrophic.
        let action = policy.action_for(&cmd.raw);
        verdict = kintsugi_core::adjust_for_policy(verdict, action, mode);

        // Decision memory has the final say — but, like policy, it can never
        // auto-downgrade a CATASTROPHIC command (that hard floor only lifts via an
        // in-the-moment human decision, never a stored/replayed one). Memory deny
        // always applies (escalation-only).
        let repo = repo_key(&cmd.cwd);
        let hash = kintsugi_core::command_hash(&cmd.raw);
        match self.log.memory_lookup(&repo, &hash) {
            Ok(Some(Decision::Allow)) if verdict.class != kintsugi_core::Class::Catastrophic => {
                verdict.decision = Decision::Allow;
                verdict.reason = format!("memory:allow ({})", verdict.reason);
            }
            Ok(Some(Decision::Deny)) => {
                verdict.decision = Decision::Deny;
                verdict.reason = format!("memory:deny ({})", verdict.reason);
            }
            _ => {}
        }
        verdict
    }

    /// Handle one proposal: decide, snapshot if destructive+allowed, record, and —
    /// if held — enqueue it for approval. Returns the verdict.
    pub fn handle(&self, cmd: ProposedCommand) -> Verdict {
        let verdict = self.decide(&cmd);
        let snapshot_id = self.maybe_snapshot(&cmd, &verdict);
        if let Err(e) = self.log.log_event(&cmd, &verdict, snapshot_id.as_deref()) {
            // Recording is best-effort at the IPC boundary; never crash the daemon.
            eprintln!("kintsugi-daemon: failed to record event: {e}");
        }
        if verdict.decision == Decision::Hold {
            if let Err(e) = self
                .log
                .enqueue_pending(&cmd, verdict.class, &verdict.reason)
            {
                eprintln!("kintsugi-daemon: failed to enqueue pending: {e}");
            }
        }
        verdict
    }

    /// Approve or deny a queued command by id: record the human decision (and, on
    /// allow, snapshot), then mark the queue entry resolved. The originating
    /// caller (MCP poll / shim) executes; this never runs the command itself.
    ///
    /// A human may approve any class here — including catastrophic — which is the
    /// deliberate human override (the *model* never can). Returns whether the id
    /// was found in the queue.
    pub fn resolve_pending(&self, id: &str, decision: Decision) -> Result<bool> {
        // While the kill-switch is engaged, nothing is approvable.
        if decision == Decision::Allow && self.kill_switch_engaged() {
            anyhow::bail!("kill-switch engaged; clear it with `kintsugi resume` before approving");
        }
        let status = if decision == Decision::Allow {
            "approved"
        } else {
            "denied"
        };
        // Claim the entry exactly once. If the CAS doesn't win, the command was
        // already resolved (or never queued) — return false rather than snapshot
        // and log a second time, which is what would double-run an approved cmd.
        if !self.log.cas_pending_status(id, "pending", status)? {
            return Ok(false);
        }
        let Some(cmd) = self.log.pending_command(id)? else {
            return Ok(false);
        };
        self.resolve(&ipc::Resolution {
            command: cmd,
            decision,
            remember: false,
        })?;
        Ok(true)
    }

    /// Snapshot the paths a command will touch, when it is allowed and not Safe.
    /// Returns the snapshot id to attach to the event, if one was taken.
    fn maybe_snapshot(&self, cmd: &ProposedCommand, verdict: &Verdict) -> Option<String> {
        if verdict.decision != Decision::Allow || verdict.class == kintsugi_core::Class::Safe {
            return None;
        }
        match kintsugi_core::capture_snapshot(&self.snapshot_dir, cmd) {
            Ok(Some(manifest)) => {
                if let Err(e) = self.log.record_snapshot(&manifest) {
                    eprintln!("kintsugi-daemon: failed to record snapshot: {e}");
                    return None;
                }
                Some(manifest.id)
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("kintsugi-daemon: snapshot failed: {e}");
                None
            }
        }
    }

    /// Handle a human's resolution of a held command: record the final decision
    /// and, if requested, remember it for this exact command in this repo.
    pub fn resolve(&self, resolution: &ipc::Resolution) -> Result<()> {
        // Kill-switch hard floor: while engaged, no Allow resolves — not via the
        // queue (resolve_pending) and not via this direct path (shim hold card /
        // raw Request::Resolve). Mirrors the guard in resolve_pending().
        if resolution.decision == Decision::Allow && self.kill_switch_engaged() {
            anyhow::bail!("kill-switch engaged; clear it with `kintsugi resume` before allowing");
        }
        let cmd = &resolution.command;
        // Re-classify so the recorded class is accurate even though a human chose.
        let m = kintsugi_core::classify(cmd);
        // A catastrophic command is never *remembered* as always-allow — the hard
        // floor must re-prompt every time; `[r]` on a catastrophic acts as allow-once.
        let remember = resolution.remember
            && !(resolution.decision == Decision::Allow
                && m.class == kintsugi_core::Class::Catastrophic);
        let reason = match resolution.decision {
            Decision::Allow if remember => "human:always-allow",
            Decision::Allow => "human:allow",
            Decision::Deny if remember => "human:always-deny",
            Decision::Deny => "human:deny",
            Decision::Hold => "human:hold",
        };
        let verdict = Verdict::rules(m.class, resolution.decision, reason);
        // Snapshot before a human-approved destructive command runs.
        let snapshot_id = self.maybe_snapshot(cmd, &verdict);
        self.log.log_event(cmd, &verdict, snapshot_id.as_deref())?;

        if remember && resolution.decision != Decision::Hold {
            let repo = repo_key(&cmd.cwd);
            let hash = kintsugi_core::command_hash(&cmd.raw);
            self.log.remember(&repo, &hash, resolution.decision)?;
        }

        // If this command was queued (e.g. a shim hold the human just answered),
        // mark the queue entry resolved so it leaves `kintsugi queue`.
        if resolution.decision != Decision::Hold {
            let status = if resolution.decision == Decision::Allow {
                "approved"
            } else {
                "denied"
            };
            let _ = self.log.set_pending_status(&cmd.id.to_string(), status);
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
            kintsugi_core::Class::Safe,
            Decision::Allow,
            format!("fs:{}", obs.kind),
        );
        self.log.log_event(&cmd, &verdict, None)?;
        Ok(())
    }

    /// Record a shell command from a human shell session (passive recording, no
    /// AI-agent hook). Logged as `agent = "shell"`, decision Allow — it is never
    /// blocked (the recorder is an audit/undo trail, not a gate). We **classify**
    /// it with the Tier-1 rules so the event carries the real class (a destructive
    /// command a DBA ran is flagged in the timeline and `kintsugi report`), and we
    /// **snapshot destructive commands** so `kintsugi undo` can recover a human's
    /// mistake. The model never runs on this path.
    ///
    /// The hard floor stays honest: this is an audit record of the past, not a
    /// gate. The "nothing un-warned" guarantee never applied to commands a human
    /// ran outside Kintsugi; the "tamper-evident record of everything" one does,
    /// which is exactly what this preserves.
    pub fn record_shell(&self, cmd: &ProposedCommand) -> Result<()> {
        // Provenance: the recorder is for human shell sessions, so force the agent
        // label to "shell" regardless of what the caller sent. A local peer that
        // can reach the socket therefore cannot forge a record attributed to an
        // AI agent ("claude-code") or the watcher ("fs-watch"); the worst it can
        // do is inject a self-reported *shell* event, which the Audit view treats
        // accordingly. (The socket is already owner-only; this is defense in depth.)
        let mut cmd = cmd.clone();
        cmd.agent = "shell".to_string();
        let m = kintsugi_core::classify(&cmd);
        // Allow, not the rule's gate decision: the command already executed, so
        // recording a Hold/Deny here would be a lie about what happened. The
        // class still rides along (verdict.class) so the timeline flags danger.
        let verdict = Verdict::rules(m.class, Decision::Allow, format!("recorded:{}", m.rule));
        // Recoverer: snapshot the paths a *destructive* human command will touch,
        // so `kintsugi undo` can roll back a person's *filesystem* mistake (rm -rf,
        // a clobbering overwrite) the same way it rolls back an agent's. The shell
        // preexec hook fires before the command runs, so this is a just-in-time
        // capture; `maybe_snapshot` no-ops for Safe commands and reflinks where it
        // can, so the common case stays cheap. Best-effort: if the snapshot loses
        // the race (or the fs can't reflink), the filesystem-watcher backstop still
        // records the change. This is a filesystem recoverer — an in-database
        // DROP/TRUNCATE is not a file, so it's flagged/recorded but recovery there
        // is your DB's PITR/backups. The honest guarantee is "recoverable", not
        // transactional.
        let snapshot_id = self.maybe_snapshot(&cmd, &verdict);
        self.log.log_event(&cmd, &verdict, snapshot_id.as_deref())?;
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
            ipc::Request::Record(cmd) => match self.record_shell(&cmd) {
                Ok(()) => ipc::Response::Ack,
                Err(e) => ipc::Response::Error {
                    message: e.to_string(),
                },
            },
            ipc::Request::ListPending => match self.log.list_pending() {
                Ok(items) => ipc::Response::PendingList { items },
                Err(e) => ipc::Response::Error {
                    message: e.to_string(),
                },
            },
            ipc::Request::PendingStatus { id } => match self.log.pending_status(&id) {
                Ok(status) => ipc::Response::Pending {
                    status: status.unwrap_or_else(|| "gone".to_string()),
                },
                Err(e) => ipc::Response::Error {
                    message: e.to_string(),
                },
            },
            ipc::Request::Approve { id } => self.resolve_pending_response(&id, Decision::Allow),
            ipc::Request::Deny { id } => self.resolve_pending_response(&id, Decision::Deny),
            ipc::Request::Status => ipc::Response::Status {
                scorer: self.scorer_name().to_string(),
            },
            ipc::Request::AuthBegin { op } => self.auth_begin(&op),
            ipc::Request::Shutdown { op, nonce, proof } => self.shutdown_op(&op, &nonce, &proof),
        }
    }

    fn resolve_pending_response(&self, id: &str, decision: Decision) -> ipc::Response {
        match self.resolve_pending(id, decision) {
            Ok(true) => ipc::Response::Ack,
            Ok(false) => ipc::Response::Error {
                message: format!("no pending command with id {id}"),
            },
            Err(e) => ipc::Response::Error {
                message: e.to_string(),
            },
        }
    }

    /// Borrow the underlying event log (read-only queries).
    pub fn log(&self) -> &EventLog {
        &self.log
    }
}

/// Load and merge the effective policy for a command's working directory:
/// global defaults (config dir) overridden by the repo's `.kintsugi.toml`.
pub fn load_policy(cwd: &std::path::Path) -> kintsugi_core::Policy {
    let global = read_policy_file(&global_policy_path()).unwrap_or_default();
    let repo = find_repo_policy(cwd)
        .and_then(|p| read_policy_file(&p))
        .unwrap_or_default();
    kintsugi_core::Policy::merge(global, repo)
}

/// Path to the global policy file. Override with `KINTSUGI_CONFIG` (used in tests).
fn global_policy_path() -> PathBuf {
    if let Ok(p) = std::env::var("KINTSUGI_CONFIG") {
        return PathBuf::from(p);
    }
    if let Some(dirs) = ProjectDirs::from("", "", "kintsugi") {
        return dirs.config_dir().join("config.toml");
    }
    std::env::temp_dir().join("kintsugi-config.toml")
}

/// Find the nearest `.kintsugi.toml` from `cwd` upward.
fn find_repo_policy(cwd: &std::path::Path) -> Option<PathBuf> {
    let mut dir = Some(cwd);
    while let Some(d) = dir {
        let candidate = d.join(".kintsugi.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

fn read_policy_file(path: &std::path::Path) -> Option<kintsugi_core::Policy> {
    let text = std::fs::read_to_string(path).ok()?;
    match kintsugi_core::Policy::parse(&text) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!(
                "kintsugi-daemon: ignoring invalid policy {}: {e}",
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
    // Record our PID so `kintsugi stop` can find and stop us (any launch path).
    let _ = std::fs::write(pid_file_path(), std::process::id().to_string());
    eprintln!(
        "kintsugi-daemon {} listening on {}",
        VERSION,
        Server::endpoint().display()
    );
    server.serve_until(
        |req| daemon.handle_request(req),
        || daemon.should_shutdown(),
    )?;
    // An authenticated shutdown landed: clean up the PID file and exit.
    let _ = std::fs::remove_file(pid_file_path());
    eprintln!("kintsugi-daemon: authenticated shutdown — exiting.");
    Ok(())
}

/// Path to the daemon's PID file (next to the event log).
pub fn pid_file_path() -> PathBuf {
    default_db_path().with_file_name("kintsugi.pid")
}

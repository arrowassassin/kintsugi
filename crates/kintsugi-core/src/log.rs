//! Append-only, hash-chained event log (SQLite).
//!
//! Every observed command becomes one immutable row. Each row's `hash` is
//! `SHA-256(prev_hash || canonical(row))`, so any edit to a past row — or any
//! reordering — breaks the chain and is detectable by [`EventLog::verify_chain`].
//!
//! Security spine: the event chain is append-only. Day-to-day "delete" is
//! **redaction** — an append-only [`redactions`](EventLog::redact) row that hides
//! an entry from views while the original row and the hash chain stay intact and
//! verifiable. True erasure is the separate, explicit [`EventLog::purge_matching`]
//! (hard delete + re-chain): it deliberately rewrites history for the purged span
//! and records a marker event, and is never invoked automatically.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::types::{Class, Decision, ProposedCommand, Verdict};

/// The genesis predecessor hash for the very first event.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors from the event log.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("time formatting error: {0}")]
    Time(#[from] time::error::Format),
    #[error("stored timestamp is not valid RFC3339: {0}")]
    TimeParse(#[from] time::error::Parse),
    #[error("stored value is not valid: {0}")]
    Corrupt(String),
}

/// A single immutable row of the event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedEvent {
    /// Monotonic sequence number (storage rowid).
    pub seq: i64,
    /// The originating command id.
    pub id: Uuid,
    /// When the command was observed.
    pub ts: OffsetDateTime,
    /// Originating agent.
    pub agent: String,
    /// Working directory (stored as a string).
    pub cwd: String,
    /// The raw command, preserved verbatim.
    pub command: String,
    /// The argument vector.
    pub argv: Vec<String>,
    /// Rule-engine classification.
    pub class: Class,
    /// The decision recorded.
    pub decision: Decision,
    /// The rule name or resolution reason behind the decision.
    pub reason: String,
    /// Tier that produced the decision.
    pub tier: u8,
    /// Optional severity score.
    pub risk: Option<u8>,
    /// Optional one-sentence summary.
    pub summary: Option<String>,
    /// Optional snapshot reference.
    pub snapshot_id: Option<String>,
    /// Optional originating session id (view metadata; not part of the hash).
    pub session: Option<String>,
    /// Hash of the predecessor row.
    pub prev_hash: String,
    /// This row's hash.
    pub hash: String,
    /// Whether this event has been redacted (hidden from default views).
    pub redacted: bool,
}

/// A filter over the event log, used by views, redaction, and purge.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Restrict to one agent (`claude-code`, `cursor`, `shim`, …).
    pub agent: Option<String>,
    /// Restrict to one session id.
    pub session: Option<String>,
    /// Only events at or after this instant.
    pub since: Option<OffsetDateTime>,
    /// Only events strictly before this instant.
    pub until: Option<OffsetDateTime>,
    /// Case-insensitive substring match on the raw command.
    pub grep: Option<String>,
    /// Restrict to one classification.
    pub class: Option<Class>,
    /// Include redacted rows (default: hidden).
    pub include_redacted: bool,
    /// Cap the number of rows returned (newest kept).
    pub limit: Option<usize>,
    /// Skip this many of the newest matching rows before applying `limit` —
    /// the page offset for `kintsugi log --page N`.
    pub offset: Option<usize>,
}

impl Filter {
    /// Build the SQL `WHERE` body (without the `WHERE` keyword) and its params.
    /// `events`-qualified so it composes with the redaction LEFT JOIN.
    fn where_clause(&self) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(a) = &self.agent {
            clauses.push("events.agent = ?".into());
            params.push(Box::new(a.clone()));
        }
        if let Some(s) = &self.session {
            clauses.push("events.session = ?".into());
            params.push(Box::new(s.clone()));
        }
        if let Some(c) = &self.class {
            clauses.push("events.class = ?".into());
            params.push(Box::new(c.as_str().to_string()));
        }
        if let Some(g) = &self.grep {
            clauses.push("events.command LIKE ? ESCAPE '\\'".into());
            params.push(Box::new(format!("%{}%", like_escape(g))));
        }
        // ts is stored as RFC3339 text; lexical compare is chronological for UTC Z.
        if let Some(since) = &self.since {
            if let Ok(s) = since.format(&Rfc3339) {
                clauses.push("events.ts >= ?".into());
                params.push(Box::new(s));
            }
        }
        if let Some(until) = &self.until {
            if let Ok(s) = until.format(&Rfc3339) {
                clauses.push("events.ts < ?".into());
                params.push(Box::new(s));
            }
        }
        if !self.include_redacted {
            clauses.push("r.event_id IS NULL".into());
        }
        let body = if clauses.is_empty() {
            "1=1".to_string()
        } else {
            clauses.join(" AND ")
        };
        (body, params)
    }
}

/// Escape LIKE wildcards so a user's grep text matches literally.
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// One entry in the approval queue (a held command awaiting a human decision).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingItem {
    /// The held command (its `id` is the queue id).
    pub command: ProposedCommand,
    /// Rule-engine classification.
    pub class: Class,
    /// Why it was held.
    pub reason: String,
    /// When it was enqueued.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
}

/// The result of verifying the hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// The chain is intact and every row hashes correctly.
    Intact,
    /// A break was found.
    Broken {
        /// The sequence number of the offending row.
        seq: i64,
        /// What went wrong.
        detail: String,
    },
}

impl ChainStatus {
    /// `true` when the chain is intact.
    pub fn is_intact(&self) -> bool {
        matches!(self, ChainStatus::Intact)
    }
}

/// Handle to the append-only event log.
pub struct EventLog {
    conn: Connection,
}

impl EventLog {
    /// Open (creating if needed) a log at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, LogError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an ephemeral in-memory log (used in tests).
    pub fn open_in_memory() -> Result<Self, LogError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, LogError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // NORMAL is safe under WAL and keeps per-event writes fast (no fsync per
        // commit). A crash can only lose the very last transactions; the surviving
        // chain stays intact and verifiable.
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Block (rather than fail) when another process holds the write lock, so
        // the read-modify-append in `log_event` serializes across processes instead
        // of forking the hash chain on a shared prev_hash.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                id         TEXT NOT NULL,
                ts         TEXT NOT NULL,
                agent      TEXT NOT NULL,
                cwd        TEXT NOT NULL,
                command    TEXT NOT NULL,
                argv       TEXT NOT NULL,
                class      TEXT NOT NULL,
                decision   TEXT NOT NULL,
                reason     TEXT NOT NULL,
                tier       INTEGER NOT NULL,
                risk       INTEGER,
                summary    TEXT,
                snapshot_id TEXT,
                prev_hash  TEXT NOT NULL,
                hash       TEXT NOT NULL,
                session    TEXT
            );

            -- Append-only redactions: hide an event from views without mutating
            -- it or breaking the chain. The original row and its hash are intact.
            CREATE TABLE IF NOT EXISTS redactions (
                event_id   TEXT PRIMARY KEY,
                ts         TEXT NOT NULL,
                reason     TEXT NOT NULL
            );

            -- Decision memory. Unlike `events`, this table is intentionally
            -- mutable state: per-repo always-allow / always-deny by command hash.
            CREATE TABLE IF NOT EXISTS memory (
                repo         TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                action       TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                PRIMARY KEY (repo, command_hash)
            );

            -- Snapshots taken before destructive ops, for `kintsugi undo`.
            CREATE TABLE IF NOT EXISTS snapshots (
                id         TEXT PRIMARY KEY,
                seq        INTEGER,
                ts         TEXT NOT NULL,
                command    TEXT NOT NULL,
                manifest   TEXT NOT NULL,
                reverted   INTEGER NOT NULL DEFAULT 0
            );

            -- The approval queue: held commands awaiting a human decision.
            -- Mutable state; status is 'pending' | 'approved' | 'denied'.
            CREATE TABLE IF NOT EXISTS pending (
                id          TEXT PRIMARY KEY,
                ts          TEXT NOT NULL,
                command     TEXT NOT NULL,
                class       TEXT NOT NULL,
                reason      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                updated_at  TEXT NOT NULL
            );
            "#,
        )?;
        // Migrate older DBs created before the `session` column existed.
        let has_session = conn
            .prepare("SELECT 1 FROM pragma_table_info('events') WHERE name = 'session'")?
            .exists([])?;
        if !has_session {
            conn.execute_batch("ALTER TABLE events ADD COLUMN session TEXT")?;
        }
        Ok(Self { conn })
    }

    /// Add a held command to the approval queue (idempotent on its id).
    pub fn enqueue_pending(
        &self,
        cmd: &ProposedCommand,
        class: Class,
        reason: &str,
    ) -> Result<(), LogError> {
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let cmd_json = serde_json::to_string(cmd)
            .map_err(|e| LogError::Corrupt(format!("pending command serialize: {e}")))?;
        self.conn.execute(
            "INSERT INTO pending (id, ts, command, class, reason, status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?2)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![cmd.id.to_string(), now, cmd_json, class.as_str(), reason],
        )?;
        Ok(())
    }

    /// The current status of a queued command, if it is in the queue.
    pub fn pending_status(&self, id: &str) -> Result<Option<String>, LogError> {
        Ok(self
            .conn
            .query_row("SELECT status FROM pending WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Set a queued command's status (`approved` | `denied`).
    pub fn set_pending_status(&self, id: &str, status: &str) -> Result<(), LogError> {
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        self.conn.execute(
            "UPDATE pending SET status = ?2, updated_at = ?3 WHERE id = ?1",
            rusqlite::params![id, status, now],
        )?;
        Ok(())
    }

    /// Atomically move a queued command from status `from` to `to`. Returns true
    /// iff *this* call performed the transition (the row existed and was `from`).
    ///
    /// This is the exactly-once guard: a held command must resolve/run once even
    /// if two `kintsugi approve`/`kintsugi run` invocations race — only the winner of
    /// the compare-and-swap proceeds; the loser sees `false` and does nothing.
    pub fn cas_pending_status(&self, id: &str, from: &str, to: &str) -> Result<bool, LogError> {
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let changed = self.conn.execute(
            "UPDATE pending SET status = ?3, updated_at = ?4 WHERE id = ?1 AND status = ?2",
            rusqlite::params![id, from, to, now],
        )?;
        Ok(changed == 1)
    }

    /// The stored command for a queued id (for resolve/re-run).
    pub fn pending_command(&self, id: &str) -> Result<Option<ProposedCommand>, LogError> {
        let json: Option<String> = self
            .conn
            .query_row("SELECT command FROM pending WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j).map_err(|e| {
                LogError::Corrupt(format!("pending command parse: {e}"))
            })?)),
            None => Ok(None),
        }
    }

    /// List the still-pending queued commands, oldest first.
    pub fn list_pending(&self) -> Result<Vec<PendingItem>, LogError> {
        let mut stmt = self.conn.prepare(
            // Order by rowid alone — it IS insertion order. We used to lead with
            // `ts ASC` and tiebreak on rowid, but the Windows runner's wall clock
            // can step backwards by a few ms (NTP slew on the VM host), which
            // made ts(second insert) < ts(first insert) and put the newer row
            // before the older one. Rowid is monotonic, so it doesn't care.
            "SELECT command, class, reason, ts FROM pending WHERE status = 'pending' ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (cmd_json, class_s, reason, ts_s) = r?;
            let command: ProposedCommand = serde_json::from_str(&cmd_json)
                .map_err(|e| LogError::Corrupt(format!("pending parse: {e}")))?;
            out.push(PendingItem {
                command,
                class: parse_class(&class_s)?,
                reason,
                ts: OffsetDateTime::parse(&ts_s, &Rfc3339)?,
            });
        }
        Ok(out)
    }

    /// Record a snapshot taken before a destructive command.
    pub fn record_snapshot(&self, manifest: &crate::snapshot::Manifest) -> Result<(), LogError> {
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let json = serde_json::to_string(manifest)
            .map_err(|e| LogError::Corrupt(format!("manifest serialize: {e}")))?;
        // Snapshots are recorded just before the event they guard is appended, so
        // the guarded event's seq is the next rowid (= current count + 1).
        let seq: i64 = self
            .conn
            .query_row("SELECT COUNT(*) + 1 FROM events", [], |r| r.get(0))?;
        self.conn.execute(
            "INSERT INTO snapshots (id, seq, ts, command, manifest, reverted) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![manifest.id, seq, now, manifest.command, json],
        )?;
        Ok(())
    }

    /// Load all snapshots not yet reverted, newest first.
    pub fn unreverted_snapshots(&self) -> Result<Vec<crate::snapshot::Manifest>, LogError> {
        let mut stmt = self
            .conn
            .prepare("SELECT manifest FROM snapshots WHERE reverted = 0 ORDER BY rowid DESC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            let json = r?;
            let m: crate::snapshot::Manifest = serde_json::from_str(&json)
                .map_err(|e| LogError::Corrupt(format!("manifest parse: {e}")))?;
            out.push(m);
        }
        Ok(out)
    }

    /// The most recent not-yet-reverted snapshot, if any.
    pub fn latest_unreverted_snapshot(
        &self,
    ) -> Result<Option<crate::snapshot::Manifest>, LogError> {
        Ok(self.unreverted_snapshots()?.into_iter().next())
    }

    /// Mark a snapshot as reverted (it has been undone).
    pub fn mark_reverted(&self, id: &str) -> Result<(), LogError> {
        self.conn
            .execute("UPDATE snapshots SET reverted = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Remember a per-repo decision for an exact command (always-allow / -deny).
    ///
    /// Only `Allow` and `Deny` are meaningful; `Hold` is rejected.
    pub fn remember(
        &self,
        repo: &str,
        command_hash: &str,
        action: crate::types::Decision,
    ) -> Result<(), LogError> {
        use crate::types::Decision;
        if action == Decision::Hold {
            return Err(LogError::Corrupt(
                "cannot remember a Hold decision".to_string(),
            ));
        }
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        self.conn.execute(
            r#"
            INSERT INTO memory (repo, command_hash, action, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(repo, command_hash) DO UPDATE SET action = ?3, updated_at = ?4
            "#,
            rusqlite::params![repo, command_hash, action.as_str(), now],
        )?;
        Ok(())
    }

    /// Look up a remembered decision for an exact command in a repo.
    pub fn memory_lookup(
        &self,
        repo: &str,
        command_hash: &str,
    ) -> Result<Option<crate::types::Decision>, LogError> {
        use crate::types::Decision;
        let action: Option<String> = self
            .conn
            .query_row(
                "SELECT action FROM memory WHERE repo = ?1 AND command_hash = ?2",
                rusqlite::params![repo, command_hash],
                |row| row.get(0),
            )
            .optional()?;
        Ok(match action.as_deref() {
            Some("allow") => Some(Decision::Allow),
            Some("deny") => Some(Decision::Deny),
            _ => None,
        })
    }

    /// Compute the canonical hash for a row given its predecessor.
    ///
    /// The hash binds every immutable field plus the predecessor hash, so neither
    /// a field edit nor a reordering can go unnoticed.
    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        prev_hash: &str,
        id: &Uuid,
        ts_rfc3339: &str,
        agent: &str,
        cwd: &str,
        command: &str,
        argv_json: &str,
        class: Class,
        decision: Decision,
        reason: &str,
        tier: u8,
        risk: Option<u8>,
        summary: Option<&str>,
        snapshot_id: Option<&str>,
    ) -> String {
        let payload = format!(
            "{prev}\u{1f}{id}\u{1f}{ts}\u{1f}{agent}\u{1f}{cwd}\u{1f}{cmd}\u{1f}{argv}\u{1f}{class}\u{1f}{dec}\u{1f}{reason}\u{1f}{tier}\u{1f}{risk}\u{1f}{summary}\u{1f}{snap}",
            prev = prev_hash,
            id = id,
            ts = ts_rfc3339,
            agent = agent,
            cwd = cwd,
            cmd = command,
            argv = argv_json,
            class = class.as_str(),
            dec = decision.as_str(),
            reason = reason,
            tier = tier,
            risk = risk.map(|r| r.to_string()).unwrap_or_default(),
            summary = summary.unwrap_or_default(),
            snap = snapshot_id.unwrap_or_default(),
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Return the hash of the most recent event, or [`GENESIS_HASH`] if empty.
    fn head_hash(&self) -> Result<String, LogError> {
        let hash: Option<String> = self
            .conn
            .query_row(
                "SELECT hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(hash.unwrap_or_else(|| GENESIS_HASH.to_string()))
    }

    /// The read-modify-append, run inside the write transaction. Returns
    /// (prev_hash, hash, seq).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn append_locked(
        &self,
        cmd: &ProposedCommand,
        verdict: &Verdict,
        ts: &str,
        cwd: &str,
        command: &str,
        argv_json: &str,
        snapshot_id: Option<&str>,
    ) -> Result<(String, String, i64), LogError> {
        let prev_hash = self.head_hash()?;
        let hash = Self::compute_hash(
            &prev_hash,
            &cmd.id,
            ts,
            &cmd.agent,
            cwd,
            command,
            argv_json,
            verdict.class,
            verdict.decision,
            &verdict.reason,
            verdict.tier,
            verdict.risk,
            verdict.summary.as_deref(),
            snapshot_id,
        );
        self.conn.execute(
            r#"
            INSERT INTO events
                (id, ts, agent, cwd, command, argv, class, decision, reason, tier, risk, summary, snapshot_id, prev_hash, hash, session)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
            rusqlite::params![
                cmd.id.to_string(),
                ts,
                cmd.agent,
                cwd,
                command,
                argv_json,
                verdict.class.as_str(),
                verdict.decision.as_str(),
                verdict.reason,
                verdict.tier as i64,
                verdict.risk.map(|r| r as i64),
                verdict.summary,
                snapshot_id,
                prev_hash,
                hash,
                cmd.session,
            ],
        )?;
        Ok((prev_hash, hash, self.conn.last_insert_rowid()))
    }

    /// Append one event built from a proposal and its verdict.
    pub fn log_event(
        &self,
        cmd: &ProposedCommand,
        verdict: &Verdict,
        snapshot_id: Option<&str>,
    ) -> Result<LoggedEvent, LogError> {
        let ts = cmd.ts.format(&Rfc3339)?;
        let cwd = cmd.cwd.to_string_lossy().to_string();

        // Redact-before-hash (security spine #6): never let a command-line secret
        // (DB connection strings, `-pSECRET`, `PGPASSWORD=…`, bearer tokens) enter
        // the append-only, hash-chained log — it could not be scrubbed later. Only
        // the secret *value* is replaced (rest verbatim); when nothing matches, the
        // command/argv are stored byte-identically (so the common case and every
        // existing test are unchanged). The argv is re-derived from the redacted
        // command so it can't leak the secret either.
        let red = crate::redact::redact_command(&cmd.raw);
        let (command, argv): (String, Vec<String>) = if red.any() {
            (red.text.clone(), crate::shell::split(&red.text))
        } else {
            (cmd.raw.clone(), cmd.argv.clone())
        };
        let argv_json = serde_json::to_string(&argv)
            .map_err(|e| LogError::Corrupt(format!("argv serialize: {e}")))?;

        // Serialize the read-modify-append: take the write lock immediately so a
        // concurrent writer (another process) blocks and then reads the updated
        // head, rather than both linking new rows to the same prev_hash.
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let (prev_hash, hash, seq) =
            match self.append_locked(cmd, verdict, &ts, &cwd, &command, &argv_json, snapshot_id) {
                Ok(v) => {
                    self.conn.execute_batch("COMMIT")?;
                    v
                }
                Err(e) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            };

        Ok(LoggedEvent {
            seq,
            id: cmd.id,
            ts: cmd.ts,
            agent: cmd.agent.clone(),
            cwd,
            command,
            argv,
            class: verdict.class,
            decision: verdict.decision,
            reason: verdict.reason.clone(),
            tier: verdict.tier,
            risk: verdict.risk,
            summary: verdict.summary.clone(),
            snapshot_id: snapshot_id.map(str::to_string),
            session: cmd.session.clone(),
            prev_hash,
            hash,
            redacted: false,
        })
    }

    /// Return the most recent `n` non-redacted events, oldest first.
    pub fn tail(&self, n: usize) -> Result<Vec<LoggedEvent>, LogError> {
        self.query(&Filter {
            limit: Some(n),
            ..Filter::default()
        })
    }

    /// Return events matching `filter`, oldest first (capped by `filter.limit`,
    /// skipping `filter.offset` of the newest matches first for pagination).
    pub fn query(&self, filter: &Filter) -> Result<Vec<LoggedEvent>, LogError> {
        let (where_body, params) = filter.where_clause();
        let limit = filter.limit.map(|n| n as i64).unwrap_or(-1);
        let offset = filter.offset.map(|n| n as i64).unwrap_or(0);
        // Take the page window of newest-by-seq rows (skip `offset`, take
        // `limit`), then re-sort ascending so the page reads chronologically.
        // SQLite accepts `LIMIT -1 OFFSET n` to mean "all, skipping n".
        let sql = format!(
            r#"
            SELECT seq, id, ts, agent, cwd, command, argv, class, decision, reason, tier,
                   risk, summary, snapshot_id, prev_hash, hash, session, redacted
            FROM (
                SELECT events.*, (r.event_id IS NOT NULL) AS redacted
                FROM events LEFT JOIN redactions r ON r.event_id = events.id
                WHERE {where_body}
                ORDER BY events.seq DESC LIMIT ? OFFSET ?
            ) ORDER BY seq ASC
            "#
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut bound: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
        bound.push(&limit);
        bound.push(&offset);
        let rows = stmt.query_map(bound.as_slice(), Self::row_to_event)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Count events matching `filter` (ignores `limit`).
    pub fn count_matching(&self, filter: &Filter) -> Result<i64, LogError> {
        let (where_body, params) = filter.where_clause();
        let sql = format!(
            "SELECT COUNT(*) FROM events LEFT JOIN redactions r ON r.event_id = events.id WHERE {where_body}"
        );
        let bound: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
        Ok(self
            .conn
            .query_row(&sql, bound.as_slice(), |row| row.get(0))?)
    }

    /// Redact a single event by id (append-only; idempotent). Returns whether a
    /// matching, not-already-redacted event existed.
    pub fn redact(&self, event_id: &str, reason: &str) -> Result<bool, LogError> {
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let exists: bool = self
            .conn
            .prepare("SELECT 1 FROM events WHERE id = ?1")?
            .exists([event_id])?;
        if !exists {
            return Ok(false);
        }
        let n = self.conn.execute(
            "INSERT INTO redactions (event_id, ts, reason) VALUES (?1, ?2, ?3)
             ON CONFLICT(event_id) DO NOTHING",
            rusqlite::params![event_id, now, reason],
        )?;
        Ok(n > 0)
    }

    /// Redact every event matching `filter` (newest-first, no limit applied).
    /// Returns the number newly redacted.
    pub fn redact_matching(&self, filter: &Filter, reason: &str) -> Result<usize, LogError> {
        // Match against not-yet-redacted rows regardless of the filter's flag.
        let f = Filter {
            include_redacted: false,
            limit: None,
            ..filter.clone()
        };
        let (where_body, params) = f.where_clause();
        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let sql = format!(
            "INSERT INTO redactions (event_id, ts, reason)
             SELECT events.id, ?, ? FROM events
             LEFT JOIN redactions r ON r.event_id = events.id
             WHERE {where_body}"
        );
        let mut bound: Vec<&dyn rusqlite::ToSql> = vec![&now, &reason];
        let pbound: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
        bound.extend(pbound);
        Ok(self.conn.execute(&sql, bound.as_slice())?)
    }

    /// **Hard erasure** — physically delete events matching `filter`, rebuild the
    /// hash chain over the survivors, and append a marker event recording the
    /// purge. Deliberately rewrites history for the purged span; never automatic.
    /// Returns the number of events removed.
    ///
    /// `include_redacted`/`limit` on the filter are ignored: purge always targets
    /// every matching row. Catastrophic-or-not is irrelevant — this is the user's
    /// explicit erasure of their own local data.
    pub fn purge_matching(&self, filter: &Filter, reason: &str) -> Result<usize, LogError> {
        let f = Filter {
            include_redacted: true,
            limit: None,
            ..filter.clone()
        };
        let (where_body, params) = f.where_clause();

        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let removed = (|| -> Result<usize, LogError> {
            // Drop redaction rows for the doomed events, then the events.
            let del_red = format!(
                "DELETE FROM redactions WHERE event_id IN (
                     SELECT events.id FROM events
                     LEFT JOIN redactions r ON r.event_id = events.id WHERE {where_body})"
            );
            let bound: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
            self.conn.execute(&del_red, bound.as_slice())?;

            let del = format!(
                "DELETE FROM events WHERE id IN (
                     SELECT events.id FROM events
                     LEFT JOIN redactions r ON r.event_id = events.id WHERE {where_body})"
            );
            let bound: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
            let n = self.conn.execute(&del, bound.as_slice())?;
            self.rechain()?;
            Ok(n)
        })();
        let removed = match removed {
            Ok(n) => {
                self.conn.execute_batch("COMMIT")?;
                n
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        };

        // Record the purge itself as an immutable marker (outside the txn so it
        // links to the freshly re-chained head).
        if removed > 0 {
            let marker = ProposedCommand::new(
                "kintsugi",
                std::path::PathBuf::from("."),
                vec!["purge".into()],
                format!("kintsugi purge --hard ({removed} event(s): {reason})"),
            );
            let verdict = Verdict::rules(Class::Safe, Decision::Allow, "audit:purge");
            self.log_event(&marker, &verdict, None)?;
        }
        Ok(removed)
    }

    /// Recompute prev_hash/hash for every surviving row in seq order so the chain
    /// is valid again after a purge. Caller holds the write transaction.
    fn rechain(&self) -> Result<(), LogError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT seq, id, ts, agent, cwd, command, argv, class, decision, reason, tier,
                   risk, summary, snapshot_id, prev_hash, hash, session, 0 AS redacted
            FROM events ORDER BY seq ASC
            "#,
        )?;
        let mut events: Vec<LoggedEvent> = Vec::new();
        for r in stmt.query_map([], Self::row_to_event)? {
            events.push(r??);
        }
        drop(stmt);

        let mut prev = GENESIS_HASH.to_string();
        for ev in events {
            let ts = ev.ts.format(&Rfc3339)?;
            let argv_json = serde_json::to_string(&ev.argv)
                .map_err(|e| LogError::Corrupt(format!("argv serialize: {e}")))?;
            let hash = Self::compute_hash(
                &prev,
                &ev.id,
                &ts,
                &ev.agent,
                &ev.cwd,
                &ev.command,
                &argv_json,
                ev.class,
                ev.decision,
                &ev.reason,
                ev.tier,
                ev.risk,
                ev.summary.as_deref(),
                ev.snapshot_id.as_deref(),
            );
            self.conn.execute(
                "UPDATE events SET prev_hash = ?1, hash = ?2 WHERE seq = ?3",
                rusqlite::params![prev, hash, ev.seq],
            )?;
            prev = hash;
        }
        Ok(())
    }

    /// Total number of events.
    pub fn count(&self) -> Result<i64, LogError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?)
    }

    /// Walk the chain from genesis and confirm every link.
    ///
    /// Recomputes each row's hash from its stored fields and verifies it both
    /// matches the stored `hash` and links to the previous row's `hash`.
    pub fn verify_chain(&self) -> Result<ChainStatus, LogError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT seq, id, ts, agent, cwd, command, argv, class, decision, reason, tier,
                   risk, summary, snapshot_id, prev_hash, hash, session, 0 AS redacted
            FROM events ORDER BY seq ASC
            "#,
        )?;
        let rows = stmt.query_map([], Self::row_to_event)?;

        let mut expected_prev = GENESIS_HASH.to_string();
        for r in rows {
            let ev = r??;

            if ev.prev_hash != expected_prev {
                return Ok(ChainStatus::Broken {
                    seq: ev.seq,
                    detail: format!(
                        "prev_hash {} does not link to predecessor {}",
                        short(&ev.prev_hash),
                        short(&expected_prev)
                    ),
                });
            }

            let ts = ev.ts.format(&Rfc3339)?;
            let argv_json = serde_json::to_string(&ev.argv)
                .map_err(|e| LogError::Corrupt(format!("argv serialize: {e}")))?;
            let recomputed = Self::compute_hash(
                &ev.prev_hash,
                &ev.id,
                &ts,
                &ev.agent,
                &ev.cwd,
                &ev.command,
                &argv_json,
                ev.class,
                ev.decision,
                &ev.reason,
                ev.tier,
                ev.risk,
                ev.summary.as_deref(),
                ev.snapshot_id.as_deref(),
            );
            if recomputed != ev.hash {
                return Ok(ChainStatus::Broken {
                    seq: ev.seq,
                    detail: format!(
                        "row contents do not match stored hash {} (recomputed {})",
                        short(&ev.hash),
                        short(&recomputed)
                    ),
                });
            }

            expected_prev = ev.hash;
        }

        Ok(ChainStatus::Intact)
    }

    fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<LoggedEvent, LogError>> {
        // Pull raw columns first; map fallible conversions into LogError.
        let seq: i64 = row.get(0)?;
        let id_s: String = row.get(1)?;
        let ts_s: String = row.get(2)?;
        let agent: String = row.get(3)?;
        let cwd: String = row.get(4)?;
        let command: String = row.get(5)?;
        let argv_s: String = row.get(6)?;
        let class_s: String = row.get(7)?;
        let decision_s: String = row.get(8)?;
        let reason: String = row.get(9)?;
        let tier: i64 = row.get(10)?;
        let risk: Option<i64> = row.get(11)?;
        let summary: Option<String> = row.get(12)?;
        let snapshot_id: Option<String> = row.get(13)?;
        let prev_hash: String = row.get(14)?;
        let hash: String = row.get(15)?;
        let session: Option<String> = row.get(16)?;
        let redacted: bool = row.get(17)?;

        Ok((|| {
            let id = Uuid::parse_str(&id_s)
                .map_err(|e| LogError::Corrupt(format!("uuid {id_s}: {e}")))?;
            let ts = OffsetDateTime::parse(&ts_s, &Rfc3339)?;
            let argv: Vec<String> = serde_json::from_str(&argv_s)
                .map_err(|e| LogError::Corrupt(format!("argv {argv_s}: {e}")))?;
            let class = parse_class(&class_s)?;
            let decision = parse_decision(&decision_s)?;
            let tier = u8::try_from(tier)
                .map_err(|_| LogError::Corrupt(format!("tier out of range: {tier}")))?;
            let risk = match risk {
                Some(r) => Some(
                    u8::try_from(r)
                        .map_err(|_| LogError::Corrupt(format!("risk out of range: {r}")))?,
                ),
                None => None,
            };
            Ok(LoggedEvent {
                seq,
                id,
                ts,
                agent,
                cwd,
                command,
                argv,
                class,
                decision,
                reason,
                tier,
                risk,
                summary,
                snapshot_id,
                session,
                prev_hash,
                hash,
                redacted,
            })
        })())
    }
}

fn parse_class(s: &str) -> Result<Class, LogError> {
    match s {
        "safe" => Ok(Class::Safe),
        "catastrophic" => Ok(Class::Catastrophic),
        "ambiguous" => Ok(Class::Ambiguous),
        other => Err(LogError::Corrupt(format!("unknown class: {other}"))),
    }
}

fn parse_decision(s: &str) -> Result<Decision, LogError> {
    match s {
        "allow" => Ok(Decision::Allow),
        "deny" => Ok(Decision::Deny),
        "hold" => Ok(Decision::Hold),
        other => Err(LogError::Corrupt(format!("unknown decision: {other}"))),
    }
}

fn short(hash: &str) -> String {
    hash.chars().take(12).collect()
}

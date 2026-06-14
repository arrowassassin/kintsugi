//! Append-only, hash-chained event log (SQLite).
//!
//! Every observed command becomes one immutable row. Each row's `hash` is
//! `SHA-256(prev_hash || canonical(row))`, so any edit to a past row — or any
//! reordering — breaks the chain and is detectable by [`EventLog::verify_chain`].
//!
//! Security spine: this log is append-only. There is deliberately no update or
//! delete API. Past events are immutable.

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
    /// Hash of the predecessor row.
    pub prev_hash: String,
    /// This row's hash.
    pub hash: String,
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
        conn.pragma_update(None, "foreign_keys", "ON")?;
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
                hash       TEXT NOT NULL
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
            "#,
        )?;
        Ok(Self { conn })
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

    /// Append one event built from a proposal and its verdict.
    pub fn log_event(
        &self,
        cmd: &ProposedCommand,
        verdict: &Verdict,
        snapshot_id: Option<&str>,
    ) -> Result<LoggedEvent, LogError> {
        let prev_hash = self.head_hash()?;
        let ts = cmd.ts.format(&Rfc3339)?;
        let cwd = cmd.cwd.to_string_lossy().to_string();
        let argv_json = serde_json::to_string(&cmd.argv)
            .map_err(|e| LogError::Corrupt(format!("argv serialize: {e}")))?;

        let hash = Self::compute_hash(
            &prev_hash,
            &cmd.id,
            &ts,
            &cmd.agent,
            &cwd,
            &cmd.raw,
            &argv_json,
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
                (id, ts, agent, cwd, command, argv, class, decision, reason, tier, risk, summary, snapshot_id, prev_hash, hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            rusqlite::params![
                cmd.id.to_string(),
                ts,
                cmd.agent,
                cwd,
                cmd.raw,
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
            ],
        )?;
        let seq = self.conn.last_insert_rowid();

        Ok(LoggedEvent {
            seq,
            id: cmd.id,
            ts: cmd.ts,
            agent: cmd.agent.clone(),
            cwd,
            command: cmd.raw.clone(),
            argv: cmd.argv.clone(),
            class: verdict.class,
            decision: verdict.decision,
            reason: verdict.reason.clone(),
            tier: verdict.tier,
            risk: verdict.risk,
            summary: verdict.summary.clone(),
            snapshot_id: snapshot_id.map(str::to_string),
            prev_hash,
            hash,
        })
    }

    /// Return the most recent `n` events, oldest first.
    pub fn tail(&self, n: usize) -> Result<Vec<LoggedEvent>, LogError> {
        // Pull the newest n by seq desc, then reverse so callers see chronological order.
        let mut stmt = self.conn.prepare(
            r#"
            SELECT seq, id, ts, agent, cwd, command, argv, class, decision, reason, tier,
                   risk, summary, snapshot_id, prev_hash, hash
            FROM (
                SELECT * FROM events ORDER BY seq DESC LIMIT ?1
            ) ORDER BY seq ASC
            "#,
        )?;
        let rows = stmt.query_map([n as i64], Self::row_to_event)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
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
                   risk, summary, snapshot_id, prev_hash, hash
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
                prev_hash,
                hash,
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

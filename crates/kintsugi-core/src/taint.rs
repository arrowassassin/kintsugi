//! Taint / provenance model (Phase 6) — pure, in-memory information-flow state.
//!
//! Tracks which agent sessions (and which files) have been influenced by
//! *untrusted* content, so the Tier-1 rules can deterministically block the
//! "lethal trifecta": untrusted input + a sensitive read + an egress sink.
//!
//! Security spine (see `CLAUDE.md`): this module only *labels* and computes a
//! deterministic outcome. It performs no I/O and makes no decision a model can
//! weaken. Taint is **monotonic** — it only ever adds caution; nothing here can
//! clear a taint except an explicit, policy-driven reset. Content is recorded by
//! *identifier only* (url / path / tool name); secret values never enter a label.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Where a piece of untrusted content entered the agent's context from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// A fetched web page / HTTP response.
    Web,
    /// A downloaded artifact (curl/wget/git clone output, etc.).
    Download,
    /// Output returned by an external MCP tool.
    Mcp,
    /// An issue / PR / ticket / email body the agent read.
    Issue,
    /// A file the agent read that is outside the trusted (repo-owned) set.
    File,
    /// Pasted clipboard content.
    Clipboard,
    /// Untrusted content ingested via a shell command.
    Shell,
    /// A web-search result snippet.
    SearchResult,
}

impl SourceKind {
    /// Stable lowercase token used in storage and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Web => "web",
            SourceKind::Download => "download",
            SourceKind::Mcp => "mcp",
            SourceKind::Issue => "issue",
            SourceKind::File => "file",
            SourceKind::Clipboard => "clipboard",
            SourceKind::Shell => "shell",
            SourceKind::SearchResult => "searchresult",
        }
    }

    /// A short human label + one-line explanation, for the Rules view. Mirrors the
    /// channels the interception layer classifies as untrusted (see
    /// `kintsugi-intercept`'s `observe`), so the app shows exactly what taints a
    /// session.
    pub fn describe(self) -> (&'static str, &'static str) {
        match self {
            SourceKind::Web => ("Web fetch", "a fetched web page / HTTP response"),
            SourceKind::Download => ("Download", "curl / wget / git clone output"),
            SourceKind::Mcp => (
                "MCP tool output",
                "results returned by an external MCP tool",
            ),
            SourceKind::Issue => (
                "Issue / PR / email",
                "a ticket or message body the agent read",
            ),
            SourceKind::File => (
                "Out-of-workspace file",
                "a read outside the trusted repo tree",
            ),
            SourceKind::Clipboard => ("Clipboard", "pasted clipboard content"),
            SourceKind::Shell => (
                "Shell-ingested",
                "untrusted content pulled in by a shell command",
            ),
            SourceKind::SearchResult => ("Web-search result", "a search-result snippet"),
        }
    }
}

/// The untrusted ingest channels provenance tracks — any of these taints the
/// session it lands in. Public so the app's Rules view can list exactly what's
/// watched, sourced from the [`SourceKind`] enum itself (no hard-coded duplicate).
pub fn untrusted_sources() -> Vec<(&'static str, &'static str)> {
    [
        SourceKind::Web,
        SourceKind::Download,
        SourceKind::Mcp,
        SourceKind::Issue,
        SourceKind::File,
        SourceKind::Clipboard,
        SourceKind::Shell,
        SourceKind::SearchResult,
    ]
    .into_iter()
    .map(SourceKind::describe)
    .collect()
}

/// A single taint origin. Recorded by identifier only — never content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintLabel {
    /// The channel the untrusted content arrived on.
    pub source_kind: SourceKind,
    /// Identifier of the source (url / path / tool name). Never a secret value.
    pub source_id: String,
    /// When the source was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    /// Agent that ingested it.
    pub agent: String,
    /// Session the ingestion belongs to.
    pub session: String,
}

impl TaintLabel {
    /// The dedup key for a label: a source is one origin regardless of repeats.
    fn key(&self) -> (SourceKind, &str) {
        (self.source_kind, self.source_id.as_str())
    }
}

/// A normalized "untrusted content entered the agent's context" event, emitted by
/// the interception layer when it observes a content-ingesting tool call (a web
/// fetch, a search, an MCP tool result, a read of an out-of-workspace file, a
/// `curl`/`wget`/`git clone`). It is the bridge from the per-agent hook surface to
/// the daemon's taint tracker: the daemon turns it into a [`TaintEvent::Ingest`].
///
/// Identifier only — `source_id` is a url / path / tool name, never payload bytes
/// (spine #6). The daemon redacts it again at ingest (segment G) as defense in
/// depth, so a credential smuggled into a url can never reach the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedIngest {
    /// The channel the untrusted content arrived on.
    pub source_kind: SourceKind,
    /// Identifier of the source (url / path / tool name). Never a secret value.
    pub source_id: String,
    /// Agent that ingested it.
    pub agent: String,
    /// Session the ingestion belongs to.
    pub session: String,
    /// Working directory the tool call ran in.
    pub cwd: PathBuf,
    /// When the source was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
}

impl ObservedIngest {
    /// Build an observation stamped at the current instant. The interception layer
    /// uses this the moment it sees a content-ingesting tool call.
    pub fn now(
        source_kind: SourceKind,
        source_id: impl Into<String>,
        agent: impl Into<String>,
        session: impl Into<String>,
        cwd: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source_kind,
            source_id: source_id.into(),
            agent: agent.into(),
            session: session.into(),
            cwd: cwd.into(),
            ts: OffsetDateTime::now_utc(),
        }
    }

    /// Lower this observation into the durable taint transition the daemon applies.
    /// (`cwd` is observation context for the trail, not part of the session label.)
    pub fn into_taint_event(self) -> TaintEvent {
        TaintEvent::Ingest {
            label: TaintLabel {
                source_kind: self.source_kind,
                source_id: self.source_id,
                ts: self.ts,
                agent: self.agent,
                session: self.session,
            },
        }
    }
}

/// The accumulated provenance set for a session or a file.
///
/// An empty set means "not tainted". `add`/`merge` dedup by `(kind, id)` so the
/// set stays a clean provenance list even when a source is read repeatedly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSet(pub Vec<TaintLabel>);

impl TaintSet {
    /// Whether anything untrusted has touched this session/file.
    pub fn is_tainted(&self) -> bool {
        !self.0.is_empty()
    }

    /// The provenance labels, in observation order.
    pub fn labels(&self) -> &[TaintLabel] {
        &self.0
    }

    /// Add a label, skipping an exact `(kind, id)` duplicate.
    pub fn add(&mut self, label: TaintLabel) {
        if !self.0.iter().any(|l| l.key() == label.key()) {
            self.0.push(label);
        }
    }

    /// Merge another set in, deduping by `(kind, id)`.
    pub fn merge(&mut self, other: &TaintSet) {
        for label in &other.0 {
            self.add(label.clone());
        }
    }
}

/// In-memory information-flow state: which sessions and files are tainted.
///
/// Pure data structure — the daemon owns persistence/rebuild-from-log; this type
/// has no I/O. Coarse, source-level granularity (no per-token dataflow): any
/// untrusted ingestion taints the whole session, and a tainted session taints
/// the files it writes.
#[derive(Debug, Default)]
pub struct TaintStore {
    sessions: HashMap<String, TaintSet>,
    paths: HashMap<PathBuf, TaintSet>,
}

impl TaintStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe untrusted content entering a session → taint the session.
    pub fn observe_ingest(&mut self, label: TaintLabel) {
        self.sessions
            .entry(label.session.clone())
            .or_default()
            .add(label);
    }

    /// A tainted session writes a file → propagate the session's taint to the path.
    /// A no-op if the session is clean.
    pub fn taint_path_from_session(&mut self, session: &str, path: impl Into<PathBuf>) {
        if let Some(set) = self.sessions.get(session).cloned() {
            if set.is_tainted() {
                self.paths.entry(path.into()).or_default().merge(&set);
            }
        }
    }

    /// A session reads a file → if the file is tainted, re-taint the session.
    /// A no-op if the path is clean.
    pub fn read_path_into_session(&mut self, session: &str, path: &Path) {
        if let Some(set) = self.paths.get(path).cloned() {
            if set.is_tainted() {
                self.sessions
                    .entry(session.to_string())
                    .or_default()
                    .merge(&set);
            }
        }
    }

    /// The session's provenance set, if any.
    pub fn session_taint(&self, session: &str) -> Option<&TaintSet> {
        self.sessions.get(session)
    }

    /// Whether the session is currently tainted.
    pub fn is_session_tainted(&self, session: &str) -> bool {
        self.sessions.get(session).is_some_and(TaintSet::is_tainted)
    }

    /// Whether the path is currently tainted.
    pub fn is_path_tainted(&self, path: &Path) -> bool {
        self.paths.get(path).is_some_and(TaintSet::is_tainted)
    }

    /// Explicit, policy-driven trust reset (`reset_on`) — clears a session's taint.
    /// This is the *only* way taint leaves a session; the model can never do it.
    pub fn reset_session(&mut self, session: &str) {
        self.sessions.remove(session);
    }
}

/// The deterministic trifecta outcome over the three legs of the lethal trifecta.
///
/// Ordered by caution: `None < Annotate < Hold < Block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trifecta {
    /// No taint-driven action.
    None,
    /// Tainted + sensitive read, no sink — annotate (hold in attended mode).
    Annotate,
    /// Tainted + egress sink, no sensitive read — hold.
    Hold,
    /// Tainted + sensitive read + egress sink — block (a hard floor).
    Block,
}

impl Trifecta {
    /// The rule identifier that produced this outcome, if any.
    pub fn rule(self) -> Option<&'static str> {
        match self {
            Trifecta::None => None,
            Trifecta::Annotate => Some("TRIFECTA-03"),
            Trifecta::Hold => Some("TRIFECTA-02"),
            Trifecta::Block => Some("TRIFECTA-01"),
        }
    }

    /// Caution rank, for monotonicity checks: `None=0 < Annotate=1 < Hold=2 < Block=3`.
    pub fn caution(self) -> u8 {
        match self {
            Trifecta::None => 0,
            Trifecta::Annotate => 1,
            Trifecta::Hold => 2,
            Trifecta::Block => 3,
        }
    }
}

/// Evaluate the trifecta rule over its three legs. Deterministic and total.
///
/// Truth table (the only blocking case is all three present):
/// - `tainted && sensitive_read && egress_sink` → [`Trifecta::Block`]  (TRIFECTA-01)
/// - `tainted && egress_sink`                   → [`Trifecta::Hold`]   (TRIFECTA-02)
/// - `tainted && sensitive_read`                → [`Trifecta::Annotate`] (TRIFECTA-03)
/// - otherwise                                  → [`Trifecta::None`]
pub fn evaluate_trifecta(tainted: bool, sensitive_read: bool, egress_sink: bool) -> Trifecta {
    match (tainted, sensitive_read, egress_sink) {
        (true, true, true) => Trifecta::Block,
        (true, false, true) => Trifecta::Hold,
        (true, true, false) => Trifecta::Annotate,
        _ => Trifecta::None,
    }
}

/// One step in a human-readable provenance trail. Identifiers only — no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum ProvStep {
    /// Untrusted content was read from a source.
    UntrustedRead {
        source_kind: SourceKind,
        source_id: String,
    },
    /// The command reads a sensitive path (identifier only).
    SensitiveRead { path: String },
    /// The command would send data to an egress target.
    EgressSink { target: String },
    /// A deterministic rule fired.
    RuleFired { rule: String },
}

/// The untrusted-read prefix of a provenance trail: one [`ProvStep::UntrustedRead`]
/// per origin in a session's (or file's) taint set, in observation order. This is
/// the forensic "everything descended from source X" chain; the daemon appends the
/// per-command legs (sensitive read → egress sink → rule fired) to complete it.
/// Identifiers only — never content.
pub fn untrusted_trail(set: &TaintSet) -> Vec<ProvStep> {
    set.labels()
        .iter()
        .map(|l| ProvStep::UntrustedRead {
            source_kind: l.source_kind,
            source_id: l.source_id.clone(),
        })
        .collect()
}

/// A persisted taint transition — the unit of durability.
///
/// An ordered stream of these fully determines a [`TaintState`]: replaying them
/// (e.g. from the append-only event log on a cold start) reconstructs the exact
/// same state, so a daemon restart never silently loses — or invents — taint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaintEvent {
    /// Untrusted content entered a session.
    Ingest { label: TaintLabel },
    /// A session wrote a file → propagate session taint to the path.
    WriteFile { session: String, path: PathBuf },
    /// A session read a file → propagate path taint to the session.
    ReadFile { session: String, path: PathBuf },
    /// A policy-driven trust reset cleared a session's taint.
    Reset { session: String },
}

impl TaintEvent {
    /// Return a copy of this event with its taint `source_id` run through
    /// [`redact::redact_source_id`](crate::redact::redact_source_id).
    ///
    /// Segment G: a source identifier (url / path / tool name) can smuggle a
    /// secret in a url's userinfo or query string. Normalizing the event at the
    /// single ingest boundary — *before* it is appended to the append-only log or
    /// applied into state — means the redacted form is the only one that ever
    /// reaches a log row, the provenance trail, or an agent-facing reason. Only
    /// [`Ingest`](TaintEvent::Ingest) carries a `source_id`; the others (which
    /// reference daemon-owned session ids and file paths, never agent-supplied
    /// source identifiers) are returned unchanged. Idempotent.
    pub fn with_redacted_source_id(&self) -> TaintEvent {
        match self {
            TaintEvent::Ingest { label } => {
                let mut label = label.clone();
                label.source_id = crate::redact::redact_source_id(&label.source_id);
                TaintEvent::Ingest { label }
            }
            other => other.clone(),
        }
    }
}

/// A durable, event-sourced view of taint state — the daemon's session/file
/// taint authority. Build it by applying [`TaintEvent`]s; rebuild it identically
/// by replaying the same ordered stream. Deterministic and I/O-free.
#[derive(Debug, Default)]
pub struct TaintState {
    store: TaintStore,
}

impl TaintState {
    /// An empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one transition, mutating state. Deterministic and total — never panics.
    pub fn apply(&mut self, event: &TaintEvent) {
        match event {
            TaintEvent::Ingest { label } => self.store.observe_ingest(label.clone()),
            TaintEvent::WriteFile { session, path } => {
                self.store.taint_path_from_session(session, path.clone());
            }
            TaintEvent::ReadFile { session, path } => {
                self.store.read_path_into_session(session, path);
            }
            TaintEvent::Reset { session } => self.store.reset_session(session),
        }
    }

    // (`with_redacted_source_id` lives on `TaintEvent` so the *same* normalized
    // event is what gets logged and applied — see that method.)

    /// Reconstruct from an ordered event stream (cold-start durability).
    pub fn from_events<'a, I>(events: I) -> Self
    where
        I: IntoIterator<Item = &'a TaintEvent>,
    {
        let mut state = Self::new();
        for event in events {
            state.apply(event);
        }
        state
    }

    /// Whether the session is currently tainted. A `None` (untracked) session is
    /// reported as not tainted; callers needing fail-closed semantics decide that
    /// separately. Convenience over `Option<&str>` since a command's session id is
    /// optional ([`ProposedCommand::session`](crate::types::ProposedCommand)).
    pub fn is_session_tainted(&self, session: Option<&str>) -> bool {
        session.is_some_and(|s| self.store.is_session_tainted(s))
    }

    /// The session's provenance set, if any.
    pub fn session_taint(&self, session: &str) -> Option<&TaintSet> {
        self.store.session_taint(session)
    }

    /// Whether the path is currently tainted.
    pub fn is_path_tainted(&self, path: &Path) -> bool {
        self.store.is_path_tainted(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn label(kind: SourceKind, id: &str, session: &str) -> TaintLabel {
        TaintLabel {
            source_kind: kind,
            source_id: id.to_string(),
            ts: OffsetDateTime::UNIX_EPOCH,
            agent: "claude-code".to_string(),
            session: session.to_string(),
        }
    }

    #[test]
    fn untrusted_source_catalog_covers_every_source_kind() {
        // One displayed entry per SourceKind, with a non-empty label + detail —
        // the Rules view advertises exactly the channels the engine taints from.
        let cat = untrusted_sources();
        assert_eq!(cat.len(), 8, "one row per SourceKind variant");
        for (label, detail) in &cat {
            assert!(!label.is_empty() && !detail.is_empty());
        }
        // describe() is the source of those rows; spot-check a couple.
        assert_eq!(SourceKind::Web.describe().0, "Web fetch");
        assert_eq!(SourceKind::Mcp.describe().0, "MCP tool output");
    }

    // --- Trifecta truth table: exhaustive over all 8 boolean combinations. ----
    // Exhaustive enumeration is a complete proof for a 3-boolean predicate, so
    // this stands in for a property test (and adds no proptest dependency).
    #[test]
    fn trifecta_truth_table_is_exhaustive_and_correct() {
        let cases = [
            // (tainted, sensitive, sink) => outcome
            ((false, false, false), Trifecta::None),
            ((false, false, true), Trifecta::None),
            ((false, true, false), Trifecta::None),
            ((false, true, true), Trifecta::None), // untainted ⇒ never fires
            ((true, false, false), Trifecta::None),
            ((true, false, true), Trifecta::Hold), // TRIFECTA-02
            ((true, true, false), Trifecta::Annotate), // TRIFECTA-03
            ((true, true, true), Trifecta::Block), // TRIFECTA-01
        ];
        for ((t, s, e), want) in cases {
            assert_eq!(
                evaluate_trifecta(t, s, e),
                want,
                "tainted={t} sensitive={s} sink={e}"
            );
        }
    }

    #[test]
    fn trifecta_blocks_only_when_all_three_present() {
        // The zero-tolerance leg: the block must require the full trifecta.
        for t in [false, true] {
            for s in [false, true] {
                for e in [false, true] {
                    let blocked = evaluate_trifecta(t, s, e) == Trifecta::Block;
                    assert_eq!(blocked, t && s && e, "t={t} s={s} e={e}");
                }
            }
        }
    }

    #[test]
    fn trifecta_is_monotonic_in_each_leg() {
        // Adding any leg never reduces caution (monotonic-caution invariant).
        for s in [false, true] {
            for e in [false, true] {
                assert!(
                    evaluate_trifecta(true, s, e).caution()
                        >= evaluate_trifecta(false, s, e).caution()
                );
            }
        }
        for t in [false, true] {
            for e in [false, true] {
                assert!(
                    evaluate_trifecta(t, true, e).caution()
                        >= evaluate_trifecta(t, false, e).caution()
                );
            }
        }
        for t in [false, true] {
            for s in [false, true] {
                assert!(
                    evaluate_trifecta(t, s, true).caution()
                        >= evaluate_trifecta(t, s, false).caution()
                );
            }
        }
    }

    #[test]
    fn trifecta_rule_names_match_outcomes() {
        assert_eq!(Trifecta::Block.rule(), Some("TRIFECTA-01"));
        assert_eq!(Trifecta::Hold.rule(), Some("TRIFECTA-02"));
        assert_eq!(Trifecta::Annotate.rule(), Some("TRIFECTA-03"));
        assert_eq!(Trifecta::None.rule(), None);
    }

    // --- Propagation -----------------------------------------------------------
    #[test]
    fn ingest_taints_the_session_only() {
        let mut store = TaintStore::new();
        assert!(!store.is_session_tainted("s1"));
        store.observe_ingest(label(SourceKind::Web, "https://evil.example/x", "s1"));
        assert!(store.is_session_tainted("s1"));
        assert!(!store.is_session_tainted("s2")); // isolation between sessions
    }

    #[test]
    fn tainted_session_taints_written_file_then_re_taints_a_reader() {
        let mut store = TaintStore::new();
        store.observe_ingest(label(SourceKind::Issue, "issue#42", "writer"));
        // writer (tainted) writes a file → file becomes tainted
        store.taint_path_from_session("writer", "/work/out.txt");
        assert!(store.is_path_tainted(Path::new("/work/out.txt")));
        // a *different*, clean session reads that file → it becomes tainted
        assert!(!store.is_session_tainted("reader"));
        store.read_path_into_session("reader", Path::new("/work/out.txt"));
        assert!(store.is_session_tainted("reader"));
    }

    #[test]
    fn clean_session_does_not_taint_files() {
        let mut store = TaintStore::new();
        store.taint_path_from_session("clean", "/work/out.txt"); // session unknown/clean
        assert!(!store.is_path_tainted(Path::new("/work/out.txt")));
    }

    #[test]
    fn reading_a_clean_path_keeps_the_session_clean() {
        let mut store = TaintStore::new();
        store.read_path_into_session("s", Path::new("/work/untracked"));
        assert!(!store.is_session_tainted("s"));
    }

    #[test]
    fn reset_clears_session_taint() {
        let mut store = TaintStore::new();
        store.observe_ingest(label(SourceKind::Web, "u", "s"));
        assert!(store.is_session_tainted("s"));
        store.reset_session("s");
        assert!(!store.is_session_tainted("s"));
    }

    #[test]
    fn labels_dedup_by_kind_and_id_but_keep_distinct_sources() {
        let mut set = TaintSet::default();
        set.add(label(SourceKind::Web, "u1", "s"));
        set.add(label(SourceKind::Web, "u1", "s")); // exact dup → ignored
        set.add(label(SourceKind::Web, "u2", "s")); // distinct id → kept
        set.add(label(SourceKind::Download, "u1", "s")); // distinct kind → kept
        assert_eq!(set.labels().len(), 3);
    }

    #[test]
    fn source_kind_tokens_are_stable() {
        assert_eq!(SourceKind::Web.as_str(), "web");
        assert_eq!(SourceKind::SearchResult.as_str(), "searchresult");
        assert_eq!(SourceKind::Mcp.as_str(), "mcp");
    }

    #[test]
    fn prov_step_serializes_with_a_step_tag_and_no_secret_fields() {
        let step = ProvStep::SensitiveRead {
            path: "~/.aws/credentials".to_string(),
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"step\":\"sensitive_read\""));
        assert!(json.contains("~/.aws/credentials")); // identifier only, never contents
    }

    // --- Event-sourced TaintState ---------------------------------------------
    #[test]
    fn apply_ingest_event_taints_the_session() {
        let mut state = TaintState::new();
        assert!(!state.is_session_tainted(Some("s")));
        state.apply(&TaintEvent::Ingest {
            label: label(SourceKind::Web, "u", "s"),
        });
        assert!(state.is_session_tainted(Some("s")));
    }

    #[test]
    fn from_events_reconstructs_state_identically() {
        // Durability: replaying the same ordered stream must reproduce the state
        // a daemon held before a restart.
        let events = vec![
            TaintEvent::Ingest {
                label: label(SourceKind::Issue, "issue#1", "writer"),
            },
            TaintEvent::WriteFile {
                session: "writer".to_string(),
                path: PathBuf::from("/work/out.txt"),
            },
            TaintEvent::ReadFile {
                session: "reader".to_string(),
                path: PathBuf::from("/work/out.txt"),
            },
        ];
        let replayed = TaintState::from_events(&events);
        assert!(replayed.is_session_tainted(Some("writer")));
        assert!(replayed.is_path_tainted(Path::new("/work/out.txt")));
        assert!(replayed.is_session_tainted(Some("reader"))); // propagated through the file

        // Building incrementally yields the same observable state.
        let mut incremental = TaintState::new();
        for e in &events {
            incremental.apply(e);
        }
        assert_eq!(
            incremental.is_session_tainted(Some("reader")),
            replayed.is_session_tainted(Some("reader"))
        );
    }

    #[test]
    fn ingest_event_source_id_is_redacted_before_it_reaches_state() {
        // Segment G: a secret-bearing source_id (url userinfo / query token) must
        // be redacted at the ingest boundary, so neither a log row (the event is
        // logged in its normalized form) nor the in-memory provenance (which feeds
        // agent-facing reasons / the IPC trail) ever holds the secret.
        let raw = TaintEvent::Ingest {
            label: label(
                SourceKind::Web,
                "https://u:ghp_tok123@evil.example/x?api_key=sk-live-9",
                "s",
            ),
        };
        let safe = raw.with_redacted_source_id();
        let TaintEvent::Ingest { label: cleaned } = &safe else {
            panic!("Ingest must stay Ingest");
        };
        assert!(!cleaned.source_id.contains("ghp_tok123"));
        assert!(!cleaned.source_id.contains("sk-live-9"));

        // The redacted event is what gets applied → the provenance label is clean.
        let mut state = TaintState::new();
        state.apply(&safe);
        let labels = state.session_taint("s").unwrap().labels();
        assert!(!labels[0].source_id.contains("ghp_tok123"));
        assert!(!labels[0].source_id.contains("sk-live-9"));

        // Non-Ingest events have no source_id and are passed through untouched —
        // their paths/sessions are daemon-owned, not agent-supplied identifiers.
        let reset = TaintEvent::Reset {
            session: "s".to_string(),
        };
        assert_eq!(reset.with_redacted_source_id(), reset);
    }

    #[test]
    fn untrusted_trail_lists_each_origin_as_a_step_in_order() {
        let mut set = TaintSet::default();
        set.add(label(SourceKind::Web, "https://evil.example/a", "s"));
        set.add(label(SourceKind::Mcp, "mcp/github/get_issue", "s"));
        let trail = untrusted_trail(&set);
        assert_eq!(
            trail,
            vec![
                ProvStep::UntrustedRead {
                    source_kind: SourceKind::Web,
                    source_id: "https://evil.example/a".to_string(),
                },
                ProvStep::UntrustedRead {
                    source_kind: SourceKind::Mcp,
                    source_id: "mcp/github/get_issue".to_string(),
                },
            ]
        );
        // A clean set has an empty trail.
        assert!(untrusted_trail(&TaintSet::default()).is_empty());
    }

    #[test]
    fn observed_ingest_lowers_into_an_ingest_taint_event() {
        // The intercept layer emits ObservedIngest; the daemon lowers it to the
        // durable Ingest transition. The label must carry the same origin (cwd is
        // trail context, not part of the session-taint identity).
        let obs = ObservedIngest {
            source_kind: SourceKind::Web,
            source_id: "https://untrusted.example/page".to_string(),
            agent: "claude-code".to_string(),
            session: "s1".to_string(),
            cwd: PathBuf::from("/work"),
            ts: OffsetDateTime::UNIX_EPOCH,
        };
        let TaintEvent::Ingest { label } = obs.clone().into_taint_event() else {
            panic!("must lower to Ingest");
        };
        assert_eq!(label.source_kind, SourceKind::Web);
        assert_eq!(label.source_id, "https://untrusted.example/page");
        assert_eq!(label.session, "s1");
        assert_eq!(label.agent, "claude-code");

        // Applying it taints exactly that session.
        let mut state = TaintState::new();
        state.apply(&obs.into_taint_event());
        assert!(state.is_session_tainted(Some("s1")));
    }

    #[test]
    fn reset_event_clears_session_taint() {
        let mut state = TaintState::new();
        state.apply(&TaintEvent::Ingest {
            label: label(SourceKind::Web, "u", "s"),
        });
        state.apply(&TaintEvent::Reset {
            session: "s".to_string(),
        });
        assert!(!state.is_session_tainted(Some("s")));
    }

    #[test]
    fn none_session_is_never_reported_tainted() {
        let mut state = TaintState::new();
        state.apply(&TaintEvent::Ingest {
            label: label(SourceKind::Web, "u", "s"),
        });
        assert!(!state.is_session_tainted(None));
    }

    #[test]
    fn taint_event_json_round_trips_with_a_kind_tag() {
        let event = TaintEvent::Ingest {
            label: label(SourceKind::Mcp, "tool:fetch", "s"),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"ingest\""));
        let back: TaintEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }
}

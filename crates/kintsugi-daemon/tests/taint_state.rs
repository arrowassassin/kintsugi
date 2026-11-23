//! Phase 6 · Item A — the daemon owns session/file taint state.

use kintsugi_core::{EventLog, SourceKind, TaintEvent, TaintLabel};
use kintsugi_daemon::Daemon;
use time::OffsetDateTime;

fn ingest(session: &str) -> TaintEvent {
    TaintEvent::Ingest {
        label: TaintLabel {
            source_kind: SourceKind::Web,
            source_id: "https://untrusted.example/x".to_string(),
            ts: OffsetDateTime::UNIX_EPOCH,
            agent: "claude-code".to_string(),
            session: session.to_string(),
        },
    }
}

#[test]
fn apply_taint_redacts_a_secret_bearing_source_id_at_the_boundary() {
    let _gate = gate();
    // Segment G: if untrusted content is observed from a url that carries a
    // credential, the daemon must redact the source_id at ingest so it can never
    // land in the append-only log or the provenance trail the model sees.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");

    {
        let daemon = Daemon::open(db.clone()).unwrap();
        daemon.apply_taint(&TaintEvent::Ingest {
            label: TaintLabel {
                source_kind: SourceKind::Web,
                source_id: "https://u:ghp_secret123@evil.example/x?token=sk-live-9".to_string(),
                ts: OffsetDateTime::UNIX_EPOCH,
                agent: "claude-code".to_string(),
                session: "s1".to_string(),
            },
        });
        assert!(daemon.is_session_tainted(Some("s1"))); // taint still tracked
        let prov = daemon.session_provenance("s1").expect("session is tainted");
        let id = &prov.labels()[0].source_id;
        assert!(
            !id.contains("ghp_secret123"),
            "userinfo secret leaked: {id}"
        );
        assert!(!id.contains("sk-live-9"), "query secret leaked: {id}");
    } // daemon dropped — the durable taint_events row is on disk

    // Item D + G interaction: the secret must not have been persisted into the
    // append-only (unscrubbable) log row either. A cold start replays the stream;
    // the replayed provenance must still be secret-free — proving the redaction
    // ran *before* the persist, not just on the live in-memory copy.
    let daemon = Daemon::open(db).unwrap();
    let prov = daemon
        .session_provenance("s1")
        .expect("taint replayed on open");
    let id = &prov.labels()[0].source_id;
    assert!(
        !id.contains("ghp_secret123"),
        "userinfo secret in log: {id}"
    );
    assert!(!id.contains("sk-live-9"), "query secret in log: {id}");
}

#[test]
fn daemon_tracks_and_resets_session_taint() {
    let _gate = gate();
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    // Clean to start; an untracked (None) session is never tainted.
    assert!(!daemon.is_session_tainted(Some("s1")));
    assert!(!daemon.is_session_tainted(None));

    // Observing untrusted content taints just that session.
    daemon.apply_taint(&ingest("s1"));
    assert!(daemon.is_session_tainted(Some("s1")));
    assert!(!daemon.is_session_tainted(Some("s2"))); // isolation between sessions

    // A policy-driven reset clears it.
    daemon.apply_taint(&TaintEvent::Reset {
        session: "s1".to_string(),
    });
    assert!(!daemon.is_session_tainted(Some("s1")));
}

#[test]
fn taint_survives_a_daemon_restart() {
    let _gate = gate();
    // Item D: taint is persisted to the durable stream and replayed on
    // Daemon::open, so a stop/start (or a watchdog relaunch) does not silently
    // clear it — the trifecta guard stays armed across restarts instead of
    // failing open.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");

    {
        let daemon = Daemon::open(db.clone()).unwrap();
        daemon.apply_taint(&ingest("s1"));
        assert!(daemon.is_session_tainted(Some("s1")));
    } // daemon dropped — simulates `kintsugi stop`

    // Cold start against the same data dir replays the durable taint stream.
    let daemon = Daemon::open(db.clone()).unwrap();
    assert!(
        daemon.is_session_tainted(Some("s1")),
        "taint must be rebuilt by replay on open (no fail-open-on-restart)"
    );

    // A persisted Reset is replayed too — taint stays cleared, never resurrected.
    daemon.apply_taint(&TaintEvent::Reset {
        session: "s1".to_string(),
    });
    drop(daemon);
    let daemon = Daemon::open(db).unwrap();
    assert!(
        !daemon.is_session_tainted(Some("s1")),
        "a replayed Reset keeps the session clean across a restart"
    );
}

/// A repo dir with an explicit provenance toggle so the test never reads the
/// developer's global policy.
/// `KINTSUGI_CONFIG` is process-global and one test sets it; serialize the file so
/// no sibling test inherits a stray opt-out mid-run.
fn gate() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn repo_with_provenance(tmp: &std::path::Path, enabled: bool) -> std::path::PathBuf {
    std::fs::write(
        tmp.join(".kintsugi.toml"),
        format!("[provenance]\nenabled = {enabled}\n"),
    )
    .unwrap();
    tmp.to_path_buf()
}

#[test]
fn a_write_file_event_round_trips_and_replays_into_path_taint() {
    let _gate = gate();
    // V1.1 Task 3: a tainted session writes a file → the path inherits the taint
    // as a durable, append-only transition → a cold start replays it → a later
    // reader of that path is tainted. Reset remains the only removal.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    let repo = repo_with_provenance(tmp.path(), true);
    let notes = repo.join("src").join("notes.rs");

    {
        let daemon = Daemon::open(db.clone()).unwrap();
        daemon.apply_taint(&ingest("writer"));
        daemon.apply_write("writer", notes.to_str().unwrap(), &repo);
    } // dropped — the WriteFile row is on disk

    // The event round-trips out of the append-only stream, unchanged.
    let log = EventLog::open(&db).unwrap();
    let events = log.load_taint_events().unwrap();
    let written: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            TaintEvent::WriteFile { session, path } => Some((session.as_str(), path)),
            _ => None,
        })
        .collect();
    assert_eq!(
        written,
        vec![("writer", &notes)],
        "exactly one WriteFile transition, path intact: {events:?}"
    );

    // Replay: the path taint survives the restart and reaches a later reader.
    let daemon = Daemon::open(&db).unwrap();
    assert!(!daemon.is_session_tainted(Some("reader")));
    daemon.apply_taint(&TaintEvent::ReadFile {
        session: "reader".to_string(),
        path: notes.clone(),
    });
    assert!(
        daemon.is_session_tainted(Some("reader")),
        "a replayed WriteFile must propagate to a reader of the path"
    );

    // And Reset is still the only way taint leaves a session.
    daemon.apply_taint(&TaintEvent::Reset {
        session: "reader".to_string(),
    });
    assert!(!daemon.is_session_tainted(Some("reader")));
}

#[test]
fn write_observation_is_ignored_when_provenance_is_disabled() {
    let _gate = gate();
    // The write propagation is gated on the same `[provenance] enabled` switch as
    // the trifecta floor. With it off, nothing is persisted (the IPC is still
    // ACKed — observation never blocks). The switch has to come from the user-owned
    // GLOBAL config: a repo file may enable a guardrail but never disable one.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, "[provenance]\nenabled = false\n").unwrap();
    std::env::set_var("KINTSUGI_CONFIG", &config);
    // Deliberately NO repo policy here: a repo file saying `true` would tighten the
    // guardrail back on (by design), which would test the opposite case.
    let repo = tmp.path().to_path_buf();
    let notes = repo.join("notes.rs");

    let daemon = Daemon::open(db.clone()).unwrap();
    // Ingest is deliberately ungated (pre-existing rule).
    daemon.apply_taint(&ingest("writer"));
    daemon.apply_write("writer", notes.to_str().unwrap(), &repo);
    drop(daemon);

    let log = EventLog::open(&db).unwrap();
    let events = log.load_taint_events().unwrap();
    assert_eq!(
        events.len(),
        1,
        "only the ingest may persist when provenance is disabled: {events:?}"
    );
    std::env::remove_var("KINTSUGI_CONFIG");
}

#[test]
fn a_clean_session_write_appends_no_transition() {
    let _gate = gate();
    // Nothing can propagate from a clean session, so the write is skipped before
    // the persist boundary — benign edits do not bloat the append-only stream
    // with no-op rows.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    let repo = repo_with_provenance(tmp.path(), true);
    let notes = repo.join("notes.rs");

    let daemon = Daemon::open(db.clone()).unwrap();
    daemon.apply_write("clean", notes.to_str().unwrap(), &repo);
    // Defensive: an empty session or path is never a valid taint key.
    daemon.apply_write("", notes.to_str().unwrap(), &repo);
    daemon.apply_write("clean", "", &repo);
    drop(daemon);

    let log = EventLog::open(&db).unwrap();
    assert!(
        log.load_taint_events().unwrap().is_empty(),
        "a clean session's write is a no-op"
    );
}

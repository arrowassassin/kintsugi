//! P0.2 acceptance: write events, verify hash-chain links and tamper detection.

use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict, GENESIS_HASH};

fn sample(raw: &str) -> ProposedCommand {
    ProposedCommand::new(
        "shim",
        "/tmp/project",
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    )
}

fn allow() -> Verdict {
    Verdict::rules(Class::Safe, Decision::Allow, "test")
}

#[test]
fn writes_three_events_with_linked_chain() {
    let log = EventLog::open_in_memory().unwrap();

    let e1 = log.log_event(&sample("ls -la"), &allow(), None).unwrap();
    let e2 = log
        .log_event(&sample("cat README.md"), &allow(), None)
        .unwrap();
    let e3 = log
        .log_event(&sample("git status"), &allow(), None)
        .unwrap();

    assert_eq!(log.count().unwrap(), 3);

    // First event links to genesis; each subsequent links to the previous hash.
    assert_eq!(e1.prev_hash, GENESIS_HASH);
    assert_eq!(e2.prev_hash, e1.hash);
    assert_eq!(e3.prev_hash, e2.hash);

    // Hashes are distinct and non-empty.
    assert_ne!(e1.hash, e2.hash);
    assert_ne!(e2.hash, e3.hash);
    assert_eq!(e1.hash.len(), 64);

    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn tail_returns_recent_events_in_order() {
    let log = EventLog::open_in_memory().unwrap();
    for i in 0..5 {
        log.log_event(&sample(&format!("echo {i}")), &allow(), None)
            .unwrap();
    }
    let tail = log.tail(3).unwrap();
    assert_eq!(tail.len(), 3);
    assert_eq!(tail[0].command, "echo 2");
    assert_eq!(tail[1].command, "echo 3");
    assert_eq!(tail[2].command, "echo 4");
}

#[test]
fn raw_command_is_preserved_verbatim() {
    let log = EventLog::open_in_memory().unwrap();
    let raw = "git commit -m \"weird   spacing and  $pecial\"";
    let ev = log
        .log_event(
            &ProposedCommand::new("claude-code", "/tmp", vec![raw.to_string()], raw),
            &allow(),
            None,
        )
        .unwrap();
    assert_eq!(ev.command, raw);
    assert_eq!(log.tail(1).unwrap()[0].command, raw);
}

#[test]
fn tampering_with_a_field_breaks_the_chain() {
    let path = tempfile::NamedTempFile::new().unwrap();
    {
        let log = EventLog::open(path.path()).unwrap();
        log.log_event(&sample("ls"), &allow(), None).unwrap();
        log.log_event(&sample("rm important.txt"), &allow(), None)
            .unwrap();
        log.log_event(&sample("git status"), &allow(), None)
            .unwrap();
        assert!(log.verify_chain().unwrap().is_intact());
    }

    // Tamper directly in SQLite: rewrite a stored command without fixing the hash.
    {
        let conn = rusqlite::Connection::open(path.path()).unwrap();
        conn.execute(
            "UPDATE events SET command = 'ls' WHERE command = 'rm important.txt'",
            [],
        )
        .unwrap();
    }

    let log = EventLog::open(path.path()).unwrap();
    let status = log.verify_chain().unwrap();
    assert!(!status.is_intact(), "tamper must be detected: {status:?}");
    match status {
        kintsugi_core::ChainStatus::Broken { seq, .. } => assert_eq!(seq, 2),
        other => panic!("expected broken chain, got {other:?}"),
    }
}

#[test]
fn deleting_a_row_breaks_the_chain() {
    let path = tempfile::NamedTempFile::new().unwrap();
    {
        let log = EventLog::open(path.path()).unwrap();
        log.log_event(&sample("one"), &allow(), None).unwrap();
        log.log_event(&sample("two"), &allow(), None).unwrap();
        log.log_event(&sample("three"), &allow(), None).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(path.path()).unwrap();
        conn.execute("DELETE FROM events WHERE seq = 2", [])
            .unwrap();
    }
    let log = EventLog::open(path.path()).unwrap();
    assert!(!log.verify_chain().unwrap().is_intact());
}

#[test]
fn empty_log_chain_is_intact() {
    let log = EventLog::open_in_memory().unwrap();
    assert!(log.verify_chain().unwrap().is_intact());
    assert_eq!(log.count().unwrap(), 0);
    assert!(log.tail(10).unwrap().is_empty());
}

#[test]
fn secret_commands_are_redacted_before_hashing_and_chain_stays_intact() {
    let log = EventLog::open_in_memory().unwrap();
    let secret = "s3cr3tPa55";
    let raw = format!("mysql -p{secret} -u root");
    let e = log.log_event(&sample(&raw), &allow(), None).unwrap();

    // The secret value never enters the command or argv columns (so it never
    // entered the hash either — redaction happens before hashing).
    assert!(!e.command.contains(secret), "command leaked: {}", e.command);
    assert!(e.command.contains("[redacted]"));
    assert!(
        !e.argv.iter().any(|a| a.contains(secret)),
        "argv leaked: {:?}",
        e.argv
    );
    // The hash chain still verifies.
    assert!(log.verify_chain().unwrap().is_intact());

    // A command with no secret is stored byte-identically (no behavior change).
    let e2 = log
        .log_event(&sample("git status"), &allow(), None)
        .unwrap();
    assert_eq!(e2.command, "git status");
    assert_eq!(e2.argv, vec!["git".to_string(), "status".to_string()]);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn taint_events_persist_in_order_across_a_reopen() {
    // Phase 6 item D: the durable taint stream round-trips and replays in order,
    // so a daemon restart reconstructs the exact TaintState (no fail-open).
    use kintsugi_core::{SourceKind, TaintEvent, TaintLabel, TaintState};
    use std::path::PathBuf;
    use time::OffsetDateTime;

    let ingest = |session: &str, id: &str| TaintEvent::Ingest {
        label: TaintLabel {
            source_kind: SourceKind::Web,
            source_id: id.to_string(),
            ts: OffsetDateTime::UNIX_EPOCH,
            agent: "claude-code".to_string(),
            session: session.to_string(),
        },
    };

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");

    // Record an ordered stream, then drop the connection (a daemon stop).
    {
        let log = EventLog::open(&db).unwrap();
        log.record_taint_event(&ingest("s1", "https://evil.test"))
            .unwrap();
        log.record_taint_event(&TaintEvent::WriteFile {
            session: "s1".to_string(),
            path: PathBuf::from("/repo/out.txt"),
        })
        .unwrap();
        log.record_taint_event(&ingest("s2", "https://other.test"))
            .unwrap();
    }

    // Reopen (cold start): the stream survives, in order.
    let log = EventLog::open(&db).unwrap();
    let events = log.load_taint_events().unwrap();
    assert_eq!(events.len(), 3, "all taint events survive the reopen");
    assert_eq!(
        events[0],
        ingest("s1", "https://evil.test"),
        "order preserved"
    );

    // Replay reconstructs the same state a live daemon would have held.
    let state = TaintState::from_events(events.iter());
    assert!(
        state.is_session_tainted(Some("s1")),
        "session taint survives a restart"
    );
    assert!(state.is_session_tainted(Some("s2")));
    assert!(!state.is_session_tainted(Some("s3")));
    assert!(
        state.is_path_tainted(std::path::Path::new("/repo/out.txt")),
        "WriteFile propagation replays too"
    );
}

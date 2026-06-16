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

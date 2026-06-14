//! P0.3 acceptance: a client sends a command, gets Allow, the event is logged.
//!
//! Unix-only because the test pins a filesystem socket path; the Windows pipe
//! path is exercised by the same code with a namespaced name.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use aegis_core::{Decision, EventLog, ProposedCommand};
use aegis_daemon::{Client, Daemon, Server};

/// Tests mutate process-global env vars (`AEGIS_SOCKET`/`AEGIS_DB`), so they must
/// not run concurrently.
fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Give each test an isolated socket + db, and serve a fixed number of requests
/// on a background thread.
struct Harness {
    _guard: MutexGuard<'static, ()>,
    _tmp: tempfile::TempDir,
    db: std::path::PathBuf,
    server: Option<thread::JoinHandle<()>>,
}

fn start(requests: usize) -> Harness {
    let guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("aegis.sock");
    let db = tmp.path().join("events.db");
    std::env::set_var("AEGIS_SOCKET", &sock);
    std::env::set_var("AEGIS_DB", &db);

    let db_for_thread = db.clone();
    // Bind in this thread so the listener exists (and queues connections) before
    // any client connects; serve on a background thread.
    let server = Server::bind().unwrap();
    let handle = thread::spawn(move || {
        let daemon = Daemon::open(&db_for_thread).unwrap();
        server.serve_n(requests, |cmd| daemon.handle(cmd)).unwrap();
    });

    Harness {
        _guard: guard,
        _tmp: tmp,
        db,
        server: Some(handle),
    }
}

impl Harness {
    fn join(&mut self) {
        if let Some(h) = self.server.take() {
            h.join().unwrap();
        }
    }
}

#[test]
fn client_gets_allow_and_event_is_logged() {
    let mut h = start(1);

    let cmd = ProposedCommand::new(
        "claude-code",
        "/tmp/project",
        vec!["rm".into(), "tmpfile".into()],
        "rm tmpfile",
    );
    let verdict = Client::send(&cmd).unwrap();

    // Phase 0 recorder: everything is allowed by Tier-1 rules.
    assert_eq!(verdict.decision, Decision::Allow);
    assert_eq!(verdict.tier, 1);

    h.join();

    // The event made it into the append-only log, verbatim.
    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].command, "rm tmpfile");
    assert_eq!(tail[0].agent, "claude-code");
    assert_eq!(tail[0].decision, Decision::Allow);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn multiple_commands_chain_in_log() {
    let mut h = start(3);

    for c in ["ls", "git status", "cargo build"] {
        let cmd = ProposedCommand::new(
            "shim",
            "/tmp/p",
            c.split_whitespace().map(str::to_string).collect(),
            c,
        );
        assert_eq!(Client::send(&cmd).unwrap().decision, Decision::Allow);
    }

    h.join();

    let log = EventLog::open(&h.db).unwrap();
    assert_eq!(log.count().unwrap(), 3);
    assert!(log.verify_chain().unwrap().is_intact());
}

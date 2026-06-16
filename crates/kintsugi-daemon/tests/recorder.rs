//! P-A3 acceptance: passive session recording (no AI-agent hook).
//!
//! A `Record` request logs a command a human already ran, classified (so a
//! destructive command is flagged) but always Allow-decisioned — it has already
//! executed, so the recorder never holds, denies, or snapshots. The hash chain
//! stays intact across recorded + proposed events.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use kintsugi_core::{Class, Decision, EventLog, ProposedCommand};
use kintsugi_daemon::{Client, Daemon, Server};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Harness {
    _guard: MutexGuard<'static, ()>,
    _tmp: tempfile::TempDir,
    db: std::path::PathBuf,
    server: Option<thread::JoinHandle<()>>,
}

fn start(requests: usize) -> Harness {
    let guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("kintsugi.sock");
    let db = tmp.path().join("events.db");
    std::env::set_var("KINTSUGI_SOCKET", &sock);
    std::env::set_var("KINTSUGI_DB", &db);

    let db_for_thread = db.clone();
    let server = Server::bind().unwrap();
    let handle = thread::spawn(move || {
        let daemon = Daemon::open(&db_for_thread).unwrap();
        server
            .serve_n(requests, |req| daemon.handle_request(req))
            .unwrap();
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
fn recorded_safe_command_is_logged_as_allow() {
    let mut h = start(1);

    let cmd = ProposedCommand::new(
        "shell",
        "/tmp/db",
        vec!["ls".into(), "-la".into()],
        "ls -la",
    );
    Client::record(&cmd).unwrap();
    h.join();

    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].agent, "shell");
    assert_eq!(tail[0].decision, Decision::Allow);
    assert_eq!(tail[0].class, Class::Safe);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn recorded_destructive_command_is_allowed_but_flagged_catastrophic() {
    // The DBA already ran a destructive command. The recorder must NOT pretend it
    // was held/denied (it ran) — but it MUST flag the class so `kintsugi report`
    // surfaces it for the audit. Allow + Catastrophic is the honest record.
    let mut h = start(1);

    let cmd = ProposedCommand::new(
        "shell",
        "/srv",
        vec!["rm".into(), "-rf".into(), "/srv/data".into()],
        "rm -rf /srv/data",
    );
    Client::record(&cmd).unwrap();
    h.join();

    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(1).unwrap();
    assert_eq!(tail[0].decision, Decision::Allow, "it already ran");
    assert_eq!(tail[0].class, Class::Catastrophic, "but flagged for audit");
    assert!(tail[0].reason.starts_with("recorded:"));
}

#[test]
fn recorded_secret_command_is_redacted_in_the_log() {
    // Passive recording must not leak a DB password into the audit log.
    let mut h = start(1);

    let cmd = ProposedCommand::new(
        "shell",
        "/srv",
        vec!["mysql".into(), "-ps3cr3tPa55".into()],
        "mysql -ps3cr3tPa55 -u root",
    );
    Client::record(&cmd).unwrap();
    h.join();

    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(1).unwrap();
    assert!(
        !tail[0].command.contains("s3cr3tPa55"),
        "secret must be redacted, got: {}",
        tail[0].command
    );
    assert!(tail[0].command.contains("[redacted]"));
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn recorded_and_proposed_events_share_one_intact_chain() {
    let mut h = start(2);

    // A proposed (agent) command and a recorded (human) command interleave; the
    // single-writer daemon keeps them on one tamper-evident chain.
    let proposed = ProposedCommand::new("claude-code", "/tmp/p", vec!["ls".into()], "ls");
    assert_eq!(Client::send(&proposed).unwrap().decision, Decision::Allow);
    let recorded = ProposedCommand::new("shell", "/tmp/p", vec!["whoami".into()], "whoami");
    Client::record(&recorded).unwrap();
    h.join();

    let log = EventLog::open(&h.db).unwrap();
    assert_eq!(log.count().unwrap(), 2);
    assert!(log.verify_chain().unwrap().is_intact());
}

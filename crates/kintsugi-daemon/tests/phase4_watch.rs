//! Phase 4 acceptance (backstop): an observed filesystem change is recorded as an
//! `fs-watch` event through the daemon's single writer, keeping the chain intact.

use kintsugi_core::Decision;
use kintsugi_daemon::{ipc, Daemon, Observation};

// The over-the-socket test is Unix-only (pins a filesystem socket); these imports
// are only used there.
#[cfg(unix)]
use kintsugi_daemon::{Client, Server};
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard, OnceLock};
#[cfg(unix)]
use std::thread;

#[cfg(unix)]
fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn observe_records_fs_event() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    daemon
        .observe(&Observation {
            kind: "modified".into(),
            path: "/work/src/main.rs".into(),
        })
        .unwrap();

    let last = daemon.log().tail(1).unwrap().pop().unwrap();
    assert_eq!(last.agent, "fs-watch");
    assert_eq!(last.command, "modified /work/src/main.rs");
    assert_eq!(last.decision, Decision::Allow);
    assert_eq!(last.reason, "fs:modified");
    assert!(daemon.log().verify_chain().unwrap().is_intact());
}

#[test]
fn observe_via_request_dispatch() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    let resp = daemon.handle_request(ipc::Request::Observe(Observation {
        kind: "created".into(),
        path: "/work/new.txt".into(),
    }));
    assert!(matches!(resp, ipc::Response::Ack));
    assert_eq!(daemon.log().tail(1).unwrap()[0].reason, "fs:created");
}

// Exercises the real serialization path (where a tag/field collision would
// surface), not just an in-process dispatch. Unix-only (pins a filesystem socket).
#[cfg(unix)]
#[test]
fn observe_over_the_socket_is_recorded() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_SOCKET", tmp.path().join("a.sock"));
    std::env::set_var("KINTSUGI_DB", tmp.path().join("e.db"));
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let db = tmp.path().join("e.db");

    let server = Server::bind().unwrap();
    let handle = thread::spawn(move || {
        let daemon = Daemon::open(&db).unwrap();
        server.serve_n(1, |req| daemon.handle_request(req)).unwrap();
    });

    Client::observe(&Observation {
        kind: "removed".into(),
        path: "/work/gone.txt".into(),
    })
    .unwrap();

    handle.join().unwrap();
    let log = kintsugi_core::EventLog::open(tmp.path().join("e.db")).unwrap();
    assert_eq!(log.tail(1).unwrap()[0].reason, "fs:removed");
}

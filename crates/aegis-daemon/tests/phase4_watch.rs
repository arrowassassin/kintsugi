//! Phase 4 acceptance (backstop): an observed filesystem change is recorded as an
//! `fs-watch` event through the daemon's single writer, keeping the chain intact.

use aegis_core::Decision;
use aegis_daemon::{ipc, Daemon, Observation};

#[test]
fn observe_records_fs_event() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
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
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    let resp = daemon.handle_request(ipc::Request::Observe(Observation {
        kind: "created".into(),
        path: "/work/new.txt".into(),
    }));
    assert!(matches!(resp, ipc::Response::Ack));
    assert_eq!(daemon.log().tail(1).unwrap()[0].reason, "fs:created");
}

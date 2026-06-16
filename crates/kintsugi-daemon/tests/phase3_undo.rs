//! Phase 3 acceptance: an allowed destructive command is snapshotted, and the
//! snapshot restores the file after it is changed/deleted.

use std::sync::{Mutex, MutexGuard, OnceLock};

use kintsugi_core::{Mode, ProposedCommand};
use kintsugi_daemon::Daemon;

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn allowed_destructive_command_is_snapshotted_and_restorable() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));

    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let file = work.join("important.txt");
    std::fs::write(&file, b"the only copy").unwrap();

    // Notify mode allows everything (and records) — so the destructive command is
    // allowed and therefore snapshotted before it would run.
    let daemon = Daemon::open(tmp.path().join("e.db"))
        .unwrap()
        .with_mode(Mode::Notify);

    let cmd = ProposedCommand::new(
        "shim",
        &work,
        vec!["rm".into(), "-rf".into(), "important.txt".into()],
        "rm -rf important.txt",
    );
    let verdict = daemon.handle(cmd);
    assert_eq!(verdict.decision, kintsugi_core::Decision::Allow);

    // A snapshot was recorded.
    let snap = daemon
        .log()
        .latest_unreverted_snapshot()
        .unwrap()
        .expect("a snapshot should have been captured");
    assert_eq!(snap.command, "rm -rf important.txt");

    // Simulate the command actually deleting the file, then undo.
    std::fs::remove_file(&file).unwrap();
    assert!(!file.exists());
    kintsugi_core::restore_snapshot(daemon.snapshot_dir(), &snap).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"the only copy");

    daemon.log().mark_reverted(&snap.id).unwrap();
    assert!(daemon.log().latest_unreverted_snapshot().unwrap().is_none());
}

#[test]
fn safe_command_is_not_snapshotted() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    daemon.handle(ProposedCommand::new(
        "shim",
        tmp.path(),
        vec!["ls".into()],
        "ls -la",
    ));
    assert!(daemon.log().latest_unreverted_snapshot().unwrap().is_none());
}

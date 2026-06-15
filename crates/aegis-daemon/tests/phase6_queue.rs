//! Approval-queue acceptance: a held command is enqueued, listable, and an
//! approve/deny resolves it (recording the human decision and leaving the queue).

use std::sync::{Mutex, MutexGuard, OnceLock};

use aegis_core::{Decision, ProposedCommand};
use aegis_daemon::Daemon;

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn propose(cwd: &std::path::Path, raw: &str) -> ProposedCommand {
    ProposedCommand::new(
        "mcp",
        cwd,
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    )
}

#[test]
fn hold_enqueues_and_approve_resolves() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    let cmd = propose(tmp.path(), "rm important.txt");
    let id = cmd.id.to_string();

    // Held → enqueued.
    assert_eq!(daemon.handle(cmd).decision, Decision::Hold);
    assert_eq!(
        daemon.log().pending_status(&id).unwrap().as_deref(),
        Some("pending")
    );
    let pending = daemon.log().list_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].command.raw, "rm important.txt");

    // Approve → recorded as human:allow, status approved, queue empties.
    assert!(daemon.resolve_pending(&id, Decision::Allow).unwrap());
    assert_eq!(
        daemon.log().pending_status(&id).unwrap().as_deref(),
        Some("approved")
    );
    assert!(daemon.log().list_pending().unwrap().is_empty());
    assert!(daemon
        .log()
        .tail(5)
        .unwrap()
        .iter()
        .any(|e| e.reason == "human:allow"));

    // A second approve of the same id is a no-op (returns false) and does NOT
    // log a second human:allow — the CAS guard prevents a double-run.
    assert!(!daemon.resolve_pending(&id, Decision::Allow).unwrap());
    let allows = daemon
        .log()
        .tail(20)
        .unwrap()
        .iter()
        .filter(|e| e.reason == "human:allow")
        .count();
    assert_eq!(allows, 1, "approve must be exactly-once");
}

#[test]
fn deny_resolves_to_denied() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    let cmd = propose(tmp.path(), "make deploy");
    let id = cmd.id.to_string();
    daemon.handle(cmd);
    assert!(daemon.resolve_pending(&id, Decision::Deny).unwrap());
    assert_eq!(
        daemon.log().pending_status(&id).unwrap().as_deref(),
        Some("denied")
    );
    assert!(daemon
        .log()
        .tail(5)
        .unwrap()
        .iter()
        .any(|e| e.reason == "human:deny"));
}

#[test]
fn resolving_unknown_id_is_false() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    assert!(!daemon.resolve_pending("nope", Decision::Allow).unwrap());
}

#[test]
fn safe_command_is_not_enqueued() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    daemon.handle(propose(tmp.path(), "ls -la"));
    assert!(daemon.log().list_pending().unwrap().is_empty());
}

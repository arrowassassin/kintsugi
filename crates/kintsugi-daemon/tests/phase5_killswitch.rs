//! Phase 5 acceptance: with the kill-switch engaged, even a Safe command is
//! denied; clearing it restores normal decisions.

use std::sync::{Mutex, MutexGuard, OnceLock};

use kintsugi_core::{Decision, ProposedCommand};
use kintsugi_daemon::{Daemon, Resolution, KILL_SWITCH_FILE};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn kill_switch_denies_everything_then_clears() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    let safe = ProposedCommand::new("shim", tmp.path(), vec!["ls".into()], "ls -la");

    // Normally safe → allowed.
    assert_eq!(daemon.decide(&safe).decision, Decision::Allow);
    assert!(!daemon.kill_switch_engaged());

    // Engage the kill-switch: even Safe is now denied.
    std::fs::write(tmp.path().join(KILL_SWITCH_FILE), b"engaged").unwrap();
    assert!(daemon.kill_switch_engaged());
    let v = daemon.decide(&safe);
    assert_eq!(v.decision, Decision::Deny);
    assert!(v.reason.contains("kill-switch"));

    // Catastrophic is still denied (and never allowed) under the kill-switch.
    let cat = ProposedCommand::new("shim", tmp.path(), vec!["rm".into()], "rm -rf /");
    assert_eq!(daemon.decide(&cat).decision, Decision::Deny);

    // Clear it: normal decisions resume.
    std::fs::remove_file(tmp.path().join(KILL_SWITCH_FILE)).unwrap();
    assert!(!daemon.kill_switch_engaged());
    assert_eq!(daemon.decide(&safe).decision, Decision::Allow);
}

#[test]
fn kill_switch_blocks_direct_resolve_allow() {
    // Regression: resolve() (the shim hold card / raw Request::Resolve path) must
    // honor the kill-switch for Allow, just like resolve_pending().
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    let cmd = ProposedCommand::new("shim", tmp.path(), vec!["rm".into()], "rm -rf build");

    std::fs::write(tmp.path().join(KILL_SWITCH_FILE), b"engaged").unwrap();
    let allow = Resolution {
        command: cmd.clone(),
        decision: Decision::Allow,
        remember: false,
    };
    assert!(
        daemon.resolve(&allow).is_err(),
        "resolve(Allow) must be refused while the kill-switch is engaged"
    );
    // Deny still resolves (it doesn't run anything).
    let deny = Resolution {
        command: cmd,
        decision: Decision::Deny,
        remember: false,
    };
    assert!(daemon.resolve(&deny).is_ok());
}

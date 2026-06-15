//! Coverage for resolution recording, decision memory, repo keying, and policy
//! loading/merging — all via direct `Daemon` calls (no socket needed).

use std::sync::{Mutex, MutexGuard, OnceLock};

use aegis_core::{Class, Decision, ProposedCommand};
use aegis_daemon::{ipc, repo_key, Daemon, Resolution};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn propose(cwd: &std::path::Path, raw: &str) -> ProposedCommand {
    ProposedCommand::new(
        "shim",
        cwd,
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    )
}

#[test]
fn resolve_allow_remember_then_memory_auto_allows() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();

    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    let cmd = propose(&repo, "rm data.bin");

    // Initially ambiguous → held.
    assert_eq!(daemon.decide(&cmd).decision, Decision::Hold);

    // Human resolves: allow + remember.
    daemon
        .resolve(&Resolution {
            command: cmd.clone(),
            decision: Decision::Allow,
            remember: true,
        })
        .unwrap();

    // Now memory auto-allows the exact command.
    let v = daemon.decide(&cmd);
    assert_eq!(v.decision, Decision::Allow);
    assert!(v.reason.contains("memory:allow"));

    // The resolution was logged as human:always-allow.
    let events = daemon.log().tail(10).unwrap();
    assert!(events.iter().any(|e| e.reason == "human:always-allow"));
}

#[test]
fn memory_never_downgrades_catastrophic() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    let cmd = propose(&repo, "rm -rf /var/data");

    // A human resolves a catastrophic command with remember=true...
    daemon
        .resolve(&Resolution {
            command: cmd.clone(),
            decision: Decision::Allow,
            remember: true,
        })
        .unwrap();

    // ...it is NOT persisted to memory (catastrophic never becomes always-allow)...
    let key = aegis_daemon::repo_key(&repo);
    let hash = aegis_core::command_hash("rm -rf /var/data");
    assert!(daemon.log().memory_lookup(&key, &hash).unwrap().is_none());

    // ...and even a directly-stored memory allow does not downgrade it on decide.
    daemon.log().remember(&key, &hash, Decision::Allow).unwrap();
    let v = daemon.decide(&cmd);
    assert_eq!(v.class, Class::Catastrophic);
    assert_eq!(v.decision, Decision::Hold, "catastrophic hard floor stands");
}

#[test]
fn resolve_deny_is_recorded() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    let cmd = propose(tmp.path(), "rm -rf /");

    daemon
        .resolve(&Resolution {
            command: cmd.clone(),
            decision: Decision::Deny,
            remember: false,
        })
        .unwrap();

    let last = daemon.log().tail(1).unwrap().pop().unwrap();
    assert_eq!(last.decision, Decision::Deny);
    assert_eq!(last.reason, "human:deny");
    assert_eq!(last.class, Class::Catastrophic);
}

#[test]
fn handle_request_dispatches_propose_and_resolve() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    let cmd = propose(tmp.path(), "ls");

    match daemon.handle_request(ipc::Request::Propose(cmd.clone())) {
        ipc::Response::Verdict(v) => assert_eq!(v.decision, Decision::Allow),
        other => panic!("expected verdict, got {other:?}"),
    }
    match daemon.handle_request(ipc::Request::Resolve(Resolution {
        command: cmd,
        decision: Decision::Allow,
        remember: false,
    })) {
        ipc::Response::Ack => {}
        other => panic!("expected ack, got {other:?}"),
    }
}

#[test]
fn repo_key_prefers_git_root_then_falls_back_to_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("proj");
    let nested = repo.join("a/b");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(&nested).unwrap();
    assert_eq!(repo_key(&nested), repo.to_string_lossy());

    let plain = tmp.path().join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    assert_eq!(repo_key(&plain), plain.to_string_lossy());
}

#[test]
fn global_and_repo_policy_merge() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    let global = tmp.path().join("global.toml");
    std::fs::write(&global, "[rules]\ndeny = [\"ls\"]\n").unwrap();
    std::env::set_var("AEGIS_CONFIG", &global);

    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(".aegis.toml"), "[rules]\nallow = [\"make\"]\n").unwrap();

    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    // Global deny applies even though there's no repo deny.
    assert_eq!(
        daemon.decide(&propose(&repo, "ls")).decision,
        Decision::Hold
    );
    // Repo allow tames an ambiguous command.
    assert_eq!(
        daemon.decide(&propose(&repo, "make")).decision,
        Decision::Allow
    );

    std::env::remove_var("AEGIS_CONFIG");
}

#[test]
fn invalid_policy_is_ignored() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(".aegis.toml"), "this is = not valid toml ][").unwrap();

    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    // Falls back to defaults: ls is still safe.
    assert_eq!(
        daemon.decide(&propose(&repo, "ls")).decision,
        Decision::Allow
    );
}

#[test]
fn with_mode_unattended_denies_catastrophic() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("none.toml"));
    let daemon = Daemon::open(tmp.path().join("e.db"))
        .unwrap()
        .with_mode(aegis_core::Mode::Unattended);
    assert_eq!(daemon.mode(), aegis_core::Mode::Unattended);
    assert_eq!(
        daemon.decide(&propose(tmp.path(), "rm -rf /")).decision,
        Decision::Deny
    );
}

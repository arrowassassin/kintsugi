//! P1.5 acceptance: a deny rule in `.kintsugi.toml` causes that command to Hold,
//! and an allow rule tames an otherwise-held ambiguous command.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};

use kintsugi_core::{Class, Decision, ProposedCommand};
use kintsugi_daemon::Daemon;

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
fn deny_rule_in_repo_policy_holds_a_safe_command() {
    let _guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("no-global.toml"));

    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join(".kintsugi.toml"),
        r#"
        [rules]
        deny = ["git status"]
        "#,
    )
    .unwrap();

    let daemon = Daemon::open(tmp.path().join("events.db")).unwrap();

    // `git status` is normally Safe → Allow, but the repo policy denies it.
    let verdict = daemon.decide(&propose(&repo, "git status"));
    assert_eq!(verdict.decision, Decision::Hold);
    assert!(verdict.reason.contains("policy:deny"));

    // A command not covered by policy is unaffected.
    let other = daemon.decide(&propose(&repo, "ls -la"));
    assert_eq!(other.decision, Decision::Allow);
}

#[test]
fn allow_rule_tames_ambiguous_but_not_catastrophic() {
    let _guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("no-global.toml"));

    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join(".kintsugi.toml"),
        r#"
        [rules]
        allow = ["make", "rm -rf"]
        "#,
    )
    .unwrap();

    let daemon = Daemon::open(tmp.path().join("events.db")).unwrap();

    // `make` is ambiguous → normally Hold; the allow rule lets it through.
    let made = daemon.decide(&propose(&repo, "make build"));
    assert_eq!(made.decision, Decision::Allow);
    assert!(made.reason.contains("policy:allow"));

    // `rm -rf /` is catastrophic → the allow rule must NOT downgrade it.
    let dangerous = daemon.decide(&propose(&repo, "rm -rf /"));
    assert_eq!(dangerous.decision, Decision::Hold);
    assert_eq!(dangerous.class, Class::Catastrophic);
}

#[test]
fn repo_policy_can_set_mode() {
    let _guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("no-global.toml"));

    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    // Notify mode: record but never block, even catastrophic.
    std::fs::write(repo.join(".kintsugi.toml"), "mode = \"notify\"\n").unwrap();

    let daemon = Daemon::open(tmp.path().join("events.db")).unwrap();
    let verdict = daemon.decide(&propose(&repo, "rm -rf /"));
    assert_eq!(verdict.decision, Decision::Allow, "notify never blocks");
    assert_eq!(
        verdict.class,
        Class::Catastrophic,
        "but class is still recorded"
    );
}

//! `kintsugi log` filters, `redact`, `purge`, and `stop` over the real CLI binary.
#![cfg(unix)]

use std::process::Command;

use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict};

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
}

/// Seed a known event set; returns the event ids in insertion order.
fn seed(db: &std::path::Path) -> Vec<String> {
    let log = EventLog::open(db).unwrap();
    let rows: [(&str, Option<&str>, &str, Class, Decision); 4] = [
        (
            "claude-code",
            Some("s1"),
            "ls",
            Class::Safe,
            Decision::Allow,
        ),
        (
            "claude-code",
            Some("s1"),
            "rm -rf build",
            Class::Catastrophic,
            Decision::Deny,
        ),
        (
            "cursor",
            Some("s2"),
            "npm test",
            Class::Safe,
            Decision::Allow,
        ),
        (
            "shim",
            None,
            "git push --force",
            Class::Catastrophic,
            Decision::Deny,
        ),
    ];
    let mut ids = Vec::new();
    for (agent, sess, raw, class, dec) in rows {
        let cmd = ProposedCommand::new(agent, "/tmp", vec![raw.to_string()], raw)
            .with_session(sess.map(str::to_string));
        let ev = log
            .log_event(&cmd, &Verdict::rules(class, dec, "t"), None)
            .unwrap();
        ids.push(ev.id.to_string());
    }
    ids
}

fn stdout_of(mut c: Command, db: &std::path::Path) -> (bool, String) {
    let out = c
        .env("KINTSUGI_DB", db)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn log_filters_by_agent_grep_and_class() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    seed(&db);

    let (ok, by_agent) = stdout_of(
        {
            let mut c = kintsugi();
            c.args(["log", "--agent", "claude-code"]);
            c
        },
        &db,
    );
    assert!(ok);
    assert!(by_agent.contains("ls") && by_agent.contains("rm -rf build"));
    assert!(!by_agent.contains("npm test"));

    let (_, by_grep) = stdout_of(
        {
            let mut c = kintsugi();
            c.args(["log", "--grep", "push"]);
            c
        },
        &db,
    );
    assert!(by_grep.contains("git push --force") && !by_grep.contains("npm test"));

    let (_, by_class) = stdout_of(
        {
            let mut c = kintsugi();
            c.args(["log", "--class", "catastrophic"]);
            c
        },
        &db,
    );
    assert!(by_class.contains("rm -rf build") && !by_class.contains("ls"));
}

#[test]
fn redact_by_id_hides_then_show_redacted_reveals() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    let ids = seed(&db);

    let r = kintsugi()
        .args(["redact", &ids[3]])
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));

    let (_, hidden) = stdout_of(
        {
            let mut c = kintsugi();
            c.arg("log");
            c
        },
        &db,
    );
    assert!(
        !hidden.contains("git push --force"),
        "redacted row must be hidden"
    );

    let (_, shown) = stdout_of(
        {
            let mut c = kintsugi();
            c.args(["log", "--show-redacted"]);
            c
        },
        &db,
    );
    assert!(
        shown.contains("redacted"),
        "placeholder visible with --show-redacted"
    );
}

#[test]
fn redact_refuses_without_id_or_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    seed(&db);
    let out = kintsugi()
        .arg("redact")
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(!out.status.success(), "must refuse to redact everything");
}

#[test]
fn bulk_redact_by_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    seed(&db);
    let out = kintsugi()
        .args(["redact", "--agent", "claude-code"])
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(out.status.success());
    let (_, t) = stdout_of(
        {
            let mut c = kintsugi();
            c.arg("log");
            c
        },
        &db,
    );
    assert!(!t.contains("rm -rf build") && t.contains("npm test"));
}

#[test]
fn purge_requires_filter_and_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    seed(&db);

    // No filter → refuse even with --yes.
    let a = kintsugi()
        .args(["purge", "--yes"])
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(!a.status.success());

    // Filter but no --yes → refuse (needs confirmation).
    let b = kintsugi()
        .args(["purge", "--agent", "claude-code"])
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(!b.status.success());

    // Filter + --yes → purges and rebuilds the chain.
    let c = kintsugi()
        .args(["purge", "--agent", "claude-code", "--yes"])
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(c.status.success(), "{}", String::from_utf8_lossy(&c.stderr));

    let (_, t) = stdout_of(
        {
            let mut x = kintsugi();
            x.arg("log");
            x
        },
        &db,
    );
    assert!(!t.contains("rm -rf build"));
    // The surviving chain still verifies.
    assert!(EventLog::open(&db)
        .unwrap()
        .verify_chain()
        .unwrap()
        .is_intact());
}

#[test]
fn stop_when_not_running_reports_it() {
    let tmp = tempfile::tempdir().unwrap();
    let out = kintsugi()
        .arg("stop")
        .env("KINTSUGI_DB", tmp.path().join("e.db"))
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("not running"));
}

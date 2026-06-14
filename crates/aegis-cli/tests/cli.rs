//! P0.7 acceptance: `aegis log` shows recorded events, `aegis status` reports the
//! log, and `aegis init` wires interception. Unix-only for the symlink checks.
#![cfg(unix)]

use std::process::Command;

use aegis_core::{Class, Decision, EventLog, ProposedCommand, Verdict};

fn aegis() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
}

fn seed_log(db: &std::path::Path) {
    let log = EventLog::open(db).unwrap();
    let a = ProposedCommand::new("claude-code", "/tmp", vec!["ls".into()], "ls");
    log.log_event(&a, &Verdict::rules(Class::Safe, Decision::Allow, "t"), None)
        .unwrap();
    let b = ProposedCommand::new(
        "shim",
        "/tmp",
        vec!["rm".into(), "-rf".into()],
        "rm -rf data",
    );
    log.log_event(
        &b,
        &Verdict::rules(Class::Catastrophic, Decision::Hold, "t"),
        None,
    )
    .unwrap();
}

#[test]
fn log_shows_recorded_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    seed_log(&db);

    let out = aegis()
        .arg("log")
        .env("AEGIS_DB", &db)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();

    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("ls"), "should list the ls event:\n{text}");
    assert!(text.contains("rm -rf data"));
    assert!(text.contains("allowed"));
    assert!(text.contains("held"));
    assert!(text.contains("[catastrophic]"));
}

#[test]
fn log_empty_shows_designed_empty_state() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aegis()
        .arg("log")
        .env("AEGIS_DB", tmp.path().join("missing.db"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("No events yet"));
}

#[test]
fn status_reports_event_count_and_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    seed_log(&db);

    let out = aegis()
        .arg("status")
        .env("AEGIS_DB", &db)
        // Point the socket somewhere unconnectable so daemon shows "stopped".
        .env("AEGIS_SOCKET", tmp.path().join("none.sock"))
        .output()
        .unwrap();

    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("events:  2"), "status:\n{text}");
    assert!(text.contains("intact"));
    assert!(text.contains("stopped"));
}

#[test]
fn init_no_daemon_creates_shims_and_wires_claude() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = home.join(".local/share");
    std::fs::create_dir_all(home.join(".claude")).unwrap();

    let out = aegis()
        .arg("init")
        .arg("--no-daemon")
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &data)
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Shims created under the data dir.
    let shim_rm = data.join("aegis/shims/rm");
    assert!(
        shim_rm.is_symlink() || shim_rm.exists(),
        "rm shim should exist"
    );

    // Claude settings wired with our hook.
    let settings = home.join(".claude/settings.json");
    let body = std::fs::read_to_string(&settings).unwrap();
    assert!(
        body.contains("aegis-hook"),
        "settings should reference aegis-hook:\n{body}"
    );
    assert!(body.contains("PreToolUse"));

    // Idempotent: running again does not duplicate the hook.
    aegis()
        .arg("init")
        .arg("--no-daemon")
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &data)
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    let body2 = std::fs::read_to_string(&settings).unwrap();
    assert_eq!(
        body2.matches("aegis-hook").count(),
        1,
        "hook must not duplicate"
    );
}

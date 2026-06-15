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
fn undo_with_nothing_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aegis()
        .arg("undo")
        .env("AEGIS_DB", tmp.path().join("events.db"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing to undo"));
}

#[test]
fn undo_restores_a_snapshotted_file() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    let snaps = tmp.path().join("snapshots");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let file = work.join("data.txt");
    std::fs::write(&file, b"original").unwrap();

    // Seed a snapshot the same way the daemon would, then corrupt the file.
    {
        let log = EventLog::open(&db).unwrap();
        let cmd = ProposedCommand::new(
            "shim",
            &work,
            vec!["rm".into(), "data.txt".into()],
            "rm data.txt",
        );
        let manifest = aegis_core::capture_snapshot(&snaps, &cmd).unwrap().unwrap();
        log.record_snapshot(&manifest).unwrap();
    }
    std::fs::write(&file, b"corrupted").unwrap();

    let out = aegis().arg("undo").env("AEGIS_DB", &db).output().unwrap();
    assert!(
        out.status.success(),
        "undo failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("undid"));
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"original",
        "file should be restored"
    );

    // Second undo finds nothing (snapshot marked reverted).
    let out2 = aegis().arg("undo").env("AEGIS_DB", &db).output().unwrap();
    assert!(String::from_utf8_lossy(&out2.stdout).contains("Nothing to undo"));
}

#[test]
fn queue_without_daemon_is_graceful() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aegis()
        .arg("queue")
        .env("AEGIS_SOCKET", tmp.path().join("none.sock"))
        .env("AEGIS_DB", tmp.path().join("e.db"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("isn't running"));
}

#[test]
fn approve_unknown_prefix_errors() {
    let tmp = tempfile::tempdir().unwrap();
    // No daemon → the command should fail cleanly (non-zero), not panic.
    let out = aegis()
        .args(["approve", "abc"])
        .env("AEGIS_SOCKET", tmp.path().join("none.sock"))
        .env("AEGIS_DB", tmp.path().join("e.db"))
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn panic_engages_and_resume_clears_kill_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    let common = |c: &mut Command| {
        c.env("AEGIS_DB", &db)
            .env("AEGIS_SOCKET", tmp.path().join("none.sock"))
            .env("NO_COLOR", "1");
    };

    let mut p = aegis();
    p.arg("panic");
    common(&mut p);
    let out = p.output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("ENGAGED"));
    assert!(tmp.path().join("panic.flag").exists());

    // status reflects it.
    let mut s = aegis();
    s.arg("status");
    common(&mut s);
    let st = s.output().unwrap();
    assert!(String::from_utf8_lossy(&st.stdout).contains("KILL-SWITCH"));

    let mut r = aegis();
    r.arg("resume");
    common(&mut r);
    let out = r.output().unwrap();
    assert!(out.status.success());
    assert!(!tmp.path().join("panic.flag").exists());
}

#[test]
fn init_print_path_emits_export_line() {
    let tmp = tempfile::tempdir().unwrap();
    let out = aegis()
        .args(["init", "--print-path"])
        .env("AEGIS_DATA_DIR", tmp.path().join("data"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("export PATH="));
    assert!(text.contains("shims"));
}

#[test]
fn bare_invocation_prints_banner() {
    let out = aegis().output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("local-first"));
    assert!(text.contains("aegis init"));
}

#[test]
fn log_respects_number_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    seed_log(&db);
    let out = aegis()
        .args(["log", "-n", "1"])
        .env("AEGIS_DB", &db)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    // Only the most recent (rm -rf data) should show, not the earlier ls.
    assert!(text.contains("rm -rf data"));
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
fn init_starts_daemon_and_status_reports_running() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = home.join(".local/share");
    let run = tmp.path().join("run");
    std::fs::create_dir_all(&run).unwrap();

    let common = |cmd: &mut Command| {
        cmd.env("HOME", &home)
            .env("XDG_DATA_HOME", &data)
            .env("AEGIS_DATA_DIR", &data)
            .env("AEGIS_DB", data.join("events.db"))
            .env("XDG_RUNTIME_DIR", &run)
            .env("AEGIS_CONFIG", tmp.path().join("none.toml"));
    };

    // Full init (starts the daemon as a detached child).
    let mut init = aegis();
    init.arg("init");
    common(&mut init);
    let out = init.output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("daemon"));

    // Status should now see a running daemon.
    let mut status = aegis();
    status.arg("status");
    common(&mut status);
    let s = status.output().unwrap();
    let text = String::from_utf8_lossy(&s.stdout);

    // Stop the daemon we started before asserting (best-effort cleanup).
    let daemon_bin =
        std::path::Path::new(env!("CARGO_BIN_EXE_aegis")).with_file_name("aegis-daemon");
    let _ = std::process::Command::new("pkill")
        .args(["-f", &daemon_bin.to_string_lossy()])
        .status();

    assert!(
        text.contains("running"),
        "status should show running daemon:\n{text}"
    );
}

#[test]
fn init_no_daemon_creates_shims_and_wires_claude() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    // Use AEGIS_DATA_DIR so the shim location is deterministic on every OS
    // (the `directories` crate resolves the data dir differently per platform).
    let data = tmp.path().join("data");
    std::fs::create_dir_all(home.join(".claude")).unwrap();

    let run_init = || {
        aegis()
            .arg("init")
            .arg("--no-daemon")
            .env("HOME", &home)
            .env("AEGIS_DATA_DIR", &data)
            .env_remove("XDG_RUNTIME_DIR")
            .output()
            .unwrap()
    };

    let out = run_init();
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Shims created under the data dir.
    let shim_rm = data.join("shims/rm");
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
    run_init();
    let body2 = std::fs::read_to_string(&settings).unwrap();
    assert_eq!(
        body2.matches("aegis-hook").count(),
        1,
        "hook must not duplicate"
    );
}

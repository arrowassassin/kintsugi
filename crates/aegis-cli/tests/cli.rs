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
fn run_without_daemon_errors() {
    let tmp = tempfile::tempdir().unwrap();
    // No daemon → `aegis run` should fail cleanly (non-zero), not panic.
    let out = aegis()
        .args(["run", "abc"])
        .env("AEGIS_SOCKET", tmp.path().join("none.sock"))
        .env("AEGIS_DB", tmp.path().join("e.db"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("daemon"));
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
    let tmp = tempfile::tempdir().unwrap();
    // Point at a dead socket + clean data dir so the banner deterministically
    // reports "not running" and suggests `aegis init`.
    let out = aegis()
        .env("AEGIS_SOCKET", tmp.path().join("none.sock"))
        .env("AEGIS_DB", tmp.path().join("events.db"))
        .env("AEGIS_DATA_DIR", tmp.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("local-first"));
    assert!(text.contains("not running"));
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
    // Page 1 (newest first) shows only the most recent (rm -rf data).
    assert!(text.contains("rm -rf data"));
    // Footer reflects the total and links to the older page.
    assert!(text.contains("of 2"), "footer should show total:\n{text}");
    assert!(
        text.contains("--page 2"),
        "footer should link older page:\n{text}"
    );
}

#[test]
fn log_pagination_shows_older_page() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    seed_log(&db); // 2 events: ls (older), rm -rf data (newer)
    let out = aegis()
        .args(["log", "-n", "1", "--page", "2"])
        .env("AEGIS_DB", &db)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    // Page 2 is the older event (ls), not the newest.
    assert!(
        text.contains("ls"),
        "page 2 should show the older ls:\n{text}"
    );
    assert!(
        !text.contains("rm -rf data"),
        "newest is on page 1, not 2:\n{text}"
    );
    assert!(
        text.contains("--page 1"),
        "should link back to the newer page"
    );

    // Paging past the end is graceful, not an empty-state lie.
    let past = aegis()
        .args(["log", "-n", "1", "--page", "9"])
        .env("AEGIS_DB", &db)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(past.status.success());
    assert!(String::from_utf8_lossy(&past.stdout).contains("no events on page 9"));
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

    // Status should now see a running daemon. Poll: the daemon binds
    // asynchronously and a loaded CI runner can be slow — 5s wasn't enough
    // on the Ubuntu runner under contention, so give it ~20s.
    let mut text = String::new();
    for _ in 0..200 {
        let mut status = aegis();
        status.arg("status");
        common(&mut status);
        text = String::from_utf8_lossy(&status.output().unwrap().stdout).into_owned();
        if text.contains("running") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Stop the daemon WE started by its recorded PID — not a broad `pkill`, which
    // would also kill daemons spawned by parallel test binaries.
    if let Ok(pid) = std::fs::read_to_string(data.join("aegis.pid")) {
        let _ = std::process::Command::new("kill").arg(pid.trim()).status();
    }

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

#[test]
fn init_wires_every_supported_cli_natively() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    // Create each CLI's config dir so detection fires for all of them.
    for dir in [
        ".claude", ".qwen", ".gemini", ".copilot", ".cursor", ".codex",
    ] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    std::fs::create_dir_all(home.join(".config/opencode")).unwrap();

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

    // Each CLI got its native config, with the right per-agent --agent flag and
    // the right event/structure for that CLI.
    let read = |p: &str| std::fs::read_to_string(home.join(p)).unwrap_or_default();

    let claude = read(".claude/settings.json");
    assert!(
        claude.contains("PreToolUse") && claude.contains("--agent claude"),
        "claude:\n{claude}"
    );

    let qwen = read(".qwen/settings.json");
    assert!(
        qwen.contains("PreToolUse") && qwen.contains("--agent qwen"),
        "qwen:\n{qwen}"
    );

    let gemini = read(".gemini/settings.json");
    assert!(
        gemini.contains("BeforeTool") && gemini.contains("--agent gemini"),
        "gemini:\n{gemini}"
    );

    let copilot = read(".copilot/hooks/aegis.json");
    assert!(
        copilot.contains("preToolUse") && copilot.contains("--agent copilot"),
        "copilot:\n{copilot}"
    );

    let cursor = read(".cursor/hooks.json");
    assert!(
        cursor.contains("beforeShellExecution") && cursor.contains("--agent cursor"),
        "cursor:\n{cursor}"
    );

    let codex = read(".codex/config.toml");
    assert!(
        codex.contains("PreToolUse") && codex.contains("--agent codex"),
        "codex:\n{codex}"
    );

    let opencode = read(".config/opencode/plugin/aegis.js");
    assert!(
        opencode.contains("tool.execute.before") && opencode.contains("--agent"),
        "opencode:\n{opencode}"
    );

    // Idempotent across the board: a second init duplicates nothing.
    run_init();
    for (p, needle) in [
        (".qwen/settings.json", "--agent qwen"),
        (".gemini/settings.json", "--agent gemini"),
        (".cursor/hooks.json", "--agent cursor"),
        (".codex/config.toml", "--agent codex"),
    ] {
        let body = read(p);
        assert_eq!(body.matches(needle).count(), 1, "{p} duplicated:\n{body}");
    }
}

#[test]
fn test_command_is_a_dry_run_classifier() {
    // Catastrophic, shown without running or contacting a daemon.
    let out = aegis()
        .args(["test", "rm -rf /"])
        .env("AEGIS_SOCKET", "/nonexistent/aegis.sock")
        .output()
        .unwrap();
    assert!(out.status.success());
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(t.contains("CATASTROPHIC"), "{t}");
    assert!(t.contains("Dry run"), "{t}");

    // Safe.
    let safe = aegis().args(["test", "git status"]).output().unwrap();
    assert!(String::from_utf8_lossy(&safe.stdout).contains("SAFE"));

    // The AST pass surfaces danger hidden in a command substitution.
    let sub = aegis()
        .args(["test", "echo \"$(git push --force)\""])
        .output()
        .unwrap();
    let st = String::from_utf8_lossy(&sub.stdout);
    assert!(
        st.contains("CATASTROPHIC"),
        "substitution should be caught:\n{st}"
    );
}

/// Drives a live daemon through `aegis queue` and the `aegis run` branches, to
/// cover the queue/run handlers (which only exercise meaningfully against a real
/// daemon + queued items). Linux-only: it relies on `setsid` to run `aegis run`
/// in a session with no controlling terminal, so the catastrophic confirmation
/// (`/dev/tty`) declines deterministically instead of blocking on input.
#[cfg(target_os = "linux")]
#[test]
fn run_and_queue_against_live_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = home.join(".local/share");
    let run = tmp.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    let db = data.join("events.db");
    let cfg = tmp.path().join("none.toml");

    let common = |cmd: &mut Command| {
        cmd.env("HOME", &home)
            .env("XDG_DATA_HOME", &data)
            .env("AEGIS_DATA_DIR", &data)
            .env("AEGIS_DB", &db)
            .env("XDG_RUNTIME_DIR", &run)
            .env("AEGIS_CONFIG", &cfg)
            .env("NO_COLOR", "1");
    };

    // Start the daemon (detached child) and wait for it to bind.
    let mut init = aegis();
    init.arg("init");
    common(&mut init);
    assert!(init.output().unwrap().status.success());
    let mut up = false;
    for _ in 0..200 {
        let mut s = aegis();
        s.arg("status");
        common(&mut s);
        if String::from_utf8_lossy(&s.output().unwrap().stdout).contains("running") {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(up, "daemon should be running");

    // Enqueue two held commands into the daemon's DB: one from a hook (no waiter
    // → `aegis run`) and one in-band from MCP (a waiter → `aegis approve`).
    let (hook_id, mcp_id, deny_id);
    {
        let log = EventLog::open(&db).unwrap();
        let hook = ProposedCommand::new(
            "claude-code",
            "/tmp/proj",
            vec!["rm".into(), "-rf".into(), "build".into()],
            "rm -rf build",
        );
        hook_id = hook.id.to_string();
        log.enqueue_pending(&hook, Class::Catastrophic, "rm:recursive")
            .unwrap();
        let mcp = ProposedCommand::new(
            "mcp",
            "/tmp/proj",
            vec!["rm".into(), "-rf".into(), "dist".into()],
            "rm -rf dist",
        );
        mcp_id = mcp.id.to_string();
        log.enqueue_pending(&mcp, Class::Catastrophic, "rm:recursive")
            .unwrap();
        let extra = ProposedCommand::new(
            "shim",
            "/tmp/proj",
            vec!["rm".into(), "-rf".into(), "tmp".into()],
            "rm -rf tmp",
        );
        deny_id = extra.id.to_string();
        log.enqueue_pending(&extra, Class::Catastrophic, "rm:recursive")
            .unwrap();
    }

    let kill = || {
        if let Ok(pid) = std::fs::read_to_string(data.join("aegis.pid")) {
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
    };

    // `aegis queue` lists both and shows the origin-aware verbs.
    let mut q = aegis();
    q.arg("queue");
    common(&mut q);
    let qt = String::from_utf8_lossy(&q.output().unwrap().stdout).into_owned();

    // `aegis run <mcp>` → in-band, redirected to approve (bails non-zero).
    let mut r1 = aegis();
    r1.args(["run", &mcp_id[..8]]);
    common(&mut r1);
    let r1o = r1.output().unwrap();
    let r1t = String::from_utf8_lossy(&r1o.stderr).into_owned();

    // `aegis run` with no id and 2 held → asks for an id (bails non-zero).
    let mut r2 = aegis();
    r2.arg("run");
    common(&mut r2);
    let r2o = r2.output().unwrap();
    let r2t = String::from_utf8_lossy(&r2o.stderr).into_owned();

    // `setsid aegis run <hook>` → no controlling tty → the confirmation declines
    // and nothing runs (covers the run-plan print + reversibility note + confirm).
    let mut r3 = Command::new("setsid");
    r3.arg(env!("CARGO_BIN_EXE_aegis"))
        .args(["run", &hook_id[..8]])
        .stdin(std::process::Stdio::null());
    common(&mut r3);
    let r3o = r3.output().unwrap();
    let r3t = String::from_utf8_lossy(&r3o.stdout).into_owned();

    // `aegis run <unknown>` while the queue is non-empty → no match (bails).
    let mut r4 = aegis();
    r4.args(["run", "zzzzzzzz"]);
    common(&mut r4);
    let r4o = r4.output().unwrap();
    let r4t = String::from_utf8_lossy(&r4o.stderr).into_owned();

    // Approve both, exercising the origin-aware messages: hook (use `aegis run`)
    // and in-band MCP (the agent may proceed).
    let mut a1 = aegis();
    a1.args(["approve", &hook_id[..8]]);
    common(&mut a1);
    let a1t = String::from_utf8_lossy(&a1.output().unwrap().stdout).into_owned();
    let mut a2 = aegis();
    a2.args(["approve", &mcp_id[..8]]);
    common(&mut a2);
    let a2t = String::from_utf8_lossy(&a2.output().unwrap().stdout).into_owned();

    // Deny the third (covers the deny branch).
    let mut d1 = aegis();
    d1.args(["deny", &deny_id[..8]]);
    common(&mut d1);
    let d1t = String::from_utf8_lossy(&d1.output().unwrap().stdout).into_owned();

    // Queue now empty → `aegis run` and `aegis queue` both say so.
    let mut r5 = aegis();
    r5.arg("run");
    common(&mut r5);
    let r5t = String::from_utf8_lossy(&r5.output().unwrap().stdout).into_owned();
    let mut q2 = aegis();
    q2.arg("queue");
    common(&mut q2);
    let q2t = String::from_utf8_lossy(&q2.output().unwrap().stdout).into_owned();

    // approve of an unknown id → clean error (covers the no-match arm).
    let mut au = aegis();
    au.args(["approve", "zzzzzzzz"]);
    common(&mut au);
    let auo = au.output().unwrap();

    kill();

    assert!(
        qt.contains("rm -rf build"),
        "queue lists the hook cmd:\n{qt}"
    );
    assert!(
        qt.contains("aegis run") && qt.contains("aegis approve"),
        "queue shows both verbs:\n{qt}"
    );
    assert!(
        !r1o.status.success() && r1t.contains("approve"),
        "in-band run redirects to approve:\n{r1t}"
    );
    assert!(
        !r2o.status.success() && r2t.contains("held"),
        "no-id with many held asks for an id:\n{r2t}"
    );
    assert!(
        r3t.contains("rm -rf build") && r3t.contains("Not run"),
        "no-tty run shows the plan and declines:\n{r3t}"
    );
    assert!(
        !r4o.status.success() && r4t.contains("no held command"),
        "unknown id:\n{r4t}"
    );
    assert!(
        a1t.contains("aegis run"),
        "hook approve points at run:\n{a1t}"
    );
    assert!(
        a2t.contains("proceed"),
        "in-band approve lets the agent proceed:\n{a2t}"
    );
    assert!(d1t.contains("denied"), "deny reports denied:\n{d1t}");
    assert!(r5t.contains("empty"), "empty queue run:\n{r5t}");
    assert!(q2t.contains("empty"), "empty queue listing:\n{q2t}");
    assert!(!auo.status.success(), "approve of unknown id errors");
}

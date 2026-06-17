//! P0.7 acceptance: `kintsugi log` shows recorded events, `kintsugi status` reports the
//! log, and `kintsugi init` wires interception. Unix-only for the symlink checks.
#![cfg(unix)]

use std::process::Command;

use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict};

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
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
    let out = kintsugi()
        .arg("undo")
        .env("KINTSUGI_DB", tmp.path().join("events.db"))
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
        let manifest = kintsugi_core::capture_snapshot(&snaps, &cmd)
            .unwrap()
            .unwrap();
        log.record_snapshot(&manifest).unwrap();
    }
    std::fs::write(&file, b"corrupted").unwrap();

    let out = kintsugi()
        .arg("undo")
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
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
    let out2 = kintsugi()
        .arg("undo")
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out2.stdout).contains("Nothing to undo"));
}

#[test]
fn enforce_shell_install_status_remove_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let etc = tmp.path().join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    let common = |c: &mut Command| {
        c.env("KINTSUGI_DATA_DIR", tmp.path())
            .env("KINTSUGI_DB", tmp.path().join("events.db"))
            .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
            // Vault path under our temp dir → "unprovisioned" so removal isn't
            // gated on a password we'd need to type. Honest scope is tested
            // separately in admin_cmd's vault flows.
            .env("KINTSUGI_VAULT", tmp.path().join("vault.bin"))
            .env("KINTSUGI_ETC_DIR", &etc)
            .env("NO_COLOR", "1");
    };

    // Off by default.
    let mut s = kintsugi();
    s.args(["admin", "enforce-shell", "--status"]);
    common(&mut s);
    let out = s.output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("off"));

    // Install — writes the managed block.
    let mut i = kintsugi();
    i.args(["admin", "enforce-shell"]);
    common(&mut i);
    let out = i.output().unwrap();
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let zshenv = std::fs::read_to_string(etc.join("zshenv")).unwrap();
    assert!(zshenv.contains("kintsugi enforced shell wiring"));
    assert!(
        zshenv.contains("shims"),
        "wiring should reference the shim dir"
    );

    // Status now reports on, and `kintsugi status` surfaces it too.
    let mut st = kintsugi();
    st.arg("status");
    common(&mut st);
    let out = st.output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    // Root-owned (CI-as-root) shows "enforced system-wide"; a user-owned temp
    // /etc shows "wiring present but NOT root-owned". Either proves status saw it.
    assert!(
        s.contains("enforced system-wide") || s.contains("wiring present"),
        "kintsugi status should surface shell enforcement, got:\n{s}"
    );

    // Remove — vault is unprovisioned, so it proceeds without a password prompt.
    let mut r = kintsugi();
    r.args(["admin", "enforce-shell", "--remove"]);
    common(&mut r);
    let out = r.output().unwrap();
    assert!(out.status.success());
    let zshenv = std::fs::read_to_string(etc.join("zshenv")).unwrap();
    assert!(
        !zshenv.contains("kintsugi enforced"),
        "block should be gone"
    );
}

#[test]
fn status_reports_backstop_off_and_shim_drift() {
    let tmp = tempfile::tempdir().unwrap();
    // The shim dir exists but is deliberately not on PATH → loud drift warning.
    std::fs::create_dir_all(tmp.path().join("shims")).unwrap();
    let out = kintsugi()
        .arg("status")
        .env("KINTSUGI_DATA_DIR", tmp.path())
        .env("KINTSUGI_DB", tmp.path().join("events.db"))
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("PATH", "/usr/bin:/bin")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("backstop: off"), "got:\n{s}");
    assert!(s.contains("NOT on PATH"), "got:\n{s}");
}

#[test]
fn status_reports_backstop_on_from_a_live_pid_file() {
    let tmp = tempfile::tempdir().unwrap();
    // watch.pid sits next to the daemon pid (KINTSUGI_DB's parent). Point it at
    // this test process, which is alive, so the backstop reads as on.
    std::fs::write(
        tmp.path().join("watch.pid"),
        format!(
            "{}\n{}\n",
            std::process::id(),
            tmp.path().join("repo").display()
        ),
    )
    .unwrap();
    let out = kintsugi()
        .arg("status")
        .env("KINTSUGI_DATA_DIR", tmp.path())
        .env("KINTSUGI_DB", tmp.path().join("events.db"))
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("backstop: watching"), "got:\n{s}");
}

#[test]
fn stop_kills_the_backstop_watcher() {
    let tmp = tempfile::tempdir().unwrap();
    // A stand-in long-running watcher process.
    let mut child = Command::new("sleep").arg("60").spawn().unwrap();
    std::fs::write(
        tmp.path().join("watch.pid"),
        format!("{}\n{}\n", child.id(), tmp.path().display()),
    )
    .unwrap();

    let out = kintsugi()
        .arg("stop")
        .env("KINTSUGI_DATA_DIR", tmp.path())
        .env("KINTSUGI_DB", tmp.path().join("events.db"))
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("backstop watcher"), "got:\n{s}");
    assert!(
        !tmp.path().join("watch.pid").exists(),
        "watch.pid should be removed"
    );
    // Reap the (now-terminated) stand-in process.
    let _ = child.wait();
}

#[test]
fn guard_forwards_exit_code_and_prepends_shim_to_path() {
    let tmp = tempfile::tempdir().unwrap();
    let common = |c: &mut Command| {
        c.env("KINTSUGI_DATA_DIR", tmp.path())
            .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
            .env("KINTSUGI_NO_AUTOSTART", "1") // don't spawn a daemon in the test
            .env("NO_COLOR", "1");
    };

    // The child's exit code is forwarded faithfully.
    let mut exit7 = kintsugi();
    exit7.args(["guard", "--", "sh", "-c", "exit 7"]);
    common(&mut exit7);
    assert_eq!(exit7.output().unwrap().status.code(), Some(7));

    // The child sees the shim dir at the front of PATH.
    let mut showpath = kintsugi();
    showpath.args(["guard", "--", "sh", "-c", "printf %s \"$PATH\""]);
    common(&mut showpath);
    let out = showpath.output().unwrap();
    let path = String::from_utf8_lossy(&out.stdout);
    let shim = tmp.path().join("shims");
    assert!(
        path.starts_with(&shim.display().to_string()),
        "shim dir should be first on PATH, got: {path}"
    );
}

#[test]
fn guard_requires_a_command() {
    let out = kintsugi().arg("guard").output().unwrap();
    // clap rejects the missing required trailing arg with a non-zero exit.
    assert!(!out.status.success());
}

#[test]
fn dry_run_flags_dangerous_commands_from_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = kintsugi()
        .arg("dry-run")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"git status\nrm -rf ./build\ncargo test\ngit push --force\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("dry-run"));
    assert!(s.contains("would have been held or blocked"));
    assert!(s.contains("rm -rf ./build"));
    assert!(s.contains("git push --force"));
}

#[test]
fn dry_run_redacts_secrets_before_printing() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = kintsugi()
        .arg("dry-run")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"PGPASSWORD=hunter2 rm -rf /var/data\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("hunter2"),
        "a secret leaked into dry-run output"
    );
    assert!(s.contains("[redacted]"));
}

#[test]
fn version_reports_the_bumped_number() {
    // Guards against the release-hygiene bug where the tag is cut without bumping
    // the crate version (so the binary self-reports a stale number).
    let out = kintsugi().arg("--version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("0.1.5"), "version should be 0.1.5, got: {s}");
}

#[test]
fn limits_prints_the_honest_threat_scope() {
    let out = kintsugi().arg("limits").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("seatbelt"));
    assert!(s.contains("undo cannot bring back"));
    assert!(s.contains("admin-lock"));
}

#[test]
fn queue_without_daemon_is_graceful() {
    let tmp = tempfile::tempdir().unwrap();
    let out = kintsugi()
        .arg("queue")
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("KINTSUGI_DB", tmp.path().join("e.db"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("isn't running"));
}

#[test]
fn run_without_daemon_errors() {
    let tmp = tempfile::tempdir().unwrap();
    // No daemon → `kintsugi run` should fail cleanly (non-zero), not panic.
    let out = kintsugi()
        .args(["run", "abc"])
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("KINTSUGI_DB", tmp.path().join("e.db"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("daemon"));
}

#[test]
fn approve_unknown_prefix_errors() {
    let tmp = tempfile::tempdir().unwrap();
    // No daemon → the command should fail cleanly (non-zero), not panic.
    let out = kintsugi()
        .args(["approve", "abc"])
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("KINTSUGI_DB", tmp.path().join("e.db"))
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn panic_engages_and_resume_clears_kill_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    let common = |c: &mut Command| {
        c.env("KINTSUGI_DB", &db)
            .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
            .env("NO_COLOR", "1");
    };

    let mut p = kintsugi();
    p.arg("panic");
    common(&mut p);
    let out = p.output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("ENGAGED"));
    assert!(tmp.path().join("panic.flag").exists());

    // status reflects it.
    let mut s = kintsugi();
    s.arg("status");
    common(&mut s);
    let st = s.output().unwrap();
    assert!(String::from_utf8_lossy(&st.stdout).contains("KILL-SWITCH"));

    let mut r = kintsugi();
    r.arg("resume");
    common(&mut r);
    let out = r.output().unwrap();
    assert!(out.status.success());
    assert!(!tmp.path().join("panic.flag").exists());
}

#[test]
fn model_use_status_remove_round_trip() {
    // No daemon running here, so `model use` persists the selection and tells the
    // user to start the daemon (rather than spawning one as a side effect).
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let model = tmp.path().join("my.gguf");
    std::fs::write(&model, b"fake-weights").unwrap();

    let common = |c: &mut Command| {
        c.env("KINTSUGI_DATA_DIR", &data)
            .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
            .env_remove("KINTSUGI_MODEL_FILE");
    };

    // use: writes the config file and reports the path.
    let mut u = kintsugi();
    u.args(["model", "use"]).arg(&model);
    common(&mut u);
    let out = u.output().unwrap();
    assert!(out.status.success(), "model use failed: {out:?}");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("model set to"), "use output: {s}");
    assert!(data.join("model.path").is_file(), "config not written");

    // status: reflects the configured model and that no engine is built.
    let mut st = kintsugi();
    st.args(["model", "status"]);
    common(&mut st);
    let out = st.output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("configured:"), "status output: {s}");
    assert!(s.contains("my.gguf"), "status should show the model: {s}");

    // remove: clears the selection.
    let mut rm = kintsugi();
    rm.args(["model", "remove"]);
    common(&mut rm);
    let out = rm.output().unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cleared the configured model"),
        "remove should confirm"
    );
    assert!(!data.join("model.path").exists(), "config not cleared");
}

#[test]
fn model_use_rejects_a_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let out = kintsugi()
        .args(["model", "use"])
        .arg(tmp.path().join("nope.gguf"))
        .env("KINTSUGI_DATA_DIR", tmp.path().join("data"))
        .output()
        .unwrap();
    assert!(!out.status.success(), "a missing file must be rejected");
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a readable file"));
}

#[test]
fn init_print_path_emits_export_line() {
    let tmp = tempfile::tempdir().unwrap();
    let out = kintsugi()
        .args(["init", "--print-path"])
        .env("KINTSUGI_DATA_DIR", tmp.path().join("data"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("export PATH="));
    assert!(text.contains("shims"));
}

#[test]
fn init_tailors_guidance_by_profile() {
    // Personal (default) posture: focused safety-net guidance, no admin machinery.
    let tmp = tempfile::tempdir().unwrap();
    let personal = kintsugi()
        .args(["init", "--no-daemon"])
        .env("HOME", tmp.path())
        .env("KINTSUGI_DATA_DIR", tmp.path().join("data"))
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .output()
        .unwrap();
    assert!(personal.status.success());
    let p = String::from_utf8_lossy(&personal.stdout);
    assert!(p.contains("You're protected"), "personal guidance: {p}");
    assert!(
        p.contains("--enterprise"),
        "should hint the enterprise posture"
    );
    assert!(
        !p.contains("admin provision"),
        "personal must not push admin steps"
    );

    // Enterprise posture: the managed-control next steps.
    let tmp2 = tempfile::tempdir().unwrap();
    let ent = kintsugi()
        .args(["init", "--no-daemon", "--enterprise"])
        .env("HOME", tmp2.path())
        .env("KINTSUGI_DATA_DIR", tmp2.path().join("data"))
        .env("KINTSUGI_SOCKET", tmp2.path().join("none.sock"))
        .output()
        .unwrap();
    assert!(ent.status.success());
    let e = String::from_utf8_lossy(&ent.stdout);
    assert!(e.contains("Enterprise setup"), "enterprise guidance: {e}");
    assert!(e.contains("admin provision"));
    assert!(e.contains("service install"));
    assert!(e.contains("record install"));
}

#[test]
fn bare_invocation_prints_banner() {
    let tmp = tempfile::tempdir().unwrap();
    // Point at a dead socket + clean data dir so the banner deterministically
    // reports "not running" and suggests `kintsugi init`.
    let out = kintsugi()
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
        .env("KINTSUGI_DB", tmp.path().join("events.db"))
        .env("KINTSUGI_DATA_DIR", tmp.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("local-first"));
    assert!(text.contains("not running"));
    assert!(text.contains("kintsugi init"));
}

#[test]
fn log_respects_number_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    seed_log(&db);
    let out = kintsugi()
        .args(["log", "-n", "1"])
        .env("KINTSUGI_DB", &db)
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
    let out = kintsugi()
        .args(["log", "-n", "1", "--page", "2"])
        .env("KINTSUGI_DB", &db)
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
    let past = kintsugi()
        .args(["log", "-n", "1", "--page", "9"])
        .env("KINTSUGI_DB", &db)
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

    let out = kintsugi()
        .arg("log")
        .env("KINTSUGI_DB", &db)
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
    let out = kintsugi()
        .arg("log")
        .env("KINTSUGI_DB", tmp.path().join("missing.db"))
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

    let out = kintsugi()
        .arg("status")
        .env("KINTSUGI_DB", &db)
        // Point the socket somewhere unconnectable so daemon shows "stopped".
        .env("KINTSUGI_SOCKET", tmp.path().join("none.sock"))
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
            .env("KINTSUGI_DATA_DIR", &data)
            .env("KINTSUGI_DB", data.join("events.db"))
            .env("XDG_RUNTIME_DIR", &run)
            // Don't spawn the default-on backstop watcher in this test (it would
            // watch the crate's working dir and linger as a stray process).
            .env("KINTSUGI_NO_WATCH", "1")
            .env("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    };

    // Full init (starts the daemon as a detached child).
    let mut init = kintsugi();
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
        let mut status = kintsugi();
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
    if let Ok(pid) = std::fs::read_to_string(data.join("kintsugi.pid")) {
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
    // Use KINTSUGI_DATA_DIR so the shim location is deterministic on every OS
    // (the `directories` crate resolves the data dir differently per platform).
    let data = tmp.path().join("data");
    std::fs::create_dir_all(home.join(".claude")).unwrap();

    let run_init = || {
        kintsugi()
            .arg("init")
            .arg("--no-daemon")
            .env("HOME", &home)
            .env("KINTSUGI_DATA_DIR", &data)
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
        body.contains("kintsugi-hook"),
        "settings should reference kintsugi-hook:\n{body}"
    );
    assert!(body.contains("PreToolUse"));

    // Idempotent: running again does not duplicate the hook.
    run_init();
    let body2 = std::fs::read_to_string(&settings).unwrap();
    assert_eq!(
        body2.matches("kintsugi-hook").count(),
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
        kintsugi()
            .arg("init")
            .arg("--no-daemon")
            .env("HOME", &home)
            .env("KINTSUGI_DATA_DIR", &data)
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

    let copilot = read(".copilot/hooks/kintsugi.json");
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

    let opencode = read(".config/opencode/plugin/kintsugi.js");
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
    let out = kintsugi()
        .args(["test", "rm -rf /"])
        .env("KINTSUGI_SOCKET", "/nonexistent/kintsugi.sock")
        .output()
        .unwrap();
    assert!(out.status.success());
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(t.contains("CATASTROPHIC"), "{t}");
    assert!(t.contains("Dry run"), "{t}");

    // Safe.
    let safe = kintsugi().args(["test", "git status"]).output().unwrap();
    assert!(String::from_utf8_lossy(&safe.stdout).contains("SAFE"));

    // The AST pass surfaces danger hidden in a command substitution.
    let sub = kintsugi()
        .args(["test", "echo \"$(git push --force)\""])
        .output()
        .unwrap();
    let st = String::from_utf8_lossy(&sub.stdout);
    assert!(
        st.contains("CATASTROPHIC"),
        "substitution should be caught:\n{st}"
    );
}

/// Drives a live daemon through `kintsugi queue` and the `kintsugi run` branches, to
/// cover the queue/run handlers (which only exercise meaningfully against a real
/// daemon + queued items). Linux-only: it relies on `setsid` to run `kintsugi run`
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
            .env("KINTSUGI_DATA_DIR", &data)
            .env("KINTSUGI_DB", &db)
            .env("XDG_RUNTIME_DIR", &run)
            .env("KINTSUGI_CONFIG", &cfg)
            .env("NO_COLOR", "1");
    };

    // Start the daemon (detached child) and wait for it to bind.
    let mut init = kintsugi();
    init.arg("init");
    common(&mut init);
    assert!(init.output().unwrap().status.success());
    let mut up = false;
    for _ in 0..200 {
        let mut s = kintsugi();
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
    // → `kintsugi run`) and one in-band from MCP (a waiter → `kintsugi approve`).
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
        if let Ok(pid) = std::fs::read_to_string(data.join("kintsugi.pid")) {
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
    };

    // `kintsugi queue` lists both and shows the origin-aware verbs.
    let mut q = kintsugi();
    q.arg("queue");
    common(&mut q);
    let qt = String::from_utf8_lossy(&q.output().unwrap().stdout).into_owned();

    // `kintsugi run <mcp>` → in-band, redirected to approve (bails non-zero).
    let mut r1 = kintsugi();
    r1.args(["run", &mcp_id[..8]]);
    common(&mut r1);
    let r1o = r1.output().unwrap();
    let r1t = String::from_utf8_lossy(&r1o.stderr).into_owned();

    // `kintsugi run` with no id and 2 held → asks for an id (bails non-zero).
    let mut r2 = kintsugi();
    r2.arg("run");
    common(&mut r2);
    let r2o = r2.output().unwrap();
    let r2t = String::from_utf8_lossy(&r2o.stderr).into_owned();

    // `setsid kintsugi run <hook>` → no controlling tty → the confirmation declines
    // and nothing runs (covers the run-plan print + reversibility note + confirm).
    let mut r3 = Command::new("setsid");
    r3.arg(env!("CARGO_BIN_EXE_kintsugi"))
        .args(["run", &hook_id[..8]])
        .stdin(std::process::Stdio::null());
    common(&mut r3);
    let r3o = r3.output().unwrap();
    let r3t = String::from_utf8_lossy(&r3o.stdout).into_owned();

    // `kintsugi run <unknown>` while the queue is non-empty → no match (bails).
    let mut r4 = kintsugi();
    r4.args(["run", "zzzzzzzz"]);
    common(&mut r4);
    let r4o = r4.output().unwrap();
    let r4t = String::from_utf8_lossy(&r4o.stderr).into_owned();

    // Approve both, exercising the origin-aware messages: hook (use `kintsugi run`)
    // and in-band MCP (the agent may proceed).
    let mut a1 = kintsugi();
    a1.args(["approve", &hook_id[..8]]);
    common(&mut a1);
    let a1t = String::from_utf8_lossy(&a1.output().unwrap().stdout).into_owned();
    let mut a2 = kintsugi();
    a2.args(["approve", &mcp_id[..8]]);
    common(&mut a2);
    let a2t = String::from_utf8_lossy(&a2.output().unwrap().stdout).into_owned();

    // Deny the third (covers the deny branch).
    let mut d1 = kintsugi();
    d1.args(["deny", &deny_id[..8]]);
    common(&mut d1);
    let d1t = String::from_utf8_lossy(&d1.output().unwrap().stdout).into_owned();

    // Queue now empty → `kintsugi run` and `kintsugi queue` both say so.
    let mut r5 = kintsugi();
    r5.arg("run");
    common(&mut r5);
    let r5t = String::from_utf8_lossy(&r5.output().unwrap().stdout).into_owned();
    let mut q2 = kintsugi();
    q2.arg("queue");
    common(&mut q2);
    let q2t = String::from_utf8_lossy(&q2.output().unwrap().stdout).into_owned();

    // approve of an unknown id → clean error (covers the no-match arm).
    let mut au = kintsugi();
    au.args(["approve", "zzzzzzzz"]);
    common(&mut au);
    let auo = au.output().unwrap();

    kill();

    assert!(
        qt.contains("rm -rf build"),
        "queue lists the hook cmd:\n{qt}"
    );
    assert!(
        qt.contains("kintsugi run") && qt.contains("kintsugi approve"),
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
        a1t.contains("kintsugi run"),
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

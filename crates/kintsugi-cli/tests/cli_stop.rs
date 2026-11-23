//! End-to-end: `kintsugi stop` against a REAL running daemon.
//!
//! In its own test binary (the cli_queue.rs pattern) so its process-global env
//! — the shared socket/db the test uses to poll daemon readiness — can't
//! contaminate the parallel tests in cli.rs. The nothing-to-stop failure mode
//! and the backstop-watcher cleanup are covered in cli.rs / log_admin.rs / admin.rs.
#![cfg(unix)]

use std::process::Command;

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
}

#[test]
fn stop_with_running_daemon_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("a.sock");
    let db = tmp.path().join("e.db");
    let config = tmp.path().join("none.toml");
    // The test process shares the daemon's socket/db so it can poll readiness.
    std::env::set_var("KINTSUGI_SOCKET", &sock);
    std::env::set_var("KINTSUGI_DB", &db);

    // Start the real daemon binary (sibling of the `kintsugi` test binary).
    // The vault override goes to the daemon too, so the SHUTDOWN handshake sees
    // the same unprovisioned vault as the CLI below — otherwise a provisioned
    // host would make the daemon demand a password proof the CLI can't give.
    let daemon_bin =
        std::path::Path::new(env!("CARGO_BIN_EXE_kintsugi")).with_file_name("kintsugi-daemon");
    let mut daemon = Command::new(&daemon_bin)
        .env("KINTSUGI_SOCKET", &sock)
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_CONFIG", &config)
        .env("KINTSUGI_VAULT", tmp.path().join("absent-vault.json"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if kintsugi_daemon::Client::is_daemon_running() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        kintsugi_daemon::Client::is_daemon_running(),
        "daemon should be up before we stop it"
    );

    // Success path (unchanged behavior): daemon running → stop → exit 0 with
    // a plain confirmation. No TTY is needed (absent vault → no proof prompt).
    let out = kintsugi()
        .arg("stop")
        .env("KINTSUGI_SOCKET", &sock)
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_VAULT", tmp.path().join("absent-vault.json"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stop with a running daemon must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("stopped the daemon"),
        "got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // It really stopped: the socket no longer answers.
    assert!(
        !kintsugi_daemon::Client::is_daemon_running(),
        "daemon should be down after stop"
    );

    // If the stop somehow failed, don't leak the daemon past the test.
    let _ = daemon.kill();
    let _ = daemon.wait();
}
